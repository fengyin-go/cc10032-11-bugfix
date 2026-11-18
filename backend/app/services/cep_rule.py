"""CEP规则领域服务：定义复杂事件处理的序列匹配规则。

增强能力: 规则语法校验、模式匹配验证、跳过策略评估、匹配结果输出到告警策略

匹配语义（序号11修复点）：
  * 滑动窗口按事件顺序贪心匹配，一次命中占用一个已消费窗口；
  * 窗口内事件整体消费，重叠事件不会再次进入同规则的下一次匹配；
  * 命中写入告警策略时按「规则 + 事件序列」签名幂等，重复执行不追加记录；
  * 写入走事务，失败时告警表回滚到原版本。
"""
from __future__ import annotations

from typing import Any

from app.services import cep_ledger
from app.services.base import BaseModuleService
from app.store import store


class CepRuleService(BaseModuleService):
    MODULE = "cep_rule"
    ENTITY = "事件序列"
    LIST_FIELDS = ["序列名称", "事件类型", "匹配顺序", "时间约束", "跳过策略", "动作输出", "最大跨度"]
    REQUIRED_FIELDS = ["序列名称", "事件类型", "匹配顺序"]
    STATUS_ORDER = ["草稿", "已部署", "运行中", "已停用"]
    ACTION_RULES = {"部署规则": "草稿", "停用规则": "运行中"}
    NEGATIVE_ACTIONS = ["停用规则"]

    def validate_rule_syntax(self, rule_name: str) -> dict[str, Any]:
        """校验CEP规则语法完整性。"""
        rule = None
        for r in store.rows(self.MODULE):
            if r.get("序列名称") == rule_name:
                rule = r
                break
        if rule is None:
            return {"ok": False, "error": f"CEP规则「{rule_name}」不存在"}

        checks = []
        event_types = [
            e.strip()
            for e in rule.get("事件类型", "").split(",")
            if e.strip()
        ]
        checks.append({"check": "event_types", "ok": len(event_types) >= 2, "detail": f"事件类型数: {len(event_types)}"})

        sequence = [
            s.strip()
            for s in rule.get("匹配顺序", "").split(",")
            if s.strip()
        ]
        checks.append({"check": "sequence_order", "ok": len(sequence) >= 2, "detail": f"匹配步骤: {len(sequence)}"})

        try:
            max_span = float(rule.get("最大跨度", "60"))
            checks.append({"check": "max_span", "ok": max_span > 0, "detail": f"最大跨度: {max_span}"})
        except (ValueError, TypeError):
            checks.append({"check": "max_span", "ok": False, "detail": "最大跨度格式错误"})

        return {
            "ok": all(c["ok"] for c in checks),
            "rule": rule_name,
            "checks": checks,
        }

    def match_and_alert(
        self, rule_name: str, events: list[dict[str, Any]],
        alert_rule_name: str | None = None,
    ) -> dict[str, Any]:
        """匹配CEP模式并把命中写入告警策略；同一序列重复执行保持幂等。"""
        rule = None
        for r in store.rows(self.MODULE):
            if r.get("序列名称") == rule_name:
                rule = r
                break
        if rule is None:
            return {"ok": False, "error": f"CEP规则「{rule_name}」不存在"}

        pattern = [
            p.strip()
            for p in rule.get("匹配顺序", "").split(",")
            if p.strip()
        ]
        event_types = [
            e.strip()
            for e in rule.get("事件类型", "").split(",")
            if e.strip()
        ]
        try:
            time_constraint = float(rule.get("时间约束", "60"))
        except (ValueError, TypeError):
            time_constraint = 60.0

        identity = cep_ledger.rule_identity(rule_name)
        # 已被本规则前序命中消费的事件不再参与匹配。
        already_consumed = cep_ledger.consumed_keys(identity)
        matches, skipped_consumed = cep_ledger.match_sequence(
            events, pattern, time_constraint, identity,
            consumed_keys=already_consumed,
        )

        target_rule = alert_rule_name or f"cep_{rule_name}"
        created = 0
        reused = 0
        skipped = 0
        alert_ids: list[int] = []
        try:
            # 整批命中一次性提交：任一条写入失败则整体回滚到原版本。
            with cep_ledger.transaction("alert_policy"):
                for match in matches:
                    outcome = cep_ledger.commit_hit(
                        match,
                        alert_rule_name=target_rule,
                        level="WARNING",
                        rule_row={
                            "事件类型": rule.get("事件类型", ""),
                            "沉默窗口": "60s",
                            "通知方式": "push",
                            "升级路径": "oncall",
                        },
                        origin="cep_rule.match_and_alert",
                    )
                    if outcome["created"]:
                        created += 1
                    elif outcome.get("skipped"):
                        # 并发场景下另一请求已先消费了同一窗口。
                        skipped += 1
                        continue
                    else:
                        reused += 1
                    alert_ids.append(outcome["alert_id"])
        except Exception as exc:  # 事务已回滚，返回可重试的失败结果
            return {
                "ok": False,
                "rule": rule_name,
                "errors": [str(exc)],
                "message": "CEP命中告警写入失败，告警表已回滚到原版本，可安全重试",
                "matches": 0,
                "created_alerts": 0,
                "reused_alerts": 0,
                "skipped_hits": 0,
                "alert_ids": [],
            }

        windows = len(matches) + skipped_consumed
        return {
            "ok": True,
            "rule": rule_name,
            "pattern": pattern,
            "event_types": event_types,
            "total_events": len(events),
            "matches": len(matches),
            "created_alerts": created,
            "reused_alerts": reused,
            "skipped_hits": skipped,
            "skipped_consumed_events": skipped_consumed,
            "alert_ids": alert_ids,
            # 候选窗口数：命中数 + 被已消费事件拦下的候选数
            "match_rate": len(matches) / max(windows, 1),
            "deduplicated": reused > 0 or skipped > 0,
            "consumed_windows": cep_ledger.consumed_windows(identity),
        }

    def list_consumed_windows(self, rule_name: str | None = None) -> dict[str, Any]:
        """列出已消费窗口：工作台据此确认哪些事件序列已被命中占用。"""
        if rule_name is not None:
            known = any(
                r.get("序列名称") == rule_name for r in store.rows(self.MODULE)
            )
            if not known:
                return {"ok": False, "error": f"CEP规则「{rule_name}」不存在"}
        snapshot = cep_ledger.consumed_windows(rule_name)
        snapshot["ok"] = True
        return snapshot

    def list_cep_alerts(self, rule_name: str | None = None) -> dict[str, Any]:
        """告警合并清单：只统计未被前序命中消费的事件对应的当前命中。"""
        return {
            "ok": True,
            "merge_list": cep_ledger.build_merge_list(rule_name),
            "retention_options": cep_ledger.describe_retention_options(),
        }

    def merge_cep_alerts(
        self, rule_name: str | None = None, policy: str | None = None,
    ) -> dict[str, Any]:
        """合并同规则重叠命中，保留一个当前版本。"""
        return cep_ledger.merge_hits(
            rule_name=rule_name,
            policy=policy or cep_ledger.DEFAULT_RETENTION,
        )

    def evaluate_skip_strategy(
        self, rule_name: str, match_count: int,
    ) -> dict[str, Any]:
        """评估跳过策略：连续匹配过多时触发跳过以避免洪水。"""
        rule = None
        for r in store.rows(self.MODULE):
            if r.get("序列名称") == rule_name:
                rule = r
                break
        if rule is None:
            return {"ok": False, "error": f"CEP规则「{rule_name}」不存在"}

        skip_strategy = rule.get("跳过策略", "SKIP_PAST_LAST")
        # 模拟评估
        should_skip = match_count > 100

        return {
            "ok": True,
            "rule": rule_name,
            "strategy": skip_strategy,
            "match_count": match_count,
            "should_skip": should_skip,
            "action": "skip_and_continue" if should_skip else "process_all",
        }

    def domain_snapshot(self) -> dict[str, Any]:
        base = super().domain_snapshot()
        rows = store.rows(self.MODULE)
        base["deployed"] = sum(1 for r in rows if r.get("status") == "已部署")
        base["running"] = sum(1 for r in rows if r.get("status") == "运行中")
        hits = cep_ledger.cep_hits()
        merge_list = cep_ledger.build_merge_list()
        base["cep_hits"] = len(hits)
        base["current_hits"] = sum(
            1 for row in hits if row.get("_cep_state", "current") == "current"
        )
        base["merged_hits"] = sum(
            1 for row in hits if row.get("_cep_state") == "merged"
        )
        base["consumed_events"] = merge_list["unique_event_count"]
        base["merge_list_size"] = merge_list["total"]
        base["duplicate_free"] = merge_list["duplicate_free"]
        return base