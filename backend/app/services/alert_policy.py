"""告警策略领域服务：定义实时计算结果的告警触发规则。

数据流角色: anomaly_detector / cep_rule → alert_policy（消费者+生产者）→ restore_plan（消费者）
增强能力: 告警升级路径、沉默窗口计算、通知分发、批量告警合并且入 restore_plan
"""
from __future__ import annotations

import time
from typing import Any

from app.services import cep_ledger
from app.services.base import BaseModuleService
from app.store import store


class AlertPolicyService(BaseModuleService):
    MODULE = "alert_policy"
    ENTITY = "告警规则"
    LIST_FIELDS = ["规则名称", "监控指标", "触发条件", "告警级别", "沉默窗口", "通知方式", "升级路径"]
    REQUIRED_FIELDS = ["规则名称", "监控指标", "触发条件"]
    STATUS_ORDER = ["草稿", "已启用", "已沉默", "已关闭"]
    ACTION_RULES = {"启用规则": "草稿", "关闭规则": "已启用"}
    NEGATIVE_ACTIONS = []

    LEVEL_ORDER = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "CRITICAL": 3}

    # ---- 跨模块数据消费与生产 ----

    def is_visible(self, row: dict[str, Any]) -> bool:
        """告警列表隐藏已合并的 CEP 旧版本，同一事件不会重复出现。

        被合并的记录仍留在台账里（供合并清单与恢复核对追溯），
        只是不再作为告警页面上的当前告警展示。
        """
        return row.get("_cep_state", "current") == "current"

    def evaluate_alert_condition(
        self, rule_name: str, metric_value: float,
    ) -> dict[str, Any]:
        """评估告警条件：解析条件表达式并与当前值比较。"""
        rule = None
        for r in store.rows(self.MODULE):
            if r.get("规则名称") == rule_name:
                rule = r
                break
        if rule is None:
            return {"ok": False, "error": f"告警规则「{rule_name}」不存在"}
        if rule.get("status") in ("已关闭", "已沉默"):
            return {"ok": False, "error": f"规则「{rule_name}」处于「{rule.get('status')}」状态"}

        condition = rule.get("触发条件", "")
        triggered = self._parse_condition(condition, metric_value)
        return {
            "ok": True,
            "rule": rule_name,
            "metric_value": metric_value,
            "condition": condition,
            "triggered": triggered,
            "level": rule.get("告警级别", "WARNING"),
        }

    @staticmethod
    def _parse_condition(condition: str, value: float) -> bool:
        """解析条件表达式: '>100', '<50', '>=200', '<=10', '==0'。"""
        import re
        match = re.match(r'(>=|<=|!=|==|>|<)\s*([0-9.]+)', condition.strip())
        if not match:
            # 默认阈值
            try:
                threshold = float(condition)
                return value > threshold
            except (ValueError, TypeError):
                return value > 100
        op, threshold_str = match.groups()
        threshold = float(threshold_str)
        if op == ">":
            return value > threshold
        elif op == "<":
            return value < threshold
        elif op == ">=":
            return value >= threshold
        elif op == "<=":
            return value <= threshold
        elif op == "==":
            return value == threshold
        elif op == "!=":
            return value != threshold
        return False

    def check_silence_window(self, rule_name: str) -> dict[str, Any]:
        """检查规则是否在沉默窗口内：最近触发的告警与当前时间差。"""
        rule = None
        for r in store.rows(self.MODULE):
            if r.get("规则名称") == rule_name:
                rule = r
                break
        if rule is None:
            return {"ok": False, "error": f"告警规则「{rule_name}」不存在"}

        # 解析沉默窗口
        silence_str = (rule.get("沉默窗口", "300s") or "300s").replace("s", "")
        try:
            silence_sec = int(silence_str)
        except (ValueError, TypeError):
            silence_sec = 300

        now = time.time()
        # 查找该规则最近的告警记录
        recent_alerts = [
            a for a in store.rows(self.MODULE)
            if a.get("规则名称") == rule_name and a.get("_created_at")
        ]
        if not recent_alerts:
            return {"ok": True, "in_silence": False, "rule": rule_name}

        latest_ts = max(a.get("_created_at", 0) for a in recent_alerts)
        in_silence = (now - latest_ts) < silence_sec
        remaining = max(0, silence_sec - (now - latest_ts)) if in_silence else 0

        return {
            "ok": True,
            "rule": rule_name,
            "silence_window": silence_sec,
            "in_silence": in_silence,
            "remaining_seconds": remaining,
            "last_alert_ts": latest_ts,
        }

    def escalate_alert(self, rule_name: str) -> dict[str, Any]:
        """告警升级：按升级路径提升告警级别并写入 restore_plan。

        若该规则已存在 CEP 命中告警，恢复方案只引用合并清单里保留的那条
        当前命中（``_alert_id`` / ``_cep_signature``），不引用被合并的旧版本。
        """
        rule = None
        for r in store.rows(self.MODULE):
            if r.get("规则名称") == rule_name:
                rule = r
                break
        if rule is None:
            return {"ok": False, "error": f"告警规则「{rule_name}」不存在"}

        escalation_path = rule.get("升级路径", "oncall").split(",")
        current_level = rule.get("告警级别", "WARNING")
        level_value = self.LEVEL_ORDER.get(current_level, 1)
        next_level_name = "CRITICAL"
        if level_value < 3:
            next_level_name = next(
                (k for k, v in self.LEVEL_ORDER.items() if v == level_value + 1),
                "CRITICAL",
            )

        kept_alert = self._retained_cep_alert(rule_name)

        with cep_ledger.transaction("restore_plan"):
            plan = {
                "id": max(
                    (int(r.get("id", 0)) for r in store.rows("restore_plan")), default=0
                ) + 1,
                "方案名称": f"告警恢复_{rule_name}_{int(time.time())}",
                "任务范围": rule.get("监控指标", "default_scope"),
                "恢复模式": "escalation_response",
                "源位点策略": "latest_alert",
                "状态复用": "resolved",
                "跳过坏数据": "true",
                "验证步骤": f"alert_level:{next_level_name},path:{','.join(escalation_path)}",
                "status": "草稿",
                "pending": True,
                "abnormal": True,
                "_alert_rule": rule_name,
                "_escalated_from": current_level,
                "_escalated_to": next_level_name,
                "_created_at": time.time(),
            }
            if kept_alert is not None:
                plan["_alert_id"] = kept_alert.get("id")
                plan["_cep_rule"] = kept_alert.get("_cep_rule", "")
                plan["_cep_signature"] = kept_alert.get("_cep_signature", "")
                plan["_restore_key"] = (
                    f"cep:{plan['_cep_rule']}:{plan['_cep_signature']}"
                )
                plan["_alert_event_keys"] = list(
                    kept_alert.get("_cep_event_keys", [])
                )
                kept_alert["_restore_plan_id"] = plan["id"]
            store.rows("restore_plan").append(plan)

        rule["告警级别"] = next_level_name
        return {
            "ok": True,
            "rule": rule_name,
            "escalated_from": current_level,
            "escalated_to": next_level_name,
            "path": escalation_path,
            "restore_plan_id": plan["id"],
            "linked_alert_id": plan.get("_alert_id"),
            "linked_cep_signature": plan.get("_cep_signature", ""),
        }

    @staticmethod
    def _retained_cep_alert(rule_name: str) -> dict[str, Any] | None:
        """找到该告警规则对应的、合并清单中保留的那条 CEP 当前命中。"""
        merge_list = cep_ledger.build_merge_list()
        candidates = [
            entry for entry in merge_list["entries"]
            if entry["alert_rule"] == rule_name or entry["rule"] == rule_name
        ]
        if not candidates:
            return None
        kept_id = min(candidates, key=lambda entry: entry["alert_id"])["alert_id"]
        return store.find("alert_policy", kept_id)

    def batch_merge_alerts(self) -> dict[str, Any]:
        """批量合并同一规则下的重复告警，减少告警风暴。

        CEP 来源的命中交给 cep_ledger 按事件重叠关系合并（只保留一个当前版本）；
        其余异常告警按规则名合并，保留最早一条并标记其余为已沉默。
        """
        cep_result = cep_ledger.merge_hits()

        rules: dict[str, list[dict[str, Any]]] = {}
        for r in store.rows(self.MODULE):
            rn = r.get("规则名称", "")
            if (
                rn
                and r.get("_anomaly_detail")
                and r.get("_source") != "cep_rule"
            ):
                rules.setdefault(rn, []).append(r)

        merges = {}
        for rn, entries in rules.items():
            if len(entries) > 1:
                # 合并：保留第一条，标记其余为已沉默
                entries.sort(key=lambda e: e.get("_created_at", 0))
                for e in entries[1:]:
                    e["status"] = "已沉默"
                    e["_merged_into"] = entries[0].get("id")
                merges[rn] = {
                    "original_count": len(entries),
                    "merged": len(entries) - 1,
                    "kept_alert_id": entries[0].get("id"),
                }

        return {
            "ok": True,
            "rules_merged": len(merges) + cep_result["rules_merged"],
            "detail": merges,
            "cep_merge": {
                "retention_policy": cep_result["retention_policy"],
                "rules_merged": cep_result["rules_merged"],
                "merged_total": cep_result["merged_total"],
                "detail": cep_result["detail"],
            },
            "merge_list": cep_result["merge_list"],
            "retention_options": cep_result["retention_options"],
        }

    def list_cep_alert_merge(self, rule_name: str | None = None) -> dict[str, Any]:
        """告警合并清单：只含未被前序命中消费的事件对应的唯一当前命中。"""
        return {
            "ok": True,
            "merge_list": cep_ledger.build_merge_list(rule_name),
            "retention_options": cep_ledger.describe_retention_options(),
        }

    def check_restore_alert_sync(self, plan_id: int | None = None) -> dict[str, Any]:
        """核对恢复方案与告警合并清单是否引用同一条保留告警。"""
        plans = [
            plan for plan in store.rows("restore_plan")
            if plan.get("_alert_id") is not None
        ]
        if plan_id is not None:
            plan = store.find("restore_plan", plan_id)
            if plan is None:
                return {"ok": False, "error": f"恢复方案 {plan_id} 不存在"}
            plans = [plan]
        report = [cep_ledger.restore_alert_sync(plan) for plan in plans]
        return {
            "ok": all(item["ok"] for item in report),
            "checked": len(report),
            "plans": report,
            "merge_list": cep_ledger.build_merge_list(),
        }

    def list_active_alerts(self) -> list[dict[str, Any]]:
        """列出所有活跃的（未沉默/未关闭）告警及其关联恢复方案。

        CEP 命中只暴露当前版本；被合并的历史版本不进活跃清单，
        保证同一事件不会在告警页面重复出现。
        """
        active = [
            r for r in store.rows(self.MODULE)
            if (
                r.get("status") == "已启用" or r.get("_anomaly_detail")
            ) and r.get("_cep_state", "current") == "current"
        ]
        result = []
        for a in active:
            entry = {
                "alert_id": a.get("id"),
                "rule": a.get("规则名称", ""),
                "metric": a.get("监控指标", ""),
                "level": a.get("告警级别", ""),
                "condition": a.get("触发条件", ""),
                "status": a.get("status", ""),
                "has_anomaly": bool(a.get("_anomaly_detail")),
            }
            if a.get("_source") == "cep_rule":
                entry["cep_rule"] = a.get("_cep_rule", "")
                entry["cep_signature"] = a.get("_cep_signature", "")
                entry["event_keys"] = list(a.get("_cep_event_keys", []))
            # 查找关联恢复方案：优先按告警 id 精确关联
            for rp in store.rows("restore_plan"):
                if rp.get("_alert_id") == a.get("id") or (
                    a.get("规则名称") and a.get("规则名称") in str(rp.get("方案名称", ""))
                ):
                    entry["linked_restore"] = rp.get("方案名称", "")
                    entry["restore_status"] = rp.get("status", "")
                    entry["restore_plan_id"] = rp.get("id")
                    break
            result.append(entry)
        return result

    def domain_snapshot(self) -> dict[str, Any]:
        base = super().domain_snapshot()
        rows = store.rows(self.MODULE)
        merge_list = cep_ledger.build_merge_list()
        base["active_alerts"] = sum(1 for r in rows if r.get("status") == "已启用")
        base["silenced"] = sum(1 for r in rows if r.get("status") == "已沉默")
        base["escalation_count"] = sum(
            1 for r in rows if r.get("告警级别") == "CRITICAL"
        )
        base["cep_alerts"] = sum(1 for r in rows if r.get("_source") == "cep_rule")
        base["cep_current_alerts"] = sum(
            1 for r in rows
            if r.get("_source") == "cep_rule"
            and r.get("_cep_state", "current") == "current"
        )
        base["cep_merged_alerts"] = sum(
            1 for r in rows
            if r.get("_source") == "cep_rule" and r.get("_cep_state") == "merged"
        )
        base["cep_merge_list_size"] = merge_list["total"]
        base["cep_duplicate_free"] = merge_list["duplicate_free"]
        return base