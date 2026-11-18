"""CEP 命中台账：CEP 规则命中 → 告警落库 → 合并清单 → 恢复引用。

这一层是「CEP 命中告警数据」的唯一持久化入口。CEP 规则服务
（``app/services/cep_rule.py``）和管道引擎（``app/pipeline.py``）两条写入路径
都必须经过这里，避免同一次命中在告警策略表里留下两种不同版本的记录。

三条硬约束：

1. 一次命中只占用一个已消费窗口。
   命中窗口内的事件整体标记为已消费；滑动窗口与上一窗口重叠的那部分事件
   不能再次参与同规则的下一次匹配，因此不会为同一事件重复生成告警。
2. 幂等。
   同一规则 + 同一事件序列（按 ``event_id``/事件键判定）只对应一条「当前」
   告警记录；重复执行只会返回已有记录，不会追加新行。并发写入由进程内锁
   串行化，只有一个线程能真正落库。
3. 事务回滚。
   写入失败时恢复告警表的原版本，不留下半条记录；恢复方案的创建同理。
"""
from __future__ import annotations

import copy
import hashlib
import threading
import time
from contextlib import contextmanager
from typing import Any, Iterable

from app.store import store

CEP_ALERT_MODULE = "alert_policy"
RESTORE_MODULE = "restore_plan"

# 合并同源命中时的保留策略。
RETENTION_EARLIEST = "earliest_match"
RETENTION_SEVERITY = "severity"
RETENTION_POLICIES = (RETENTION_EARLIEST, RETENTION_SEVERITY)
DEFAULT_RETENTION = RETENTION_EARLIEST

LEVEL_ORDER = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "CRITICAL": 3}

# 进程内互斥锁：内存仓库没有数据库事务，用 RLock 保证「检查 + 写入」原子。
_LOCK = threading.RLock()


@contextmanager
def transaction(*modules: str):
    """对若干模块表做快照，异常时整表回滚到快照。"""
    with _LOCK:
        snapshots = {module: copy.deepcopy(store.rows(module)) for module in modules}
        try:
            yield
        except Exception:
            for module, snapshot in snapshots.items():
                store.rows(module)[:] = snapshot
            raise


# ---------------------------------------------------------------------------
# 事件键与匹配签名
# ---------------------------------------------------------------------------

def event_key(event: dict[str, Any]) -> str:
    """事件的稳定标识：优先业务事件号，退化到「类型@时间」。"""
    for name in ("event_id", "事件ID", "id"):
        value = event.get(name)
        if value not in (None, "", 0, "0"):
            return str(value)
    return f"{event.get('event_type', 'unknown')}@{event.get('event_time', 0)}"


def sequence_signature(
    rule_identity: str, pattern: Iterable[str], event_keys: Iterable[str],
) -> str:
    """规则 + 模式 + 事件序列的唯一指纹，用作幂等键。"""
    payload = "\x1f".join([
        rule_identity,
        ",".join(pattern),
        ",".join(event_keys),
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]


def rule_identity(rule_name: str) -> str:
    """CEP 规则身份：不同入口传入的名称统一归一化。"""
    return str(rule_name or "").strip()


def make_match(
    rule_name: str,
    pattern: list[str],
    window: list[dict[str, Any]],
    sequence_index: int = 0,
) -> dict[str, Any]:
    """由命中窗口构造标准匹配对象。"""
    keys = [event_key(event) for event in window]
    identity = rule_identity(rule_name)
    return {
        "rule": identity,
        "pattern": list(pattern),
        "events": list(window),
        "event_keys": keys,
        "event_ids": keys,
        "start_ts": window[0].get("event_time", 0) if window else 0,
        "end_ts": window[-1].get("event_time", 0) if window else 0,
        "sequence_index": sequence_index,
        "signature": sequence_signature(identity, pattern, keys),
    }


# ---------------------------------------------------------------------------
# 非重叠匹配
# ---------------------------------------------------------------------------

def match_sequence(
    events: list[dict[str, Any]],
    pattern: list[str],
    time_constraint_sec: float,
    rule_name: str,
    consumed_keys: Iterable[str] | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """在事件流上做贪心的非重叠模式匹配。

    返回 ``(matches, skipped_consumed)``：

    * 命中一个窗口后直接跳过整个窗口，窗口内事件视为已消费，
      后续窗口不能再复用它们（修复滑动窗口重叠导致的重复计数）；
    * 命中所需事件只要有一个已被前序命中消费，该候选窗口直接跳过，
      并计入 ``skipped_consumed``。
    """
    if not events or not pattern:
        return [], 0

    consumed = set(consumed_keys or ())
    ordered = sorted(
        events,
        key=lambda event: (event.get("event_time", 0), event_key(event)),
    )
    pattern_len = len(pattern)
    matches: list[dict[str, Any]] = []
    skipped_consumed = 0
    index = 0
    sequence_index = 0

    while index + pattern_len <= len(ordered):
        window = ordered[index:index + pattern_len]
        keys = [event_key(event) for event in window]
        if any(key in consumed for key in keys):
            skipped_consumed += 1
            index += 1
            continue
        if window[-1].get("event_time", 0) - window[0].get("event_time", 0) > time_constraint_sec:
            index += 1
            continue
        if all(
            window[offset].get("event_type", "") == pattern[offset]
            for offset in range(pattern_len)
        ):
            matches.append(make_match(rule_name, pattern, window, sequence_index))
            sequence_index += 1
            # 整个窗口被消费：下一次匹配从窗口之后开始，绝不重叠。
            index += pattern_len
            consumed.update(keys)
        else:
            index += 1

    return matches, skipped_consumed


# ---------------------------------------------------------------------------
# 台账读取
# ---------------------------------------------------------------------------

def cep_hits(rule_name: str | None = None) -> list[dict[str, Any]]:
    """返回 CEP 命中告警记录；默认包含已合并的历史版本。"""
    identity = rule_identity(rule_name) if rule_name else None
    rows = [
        row for row in store.rows(CEP_ALERT_MODULE)
        if row.get("_source") == "cep_rule" and row.get("_cep_signature")
    ]
    if identity is not None:
        rows = [row for row in rows if row.get("_cep_rule") == identity]
    return rows


def current_hits(rule_name: str | None = None) -> list[dict[str, Any]]:
    """只返回当前生效的命中版本（已合并的旧版本不再算数）。"""
    return [
        row for row in cep_hits(rule_name)
        if row.get("_cep_state", "current") == "current"
    ]


def consumed_keys(rule_name: str) -> dict[str, int]:
    """规则维度的已消费事件索引：事件键 → 消费它的告警 id。

    已合并历史版本消费过的事件同样不能再次形成当前告警，因此一并计入。
    """
    index: dict[str, int] = {}
    for row in cep_hits(rule_name):
        alert_id = row.get("id")
        for key in row.get("_cep_event_keys", []):
            index.setdefault(str(key), alert_id)
    return index


def consumed_windows(rule_name: str | None = None) -> dict[str, Any]:
    """已消费窗口清单：供 CEP 工作台查看。"""
    identities = (
        [rule_identity(rule_name)] if rule_name
        else sorted({row.get("_cep_rule", "") for row in cep_hits()})
    )
    windows: list[dict[str, Any]] = []
    for identity in identities:
        for row in sorted(
            cep_hits(identity),
            key=lambda item: (
                (item.get("_cep_window") or {}).get("start_ts", 0),
                item.get("_created_at", 0),
                int(item.get("id", 0)),
            ),
        ):
            window = row.get("_cep_window") or {}
            keys = list(row.get("_cep_event_keys", []))
            windows.append({
                "alert_id": row.get("id"),
                "rule": identity,
                "alert_rule": row.get("_cep_alert_rule") or row.get("规则名称", ""),
                "signature": row.get("_cep_signature", ""),
                "pattern": list(row.get("_cep_pattern", [])),
                "event_keys": keys,
                "event_count": len(keys),
                "start_ts": window.get("start_ts", 0),
                "end_ts": window.get("end_ts", 0),
                "sequence_index": window.get("sequence_index", 0),
                "state": row.get("_cep_state", "current"),
                "level": row.get("告警级别", ""),
                "status": row.get("status", ""),
                "merged_into": row.get("_merged_into"),
                "created_at": row.get("_created_at", 0),
            })
    total_keys = {key for window in windows for key in window["event_keys"]}
    return {
        "rule": rule_identity(rule_name) if rule_name else None,
        "windows": windows,
        "total_windows": len(windows),
        "current_windows": sum(1 for item in windows if item["state"] == "current"),
        "consumed_event_count": len(total_keys),
    }


def build_merge_list(rule_name: str | None = None) -> dict[str, Any]:
    """告警合并清单：只包含未被前序命中消费掉的「当前」命中。

    每条当前命中消费的事件集合两两不重叠；一旦出现重复事件，
    说明存在重叠窗口写出的旧版本，合并清单会把它标出来。
    """
    entries: list[dict[str, Any]] = []
    seen_keys: dict[tuple[str, str], int] = {}
    overlapping: list[dict[str, Any]] = []
    by_rule: dict[str, int] = {}

    for row in sorted(
        current_hits(rule_name),
        key=lambda item: (
            item.get("_cep_rule", ""),
            (item.get("_cep_window") or {}).get("start_ts", 0),
            item.get("_created_at", 0),
            int(item.get("id", 0)),
        ),
    ):
        identity = row.get("_cep_rule", "")
        keys = [str(key) for key in row.get("_cep_event_keys", [])]
        # 不同规则可以各自消费同一事件；冲突只在同规则内认定。
        conflicts = sorted({
            seen_keys[(identity, key)]
            for key in keys
            if (identity, key) in seen_keys
        })
        if conflicts:
            overlapping.append({
                "alert_id": row.get("id"),
                "rule": identity,
                "conflicts_with": conflicts,
                "event_keys": keys,
            })
        for key in keys:
            seen_keys.setdefault((identity, key), row.get("id"))
        by_rule[identity] = by_rule.get(identity, 0) + 1
        window = row.get("_cep_window") or {}
        entries.append({
            "alert_id": row.get("id"),
            "rule": identity,
            "alert_rule": row.get("_cep_alert_rule") or row.get("规则名称", ""),
            "signature": row.get("_cep_signature", ""),
            "pattern": list(row.get("_cep_pattern", [])),
            "event_keys": keys,
            "event_count": len(keys),
            "start_ts": window.get("start_ts", 0),
            "end_ts": window.get("end_ts", 0),
            "sequence_index": window.get("sequence_index", 0),
            "level": row.get("告警级别", ""),
            "status": row.get("status", ""),
            "version": row.get("_cep_version", 1),
            "restore_plan_id": row.get("_restore_plan_id"),
            "overlaps_previous": bool(conflicts),
            "created_at": row.get("_created_at", 0),
        })

    return {
        "entries": entries,
        "total": len(entries),
        "by_rule": by_rule,
        "unique_event_count": len(seen_keys),
        "overlapping": overlapping,
        "duplicate_free": not overlapping,
        "retention_policy": DEFAULT_RETENTION,
    }


# ---------------------------------------------------------------------------
# 写入：幂等 + 事务
# ---------------------------------------------------------------------------

def _safe_id(row: dict[str, Any]) -> int:
    try:
        return int(row.get("id", 0))
    except (TypeError, ValueError):
        return 0


def _next_alert_id() -> int:
    return max(
        (_safe_id(row) for row in store.rows(CEP_ALERT_MODULE)), default=0,
    ) + 1


def _find_current(signature: str, identity: str) -> dict[str, Any] | None:
    for row in store.rows(CEP_ALERT_MODULE):
        if (
            row.get("_source") == "cep_rule"
            and row.get("_cep_signature") == signature
            and row.get("_cep_rule") == identity
            and row.get("_cep_state", "current") == "current"
        ):
            return row
    return None


def _build_alert_entry(
    match: dict[str, Any],
    *,
    alert_rule_name: str,
    level: str,
    rule_row: dict[str, Any] | None,
    origin: str,
) -> dict[str, Any]:
    rule_row = rule_row or {}
    window = {
        "start_ts": match.get("start_ts", 0),
        "end_ts": match.get("end_ts", 0),
        "sequence_index": match.get("sequence_index", 0),
    }
    keys = list(match.get("event_keys", []))
    metric = rule_row.get("事件类型") or ",".join(match.get("pattern", []))
    return {
        "id": _next_alert_id(),
        "规则名称": alert_rule_name,
        "监控指标": metric,
        "触发条件": f"cep_sequence_signature={match['signature']}",
        "告警级别": level,
        "沉默窗口": rule_row.get("沉默窗口") or "60s",
        "通知方式": rule_row.get("通知方式") or "push",
        "升级路径": rule_row.get("升级路径") or "oncall",
        "status": "已启用",
        "pending": True,
        "abnormal": True,
        "_source": "cep_rule",
        "_cep_origin": origin,
        "_cep_rule": match["rule"],
        "_cep_alert_rule": alert_rule_name,
        "_cep_pattern": list(match.get("pattern", [])),
        "_cep_signature": match["signature"],
        "_cep_event_keys": keys,
        "_cep_event_ids": list(match.get("event_ids", keys)),
        "_cep_window": window,
        "_cep_match_count": 1,
        "_cep_state": "current",
        "_cep_retention": DEFAULT_RETENTION,
        "_cep_version": 1,
        "_created_at": time.time(),
    }


def _validate_committed(entry: dict[str, Any]) -> None:
    """落库后的自检；失败会抛出，由事务把表回滚到原版本。"""
    if not entry.get("_cep_signature") or not entry.get("_cep_event_keys"):
        raise ValueError("CEP 命中告警记录缺少签名或事件键")


def commit_hit(
    match: dict[str, Any],
    *,
    alert_rule_name: str,
    level: str = "WARNING",
    rule_row: dict[str, Any] | None = None,
    origin: str = "cep_rule",
) -> dict[str, Any]:
    """事务化写入一次命中；同一签名只落一行，重复调用直接复用。

    含「已被同规则前序命中消费」事件的候选窗口不会落库，
    返回 ``skipped=True``，从写入侧兜住重叠窗口。
    """
    identity = match["rule"]
    with transaction(CEP_ALERT_MODULE):
        existing = _find_current(match["signature"], identity)
        if existing is not None:
            return {
                "created": False,
                "deduplicated": True,
                "skipped": False,
                "entry": existing,
                "alert_id": existing.get("id"),
            }
        consumed = consumed_keys(identity)
        conflicting = sorted({
            str(key) for key in match.get("event_keys", []) if str(key) in consumed
        })
        if conflicting:
            return {
                "created": False,
                "deduplicated": False,
                "skipped": True,
                "reason": "命中窗口包含已被前序命中消费的事件",
                "consumed_by": sorted({consumed[key] for key in conflicting}),
                "event_keys": conflicting,
                "alert_id": None,
            }
        entry = _build_alert_entry(
            match,
            alert_rule_name=alert_rule_name,
            level=level,
            rule_row=rule_row,
            origin=origin,
        )
        store.rows(CEP_ALERT_MODULE).append(entry)
        _validate_committed(entry)
    return {
        "created": True,
        "deduplicated": False,
        "skipped": False,
        "entry": entry,
        "alert_id": entry.get("id"),
    }


# ---------------------------------------------------------------------------
# 合并：同一事件落在多个重叠窗口时，只保留一个当前版本
# ---------------------------------------------------------------------------

def _retention_sort_key(row: dict[str, Any], policy: str):
    window = row.get("_cep_window") or {}
    earliest = (
        window.get("start_ts", 0),
        row.get("_created_at", 0),
        _safe_id(row),
    )
    if policy == RETENTION_SEVERITY:
        rank = LEVEL_ORDER.get(str(row.get("告警级别", "")), 0)
        return (-rank, *earliest)
    return earliest


def _overlap_components(rows: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """按「共享事件」把命中记录分组，同一组内只能保留一个当前版本。"""
    parent = list(range(len(rows)))

    def find(node: int) -> int:
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    def union(left: int, right: int) -> None:
        root_left, root_right = find(left), find(right)
        if root_left != root_right:
            parent[root_right] = root_left

    owner: dict[str, int] = {}
    for index, row in enumerate(rows):
        for key in row.get("_cep_event_keys", []):
            key = str(key)
            if key in owner:
                union(owner[key], index)
            else:
                owner[key] = index

    grouped: dict[int, list[dict[str, Any]]] = {}
    for index, row in enumerate(rows):
        grouped.setdefault(find(index), []).append(row)
    return [group for group in grouped.values() if len(group) > 1]


def _repoint_restore_plans(kept: dict[str, Any], merged: dict[str, Any]) -> list[int]:
    """把引用被合并版本的恢复方案改指向保留的那条告警。"""
    repointed: list[int] = []
    kept_signature = kept.get("_cep_signature", "")
    identity = kept.get("_cep_rule", "")
    for plan in store.rows(RESTORE_MODULE):
        if (
            plan.get("_cep_signature") == merged.get("_cep_signature")
            or plan.get("_alert_id") == merged.get("id")
        ):
            plan["_alert_id"] = kept.get("id")
            plan["_cep_signature"] = kept_signature
            plan["_restore_key"] = f"cep:{identity}:{kept_signature}"
            plan.setdefault("_superseded_alert_ids", []).append(merged.get("id"))
            repointed.append(_safe_id(plan))
    return repointed


def merge_hits(
    rule_name: str | None = None,
    policy: str = DEFAULT_RETENTION,
) -> dict[str, Any]:
    """合并同规则下共享事件的重叠命中。

    两种保留策略都只会留下一个当前版本：

    * ``earliest_match``（默认）：保留最早命中。事件集合在第一次命中时即被
      消费，后续重叠窗口天然属于重复记录；告警数量和恢复范围都最小且可复现。
    * ``severity``：保留最严重命中。会改变保留记录的级别和起止窗口，
      从而改变恢复方案的触发范围，仅在同一事件确实需要升级处理时使用。
    """
    if policy not in RETENTION_POLICIES:
        return {
            "ok": False,
            "error": f"未知保留策略「{policy}」，可选：{', '.join(RETENTION_POLICIES)}",
        }

    identities = (
        [rule_identity(rule_name)] if rule_name
        else sorted({row.get("_cep_rule", "") for row in cep_hits()})
    )
    details: list[dict[str, Any]] = []

    with transaction(CEP_ALERT_MODULE, RESTORE_MODULE):
        for identity in identities:
            rows = current_hits(identity)
            for group in _overlap_components(rows):
                ordered = sorted(group, key=lambda row: _retention_sort_key(row, policy))
                kept = ordered[0]
                merged_rows = ordered[1:]
                for row in merged_rows:
                    row["_cep_state"] = "merged"
                    row["_cep_version"] = int(row.get("_cep_version", 1))
                    row["status"] = "已沉默"
                    row["pending"] = False
                    row["_merged_into"] = kept.get("id")
                    row["_merged_at"] = time.time()
                    row["_merged_policy"] = policy
                    _repoint_restore_plans(kept, row)
                kept["_cep_state"] = "current"
                kept["_cep_version"] = max(
                    int(kept.get("_cep_version", 1)),
                    *(int(row.get("_cep_version", 1)) for row in merged_rows),
                ) if merged_rows else int(kept.get("_cep_version", 1))
                details.append({
                    "rule": identity,
                    "retention_policy": policy,
                    "original_count": len(group),
                    "merged": len(merged_rows),
                    "kept_alert_id": kept.get("id"),
                    "kept_signature": kept.get("_cep_signature", ""),
                    "merged_alert_ids": [row.get("id") for row in merged_rows],
                    "merged_signatures": [row.get("_cep_signature", "") for row in merged_rows],
                    "consumed_event_keys": sorted({
                        str(key)
                        for row in group
                        for key in row.get("_cep_event_keys", [])
                    }),
                })

    return {
        "ok": True,
        "retention_policy": policy,
        "rules_merged": len({detail["rule"] for detail in details}),
        "merged_total": sum(detail["merged"] for detail in details),
        "detail": details,
        "merge_list": build_merge_list(rule_name),
        "retention_options": describe_retention_options(),
    }


def describe_retention_options() -> list[dict[str, str]]:
    """两种合并取舍的说明，供接口/工作台展示评估结论。"""
    return [
        {
            "policy": RETENTION_EARLIEST,
            "label": "保留最早命中",
            "effect": "重叠窗口只留最早一条，告警数量最少，恢复范围稳定可复现；默认策略。",
        },
        {
            "policy": RETENTION_SEVERITY,
            "label": "保留最严重命中",
            "effect": "重叠窗口保留级别最高的一条，级别与窗口可能后移，恢复范围随之扩大。",
        },
    ]


# ---------------------------------------------------------------------------
# 恢复方案与合并清单的一致性核对
# ---------------------------------------------------------------------------

def restore_alert_sync(plan: dict[str, Any]) -> dict[str, Any]:
    """核对恢复方案引用的是否为合并清单里唯一保留的那条当前命中。"""
    alert_id = plan.get("_alert_id")
    signature = plan.get("_cep_signature") or ""
    identity = plan.get("_cep_rule") or ""

    alert = None
    if isinstance(alert_id, int):
        alert = store.find(CEP_ALERT_MODULE, alert_id)
    if alert is None and signature:
        alert = next(
            (
                row for row in cep_hits(identity)
                if row.get("_cep_signature") == signature
            ),
            None,
        )

    merge_list = build_merge_list(identity or None)
    listed_ids = {entry["alert_id"] for entry in merge_list["entries"]}
    checks: list[dict[str, Any]] = []

    checks.append({
        "check": "alert_exists",
        "ok": alert is not None,
        "detail": alert_id,
    })
    alert_state = (alert or {}).get("_cep_state", "missing")
    checks.append({
        "check": "alert_is_current",
        "ok": bool(alert) and alert_state == "current",
        "detail": alert_state,
    })
    checks.append({
        "check": "alert_in_merge_list",
        "ok": bool(alert) and alert.get("id") in listed_ids,
        "detail": (alert or {}).get("id"),
    })
    checks.append({
        "check": "signature_matches",
        "ok": bool(alert) and (
            not signature or alert.get("_cep_signature") == signature
        ),
        "detail": {
            "plan": signature,
            "alert": (alert or {}).get("_cep_signature", ""),
        },
    })
    checks.append({
        "check": "merge_list_duplicate_free",
        "ok": merge_list["duplicate_free"],
        "detail": merge_list["overlapping"],
    })

    return {
        "ok": all(check["ok"] for check in checks),
        "plan_id": plan.get("id"),
        "plan": plan.get("方案名称", ""),
        "rule": identity,
        "alert_id": (alert or {}).get("id"),
        "alert_signature": (alert or {}).get("_cep_signature", ""),
        "alert_event_keys": (alert or {}).get("_cep_event_keys", []),
        "alert_level": (alert or {}).get("告警级别", ""),
        "alert_state": alert_state,
        "checks": checks,
        "merge_list": merge_list,
    }
