"""CEP 命中台账接口：匹配写入、已消费窗口、告警合并清单与恢复核对。

这些是固定路径，必须在通用资源路由（``/api/{module}/{entry_id}``）之前注册，
否则会被 ``entry_id`` 的整型校验拦住。
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, HTTPException, Query

from app.services import cep_ledger, service_for

router = APIRouter(prefix="/api", tags=["CEP命中台账"])


def _cep_service():
    service = service_for("cep_rule")
    if service is None:  # pragma: no cover - 注册表缺失属于配置错误
        raise HTTPException(status_code=500, detail="CEP规则服务未注册")
    return service


def _alert_service():
    service = service_for("alert_policy")
    if service is None:  # pragma: no cover
        raise HTTPException(status_code=500, detail="告警策略服务未注册")
    return service


def _restore_service():
    service = service_for("restore_plan")
    if service is None:  # pragma: no cover
        raise HTTPException(status_code=500, detail="故障恢复服务未注册")
    return service


# ---- CEP 规则侧 ----

@router.get("/cep_rule/consumed-windows")
def list_consumed_windows(rule_name: str | None = Query(default=None)) -> dict[str, Any]:
    """已消费窗口：工作台确认哪些事件序列已被命中占用。"""
    return _cep_service().list_consumed_windows(rule_name)


@router.get("/cep_rule/cep-alerts")
def list_cep_alerts(rule_name: str | None = Query(default=None)) -> dict[str, Any]:
    """CEP 命中告警合并清单（只含唯一当前命中）。"""
    return _cep_service().list_cep_alerts(rule_name)


@router.post("/cep_rule/{rule_name}/matches")
def match_rule(
    rule_name: str,
    payload: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    """读取事件序列、匹配规则并写入告警；同一序列重复提交幂等。"""
    events = payload.get("events") or []
    alert_rule_name = payload.get("alert_rule_name")
    return _cep_service().match_and_alert(
        rule_name, events, alert_rule_name=alert_rule_name,
    )


@router.post("/cep_rule/merge-alerts")
def merge_cep_alerts(payload: dict[str, Any] = Body(default_factory=dict)) -> dict[str, Any]:
    """合并重叠命中；policy 取 earliest_match（默认）或 severity。"""
    return _cep_service().merge_cep_alerts(
        rule_name=payload.get("rule_name"),
        policy=payload.get("policy"),
    )


# ---- 告警策略侧 ----

@router.get("/alert_policy/cep-merge")
def list_alert_merge(rule_name: str | None = Query(default=None)) -> dict[str, Any]:
    """告警策略模块读取 CEP 命中并给出合并清单。"""
    return _alert_service().list_cep_alert_merge(rule_name)


@router.post("/alert_policy/batch-merge")
def batch_merge_alerts() -> dict[str, Any]:
    """批量合并重复告警，只保留一个当前版本并回写恢复引用。"""
    return _alert_service().batch_merge_alerts()


@router.get("/alert_policy/restore-sync")
def check_alert_restore_sync(plan_id: int | None = Query(default=None)) -> dict[str, Any]:
    """核对恢复方案引用的告警是否仍在合并清单里。"""
    return _alert_service().check_restore_alert_sync(plan_id)


# ---- 故障恢复侧 ----

@router.get("/restore_plan/alert-sync")
def list_restore_alert_sync(plan_id: int | None = Query(default=None)) -> dict[str, Any]:
    """故障恢复详情页通过接口核对引用的 CEP 告警版本。"""
    return _restore_service().check_alert_sync(plan_id)


@router.get("/restore_plan/linked-alerts")
def list_restore_linked_alerts() -> dict[str, Any]:
    """恢复方案 → 保留告警的对照清单。"""
    return {
        "ok": True,
        "items": _restore_service().list_linked_alerts(),
        "merge_list": cep_ledger.build_merge_list(),
    }
