"""序号11：CEP 滑动序列命中 → 告警落库 → 合并清单 → 恢复引用 的边界测试。

覆盖：
  * 一次命中只占用一个已消费窗口，重叠事件不重复计数；
  * 同一序列重复执行幂等，并发写入只生效一次；
  * 事务失败保持告警表原版本；
  * 合并清单只统计未被前序命中消费的事件；
  * 两种保留策略都只留下一个当前版本；
  * CEP 规则服务与管道引擎两条持久化路径收敛到同一版本；
  * 恢复方案只引用保留告警，刷新后仍可核对。
"""
from __future__ import annotations

import copy
import threading
import time

import pytest

from app import pipeline
from app.services import cep_ledger
from app.services import service_for
from app.store import store


RULE_NAME = "login_fail_rule"
ALERT_RULE = "cep_login_fail_rule"


@pytest.fixture(autouse=True)
def _isolated_store():
    """每个用例前后恢复全部内存表，避免互相污染。"""
    snapshot = copy.deepcopy(store._tables)
    try:
        store.rows("cep_rule").append({
            "id": 900,
            "序列名称": RULE_NAME,
            "事件类型": "login_fail",
            "匹配顺序": "login_fail,login_fail,login_fail",
            "时间约束": "60",
            "跳过策略": "SKIP_PAST_LAST",
            "动作输出": "alert",
            "最大跨度": "60",
            "status": "运行中",
            "pending": False,
            "abnormal": False,
        })
        # 管道入口的 trigger_alert_for_cep_matches 需要先存在告警规则。
        store.rows("alert_policy").append({
            "id": 950,
            "规则名称": ALERT_RULE,
            "监控指标": "login_fail",
            "触发条件": ">0",
            "告警级别": "WARNING",
            "沉默窗口": "60s",
            "通知方式": "push",
            "升级路径": "oncall",
            "status": "已启用",
            "pending": True,
            "abnormal": True,
        })
        yield
    finally:
        store._tables.clear()
        store._tables.update(copy.deepcopy(snapshot))


def _events(types: list[str], prefix: str = "e", base_ts: float = 1000.0):
    return [
        {
            "event_id": f"{prefix}{index}",
            "event_type": event_type,
            "event_time": base_ts + index,
        }
        for index, event_type in enumerate(types)
    ]


def _cep_service():
    return service_for("cep_rule")


# ---------------------------------------------------------------------------
# 命中窗口的边界处理
# ---------------------------------------------------------------------------

class TestConsumedWindowBoundary:
    def test_overlapping_sliding_sequence_counts_once(self):
        """连续 5 个同类型事件只应产生 1 个命中，而不是 3 个重叠窗口。"""
        events = _events(["login_fail"] * 5)
        result = _cep_service().match_and_alert(RULE_NAME, events)

        assert result["matches"] == 1
        assert result["created_alerts"] == 1
        assert result["consumed_windows"]["total_windows"] == 1
        assert result["consumed_windows"]["consumed_event_count"] == 3
        hits = cep_ledger.cep_hits(RULE_NAME)
        assert len(hits) == 1
        assert hits[0]["_cep_event_keys"] == ["e0", "e1", "e2"]

    def test_disjoint_sequences_each_get_one_window(self):
        """互不重叠的两段序列各自命中一次，事件互不共享。"""
        events = _events(
            ["login_fail"] * 3 + ["access_granted"] + ["login_fail"] * 3
        )
        result = _cep_service().match_and_alert(RULE_NAME, events)

        assert result["matches"] == 2
        hits = cep_ledger.cep_hits(RULE_NAME)
        key_sets = [set(hit["_cep_event_keys"]) for hit in hits]
        assert key_sets[0].isdisjoint(key_sets[1])
        merge_list = cep_ledger.build_merge_list(RULE_NAME)
        assert merge_list["duplicate_free"] is True
        assert merge_list["unique_event_count"] == 6

    def test_rerun_does_not_reuse_consumed_events(self):
        """被前一序列消费的事件不能再次形成同规则当前告警。"""
        events = _events(["login_fail"] * 5)
        first = _cep_service().match_and_alert(RULE_NAME, events)
        second = _cep_service().match_and_alert(RULE_NAME, events)

        assert first["created_alerts"] == 1
        assert second["matches"] == 0
        assert second["created_alerts"] == 0
        assert second["skipped_consumed_events"] > 0
        assert len(cep_ledger.current_hits(RULE_NAME)) == 1

    def test_shared_event_cannot_form_second_alert(self):
        """共享事件 a2 已消费，含它的候选窗口必须被跳过。"""
        _cep_service().match_and_alert(
            RULE_NAME, _events(["login_fail"] * 3, prefix="a"),
        )
        # 第二批只有两个新事件，恰好靠已消费的 a2 凑成窗口。
        overlapping = _events(["login_fail"] * 2, prefix="b")
        overlapping.append({
            "event_id": "a2",
            "event_type": "login_fail",
            "event_time": 1002.5,
        })
        result = _cep_service().match_and_alert(RULE_NAME, overlapping)

        assert result["matches"] == 0
        assert result["created_alerts"] == 0
        hits = cep_ledger.cep_hits(RULE_NAME)
        assert len(hits) == 1
        all_keys = [key for hit in hits for key in hit["_cep_event_keys"]]
        assert len(all_keys) == len(set(all_keys)), "同一事件不能出现在两条命中里"


# ---------------------------------------------------------------------------
# 幂等与并发
# ---------------------------------------------------------------------------

class TestIdempotencyAndConcurrency:
    def test_repeat_same_sequence_is_idempotent(self):
        events = _events(["login_fail"] * 3)
        first = _cep_service().match_and_alert(RULE_NAME, events)
        second = _cep_service().match_and_alert(RULE_NAME, events)

        assert first["created_alerts"] == 1
        assert second["created_alerts"] == 0
        assert second["reused_alerts"] >= 0
        assert len(cep_ledger.cep_hits(RULE_NAME)) == 1

    def test_concurrent_writes_commit_once(self):
        """并发重试只保留一个一致版本。"""
        events = _events(["login_fail"] * 3, prefix="c")
        results: list[dict] = []
        errors: list[BaseException] = []

        def worker() -> None:
            try:
                results.append(_cep_service().match_and_alert(RULE_NAME, events))
            except BaseException as exc:  # pragma: no cover - 失败才记录
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert not errors
        assert sum(result["created_alerts"] for result in results) == 1
        hits = cep_ledger.cep_hits(RULE_NAME)
        assert len(hits) == 1
        assert hits[0]["_cep_state"] == "current"

    def test_commit_hit_skips_window_with_consumed_events(self):
        """直接调用台账写入时，含已消费事件的窗口同样被拒绝落库。"""
        match = cep_ledger.make_match(
            RULE_NAME,
            ["login_fail"] * 3,
            _events(["login_fail"] * 3, prefix="k"),
        )
        first = cep_ledger.commit_hit(match, alert_rule_name=ALERT_RULE)
        second = cep_ledger.commit_hit(match, alert_rule_name=ALERT_RULE)

        assert first["created"] is True
        assert second["created"] is False
        assert second["deduplicated"] is True
        overlapping = cep_ledger.make_match(
            RULE_NAME,
            ["login_fail"] * 3,
            _events(["login_fail"] * 3, prefix="k")[1:] + [
                {"event_id": "k3", "event_type": "login_fail", "event_time": 1003},
            ],
        )
        third = cep_ledger.commit_hit(overlapping, alert_rule_name=ALERT_RULE)
        assert third["created"] is False
        assert third["skipped"] is True
        assert len(cep_ledger.cep_hits(RULE_NAME)) == 1

    def test_transaction_failure_keeps_original_version(self, monkeypatch):
        """事务失败时告警表回滚到原版本，不留半条记录。"""
        _cep_service().match_and_alert(RULE_NAME, _events(["login_fail"] * 3))
        before = copy.deepcopy(store.rows("alert_policy"))

        events = _events(
            ["login_fail"] * 3, prefix="z", base_ts=5000.0,
        )
        monkeypatch.setattr(
            cep_ledger, "_validate_committed",
            lambda entry: (_ for _ in ()).throw(ValueError("写入校验失败")),
        )
        result = _cep_service().match_and_alert(RULE_NAME, events)
        assert result["ok"] is False
        assert "回滚" in result["message"]
        assert store.rows("alert_policy") == before

    def test_rollback_context_restores_table(self):
        before = copy.deepcopy(store.rows("alert_policy"))
        with pytest.raises(RuntimeError):
            with cep_ledger.transaction("alert_policy"):
                store.rows("alert_policy").append({"id": 99999})
                raise RuntimeError("boom")
        assert store.rows("alert_policy") == before


# ---------------------------------------------------------------------------
# 告警合并清单
# ---------------------------------------------------------------------------

def _seed_overlapping_hits() -> None:
    """构造历史遗留的重叠命中：两条记录共享事件 b。"""
    now = time.time()
    for index, (level, start, keys) in enumerate(
        [("WARNING", 10.0, ["a", "b"]), ("CRITICAL", 20.0, ["b", "c"])]
    ):
        store.rows("alert_policy").append({
            "id": 700 + index,
            "规则名称": ALERT_RULE,
            "监控指标": "A,B",
            "触发条件": "legacy",
            "告警级别": level,
            "沉默窗口": "60s",
            "通知方式": "push",
            "升级路径": "oncall",
            "status": "已启用",
            "pending": True,
            "abnormal": True,
            "_source": "cep_rule",
            "_cep_rule": RULE_NAME,
            "_cep_alert_rule": ALERT_RULE,
            "_cep_pattern": ["A", "B"],
            "_cep_signature": f"legacy{index}",
            "_cep_event_keys": keys,
            "_cep_window": {"start_ts": start, "end_ts": start + 1, "sequence_index": 0},
            "_cep_state": "current",
            "_created_at": now + index,
        })


class TestMergeList:
    def test_merge_list_only_counts_unconsumed_events(self):
        events = _events(["login_fail"] * 5)
        _cep_service().match_and_alert(RULE_NAME, events)
        merge_list = cep_ledger.build_merge_list(RULE_NAME)

        assert merge_list["total"] == 1
        assert merge_list["unique_event_count"] == 3
        assert merge_list["duplicate_free"] is True
        entry = merge_list["entries"][0]
        assert set(entry["event_keys"]) == {"e0", "e1", "e2"}

    def test_merge_list_flags_overlapping_legacy_versions(self):
        _seed_overlapping_hits()
        merge_list = cep_ledger.build_merge_list(RULE_NAME)

        assert merge_list["duplicate_free"] is False
        assert len(merge_list["overlapping"]) == 1

    @pytest.mark.parametrize(
        ("policy", "expected_alert_id", "expected_level"),
        [
            ("earliest_match", 700, "WARNING"),
            ("severity", 701, "CRITICAL"),
        ],
    )
    def test_both_policies_keep_single_current_version(
        self, policy, expected_alert_id, expected_level,
    ):
        _seed_overlapping_hits()
        result = cep_ledger.merge_hits(RULE_NAME, policy=policy)

        assert result["ok"] is True
        assert result["merged_total"] == 1
        current = cep_ledger.current_hits(RULE_NAME)
        assert [hit["id"] for hit in current] == [expected_alert_id]
        assert current[0]["告警级别"] == expected_level
        assert cep_ledger.build_merge_list(RULE_NAME)["total"] == 1
        merged = store.find("alert_policy", 700 if policy == "severity" else 701)
        assert merged["_cep_state"] == "merged"
        assert merged["status"] == "已沉默"

    def test_unknown_policy_rejected(self):
        result = cep_ledger.merge_hits(RULE_NAME, policy="keep_all")
        assert result["ok"] is False
        assert "earliest_match" in result["error"]

    def test_merge_is_idempotent(self):
        _seed_overlapping_hits()
        first = cep_ledger.merge_hits(RULE_NAME)
        second = cep_ledger.merge_hits(RULE_NAME)
        assert first["merged_total"] == 1
        assert second["merged_total"] == 0
        assert len(cep_ledger.current_hits(RULE_NAME)) == 1


# ---------------------------------------------------------------------------
# 两条持久化路径的一致性
# ---------------------------------------------------------------------------

class TestPersistencePaths:
    def test_service_and_pipeline_share_one_version(self):
        """CEP 规则服务与管道引擎对同一序列只保留一个版本。"""
        events = _events(["login_fail"] * 3, prefix="p")
        service_result = _cep_service().match_and_alert(RULE_NAME, events)

        matches = pipeline.match_cep_pattern(
            events, ["login_fail"] * 3, 60.0, rule_name=RULE_NAME,
        )
        pipeline_result = pipeline.trigger_alert_for_cep_matches(
            matches, ALERT_RULE,
        )

        assert service_result["created_alerts"] == 1
        assert pipeline_result["created_alerts"] == 0
        assert pipeline_result["reused_alerts"] == 1
        hits = cep_ledger.cep_hits(RULE_NAME)
        assert len(hits) == 1
        assert hits[0]["_cep_signature"] == service_result["consumed_windows"]["windows"][0]["signature"]

    def test_pipeline_repeat_is_idempotent(self):
        events = _events(["login_fail"] * 3, prefix="q")
        first_matches = pipeline.match_cep_pattern(
            events, ["login_fail"] * 3, 60.0, rule_name=RULE_NAME,
        )
        pipeline.trigger_alert_for_cep_matches(first_matches, ALERT_RULE)
        second_matches = pipeline.match_cep_pattern(
            events, ["login_fail"] * 3, 60.0, rule_name=RULE_NAME,
        )
        result = pipeline.trigger_alert_for_cep_matches(second_matches, ALERT_RULE)

        assert result["triggered"] is False
        assert len(cep_ledger.cep_hits(RULE_NAME)) == 1

    def test_pipeline_match_is_non_overlapping(self):
        events = _events(["login_fail"] * 5)
        matches = pipeline.match_cep_pattern(
            events, ["login_fail"] * 3, 60.0, rule_name=RULE_NAME,
        )
        assert len(matches) == 1
        assert matches[0]["event_keys"] == ["e0", "e1", "e2"]


# ---------------------------------------------------------------------------
# 恢复方案与刷新核对
# ---------------------------------------------------------------------------

class TestRestoreReference:
    def test_restore_plan_references_retained_alert(self):
        store.rows("alert_policy").append({
            "id": 42,
            "规则名称": ALERT_RULE,
            "监控指标": "login_fail",
            "触发条件": ">0",
            "告警级别": "WARNING",
            "沉默窗口": "60s",
            "通知方式": "push",
            "升级路径": "oncall",
            "status": "已启用",
            "pending": True,
            "abnormal": True,
        })
        _cep_service().match_and_alert(RULE_NAME, _events(["login_fail"] * 3))

        escalation = service_for("alert_policy").escalate_alert(ALERT_RULE)
        assert escalation["ok"] is True
        alert_id = escalation["linked_alert_id"]
        alert = store.find("alert_policy", alert_id)
        assert alert["_cep_state"] == "current"

        sync = service_for("restore_plan").check_alert_sync(
            escalation["restore_plan_id"],
        )
        assert sync["ok"] is True
        assert sync["plans"][0]["alert_id"] == alert_id
        assert sync["plans"][0]["alert_signature"] == alert["_cep_signature"]

    def test_merged_version_repoints_restore_plan(self):
        _seed_overlapping_hits()
        store.rows("restore_plan").append({
            "id": 800,
            "方案名称": "恢复_legacy",
            "任务范围": "login_security",
            "恢复模式": "restart",
            "源位点策略": "latest_snapshot",
            "状态复用": "reuse",
            "跳过坏数据": "false",
            "验证步骤": "x",
            "status": "草稿",
            "_alert_id": 701,
            "_cep_rule": RULE_NAME,
            "_cep_signature": "legacy1",
            "_restore_key": f"cep:{RULE_NAME}:legacy1",
        })

        cep_ledger.merge_hits(RULE_NAME, policy="earliest_match")

        plan = store.find("restore_plan", 800)
        assert plan["_alert_id"] == 700
        assert plan["_cep_signature"] == "legacy0"
        assert cep_ledger.restore_alert_sync(plan)["ok"] is True
        assert 701 in plan["_superseded_alert_ids"]

    def test_refresh_rereads_persisted_state(self):
        """刷新后重新进入仍读到同一份持久化命中数据。"""
        _cep_service().match_and_alert(RULE_NAME, _events(["login_fail"] * 3))
        first = cep_ledger.build_merge_list(RULE_NAME)
        second = cep_ledger.build_merge_list(RULE_NAME)
        assert first["entries"] == second["entries"]

        windows_first = cep_ledger.consumed_windows(RULE_NAME)
        windows_second = cep_ledger.consumed_windows(RULE_NAME)
        assert windows_first == windows_second
        assert windows_first["total_windows"] == 1

    def test_generate_restore_plan_is_idempotent_for_same_alert(self):
        _cep_service().match_and_alert(RULE_NAME, _events(["login_fail"] * 3))
        first = pipeline.generate_restore_plan(
            3, "login_security", rule_name=RULE_NAME,
        )
        second = pipeline.generate_restore_plan(
            3, "login_security", rule_name=RULE_NAME,
        )
        assert first["id"] == second["id"]
        assert second.get("plan_created") is False
        plan = store.find("restore_plan", first["id"])
        assert plan["_alert_id"] is not None
        assert plan["_cep_signature"]

    def test_merged_rows_hidden_from_alert_list(self):
        _seed_overlapping_hits()
        service = service_for("alert_policy")
        before, _ = service.list_entries(page=1, size=200)
        cep_before = [row for row in before if row.get("_source") == "cep_rule"]
        assert len(cep_before) == 2

        cep_ledger.merge_hits(RULE_NAME)

        after, total = service.list_entries(page=1, size=200)
        cep_after = [row for row in after if row.get("_source") == "cep_rule"]
        assert len(cep_after) == 1
        assert cep_after[0]["_cep_state"] == "current"
        assert total == len(after)

    def test_alert_module_snapshot_reports_no_duplicates(self):
        _cep_service().match_and_alert(RULE_NAME, _events(["login_fail"] * 3))
        snapshot = service_for("alert_policy").domain_snapshot()
        assert snapshot["cep_current_alerts"] == 1
        assert snapshot["cep_duplicate_free"] is True
        active = service_for("alert_policy").list_active_alerts()
        cep_ids = [item["alert_id"] for item in active if "cep_signature" in item]
        assert len(cep_ids) == len(set(cep_ids))
