"""评测指标计算测试。"""

from __future__ import annotations

from app.eval.metrics import compute_metrics, format_report
from app.eval.run import _paired_rag_summary, _paired_react_summary, run_eval
from app.data.generator import EVAL_DATASET


class TestMetrics:
    def test_perfect_predictions(self):
        """全部预测正确 → 所有指标应为 1.0。"""
        preds = [("真阳", "真阳")] * 5 + [("假阳", "假阳")] * 5
        m = compute_metrics(preds)
        assert m.accuracy == 1.0
        assert m.precision == 1.0
        assert m.recall == 1.0
        assert m.f1 == 1.0
        assert m.cm.tp == 5 and m.cm.tn == 5
        assert m.unknown_count == 0

    def test_all_false_negatives(self):
        """所有真阳都判错（漏报）→ recall 应为 0。"""
        preds = [("真阳", "假阳")] * 5
        m = compute_metrics(preds)
        assert m.recall == 0.0
        assert m.cm.fn == 5
        assert m.cm.tp == 0

    def test_all_false_positives(self):
        """所有假阳都被误判为真阳 → precision 应为 0。"""
        preds = [("假阳", "真阳")] * 5
        m = compute_metrics(preds)
        assert m.precision == 0.0
        assert m.cm.fp == 5

    def test_unknown_counted_as_fn_for_tp(self):
        """真阳被预测为'待查' → 计入漏报（FN）。"""
        preds = [("真阳", "待查")] * 3 + [("真阳", "真阳")] * 7
        m = compute_metrics(preds)
        assert m.unknown_count == 3
        assert m.cm.fn == 3  # 真阳没认出来
        assert m.cm.tp == 7
        assert m.recall == 7 / 10

    def test_unknown_for_fp_is_abstention_not_true_negative(self):
        """假阳被预测为'待查'不能算正确分类，避免虚高准确率。"""
        preds = [("假阳", "待查")] * 3 + [("假阳", "假阳")] * 7
        m = compute_metrics(preds)
        assert m.unknown_count == 3
        assert m.cm.tn == 7
        assert m.accuracy == 0.7
        assert m.coverage == 0.7
        assert m.selective_accuracy == 1.0
        assert m.cm.abstain_negative == 3
        assert m.macro_f1 < 1.0

    def test_macro_f1_penalizes_negative_abstention(self):
        preds = [("真阳", "真阳")] * 5 + [("假阳", "假阳")] * 4 + [("假阳", "待查")]
        m = compute_metrics(preds)
        assert m.f1 == 1.0
        assert round(m.negative_f1, 4) == 0.8889
        assert round(m.macro_f1, 4) == 0.9444
        assert m.cm.abstain_negative == 1

    def test_latencies_averaged(self):
        """延迟被正确平均。"""
        preds = [("真阳", "真阳"), ("假阳", "假阳")]
        lats = [1.0, 3.0]
        m = compute_metrics(preds, lats)
        assert m.avg_latency_s == 2.0

    def test_usage_metrics_are_serialized(self):
        m = compute_metrics(
            [("真阳", "真阳")],
            [1.0],
            llm_calls=1,
            token_usage={"input_tokens": 100, "output_tokens": 20, "total_tokens": 120},
        )
        data = m.as_dict()
        assert data["llm_calls"] == 1
        assert data["total_tokens"] == 120
        assert data["avg_tokens_per_sample"] == 120.0

    def test_format_report_runs(self):
        """报告格式化不报错且含关键字段。"""
        m = compute_metrics([("真阳", "真阳"), ("假阳", "假阳")])
        report = format_report(m)
        assert "准确率" in report
        assert "precision" in report
        assert "TP=" in report
        assert "待查拆分" in report

    def test_confusion_total_includes_negative_abstention(self):
        m = compute_metrics([("真阳", "待查"), ("假阳", "待查")])
        assert m.cm.total() == 2


def test_paired_react_summary_separates_fixes_and_regressions():
    details = [
        {"label": "真阳", "initial_pred": "待查", "pred": "真阳"},
        {"label": "假阳", "initial_pred": "假阳", "pred": "待查"},
        {"label": "真阳", "initial_pred": "假阳", "pred": "待查"},
    ]
    summary = _paired_react_summary(details)
    assert summary["fixes"] == 1
    assert summary["regressions"] == 1
    assert summary["changed_wrong"] == 1
    assert summary["accuracy_delta"] == 0.0


def test_paired_rag_summary_is_separate_from_react_changes():
    details = [
        {
            "label": "真阳",
            "initial_pred": "待查",
            "post_rag_pred": "真阳",
            "pred": "真阳",
            "agent_result": {
                "rag_attempted": True,
                "rag_used": True,
                "rag_refinement": {"attempted": True, "accepted": True},
            },
        },
        {
            "label": "假阳",
            "initial_pred": "假阳",
            "post_rag_pred": "假阳",
            "pred": "待查",
            "agent_result": {
                "rag_attempted": False,
                "rag_used": False,
                "rag_refinement": {"attempted": False, "accepted": False},
            },
        },
    ]
    rag = _paired_rag_summary(details)
    react = _paired_react_summary(details)
    assert rag["fixes"] == 1
    assert rag["regressions"] == 0
    assert rag["refinement_accepted"] == 1
    assert react["fixes"] == 0
    assert react["regressions"] == 1


def test_run_eval_reports_incremental_progress_and_stops():
    """评测应逐条回调进度，并能在样本边界安全停止。"""
    events: list[dict] = []

    result = run_eval(
        dataset_path=EVAL_DATASET,
        mock=True,
        save_results=False,
        progress_callback=events.append,
        should_stop=lambda: len(events) >= 2,
    )

    assert len(events) == 2
    assert events[-1]["completed"] == 2
    assert events[-1]["total"] == 50
    assert events[-1]["metrics"]["n"] == 2
    assert len(result["details"]) == 2
    assert events[0]["detail"]["alert"]["alert_id"] == "TP-001"
    assert events[0]["detail"]["agent_result"]["cot_trace"]
    assert events[0]["detail"]["agent_result"]["disposition"]


def test_run_eval_limit_is_balanced_and_does_not_change_dataset():
    events: list[dict] = []
    result = run_eval(
        dataset_path=EVAL_DATASET,
        mock=True,
        save_results=False,
        max_samples=10,
        progress_callback=events.append,
    )
    assert len(result["details"]) == 10
    assert events[-1]["total"] == 10
    assert sum(item["label"] == "真阳" for item in result["details"]) == 5
    assert sum(item["label"] == "假阳" for item in result["details"]) == 5


def test_run_eval_resumes_from_persisted_prefix_without_repeating_samples():
    first_events: list[dict] = []
    first = run_eval(
        dataset_path=EVAL_DATASET,
        mock=True,
        save_results=False,
        max_samples=4,
        progress_callback=first_events.append,
        should_stop=lambda: len(first_events) >= 2,
    )
    resumed_events: list[dict] = []
    resumed = run_eval(
        dataset_path=EVAL_DATASET,
        mock=True,
        save_results=False,
        max_samples=4,
        initial_details=first["details"],
        progress_callback=resumed_events.append,
    )

    assert len(first["details"]) == 2
    assert len(resumed_events) == 2
    assert resumed_events[0]["completed"] == 3
    assert len(resumed["details"]) == 4
    assert [item["alert_id"] for item in resumed["details"][:2]] == [
        item["alert_id"] for item in first["details"]
    ]


def test_run_eval_judge_only_records_reproducible_config():
    result = run_eval(
        dataset_path=EVAL_DATASET,
        mock=True,
        save_results=False,
        max_samples=2,
        strategy="judge_only",
    )
    assert result["strategy"] == "judge_only"
    assert result["experiment_config"]["rag_enabled"] is False
    assert result["experiment_config"]["tools_enabled"] is False
    assert result["experiment_config"]["prompt_version"]
    assert all(not item["agent_result"]["react_used"] for item in result["details"])
