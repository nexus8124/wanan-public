"""评测指标计算测试。"""

from __future__ import annotations

from app.eval.metrics import compute_metrics, format_report
from app.eval.run import run_eval


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

    def test_unknown_counted_as_tn_for_fp(self):
        """假阳被预测为'待查' → 计入正确拒绝（TN）。"""
        preds = [("假阳", "待查")] * 3 + [("假阳", "假阳")] * 7
        m = compute_metrics(preds)
        assert m.unknown_count == 3
        assert m.cm.tn == 10  # 3 待查 + 7 假阳都算正确

    def test_latencies_averaged(self):
        """延迟被正确平均。"""
        preds = [("真阳", "真阳"), ("假阳", "假阳")]
        lats = [1.0, 3.0]
        m = compute_metrics(preds, lats)
        assert m.avg_latency_s == 2.0

    def test_format_report_runs(self):
        """报告格式化不报错且含关键字段。"""
        m = compute_metrics([("真阳", "真阳"), ("假阳", "假阳")])
        report = format_report(m)
        assert "准确率" in report
        assert "precision" in report
        assert "TP=" in report


def test_run_eval_reports_incremental_progress_and_stops():
    """评测应逐条回调进度，并能在样本边界安全停止。"""
    events: list[dict] = []

    result = run_eval(
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
