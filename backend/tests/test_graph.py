"""Agent 图端到端测试（MVP 版）。

用 mock LLM 验证 preprocess → judge → output 完整链路。
不耗 token，CI 友好。
"""

from __future__ import annotations

import pytest

from app.agent.graph import build_graph, judge_alert
from app.agent.nodes import preprocess_node
from app.data.loader import load_alerts
from app.models.llm import get_llm


# ============================================================
# fixtures
# ============================================================


@pytest.fixture
def mock_graph():
    """注入 mock LLM 的编译图。"""
    return build_graph(llm=get_llm(mock=True))


@pytest.fixture
def tp_alert():
    return {
        "alert_id": "TP-TEST",
        "timestamp": "2026-07-18T02:13:44Z",
        "source": "edr",
        "severity": "high",
        "src_ip": "10.20.33.51",
        "dst_ip": "185.220.101.34",
        "src_port": 49832,
        "dst_port": 4444,
        "protocol": "TCP",
        "rule_name": "Suspicious reverse shell to known C2",
        "description": "powershell.exe 由 WINWORD.EXE 启动外连 185.220.101.34:4444",
    }


@pytest.fixture
def fp_alert():
    return {
        "alert_id": "FP-TEST",
        "timestamp": "2026-07-18T01:00:12Z",
        "source": "ids",
        "severity": "low",
        "src_ip": "10.20.30.5",
        "dst_ip": "10.20.40.7",
        "src_port": 51230,
        "dst_port": 22,
        "protocol": "TCP",
        "rule_name": "Possible port scan",
        "description": "运维主机健康检查 nightly monitor 脚本",
    }


# ============================================================
# 节点1 preprocess 单元测试
# ============================================================


class TestPreprocess:
    def test_extracts_features(self, tp_alert):
        out = preprocess_node({"alert": tp_alert})
        f = out["normalized_features"]
        assert f["source_device"] == "edr"
        assert f["severity"] == "high"
        assert f["dst_port"] == 4444
        assert f["dst_port_class"] == "registered"

    def test_direction_internal_to_external(self, tp_alert):
        out = preprocess_node({"alert": tp_alert})
        assert "外连" in out["normalized_features"]["direction"]

    def test_direction_lateral(self, fp_alert):
        out = preprocess_node({"alert": fp_alert})
        assert "横向" in out["normalized_features"]["direction"]

    def test_port_class_classification(self):
        cases = [
            (80, "well_known"),
            (4444, "registered"),
            (50000, "ephemeral"),
            (None, "unknown"),
        ]
        for port, expected in cases:
            out = preprocess_node(
                {"alert": {"src_port": None, "dst_port": port}}
            )
            assert out["normalized_features"]["dst_port_class"] == expected

    def test_hour_extraction(self):
        out = preprocess_node(
            {"alert": {"timestamp": "2026-07-18T14:30:00Z"}}
        )
        # UTC 14:30 → hour 14（或本地时区，但应该是个 0-23 的 int）
        h = out["normalized_features"]["hour_of_day"]
        assert h is not None and 0 <= h <= 23


# ============================================================
# 端到端 mock 链路
# ============================================================


class TestEndToEnd:
    def test_tp_judged_correctly(self, mock_graph, tp_alert):
        """真阳告警被 mock 规则判为真阳。"""
        result = mock_graph.invoke({"alert": tp_alert})
        assert result["judgment"] == "真阳"
        assert result["confidence"] > 0.7
        # CoT 必须 5 步（赛题挑战任务要求"展示完整思维链"）
        assert len(result["cot_trace"]) >= 5

    def test_fp_judged_correctly(self, mock_graph, fp_alert):
        """假阳告警被 mock 规则判为假阳。"""
        result = mock_graph.invoke({"alert": fp_alert})
        assert result["judgment"] == "假阳"
        assert result["confidence"] > 0.7

    def test_output_contains_full_result(self, mock_graph, tp_alert):
        """output 节点输出结构完整的 result。"""
        result = mock_graph.invoke({"alert": tp_alert})["result"]
        assert result["alert_id"] == "TP-TEST"
        assert result["judgment"] in {"真阳", "假阳", "待查"}
        assert "confidence" in result
        assert "reason" in result
        assert "cot_trace" in result
        assert "features" in result

    def test_judge_alert_helper(self, tp_alert):
        """便捷函数 judge_alert 直接返回 result dict。"""
        r = judge_alert(tp_alert, llm=get_llm(mock=True))
        assert r["alert_id"] == "TP-TEST"
        assert r["judgment"] == "真阳"


# ============================================================
# 数据加载（保留 Week 1 的测试）
# ============================================================


class TestData:
    def test_load_alerts_default_dataset(self):
        alerts = load_alerts()
        assert len(alerts) == 10
        tp = [a for a in alerts if a.label == "真阳"]
        fp = [a for a in alerts if a.label == "假阳"]
        assert len(tp) == 5 and len(fp) == 5

    def test_load_alerts_validates_schema(self):
        for a in load_alerts():
            assert a.source in {"siem", "edr", "firewall", "ids", "waf", "ips", "ndr"}
            assert a.severity in {"high", "medium", "low", "info"}
            assert a.label in {"真阳", "假阳", "待查", None}
