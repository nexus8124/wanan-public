"""ReAct 工具集与循环逻辑测试。"""

from __future__ import annotations

import pytest

from app.agent.graph import (
    REACT_CONFIDENCE_THRESHOLD,
    REACT_MAX_STEPS,
    _judge_router,
    _react_router,
)
from app.agent.nodes import disposition_node, tool_executor_node
from app.agent.state import AgentState
from app.agent.tools import (
    TOOL_REGISTRY,
    execute_tool,
    format_tool_catalog_for_prompt,
)


# ============================================================
# 工具单元测试
# ============================================================


class TestTools:
    """8 个工具的行为测试。"""

    TP_CTX = {
        "alert_id": "TP-001",
        "src_ip": "10.20.33.51",
        "dst_ip": "185.220.101.34",
        "rule_name": "Suspicious reverse shell to known C2",
        "description": "powershell.exe 外连 C2",
    }
    FP_CTX = {
        "alert_id": "FP-001",
        "src_ip": "10.20.30.5",
        "dst_ip": "10.20.40.7",
        "rule_name": "Possible port scan",
        "description": "health check nightly monitor",
    }

    def test_all_8_tools_registered(self):
        """赛题要求 8 个工具，必须全部在注册表里。"""
        expected = {
            "fetch_endpoint_logs", "fetch_network_flows", "check_threat_intel",
            "query_similar_alerts", "search_attck_technique", "lookup_cve",
            "suggest_block_ip", "suggest_isolate_host",
        }
        assert set(TOOL_REGISTRY.keys()) == expected

    def test_endpoint_logs_differ_for_tp_vs_fp(self):
        """工具必须有状态：真阳返回可疑进程，假阳返回正常。"""
        tp = execute_tool("fetch_endpoint_logs", self.TP_CTX, {"host_ip": "10.20.33.51"})
        fp = execute_tool("fetch_endpoint_logs", self.FP_CTX, {"host_ip": "10.20.30.5"})
        assert len(tp["suspicious_processes"]) > 0, "真阳应返回可疑进程"
        assert len(fp["suspicious_processes"]) == 0, "假阳不应有可疑进程"

    def test_threat_intel_identifies_malicious_ip(self):
        """威胁情报能识别已知恶意 IP。"""
        r = execute_tool("check_threat_intel", self.TP_CTX, {"indicator": "185.220.101.34"})
        assert r["malicious"] is True
        assert len(r["tags"]) > 0

    def test_threat_intel_clean_ip(self):
        """干净 IP 不报恶意。"""
        r = execute_tool("check_threat_intel", self.TP_CTX, {"indicator": "8.8.8.8"})
        assert r["malicious"] is False

    def test_attck_search_returns_matches(self):
        """ATT&CK 查询能命中关键词。"""
        r = execute_tool("search_attck_technique", self.TP_CTX, {"keyword": "powershell"})
        assert r["total"] >= 1
        assert any(t["id"] == "T1059.001" for t in r["matches"])

    def test_cve_lookup(self):
        """CVE 查询能命中。"""
        r = execute_tool("lookup_cve", self.TP_CTX, {"keyword": "openssh"})
        assert r["total"] >= 1

    def test_block_ip_generates_ticket_not_executed(self):
        """处置工具生成工单但不执行（安全设计）。"""
        r = execute_tool(
            "suggest_block_ip", self.TP_CTX,
            {"ip": "185.220.101.34", "reason": "C2"},
        )
        assert r["executed"] is False
        assert "ticket_id" in r
        assert r["action"] == "block_ip"

    def test_isolate_host_generates_ticket(self):
        r = execute_tool(
            "suggest_isolate_host", self.TP_CTX,
            {"host_ip": "10.20.33.51"},
        )
        assert r["executed"] is False
        assert r["action"] == "isolate_host"

    def test_unknown_tool_returns_error(self):
        """未知工具不崩，返回错误。"""
        r = execute_tool("nonexistent_tool", self.TP_CTX, {})
        assert "error" in r

    def test_tool_catalog_format(self):
        """工具目录能格式化成 prompt 文本。"""
        catalog = format_tool_catalog_for_prompt()
        assert "fetch_endpoint_logs" in catalog
        assert "suggest_block_ip" in catalog


# ============================================================
# 路由逻辑测试（_judge_router / _react_router）
# ============================================================


class TestRouters:
    """循环路由的终止条件测试。"""

    def test_judge_router_high_confidence_skips_react(self):
        """高置信直接进 disposition。"""
        state: AgentState = {"confidence": 0.95, "judgment": "真阳"}  # type: ignore
        assert _judge_router(state) == "disposition"

    def test_judge_router_low_confidence_enters_react(self):
        """低置信进 ReAct。"""
        state: AgentState = {"confidence": 0.5, "judgment": "待查"}  # type: ignore
        assert _judge_router(state) == "react_decide"

    def test_judge_router_threshold_boundary(self):
        """边界：正好 0.85 应跳过 ReAct（>= 判定）。"""
        state: AgentState = {"confidence": REACT_CONFIDENCE_THRESHOLD, "judgment": "真阳"}  # type: ignore
        assert _judge_router(state) == "disposition"

    def test_judge_router_high_conf_but_unknown_goes_react(self):
        """高置信但 judgment 是待查 → 仍进 ReAct（待查必须查证）。"""
        state: AgentState = {"confidence": 0.9, "judgment": "待查"}  # type: ignore
        assert _judge_router(state) == "react_decide"

    def test_react_router_continues_when_action_pending(self):
        """有 next_action 且步数未满 → 继续。"""
        state: AgentState = {  # type: ignore
            "react_steps": [{"tool": "fetch_endpoint_logs"}],
            "next_action": {"tool": "check_threat_intel", "args": {}},
            "confidence": 0.6,
        }
        assert _react_router(state) == "tool_executor"

    def test_react_router_stops_on_max_steps(self):
        """步数达上限 → 强制跳出（防无限循环）。"""
        state: AgentState = {  # type: ignore
            "react_steps": [{"tool": f"t{i}"} for i in range(REACT_MAX_STEPS)],
            "next_action": {"tool": "another", "args": {}},
            "confidence": 0.5,
        }
        assert _react_router(state) == "disposition"

    def test_react_router_stops_when_no_next_action(self):
        """LLM 说 need_more_info=false → 跳出。"""
        state: AgentState = {  # type: ignore
            "react_steps": [{"tool": "fetch_endpoint_logs"}],
            "next_action": None,
            "confidence": 0.6,
        }
        assert _react_router(state) == "disposition"

    def test_react_router_stops_when_confidence_high(self):
        """调完工具置信度达标 → 跳出。"""
        state: AgentState = {  # type: ignore
            "react_steps": [{"tool": "fetch_endpoint_logs"}],
            "next_action": {"tool": "another", "args": {}},
            "confidence": 0.95,
        }
        assert _react_router(state) == "disposition"


# ============================================================
# 节点单元测试
# ============================================================


class TestNodes:
    def test_tool_executor_appends_step(self):
        """tool_executor 正确追加步骤到 react_steps。"""
        state: AgentState = {  # type: ignore
            "alert": {"alert_id": "TP-001", "src_ip": "10.20.33.51", "dst_ip": "185.220.101.34"},
            "react_steps": [],
            "tools_called": [],
            "next_action": {"tool": "check_threat_intel", "args": {"indicator": "185.220.101.34"}},
        }
        out = tool_executor_node(state)
        assert len(out["react_steps"]) == 1
        assert out["react_steps"][0]["tool"] == "check_threat_intel"
        assert "check_threat_intel" in out["tools_called"]
        assert out["react_steps"][0]["result"]["malicious"] is True

    def test_disposition_for_true_positive(self):
        """真阳 → 封禁+隔离工单。"""
        state: AgentState = {  # type: ignore
            "alert": {"alert_id": "TP-001", "src_ip": "10.20.33.51", "dst_ip": "185.220.101.34"},
            "judgment": "真阳",
            "confidence": 0.95,
        }
        out = disposition_node(state)
        disp = out["disposition"]
        assert disp["action"] == "block_and_isolate"
        assert len(disp["tickets"]) == 2  # 封 IP + 隔离主机
        assert disp["severity"] == "critical"

    def test_disposition_for_false_positive(self):
        """假阳 → 加白建议。"""
        state: AgentState = {  # type: ignore
            "alert": {"alert_id": "FP-001", "src_ip": "10.20.30.5", "dst_ip": "10.20.40.7"},
            "judgment": "假阳",
            "confidence": 0.9,
        }
        out = disposition_node(state)
        assert out["disposition"]["action"] == "whitelist"
        assert out["disposition"]["severity"] == "info"

    def test_disposition_for_unknown(self):
        """待查 → 升级人工。"""
        state: AgentState = {  # type: ignore
            "alert": {"alert_id": "X-001", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"},
            "judgment": "待查",
            "confidence": 0.4,
        }
        out = disposition_node(state)
        assert out["disposition"]["action"] == "escalate_human"
