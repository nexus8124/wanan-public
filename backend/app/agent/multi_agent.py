"""面向 SOC 告警的受控多智能体编排。

该实现刻意采用“一个数据源、一个工具所有者”：协调器只规划，专业智能体只读
自己的数据源，验证智能体只融合已经取得的证据。它与 ReAct 是独立评测策略，
不会在多智能体内部再次启动一套无界 ReAct 循环。
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel

from app.agent.nodes import (
    _agent_visible_alert,
    _bind_structured_output,
    _estimate_tokens,
    _remaining_global_timeout,
)
from app.agent.prompts import build_multi_agent_verify_prompt
from app.agent.state import AgentState
from app.agent.tooling import ControlledToolExecutor, ExecutionPolicy, ToolContext
from app.agent.tools import TOOL_REGISTRY
from app.models.schemas import MultiAgentVerdict

logger = logging.getLogger(__name__)

MULTI_AGENT_CONFIDENCE_THRESHOLD = 0.85


def should_enter_multi_agent(state: AgentState) -> bool:
    """只把需要补证的样本送入多智能体团队。"""
    alert = state.get("alert") or {}
    payload = alert.get("raw_payload") or {}
    has_real_sources = bool(
        payload.get("_evidence_ref")
        or payload.get("_evidence_store")
        or payload.get("evidence_capabilities")
        or payload.get("temporal_context")
    )
    return bool(
        has_real_sources
        or state.get("judgment") == "待查"
        or float(state.get("confidence", 0.0)) < MULTI_AGENT_CONFIDENCE_THRESHOLD
    )


def _first_endpoint_target(alert: dict[str, Any]) -> str | None:
    payload = alert.get("raw_payload") or {}
    targets = (payload.get("query_targets") or {}).get("endpoint") or []
    if targets:
        target = targets[0]
        if isinstance(target, dict):
            return str(target.get("ip") or target.get("host_ip") or "") or None
        return str(target) or None
    if alert.get("source") == "edr":
        return str(alert.get("src_ip") or alert.get("dst_ip") or "") or None
    return None


def _first_network_target(alert: dict[str, Any]) -> str | None:
    payload = alert.get("raw_payload") or {}
    targets = (payload.get("query_targets") or {}).get("network_ips") or []
    if targets:
        return str(targets[0]) or None
    if alert.get("source") in {"firewall", "ids", "ips", "ndr", "waf"}:
        return str(alert.get("src_ip") or alert.get("dst_ip") or "") or None
    return None


def multi_agent_plan_node(state: AgentState) -> AgentState:
    """协调器基于可用数据源生成任务账本和有界专业任务队列。"""
    alert = state["alert"]
    payload = alert.get("raw_payload") or {}
    capabilities = set(payload.get("evidence_capabilities") or [])
    assignments: list[dict[str, Any]] = []

    # 上下文智能体负责读取检测器原始事件和时间窗口，不访问评测标签。
    assignments.append({
        "agent": "context_agent",
        "capability": "detector_context",
        "tool": "inspect_alert_context",
        "args": {},
        "status": "pending",
        "purpose": "核验检测器原始事件、时间窗口和可用证据源",
    })

    endpoint_ip = _first_endpoint_target(alert)
    if endpoint_ip and ("endpoint_logs" in capabilities or alert.get("source") == "edr"):
        assignments.append({
            "agent": "endpoint_agent",
            "capability": "endpoint_logs",
            "tool": "fetch_endpoint_logs",
            "args": {"host_ip": endpoint_ip},
            "status": "pending",
            "purpose": "核验进程、认证和端点行为证据",
        })

    network_ip = _first_network_target(alert)
    if network_ip and (
        {"network_alerts", "network_flows", "netflow"} & capabilities
        or alert.get("source") in {"firewall", "ids", "ips", "ndr", "waf"}
    ):
        assignments.append({
            "agent": "network_agent",
            "capability": "network_evidence",
            "tool": "fetch_network_flows",
            "args": {"host_ip": network_ip, "window_min": 30},
            "status": "pending",
            "purpose": "核验连接、流量和网络检测证据",
        })

    policy = state.get("execution_policy", {})
    max_steps = int(policy.get("max_steps", 3))
    assignments = assignments[:max_steps]
    knowledge_ids = [
        str(item.get("knowledge_id"))
        for item in state.get("knowledge_hits", [])
        if item.get("knowledge_id")
    ]
    planned_agents = [item["agent"] for item in assignments]
    if knowledge_ids:
        planned_agents.append("knowledge_agent")

    task_ledger = {
        "known_facts": {
            "alert_id": alert.get("alert_id"),
            "source": alert.get("source"),
            "severity": alert.get("severity"),
            "rule_name": alert.get("rule_name"),
            "src_ip": alert.get("src_ip"),
            "dst_ip": alert.get("dst_ip"),
        },
        "working_hypothesis": {
            "judgment": state.get("judgment", "待查"),
            "confidence": state.get("confidence", 0.0),
            "reason": state.get("reason", ""),
        },
        "unknowns": [item["purpose"] for item in assignments],
        "plan": [
            {"agent": item["agent"], "purpose": item["purpose"]}
            for item in assignments
        ],
        "knowledge_ids": knowledge_ids,
    }
    progress_ledger = {
        "status": "investigating",
        "planned_agents": planned_agents,
        "completed_agents": ["knowledge_agent"] if knowledge_ids else [],
        "current_agent": None,
        "new_evidence_ids": [],
        "stalled_count": 0,
        "remaining_tasks": len(assignments),
    }
    steps: list[dict[str, Any]] = []
    if knowledge_ids:
        steps.append({
            "step": 1,
            "agent": "knowledge_agent",
            "capability": "security_knowledge",
            "tool": "rag_retrieve",
            "args": {},
            "status": "completed",
            "summary": f"复核本轮已召回的 {len(knowledge_ids)} 条安全知识",
            "knowledge_ids": knowledge_ids,
        })
    return {
        "multi_agent_entered": True,
        "task_ledger": task_ledger,
        "progress_ledger": progress_ledger,
        "agent_queue": assignments,
        "multi_agent_steps": steps,
    }


def multi_agent_has_tasks(state: AgentState) -> str:
    """LangGraph 条件路由：继续专业调查或进入最终验证。"""
    if state.get("termination_reason") in {
        "global_timeout", "tool_step_budget_exhausted"
    }:
        return "verify"
    return "worker" if state.get("agent_queue") else "verify"


def multi_agent_worker_node(state: AgentState) -> AgentState:
    """执行队首专业智能体任务；工具权限由协调器的固定映射决定。"""
    queue = list(state.get("agent_queue", []))
    if not queue:
        return {}
    assignment = dict(queue.pop(0))
    policy_data = state.get("execution_policy", {})
    policy = ExecutionPolicy(**{
        key: value for key, value in policy_data.items()
        if key in ExecutionPolicy.__dataclass_fields__
    })
    existing_steps = list(state.get("multi_agent_steps", []))
    tool_steps = [step for step in existing_steps if step.get("tool") != "rag_retrieve"]
    if len(tool_steps) >= policy.max_steps:
        return {
            "agent_queue": [],
            "termination_reason": "tool_step_budget_exhausted",
        }

    started = state.get("agent_started_monotonic", time.monotonic())
    if time.monotonic() - started >= policy.global_timeout_s:
        return {"agent_queue": [], "termination_reason": "global_timeout"}

    deadline = started + policy.global_timeout_s
    executor = ControlledToolExecutor(TOOL_REGISTRY, policy)
    tool_result = executor.execute_sync(
        assignment["tool"],
        assignment.get("args", {}),
        ToolContext(
            alert=state["alert"],
            sample_id=str(state["alert"].get("alert_id", "")),
            deadline_monotonic=deadline,
        ),
        prior_fingerprints=set(state.get("tool_call_fingerprints", [])),
    )
    result = tool_result.model_dump(mode="json")
    new_evidence = result.get("evidence", [])
    usable_ids = [
        item.get("evidence_id") for item in new_evidence
        if item.get("evidence_id") and item.get("usable", True)
    ]
    assignment.update({
        "status": "completed" if result.get("success") else result.get("status", "failed"),
        "result": result,
    })
    existing_steps.append({
        "step": len(existing_steps) + 1,
        **assignment,
    })

    tools_called = list(state.get("tools_called", []))
    if assignment["tool"] not in tools_called:
        tools_called.append(assignment["tool"])
    fingerprints = list(state.get("tool_call_fingerprints", []))
    if result.get("call_fingerprint"):
        fingerprints.append(result["call_fingerprint"])
    evidence = list(state.get("evidence", [])) + new_evidence

    progress = dict(state.get("progress_ledger", {}))
    completed_agents = list(progress.get("completed_agents", []))
    if assignment["agent"] not in completed_agents:
        completed_agents.append(assignment["agent"])
    evidence_ids = list(progress.get("new_evidence_ids", [])) + usable_ids
    stalled = int(progress.get("stalled_count", 0))
    progress.update({
        "current_agent": assignment["agent"],
        "completed_agents": completed_agents,
        "new_evidence_ids": list(dict.fromkeys(evidence_ids)),
        "stalled_count": 0 if usable_ids else stalled + 1,
        "remaining_tasks": len(queue),
        "status": "investigating" if queue else "verifying",
    })
    logger.info(
        "multi_agent worker=%s tool=%s status=%s evidence=%d",
        assignment["agent"], assignment["tool"], result.get("status"), len(usable_ids),
    )
    return {
        "agent_queue": queue,
        "multi_agent_steps": existing_steps,
        "progress_ledger": progress,
        "tools_called": tools_called,
        "evidence": evidence,
        "tool_call_fingerprints": fingerprints,
        "no_evidence_count": state.get("no_evidence_count", 0) + (0 if usable_ids else 1),
    }


def make_multi_agent_verify_node(llm: BaseChatModel):
    """创建只读验证智能体，融合各专业智能体已经取得的证据。"""
    prompt = build_multi_agent_verify_prompt()
    structured_llm = _bind_structured_output(llm, MultiAgentVerdict)

    def multi_agent_verify_node(state: AgentState) -> AgentState:
        alert_json = json.dumps(
            _agent_visible_alert(state["alert"]), ensure_ascii=False, default=str
        )
        ledger_text = json.dumps(
            state.get("task_ledger", {}), ensure_ascii=False, default=str
        )
        findings_text = json.dumps(
            state.get("multi_agent_steps", []), ensure_ascii=False, default=str
        )
        verdict: MultiAgentVerdict | None = None
        try:
            prompt_value = prompt.invoke({
                "alert_json": alert_json,
                "current_judgment": state.get("judgment", "待查"),
                "current_confidence": state.get("confidence", 0.0),
                "current_reason": state.get("reason", ""),
                "task_ledger": ledger_text,
                "agent_findings": findings_text,
                "rag_context": state.get("rag_context") or "(本次未启用 RAG)",
            })
            verdict = structured_llm.invoke(
                prompt_value, timeout=_remaining_global_timeout(state)
            )
        except Exception as exc:
            logger.exception("multi_agent verifier failed: %s", exc)

        progress = dict(state.get("progress_ledger", {}))
        progress.update({"current_agent": "verifier_agent", "status": "completed"})
        base_update: AgentState = {
            "multi_agent_verified": verdict is not None,
            "progress_ledger": progress,
            "llm_calls_used": state.get("llm_calls_used", 0) + 1,
            "estimated_tokens_used": state.get("estimated_tokens_used", 0)
            + _estimate_tokens(alert_json, ledger_text, findings_text),
        }
        if verdict is None:
            base_update["termination_reason"] = "multi_agent_verifier_failed"
            return base_update

        available_evidence = {
            item.get("evidence_id") for item in state.get("evidence", [])
            if item.get("evidence_id")
            and item.get("usable", True)
            and item.get("kind") != "knowledge_reference"
        }
        valid_evidence = [
            item for item in verdict.cited_evidence if item in available_evidence
        ]
        available_knowledge = {
            item.get("knowledge_id") for item in state.get("knowledge_hits", [])
            if item.get("knowledge_id")
        }
        valid_knowledge = [
            item for item in verdict.cited_knowledge if item in available_knowledge
        ]

        prior = state.get("judgment", "待查")
        changed = verdict.judgment != prior
        reject_reason: str | None = None
        if prior in {"真阳", "假阳"} and verdict.judgment == "待查":
            reject_reason = "resolved_verdict_cannot_be_downgraded_to_pending"
        elif changed and not valid_evidence:
            reject_reason = "multi_agent_change_requires_event_evidence"

        base_update.update({
            "cited_evidence": list(dict.fromkeys(
                state.get("cited_evidence", []) + valid_evidence
            )),
            "cited_knowledge": list(dict.fromkeys(
                state.get("cited_knowledge", []) + valid_knowledge
            )),
            "cot_trace": state.get("cot_trace", [])
            + [f"[多智能体验证] {verdict.analysis}"],
        })
        if reject_reason:
            base_update["termination_reason"] = reject_reason
            base_update["cot_trace"] = base_update["cot_trace"] + [
                f"[多智能体保护] 拒绝无有效事件证据的结论变化：{reject_reason}"
            ]
        else:
            base_update.update({
                "judgment": verdict.judgment,
                "confidence": verdict.confidence,
                "reason": verdict.reason,
                "termination_reason": "multi_agent_completed",
            })
        return base_update

    return multi_agent_verify_node
