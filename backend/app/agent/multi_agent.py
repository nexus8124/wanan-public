"""面向 SOC 告警的有界自主多智能体 ReAct 编排。

协调器由 LLM 生成首轮计划；每个专业智能体取得一次新观测后，重规划器都会
基于反馈决定替换后续任务或进入验证。所有模型计划都必须经过能力、参数、工具
所有权、重复调用和预算校验，模型不能借“自主规划”绕过执行护栏。
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
from app.agent.prompts import (
    build_multi_agent_plan_prompt,
    build_multi_agent_replan_prompt,
    build_multi_agent_verify_prompt,
)
from app.agent.state import AgentState
from app.agent.tooling import (
    ControlledToolExecutor,
    ExecutionPolicy,
    ToolContext,
    call_fingerprint,
)
from app.agent.tools import TOOL_CATALOG, TOOL_REGISTRY
from app.models.schemas import (
    InvestigationTask,
    MultiAgentPlan,
    MultiAgentReplan,
    MultiAgentVerdict,
)

logger = logging.getLogger(__name__)

MULTI_AGENT_CONFIDENCE_THRESHOLD = 0.85

_TOOL_OWNERS = {
    "inspect_alert_context": ("context_agent", "detector_context"),
    "fetch_endpoint_logs": ("endpoint_agent", "endpoint_logs"),
    "fetch_network_flows": ("network_agent", "network_evidence"),
    "check_threat_intel": ("intel_agent", "threat_intelligence"),
    "query_similar_alerts": ("history_agent", "alert_history"),
    "search_attck_technique": ("knowledge_agent", "security_knowledge"),
    "search_sigma_rule": ("knowledge_agent", "security_knowledge"),
    "search_playbook": ("knowledge_agent", "security_knowledge"),
    "lookup_cve": ("knowledge_agent", "security_knowledge"),
}
_PUBLIC_DATASETS = {"AIT-ADS", "AIT-ADS-EVENT-GOLD", "TON-IOT-INDUSTRIAL"}


def _planner_tool_catalog() -> str:
    lines = []
    for item in TOOL_CATALOG:
        if item["name"] not in _TOOL_OWNERS:
            continue
        args = ", ".join(item["args"]) or "无参数"
        owner, _ = _TOOL_OWNERS[item["name"]]
        lines.append(f"- {owner}: {item['name']}({args}) — {item['description']}")
    return "\n".join(lines)


def should_enter_multi_agent(state: AgentState) -> bool:
    """只把需要补证的样本送入多智能体团队。"""
    alert = state.get("alert") or {}
    payload = alert.get("raw_payload") or {}
    capabilities = set(payload.get("evidence_capabilities") or [])
    # Enter the expensive team path immediately only when the case can actually
    # cross-check detector context against a second modality.  A lone opaque
    # reference or temporal count still remains available to ReAct, but does not
    # by itself justify running every specialist on every easy sample.
    has_cross_source_evidence = bool(
        "detector_context" in capabilities
        and ({"endpoint_logs", "network_alerts", "network_flows", "netflow"} & capabilities)
    )
    if payload.get("dataset") != "AIT-ADS-EVENT-GOLD":
        has_cross_source_evidence = bool(
            payload.get("_evidence_ref")
            or payload.get("_evidence_store")
            or capabilities
            or payload.get("temporal_context")
        )
    return bool(
        has_cross_source_evidence
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


def _fallback_assignments(alert: dict[str, Any]) -> list[dict[str, Any]]:
    """模型计划失败时使用的最小、标签无关能力路由。"""
    payload = alert.get("raw_payload") or {}
    capabilities = set(payload.get("evidence_capabilities") or [])
    assignments: list[dict[str, Any]] = [{
        "agent": "context_agent",
        "capability": "detector_context",
        "tool": "inspect_alert_context",
        "args": {},
        "status": "pending",
        "purpose": "核验检测器原始事件、时间窗口和可用证据源",
        "success_criteria": "确认告警上下文和可查询的数据源",
    }]

    endpoint_ip = _first_endpoint_target(alert)
    if endpoint_ip and ("endpoint_logs" in capabilities or alert.get("source") == "edr"):
        assignments.append({
            "agent": "endpoint_agent",
            "capability": "endpoint_logs",
            "tool": "fetch_endpoint_logs",
            "args": {"host_ip": endpoint_ip},
            "status": "pending",
            "purpose": "核验进程、认证和端点行为证据",
            "success_criteria": "取得与告警时间和主机一致的端点记录",
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
            "success_criteria": "取得与告警目标一致的网络侧记录",
        })
    return assignments


def _target_values(items: list[Any]) -> list[str]:
    values: list[str] = []
    for item in items:
        value = (
            item.get("ip") or item.get("host_ip") or item.get("host")
            if isinstance(item, dict) else item
        )
        if value not in (None, ""):
            values.append(str(value))
    return list(dict.fromkeys(values))


def _validated_assignment(
    alert: dict[str, Any],
    task: InvestigationTask | dict[str, Any],
    seen_fingerprints: set[str],
) -> dict[str, Any] | None:
    """把模型计划收敛到真实能力、真实目标和固定工具所有权。"""
    raw = task.model_dump(mode="python") if isinstance(task, InvestigationTask) else dict(task)
    tool = str(raw.get("tool") or "")
    if tool not in _TOOL_OWNERS or tool not in TOOL_REGISTRY:
        return None
    payload = alert.get("raw_payload") or {}
    capabilities = set(payload.get("evidence_capabilities") or [])
    targets = payload.get("query_targets") or {}
    dataset = payload.get("dataset")
    args = dict(raw.get("args") or {})

    if tool == "inspect_alert_context":
        args = {}
    elif tool == "fetch_endpoint_logs":
        allowed = _target_values(list(targets.get("endpoint") or []))
        if not allowed and alert.get("source") == "edr":
            allowed = _target_values([alert.get("src_ip"), alert.get("dst_ip")])
        if capabilities and "endpoint_logs" not in capabilities:
            return None
        host = str(args.get("host_ip") or (allowed[0] if allowed else ""))
        if not host or (allowed and host not in allowed):
            return None
        args = {"host_ip": host}
    elif tool == "fetch_network_flows":
        allowed = _target_values(list(targets.get("network_ips") or []))
        if not allowed and alert.get("source") in {"firewall", "ids", "ips", "ndr", "waf"}:
            allowed = _target_values([alert.get("src_ip"), alert.get("dst_ip")])
        if capabilities and not (
            {"network_alerts", "network_flows", "netflow"} & capabilities
        ):
            return None
        host = str(args.get("host_ip") or (allowed[0] if allowed else ""))
        if not host or (allowed and host not in allowed):
            return None
        try:
            window = max(1, min(120, int(args.get("window_min", 30))))
        except (TypeError, ValueError):
            window = 30
        args = {"host_ip": host, "window_min": window}
    elif tool == "check_threat_intel":
        if dataset in _PUBLIC_DATASETS:
            return None
        allowed = _target_values([alert.get("src_ip"), alert.get("dst_ip")])
        indicator = str(args.get("indicator") or (allowed[0] if allowed else ""))
        if not indicator or (allowed and indicator not in allowed):
            return None
        args = {"indicator": indicator}
    elif tool == "query_similar_alerts":
        if dataset in _PUBLIC_DATASETS:
            return None
        rule_name = str(args.get("rule_name") or alert.get("rule_name") or "").strip()
        if not rule_name:
            return None
        args = {"rule_name": rule_name[:200]}
    else:
        keyword = str(args.get("keyword") or alert.get("rule_name") or "").strip()
        if not keyword:
            return None
        args = {"keyword": keyword[:200]}

    fingerprint = call_fingerprint(tool, args)
    if fingerprint in seen_fingerprints:
        return None
    seen_fingerprints.add(fingerprint)
    owner, capability = _TOOL_OWNERS[tool]
    return {
        "agent": owner,
        "capability": capability,
        "tool": tool,
        "args": args,
        "status": "pending",
        "purpose": str(raw.get("purpose") or "补充与当前假设相关的证据")[:300],
        "success_criteria": str(
            raw.get("success_criteria") or "取得可归因的相关证据"
        )[:300],
    }


def _validated_assignments(
    state: AgentState,
    tasks: list[InvestigationTask | dict[str, Any]],
    limit: int,
) -> list[dict[str, Any]]:
    alert = state["alert"]
    seen = set(state.get("tool_call_fingerprints", []))
    output: list[dict[str, Any]] = []
    for task in tasks:
        assignment = _validated_assignment(alert, task, seen)
        if assignment:
            output.append(assignment)
        if len(output) >= limit:
            break

    payload = alert.get("raw_payload") or {}
    requires_context = bool(payload.get("_evidence_ref") and payload.get("_evidence_store"))
    context_fp = call_fingerprint("inspect_alert_context", {})
    if (
        requires_context
        and context_fp not in set(state.get("tool_call_fingerprints", []))
        and not any(item["tool"] == "inspect_alert_context" for item in output)
    ):
        context = _validated_assignment(
            alert,
            _fallback_assignments(alert)[0],
            set(state.get("tool_call_fingerprints", [])),
        )
        if context:
            output.insert(0, context)
    return output[:limit]


def _initial_plan_update(
    state: AgentState,
    assignments: list[dict[str, Any]],
    *,
    objective: str,
    rationale: str,
    planner_mode: str,
    llm_call: bool,
) -> AgentState:
    alert = state["alert"]
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
        "objective": objective,
        "planner_mode": planner_mode,
        "rationale": rationale,
        "unknowns": [item["purpose"] for item in assignments],
        "plan": [
            {"agent": item["agent"], "purpose": item["purpose"]}
            for item in assignments
        ],
        "knowledge_ids": knowledge_ids,
        "revisions": [],
    }
    progress_ledger = {
        "status": "investigating",
        "planner_mode": planner_mode,
        "replan_count": 0,
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
        "react_entered": planner_mode == "llm_autonomous_react",
        "task_ledger": task_ledger,
        "progress_ledger": progress_ledger,
        "agent_queue": assignments,
        "multi_agent_steps": steps,
        "planner_trace": [{
            "round": 0,
            "mode": planner_mode,
            "objective": objective,
            "rationale": rationale,
            "tasks": [
                {key: item.get(key) for key in ("agent", "tool", "args", "purpose")}
                for item in assignments
            ],
        }],
        "replan_count": 0,
        "cot_trace": state.get("cot_trace", []) + [f"[SuperAgent 计划] {rationale}"],
        "llm_calls_used": state.get("llm_calls_used", 0) + (1 if llm_call else 0),
    }


def multi_agent_plan_node(state: AgentState) -> AgentState:
    """无 LLM 规划的兼容/消融节点。"""
    policy = state.get("execution_policy", {})
    max_steps = int(policy.get("max_steps", 3))
    assignments = _validated_assignments(
        state, _fallback_assignments(state["alert"]), max_steps
    )
    return _initial_plan_update(
        state,
        assignments,
        objective="对当前告警进行最小必要的跨源核验",
        rationale="使用可用证据能力生成确定性兜底计划",
        planner_mode="validated_fallback",
        llm_call=False,
    )


def make_multi_agent_plan_node(llm: BaseChatModel):
    """创建由 LLM 提案、由框架校验的自主协调器。"""
    prompt = build_multi_agent_plan_prompt(_planner_tool_catalog())
    structured_llm = _bind_structured_output(llm, MultiAgentPlan)

    def autonomous_plan_node(state: AgentState) -> AgentState:
        alert = state["alert"]
        visible_alert = json.dumps(
            _agent_visible_alert(alert), ensure_ascii=False, default=str
        )
        capabilities = json.dumps(
            (alert.get("raw_payload") or {}).get("evidence_capabilities") or [],
            ensure_ascii=False,
        )
        plan: MultiAgentPlan | None = None
        try:
            prompt_value = prompt.invoke({
                "alert_json": visible_alert,
                "current_judgment": state.get("judgment", "待查"),
                "current_confidence": state.get("confidence", 0.0),
                "current_reason": state.get("reason", ""),
                "capabilities": capabilities,
            })
            plan = structured_llm.invoke(
                prompt_value, timeout=_remaining_global_timeout(state)
            )
        except Exception as exc:
            logger.exception("autonomous multi-agent planning failed: %s", exc)

        policy = state.get("execution_policy", {})
        max_steps = int(policy.get("max_steps", 3))
        assignments = _validated_assignments(
            state, list(plan.tasks) if plan else [], max_steps
        )
        used_fallback = not assignments
        if not assignments:
            assignments = _validated_assignments(
                state, _fallback_assignments(alert), max_steps
            )
        objective = plan.objective if plan else "对当前告警完成跨源证据核验"
        rationale = (
            plan.rationale if plan else "模型计划不可用，已切换到受控能力兜底计划"
        )
        update = _initial_plan_update(
            state,
            assignments,
            objective=objective,
            rationale=rationale,
            planner_mode=(
                "llm_autonomous_react"
                if plan and not used_fallback else "validated_fallback"
            ),
            llm_call=True,
        )
        # This graph branch is ReAct-enabled even when the LLM plan itself has
        # to fall back to a framework-generated safe plan.
        update["react_entered"] = True
        update["estimated_tokens_used"] = state.get("estimated_tokens_used", 0) + _estimate_tokens(
            visible_alert, capabilities, plan.model_dump() if plan else "planner_failed"
        )
        return update

    return autonomous_plan_node


def _remaining_tool_budget(state: AgentState) -> int:
    policy = state.get("execution_policy", {})
    completed = sum(
        1 for step in state.get("multi_agent_steps", [])
        if step.get("tool") != "rag_retrieve"
    )
    return max(0, int(policy.get("max_steps", 3)) - completed)


def multi_agent_after_worker(state: AgentState) -> str:
    """每次观测后选择重规划；预算耗尽时直接交给验证智能体。"""
    policy = state.get("execution_policy", {})
    if state.get("termination_reason") in {
        "global_timeout", "tool_step_budget_exhausted"
    }:
        return "verify"
    if _remaining_tool_budget(state) <= 0:
        return "verify"
    if state.get("no_evidence_count", 0) >= int(
        policy.get("max_no_evidence", 2)
    ):
        return "verify"
    # Judge + planner + replanners share one hard LLM budget. Reserve the last
    # call for the evidence-fusion verifier.
    if state.get("llm_calls_used", 0) >= int(
        policy.get("max_llm_calls", 5)
    ) - 1:
        return "verify"
    return "replan"


def make_multi_agent_replan_node(llm: BaseChatModel):
    """创建观察驱动的重规划节点（ReAct 中的 Observe → Re-plan）。"""
    prompt = build_multi_agent_replan_prompt(_planner_tool_catalog())
    structured_llm = _bind_structured_output(llm, MultiAgentReplan)

    def multi_agent_replan_node(state: AgentState) -> AgentState:
        remaining_budget = _remaining_tool_budget(state)
        current_queue = list(state.get("agent_queue", []))
        alert_json = json.dumps(
            _agent_visible_alert(state["alert"]), ensure_ascii=False, default=str
        )
        ledger_text = json.dumps(
            state.get("task_ledger", {}), ensure_ascii=False, default=str
        )
        findings_text = json.dumps(
            state.get("multi_agent_steps", []), ensure_ascii=False, default=str
        )
        remaining_text = json.dumps(
            current_queue, ensure_ascii=False, default=str
        )
        decision: MultiAgentReplan | None = None
        try:
            prompt_value = prompt.invoke({
                "alert_json": alert_json,
                "task_ledger": ledger_text,
                "agent_findings": findings_text,
                "remaining_tasks": remaining_text,
                "remaining_budget": remaining_budget,
            })
            decision = structured_llm.invoke(
                prompt_value, timeout=_remaining_global_timeout(state)
            )
        except Exception as exc:
            logger.exception("autonomous multi-agent replanning failed: %s", exc)

        next_queue: list[dict[str, Any]] = []
        observation = "未取得可用的模型重规划结果"
        rationale = "保留经框架校验的剩余计划；没有剩余任务则进入验证"
        outcome = "continue" if current_queue else "verify"
        if decision is not None:
            observation = decision.observation
            rationale = decision.rationale
            outcome = decision.decision
            if decision.decision == "continue":
                next_queue = _validated_assignments(
                    state, list(decision.tasks), remaining_budget
                )

        # Invalid model proposals do not erase an already safe plan. Revalidate
        # the old queue against fingerprints collected by the latest worker.
        if outcome == "continue" and not next_queue:
            next_queue = _validated_assignments(
                state, current_queue, remaining_budget
            )
        if not next_queue:
            outcome = "verify"

        replan_count = state.get("replan_count", 0) + 1
        trace = list(state.get("planner_trace", []))
        trace.append({
            "round": replan_count,
            "mode": "observe_and_replan",
            "observation": observation,
            "decision": outcome,
            "rationale": rationale,
            "tasks": [
                {key: item.get(key) for key in ("agent", "tool", "args", "purpose")}
                for item in next_queue
            ],
        })

        ledger = dict(state.get("task_ledger", {}))
        revisions = list(ledger.get("revisions", []))
        revisions.append({
            "round": replan_count,
            "observation": observation,
            "decision": outcome,
            "rationale": rationale,
        })
        ledger.update({
            "revisions": revisions,
            "rationale": rationale,
            "plan": [
                {"agent": item["agent"], "purpose": item["purpose"]}
                for item in next_queue
            ],
            "unknowns": [item["purpose"] for item in next_queue],
        })

        progress = dict(state.get("progress_ledger", {}))
        planned = list(progress.get("planned_agents", []))
        for item in next_queue:
            if item["agent"] not in planned:
                planned.append(item["agent"])
        progress.update({
            "planner_mode": "llm_autonomous_react",
            "replan_count": replan_count,
            "planned_agents": planned,
            "remaining_tasks": len(next_queue),
            "status": "investigating" if next_queue else "verifying",
        })
        return {
            "agent_queue": next_queue,
            "task_ledger": ledger,
            "progress_ledger": progress,
            "planner_trace": trace,
            "replan_count": replan_count,
            "react_entered": True,
            "cot_trace": state.get("cot_trace", []) + [
                f"[ReAct 重规划 {replan_count}] {observation}；{rationale}"
            ],
            "llm_calls_used": state.get("llm_calls_used", 0) + 1,
            "estimated_tokens_used": state.get("estimated_tokens_used", 0)
            + _estimate_tokens(
                alert_json,
                ledger_text,
                findings_text,
                remaining_text,
                decision.model_dump() if decision else "replanner_failed",
            ),
        }

    return multi_agent_replan_node


def multi_agent_has_tasks(state: AgentState) -> str:
    """LangGraph 条件路由：继续专业调查或进入最终验证。"""
    if state.get("termination_reason") in {
        "global_timeout", "tool_step_budget_exhausted"
    }:
        return "verify"
    return "worker" if state.get("agent_queue") else "verify"


def multi_agent_worker_node(state: AgentState) -> AgentState:
    """执行重规划器选中的队首任务，并把工具返回值登记为观测。"""
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
    react_steps = list(state.get("react_steps", []))
    if state.get("react_entered"):
        react_steps.append({
            "step": len(react_steps) + 1,
            "agent": assignment["agent"],
            "tool": assignment["tool"],
            "args": assignment.get("args", {}),
            "result": result,
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
        "status": "observing" if state.get("react_entered") else (
            "investigating" if queue else "verifying"
        ),
    })
    logger.info(
        "multi_agent worker=%s tool=%s status=%s evidence=%d",
        assignment["agent"], assignment["tool"], result.get("status"), len(usable_ids),
    )
    return {
        "agent_queue": queue,
        "multi_agent_steps": existing_steps,
        "react_steps": react_steps,
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
