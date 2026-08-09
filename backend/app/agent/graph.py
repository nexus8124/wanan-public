"""LangGraph 主图（带 ReAct 循环版）。

链路：
    START → preprocess → judge → selective_rag（可选）─┬─ 高置信 → disposition → output → END
                                                        │
                                                        └─ 低置信 → react_decide ─┐
                                           ↑               ↓
                                           └─ tool_executor ┘
                                           ↓ (证据够 / 步数满)
                                        disposition → output → END

赛题对齐：
  - 基础任务（70分）：preprocess + judge + output
  - 进阶任务（20分）：selective RAG + guarded refinement
  - 挑战任务（10分）：react_decide 循环 + disposition 处置闭环
"""

from __future__ import annotations

from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langgraph.graph import END, START, StateGraph

from app.agent.nodes import (
    disposition_node,
    make_judge_node,
    make_rag_refine_node,
    make_rag_retrieve_node,
    make_react_decide_node,
    output_node,
    preprocess_node,
    tool_executor_node,
)
from app.agent.state import AgentState
from app.models.llm import get_llm, provider_is_configured

# 触发 ReAct 的置信度阈值（低于此值进入循环）
REACT_CONFIDENCE_THRESHOLD = 0.85
# 最大 ReAct 步数（硬上限，防止无限循环）
REACT_MAX_STEPS = 3


def _judge_router(state: AgentState) -> str:
    """judge 后的路由：高置信直接处置，低置信进 ReAct。

    Returns: "disposition" 或 "react_decide"
    """
    confidence = state.get("confidence", 0.0)
    payload = (state.get("alert") or {}).get("raw_payload") or {}
    # Multi-source benchmark cases must execute at least one evidence query;
    # otherwise a high-confidence initial Judge would bypass the ReAct experiment.
    if payload.get("_evidence_ref") and payload.get("_evidence_store"):
        return "react_decide"
    # 真阳/假阳且高置信 → 直接处置；待查或低置信 → ReAct
    if confidence >= REACT_CONFIDENCE_THRESHOLD and state.get("judgment") in {"真阳", "假阳"}:
        return "disposition"
    return "react_decide"


def _react_router(state: AgentState) -> str:
    """react_decide 后的路由：是否继续循环。

    Returns:
        "tool_executor" — 继续调工具（need_more_info=true 且有 next_action）
        "disposition"   — 跳出循环进入处置
    """
    react_steps = state.get("react_steps", [])
    # 硬上限：步数用尽
    max_steps = int(state.get("execution_policy", {}).get(
        "max_steps", REACT_MAX_STEPS
    ))
    if len(react_steps) >= max_steps:
        return "disposition"
    # LLM 说不需要更多信息了
    next_action = state.get("next_action")
    if not next_action:
        return "disposition"
    # 不重复执行完全相同的查询。重复调用不会产生新证据，只会额外消耗一次
    # 工具后的 LLM 决策；此时保留 react_decide 已给出的最新判定并结束。
    if any(
        step.get("tool") == next_action.get("tool")
        and step.get("args", {}) == next_action.get("args", {})
        for step in react_steps
    ):
        return "disposition"
    # 置信度够高了，不必再调
    payload = (state.get("alert") or {}).get("raw_payload") or {}
    capabilities = set(payload.get("evidence_capabilities") or [])
    called_tools = {str(step.get("tool")) for step in react_steps}
    query_targets = payload.get("query_targets") or {}
    required_tools: set[str] = set()
    if "endpoint_logs" in capabilities and query_targets.get("endpoint"):
        required_tools.add("fetch_endpoint_logs")
    if "network_alerts" in capabilities and query_targets.get("network_ips"):
        required_tools.add("fetch_network_flows")
    pending_real_sources = required_tools - called_tools
    must_query_external = bool(
        payload.get("_evidence_ref")
        and payload.get("_evidence_store")
        and (
            not react_steps
            or pending_real_sources
        )
    )
    if (
        state.get("confidence", 0.0) >= REACT_CONFIDENCE_THRESHOLD
        and not must_query_external
    ):
        return "disposition"
    # 继续调工具
    return "tool_executor"


def build_graph(
    llm: BaseChatModel | None = None,
    *,
    enable_react: bool = True,
    enable_rag: bool = False,
    rag_service: Any | None = None,
):
    """构建并编译带 ReAct 循环的 Agent 图。

    参数：
        llm: 注入的 LLM；None 则用默认 DeepSeek（无 key 时会报错，测试应传 mock）
    """
    if llm is None:
        llm = get_llm()

    judge_node = make_judge_node(llm)
    react_decide_node = make_react_decide_node(llm)

    graph = StateGraph(AgentState)
    graph.add_node("preprocess", preprocess_node)
    if enable_rag:
        graph.add_node("rag_retrieve", make_rag_retrieve_node(rag_service))
        graph.add_node("rag_refine", make_rag_refine_node(llm))
    graph.add_node("judge", judge_node)
    graph.add_node("react_decide", react_decide_node)
    graph.add_node("tool_executor", tool_executor_node)
    graph.add_node("disposition", disposition_node)
    graph.add_node("output", output_node)

    graph.add_edge(START, "preprocess")
    graph.add_edge("preprocess", "judge")

    # RAG 采用选择性后融合：先形成无知识基线，再仅对低置信/待查样本检索。
    post_judge_node = "judge"
    if enable_rag:
        graph.add_edge("judge", "rag_retrieve")
        graph.add_edge("rag_retrieve", "rag_refine")
        post_judge_node = "rag_refine"

    # Judge / RAG 后融合之后分叉
    if enable_react:
        graph.add_conditional_edges(
            post_judge_node,
            _judge_router,
            {"disposition": "disposition", "react_decide": "react_decide"},
        )
    else:
        # 可复现的无工具基线：每条样本只经过一次 judge 模型调用。
        graph.add_edge(post_judge_node, "disposition")

    # react_decide 后分叉（自循环 or 跳出）
    graph.add_conditional_edges(
        "react_decide",
        _react_router,
        {"tool_executor": "tool_executor", "disposition": "disposition"},
    )

    # tool_executor 回到 react_decide（形成循环）
    graph.add_edge("tool_executor", "react_decide")

    # 处置后输出
    graph.add_edge("disposition", "output")
    graph.add_edge("output", END)

    return graph.compile()


def judge_alert(
    alert: dict,
    llm: BaseChatModel | None = None,
    *,
    enable_react: bool = True,
    enable_rag: bool = False,
    rag_service: Any | None = None,
    callbacks: list[Any] | None = None,
    event_callback: Any | None = None,
) -> dict:
    """便捷函数：传入一条告警 dict，返回最终研判结果。

    给 API / 评测脚本用。
    """
    graph = build_graph(
        llm=llm,
        enable_react=enable_react,
        enable_rag=enable_rag,
        rag_service=rag_service,
    )
    config = {"callbacks": callbacks} if callbacks else None
    if event_callback is None:
        final_state = graph.invoke({"alert": alert}, config=config)
        return final_state["result"]  # type: ignore[no-any-return]

    event_callback({"type": "sample_started", "alert_id": alert.get("alert_id")})
    final_result: dict | None = None
    node_event_types = {
        "preprocess": "preprocess_completed",
        "rag_retrieve": "knowledge_retrieved",
        "rag_refine": "knowledge_refined",
        "judge": "judge_completed",
        "react_decide": "decision_updated",
        "tool_executor": "tool_completed",
        "disposition": "disposition_completed",
        "output": "sample_completed",
    }
    for update in graph.stream(
        {"alert": alert}, config=config, stream_mode="updates"
    ):
        for node_name, node_update in update.items():
            if node_name == "react_decide" and node_update.get("next_action"):
                event_callback({
                    "type": "tool_started",
                    "alert_id": alert.get("alert_id"),
                    "node": node_name,
                    "tool": node_update["next_action"].get("tool"),
                    "args": node_update["next_action"].get("args", {}),
                })
            event_callback({
                "type": node_event_types.get(node_name, "agent_updated"),
                "alert_id": alert.get("alert_id"),
                "node": node_name,
                "data": node_update,
            })
            if node_name == "output":
                final_result = node_update.get("result")
    if final_result is None:
        raise RuntimeError("Agent graph ended without an output result")
    return final_result


def _main() -> None:
    """命令行 demo：跑一条样例告警，验证完整链路。

    用法：uv run python -m app.agent.graph
    行为：
      - 已配 DEEPSEEK_API_KEY：走真实 DeepSeek（产生 token 费用）
      - 未配 key：自动降级 mock
    """
    from app.core.config import get_settings
    from app.data.loader import load_alerts

    settings = get_settings()
    use_mock = not provider_is_configured(settings)
    mode_label = (
        "mock LLM（未配 key）"
        if use_mock
        else f"真实 {settings.llm_provider} / {settings.llm_model}"
    )

    llm = get_llm(mock=use_mock)
    # 选一条低置信度（会触发 ReAct）的告警：EVTP-002 之前评测是待查
    alerts = load_alerts()
    alert = None
    for a in alerts:
        d = a.model_dump(mode="json")
        if a.alert_id == "EVTP-002":
            alert = d
            break
    if alert is None:
        alert = alerts[0].model_dump(mode="json")
    alert.pop("label", None)

    result = judge_alert(alert, llm=llm)
    print(f"=== Agent 研判 Demo（{mode_label}）===")
    print(f"告警: {result['alert_id']} | {alert['rule_name']}")
    print(f"判定: {result['judgment']} (置信度 {result['confidence']:.2f})")
    print(f"理由: {result['reason']}")
    print(f"方向: {result['features'].get('direction')}")
    print(f"是否走了 ReAct: {result['react_used']}")
    if result["react_used"]:
        print(f"ReAct 步数: {len(result['react_steps'])}, 调用工具: {result['tools_called']}")
        for step in result["react_steps"]:
            verdict = step["result"].get("verdict", str(step["result"])[:60])
            print(f"  步{step['step']} {step['tool']}({step['args']}) → {verdict}")
    if result.get("disposition"):
        disp = result["disposition"]
        print(f"处置: {disp['action']} ({disp['severity']}) - {disp['summary']}")
        for t in disp.get("tickets", []):
            print(f"  工单: {t.get('ticket_id')} {t.get('action')} → {t.get('target')}")


if __name__ == "__main__":
    _main()
