"""LangGraph 主图（带 ReAct 循环版）。

链路：
    START → preprocess → judge ─┬─ 高置信 → disposition → output → END
                                │
                                └─ 低置信 → react_decide ─┐
                                           ↑               ↓
                                           └─ tool_executor ┘
                                           ↓ (证据够 / 步数满)
                                        disposition → output → END

赛题对齐：
  - 基础任务（70分）：preprocess + judge + output
  - 挑战任务（10分）：react_decide 循环 + disposition 处置闭环
"""

from __future__ import annotations

from langchain_core.language_models.chat_models import BaseChatModel
from langgraph.graph import END, START, StateGraph

from app.agent.nodes import (
    disposition_node,
    make_judge_node,
    make_react_decide_node,
    output_node,
    preprocess_node,
    tool_executor_node,
)
from app.agent.state import AgentState
from app.models.llm import get_llm

# 触发 ReAct 的置信度阈值（低于此值进入循环）
REACT_CONFIDENCE_THRESHOLD = 0.85
# 最大 ReAct 步数（硬上限，防止无限循环）
REACT_MAX_STEPS = 5


def _judge_router(state: AgentState) -> str:
    """judge 后的路由：高置信直接处置，低置信进 ReAct。

    Returns: "disposition" 或 "react_decide"
    """
    confidence = state.get("confidence", 0.0)
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
    if len(react_steps) >= REACT_MAX_STEPS:
        return "disposition"
    # LLM 说不需要更多信息了
    next_action = state.get("next_action")
    if not next_action:
        return "disposition"
    # 置信度够高了，不必再调
    if state.get("confidence", 0.0) >= REACT_CONFIDENCE_THRESHOLD:
        return "disposition"
    # 继续调工具
    return "tool_executor"


def build_graph(llm: BaseChatModel | None = None):
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
    graph.add_node("judge", judge_node)
    graph.add_node("react_decide", react_decide_node)
    graph.add_node("tool_executor", tool_executor_node)
    graph.add_node("disposition", disposition_node)
    graph.add_node("output", output_node)

    graph.add_edge(START, "preprocess")
    graph.add_edge("preprocess", "judge")

    # judge 后分叉
    graph.add_conditional_edges(
        "judge",
        _judge_router,
        {"disposition": "disposition", "react_decide": "react_decide"},
    )

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


def judge_alert(alert: dict, llm: BaseChatModel | None = None) -> dict:
    """便捷函数：传入一条告警 dict，返回最终研判结果。

    给 API / 评测脚本用。
    """
    graph = build_graph(llm=llm)
    final_state = graph.invoke({"alert": alert})
    return final_state["result"]  # type: ignore[no-any-return]


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
    use_mock = not settings.deepseek_api_key
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
