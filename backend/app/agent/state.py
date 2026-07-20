"""LangGraph 全局状态。

赛题贴合：State 是"分层递进"的载体，三层任务的字段都在这里。
  - 基础任务（70分）：alert / normalized_features / judgment / confidence / reason
  - 进阶任务（20分）：rag_context            ← Week 4 接入
  - 挑战任务（10分）：react_steps / tools_called / disposition  ← Week 5 接入
"""

from __future__ import annotations

from typing import TypedDict


class AgentState(TypedDict, total=False):
    """Agent 全局状态。

    `total=False` 让节点可以只更新自己负责的字段，
    其余字段保持原值（LangGraph 默认会浅合并 dict 返回值到 state）。

    字段流向：
        alert (输入)
        ↓ preprocess_node
        normalized_features
        ↓ judge_node
        cot_trace / judgment / confidence / reason
        ↓ output_node
        result（结构化最终输出）
    """

    # ----- 输入 -----
    alert: dict  # 原始告警（dict 形式，便于跨节点传递）

    # ----- 节点1 preprocess 输出 -----
    normalized_features: dict[str, str | int | None]
    # 例：{"src_port_class": "ephemeral", "is_internal_dst": True, "hour_of_day": 14}

    # ----- 节点3 judge 输出（MVP 核心） -----
    cot_trace: list[str]   # 5 步思维链
    judgment: str          # "真阳" | "假阳" | "待查"
    confidence: float      # 0.0 - 1.0
    reason: str            # 一句话总结

    # ----- 节点5a output 输出 -----
    result: dict           # 给 API/前端的最终结构化结果

    # ----- Week 4 RAG 接入（进阶任务） -----
    rag_context: str       # 知识库检索结果文本

    # ----- Week 5 ReAct 接入（挑战任务） -----
    # next_action: react_decide 输出、tool_executor 消费的中间字段
    # （必须声明为 state channel，否则 LangGraph 会丢弃）
    next_action: dict | None  # {"tool": str, "args": dict} 或 None
    react_steps: list[dict]   # ReAct 每步记录
    tools_called: list[str]   # 调用过的工具名
    disposition: dict         # 处置建议
    react_entered: bool       # 是否进入过 react_decide（即使没调工具）
