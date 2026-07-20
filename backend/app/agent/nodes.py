"""LangGraph 业务节点（MVP 版）。

三个节点对应赛题基础任务的完整链路：
    preprocess_node (节点1) → judge_node (节点3) → output_node (节点5a)

后续扩展（Week 4-5）：
    在 judge 前插入 rag_node；在 output 前根据 confidence 分叉到 react_loop。
"""

from __future__ import annotations

import ipaddress
import json
import logging
from datetime import datetime
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel

from app.agent.prompts import (
    build_judge_prompt,
    build_react_prompt,
    features_to_text,
    format_evidence,
    format_tools_called,
)
from app.agent.state import AgentState
from app.models.schemas import Judgment

logger = logging.getLogger(__name__)


def _bind_structured_output(llm: BaseChatModel, schema):
    """根据 LLM 类型选合适的结构化输出绑定方式。

    DeepSeek V4 实测发现：
      - method="json_schema"  → 报错 "response_format type unavailable"
      - method="function_calling" → 极不稳定，66% 请求不触发 tool call（返回 None）
      - method="json_mode" → 稳定可靠（response_format=json_object + Pydantic 解析）

    所以 DeepSeek 默认用 json_mode。FakeJudgeLLM 自定义了 with_structured_output。
    """
    from app.models.llm import FakeJudgeLLM

    if isinstance(llm, FakeJudgeLLM):
        return llm.with_structured_output(schema)

    # DeepSeek V4：json_mode 最稳定
    try:
        return llm.with_structured_output(schema, method="json_mode")
    except (TypeError, NotImplementedError):
        return llm.with_structured_output(schema)


# ============================================================
# 节点 1：告警预处理与归一化
# ============================================================


def _is_internal_ip(ip: str | None) -> bool | None:
    """判断是否内网 IP（10./172.16-31./192.168.）。"""
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return None


def _port_class(port: int | None) -> str:
    """端口分类：well_known / registered / ephemeral / unknown。"""
    if port is None:
        return "unknown"
    if port <= 1023:
        return "well_known"
    if port <= 49151:
        return "registered"
    return "ephemeral"


def preprocess_node(state: AgentState) -> AgentState:
    """节点1：从原始告警提取归一化特征。

    纯规则处理，不调 LLM（省 token，确定性）。
    输出 normalized_features dict，供 judge 节点使用。
    """
    alert: dict[str, Any] = state["alert"]
    src_ip = alert.get("src_ip")
    dst_ip = alert.get("dst_ip")
    ts = alert.get("timestamp")

    # 解析时间（容忍 ISO 字符串或已解析 datetime）
    hour_of_day: int | None = None
    if ts:
        try:
            dt = ts if isinstance(ts, datetime) else datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            hour_of_day = dt.hour
        except (ValueError, TypeError):
            hour_of_day = None

    src_internal = _is_internal_ip(src_ip)
    dst_internal = _is_internal_ip(dst_ip)

    # 流量方向推断
    if src_internal is True and dst_internal is True:
        direction = "横向（内→内）"
    elif src_internal is True and dst_internal is False:
        direction = "外连（内→外）"
    elif src_internal is False and dst_internal is True:
        direction = "入站（外→内）"
    else:
        direction = "未知"

    features: dict[str, str | int | None] = {
        "source_device": alert.get("source"),
        "severity": alert.get("severity"),
        "protocol": alert.get("protocol"),
        "src_port_class": _port_class(alert.get("src_port")),
        "dst_port": alert.get("dst_port"),
        "dst_port_class": _port_class(alert.get("dst_port")),
        "src_internal": src_internal,
        "dst_internal": dst_internal,
        "direction": direction,
        "hour_of_day": hour_of_day,
        "rule_name": alert.get("rule_name"),
    }
    logger.debug("preprocess features: %s", features)
    return {"normalized_features": features}


# ============================================================
# 节点 3：LLM 研判 + CoT（MVP 最核心）
# ============================================================


# 失败时的兜底判定（避免 LLM 异常导致整个图崩）
_FALLBACK_JUDGMENT = Judgment(
    cot=["LLM 调用异常，无法完成推理，进入待查兜底。"],
    judgment="待查",
    confidence=0.0,
    reason="LLM 调用失败，需人工介入。",
)


def make_judge_node(llm: BaseChatModel):
    """工厂：返回绑定了 LLM 的 judge_node。

    用闭包注入 LLM，便于：
      1. 测试时传入 mock LLM
      2. Week 5 ReAct 循环复用同一 LLM 实例

    结构化输出策略：
      - FakeJudgeLLM（测试）：自定义 with_structured_output，直接返回 Judgment
      - 真实 DeepSeek：用 method="function_calling"
        （DeepSeek 不支持 json_schema response_format，但支持 function calling）
      - 其他 OpenAI 兼容模型：默认 method（json_schema），兼容性最好
    """
    prompt = build_judge_prompt()
    structured_llm = _bind_structured_output(llm, Judgment)
    chain = prompt | structured_llm

    def judge_node(state: AgentState) -> AgentState:
        alert: dict[str, Any] = state["alert"]
        features: dict[str, Any] = state.get("normalized_features", {})

        alert_json = json.dumps(alert, ensure_ascii=False, default=str)
        features_text = features_to_text(features)

        result: Judgment | None = None
        try:
            result = chain.invoke(
                {"alert_json": alert_json, "features_text": features_text}
            )
        except Exception as e:
            # 方案 5.2 风格：错误兜底，不让单条告警拖垮整个评测
            logger.exception("judge_node LLM 调用失败: %s", e)

        # DeepSeek 偶发不触发 tool call → result 为 None，也要兜底
        if result is None:
            logger.warning(
                "judge_node 返回 None（LLM 未触发 tool call），使用兜底: %s",
                alert.get("alert_id"),
            )
            result = _FALLBACK_JUDGMENT

        logger.info(
            "judge: %s conf=%.2f alert=%s",
            result.judgment,
            result.confidence,
            alert.get("alert_id"),
        )
        return {
            "cot_trace": result.cot,
            "judgment": result.judgment,
            "confidence": result.confidence,
            "reason": result.reason,
        }

    return judge_node


# ============================================================
# 节点 5a：结果输出
# ============================================================


def output_node(state: AgentState) -> AgentState:
    """节点5a：把判定结果整理成给 API/前端的最终结构。

    D4 扩展：补充 react_steps / tools_called / disposition 字段（如果走了 ReAct）。
    保持向后兼容：未走 ReAct 时这些字段为空。
    """
    alert: dict[str, Any] = state["alert"]
    react_steps = state.get("react_steps", [])
    result = {
        "alert_id": alert.get("alert_id"),
        "judgment": state.get("judgment"),
        "confidence": state.get("confidence"),
        "reason": state.get("reason"),
        "cot_trace": state.get("cot_trace", []),
        "features": state.get("normalized_features", {}),
        # ----- D4 ReAct 扩展 -----
        "react_used": bool(state.get("react_entered", False)),
        "react_steps": react_steps,
        "tools_called": state.get("tools_called", []),
        "disposition": state.get("disposition"),
    }
    return {"result": result}


# ============================================================
# 节点 5b：ReAct 决策（挑战任务核心）
# ============================================================


def make_react_decide_node(llm: BaseChatModel):
    """工厂：返回绑定了 LLM 的 react_decide_node。

    职责：根据当前证据决定"再调一个工具"还是"证据已足够"。
    用 json_mode 保证结构化输出稳定（与 judge_node 同策略）。
    """
    from app.agent.tools import format_tool_catalog_for_prompt
    from app.models.schemas import ReactDecision

    prompt = build_react_prompt(format_tool_catalog_for_prompt())
    structured_llm = _bind_structured_output(llm, ReactDecision)
    chain = prompt | structured_llm

    def react_decide_node(state: AgentState) -> AgentState:
        alert: dict[str, Any] = state["alert"]
        react_steps: list[dict] = state.get("react_steps", [])
        step = len(react_steps) + 1
        react_entered = True  # 标记进入过 ReAct

        alert_json = json.dumps(alert, ensure_ascii=False, default=str)
        evidence_text = format_evidence(react_steps)
        tools_called_text = format_tools_called(react_steps)

        decision = None
        try:
            decision = chain.invoke(
                {
                    "alert_json": alert_json,
                    "evidence_text": evidence_text,
                    "tools_called_text": tools_called_text,
                    "step": step,
                }
            )
        except Exception as e:
            logger.exception("react_decide LLM 调用失败: %s", e)

        if decision is None:
            # 兜底：不再调工具，保持原判定
            logger.warning("react_decide 返回 None，使用兜底（停止循环）")
            return {
                "next_action": None,
                "confidence": state.get("confidence", 0.5),
                "react_entered": react_entered,
            }

        logger.info(
            "react_decide step=%d need_more=%s conf=%.2f next=%s",
            step,
            decision.need_more_info,
            decision.confidence,
            decision.next_action.tool if decision.next_action else "None",
        )
        return {
            "next_action": (
                decision.next_action.model_dump() if decision.next_action else None
            ),
            "confidence": decision.confidence,
            "judgment": decision.judgment,
            "reason": decision.reasoning,
            "react_entered": react_entered,
            # 把 reasoning 也追加到 cot_trace，保持思维链完整可见
            "cot_trace": state.get("cot_trace", []) + [f"[ReAct 步{step}] {decision.reasoning}"],
        }

    return react_decide_node


def tool_executor_node(state: AgentState) -> AgentState:
    """执行 LLM 决定的工具调用（纯 Python，不调 LLM）。

    从 state.next_action 取工具名和参数，调用 tools.execute_tool，
    把结果 append 到 react_steps。
    """
    from app.agent.tools import execute_tool

    alert: dict[str, Any] = state["alert"]
    next_action = state.get("next_action")

    if not next_action:
        # 没有下一步动作，直接返回（不应到达，router 会拦截）
        return {}

    tool_name = next_action.get("tool")
    args = next_action.get("args", {})

    result = execute_tool(tool_name, alert_ctx=alert, args=args)

    react_steps = list(state.get("react_steps", []))
    react_steps.append(
        {
            "step": len(react_steps) + 1,
            "tool": tool_name,
            "args": args,
            "result": result,
        }
    )
    tools_called = list(state.get("tools_called", []))
    if tool_name not in tools_called:
        tools_called.append(tool_name)

    logger.info("tool_executor: %s(%s) → %s", tool_name, args, str(result.get("verdict", ""))[:60])
    return {"react_steps": react_steps, "tools_called": tools_called}


# ============================================================
# 节点 6：处置建议（处置闭环）
# ============================================================


def disposition_node(state: AgentState) -> AgentState:
    """根据最终判定生成处置建议。

    赛题贴合："从发现威胁到处置闭环"
    - 真阳 → suggest_block_ip + suggest_isolate_host
    - 假阳 → 加白
    - 待查 → 升级人工
    """
    from app.agent.tools import execute_tool

    alert: dict[str, Any] = state["alert"]
    judgment = state.get("judgment", "待查")
    confidence = state.get("confidence", 0.0)
    src_ip = alert.get("src_ip", "")
    dst_ip = alert.get("dst_ip", "")

    disposition: dict[str, Any]
    if judgment == "真阳":
        # 真阳：封禁目的 IP（C2/攻击源）+ 隔离源主机（疑似失陷）
        tickets = []
        if dst_ip:
            t1 = execute_tool(
                "suggest_block_ip", alert_ctx=alert,
                args={"ip": dst_ip, "reason": f"判定真阳，置信度 {confidence:.2f}"},
            )
            tickets.append(t1)
        if src_ip:
            t2 = execute_tool(
                "suggest_isolate_host", alert_ctx=alert,
                args={"host_ip": src_ip, "reason": f"疑似失陷终端（置信度 {confidence:.2f}）"},
            )
            tickets.append(t2)
        disposition = {
            "action": "block_and_isolate" if (src_ip and dst_ip) else "block_ip",
            "summary": f"判定真阳（置信度 {confidence:.2f}），建议封禁攻击源 {dst_ip} 并隔离失陷主机 {src_ip}",
            "tickets": tickets,
            "severity": "critical" if confidence >= 0.9 else "high",
        }
    elif judgment == "假阳":
        disposition = {
            "action": "whitelist",
            "summary": f"判定假阳（置信度 {confidence:.2f}），建议将规则/源加入白名单，避免重复误报",
            "tickets": [],
            "severity": "info",
        }
    else:  # 待查
        disposition = {
            "action": "escalate_human",
            "summary": f"判定待查（置信度 {confidence:.2f}），证据不足，建议升级人工分析",
            "tickets": [],
            "severity": "medium",
        }

    logger.info("disposition: %s severity=%s", disposition["action"], disposition["severity"])
    return {"disposition": disposition}
