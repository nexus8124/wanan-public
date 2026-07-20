"""CoT Prompt 模板（MVP 最核心）。

赛题原文要求："从流量异常→关联终端进程→定位身份账号→判定内鬼行为"。
本 Prompt 复刻这个推理范式，要求 LLM 输出 5 步思维链 + 结构化判定。

设计要点（方案 B3 + 5.3）：
1. 明确角色和任务
2. 强制 5 步 CoT 推理
3. 输出 JSON Schema（配合 with_structured_output）
4. Few-shot 示例（真阳/假阳各一）—— 显著提升准确率
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.prompts.chat import (
    AIMessagePromptTemplate,
    HumanMessagePromptTemplate,
    SystemMessagePromptTemplate,
)
from langchain_core.prompts.prompt import PromptTemplate

# ============================================================
# 系统提示词：定义角色 + 推理范式
# ============================================================

SYSTEM_PROMPT = """你是资深网络安全分析师，专长是 SOC 告警研判。
你的任务：判断一条告警是【真阳】（真实攻击）还是【假阳】（误报），或信息不足以判定为【待查】。

必须严格按以下 5 步思维链（Chain-of-Thought）逐步推理：
1. 流量特征分析：观察协议、端口、方向（内→外/外→内/横向）、载荷特征。
2. 行为意图判断：是否符合已知攻击模式（C2 外连、横向移动、漏洞利用、暴力破解等）。
3. 关联上下文：源/目的 IP 是否可信、是否内网、是否首次出现、端口是否合理。
4. 历史模式对比：是否像已知的业务流量、健康检查、定时任务、CDN 回源等常见误报。
5. 综合判定：基于以上证据给出结论（真阳/假阳/待查）和置信度。

判定原则：
- 只有人工可核实的业务行为模式（健康检查、定时任务、CDN、内部业务流量、签名脚本等）才判假阳。
- 外连已知 C2、横向到域控、编码 PowerShell、SQLi 特征载荷、暴破模式等判真阳。
- 证据矛盾或不足时判"待查"，置信度 < 0.6，不要硬猜。

输出必须为指定 JSON 结构，cot 字段是 5 步推理，每步一句话。"""


# ============================================================
# 用户提示词模板：告警信息占位符
# ============================================================

USER_TEMPLATE = """请研判以下安全告警：

【告警信息】
{alert_json}

【归一化特征】
{features_text}

按 5 步思维链推理后，输出结构化判定结果。"""


# ============================================================
# Few-shot 示例（真阳 / 假阳各一）
# 方案 B3 关键技巧：few-shot 显著提升准确率
# ============================================================

FEWSHOT_EXAMPLES: list[dict[str, Any]] = [
    # —— 真阳示例 ——
    {
        "alert": {
            "alert_id": "TP-EX",
            "source": "edr",
            "severity": "high",
            "src_ip": "10.20.33.51",
            "dst_ip": "185.220.101.34",
            "dst_port": 4444,
            "protocol": "TCP",
            "rule_name": "Suspicious reverse shell",
            "description": "powershell.exe 由 WINWORD.EXE 启动外连 185.220.101.34:4444",
        },
        "output": {
            "cot": [
                "流量特征：内网主机 10.20.33.51 主动外连 185.220.101.34:4444/TCP，4444 是经典的 reverse shell 端口。",
                "行为意图：powershell.exe 由 WINWORD.EXE 启动，是钓鱼宏落地的典型父子进程链，符合命令控制阶段。",
                "关联上下文：目的 IP 为公网境外地址，端口非常规业务端口，源主机是普通办公终端不应主动外连。",
                "历史模式：符合 C2 通信模式，与任何已知业务流量都不匹配。",
                "综合判定：高度疑似钓鱼+命令控制，判定真阳。",
            ],
            "judgment": "真阳",
            "confidence": 0.92,
            "reason": "Word 启动 PowerShell 外连 4444 端口，是钓鱼+C2 的典型链路。",
        },
    },
    # —— 假阳示例 ——
    {
        "alert": {
            "alert_id": "FP-EX",
            "source": "ids",
            "severity": "low",
            "src_ip": "10.20.30.5",
            "dst_ip": "10.20.40.7",
            "dst_port": 22,
            "protocol": "TCP",
            "rule_name": "Possible port scan",
            "description": "运维主机对域控连续 TCP SYN",
        },
        "output": {
            "cot": [
                "流量特征：内网→内网，目标端口固定 22（SSH），单次连接后即 RST。",
                "行为意图：不像扫描（扫描会扫多端口），更像单点健康检查。",
                "关联上下文：源是运维网段主机，目标是域控 SSH 端口，方向合理。",
                "历史模式：每日 01:00 定时出现，匹配 nightly-monitor 脚本特征。",
                "综合判定：可核实的定时业务行为，判定假阳（误报）。",
            ],
            "judgment": "假阳",
            "confidence": 0.88,
            "reason": "固定时间、固定端口、来自运维主机，是定时监控脚本的正常行为。",
        },
    },
]


def _compact_json(obj: Any) -> str:
    """紧凑 JSON，去掉换行减少 token。"""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def features_to_text(features: dict) -> str:
    """把归一化特征 dict 转成易读的文本（喂给 LLM）。"""
    if not features:
        return "(无)"
    return "\n".join(f"  - {k}: {v}" for k, v in features.items())


def _example_to_user_text(ex: dict[str, Any]) -> str:
    """把 few-shot 示例转成 user message 文本。"""
    return USER_TEMPLATE.format(
        alert_json=_compact_json(ex["alert"]),
        features_text="(示例已省略归一化特征)",
    )


def build_judge_prompt() -> ChatPromptTemplate:
    """构建研判 Prompt（system + few-shot pairs + user 模板）。

    few-shot 的 user/ai 文本是已渲染好的字面字符串（含 JSON 字面量），
    用 NoPromptTemplate 包装避免被 str.format 当占位符解析。
    最后一条 user 才是真正带 {alert_json}/{features_text} 占位符的模板。

    用法：
        prompt = build_judge_prompt()
        chain = prompt | llm.with_structured_output(Judgment)
        result: Judgment = chain.invoke({"alert_json": ..., "features_text": ...})
    """
    messages: list[Any] = [
        SystemMessagePromptTemplate.from_template(SYSTEM_PROMPT),
    ]
    # few-shot：把示例渲染成 (Human, AI) 对，直接用字面字符串
    for ex in FEWSHOT_EXAMPLES:
        user_text = _example_to_user_text(ex)
        ai_text = _compact_json(ex["output"])
        messages.append(
            HumanMessagePromptTemplate(prompt=PromptTemplate.from_template(_escape(user_text)))
        )
        messages.append(
            AIMessagePromptTemplate(prompt=PromptTemplate.from_template(_escape(ai_text)))
        )
    # 最后一条：带占位符的真实 user 模板（不转义）
    messages.append(HumanMessagePromptTemplate.from_template(USER_TEMPLATE))

    return ChatPromptTemplate(messages=messages)


def _escape(text: str) -> str:
    """把字面 { } 转义为 {{ }}，避免 str.format 把 JSON 当占位符。"""
    return text.replace("{", "{{").replace("}", "}}")


# ============================================================
# ReAct 决策 Prompt（节点5b react_decide 用）
# 赛题贴合："观测、反馈、重新规划的 ReAct 能力"
# ============================================================

REACT_SYSTEM_PROMPT = """你是安全运营的 ReAct 决策智能体。
当前正在处理一条告警，初步研判置信度不足，需要你决定下一步动作：
- 调用工具补充证据（need_more_info=true），或
- 认为证据已足够，给出最终判定（need_more_info=false）

决策原则：
1. **默认倾向调工具**：只要置信度 < 0.85 且步数 < 3，就应该 need_more_info=true 并调用工具收集证据，而不是直接判待查。判"待查"是最后手段。
2. 优先查端点日志（fetch_endpoint_logs）、网络流量（fetch_network_flows）、威胁情报（check_threat_intel），按相关性选一个。
3. 一次只调一个工具，看完结果再决定下一步（标准 ReAct 范式）。
4. 工具结果支持攻击假设 → 提升置信度；反之降低。
5. 一旦证据充分（置信度 ≥ 0.85）或已调 3 个工具仍无定论，应停止调工具，输出最终判定。
6. 不要调处置类工具（suggest_block_ip / suggest_isolate_host），处置由后续节点统一生成。

可选工具目录：
{tool_catalog}

【输出格式】严格按以下 JSON 结构输出，字段名必须完全一致：
{{
  "analysis": "对当前证据的分析",
  "judgment": "真阳 或 假阳 或 待查",
  "confidence": 0.0到1.0的小数,
  "need_more_info": true或false,
  "next_action": {{
    "tool": "工具名（必须来自上方目录）",
    "args": {{"参数名": "参数值"}}
  }},
  "reasoning": "本次决策的推理过程"
}}

字段说明：
- judgment：只能填"真阳""假阳""待查"三个中文词之一
- next_action.args：注意是 "args" 不是 "parameters"，是字典格式
- 当 need_more_info=false 时，next_action 必须为 null"""


REACT_USER_TEMPLATE = """【原始告警】
{alert_json}

【当前已收集的证据】
{evidence_text}

【已调用工具】
{tools_called_text}

【当前步数】第 {step} 步（最多 5 步，超过将强制结束）

请决策：是否需要再调工具？如果需要，调哪个、传什么参数？给出更新后的判定和置信度。"""


def build_react_prompt(tool_catalog: str) -> ChatPromptTemplate:
    """构建 ReAct 决策 Prompt。

    与 judge prompt 不同：这个 prompt 不含 few-shot（避免 token 膨胀），
    依赖 judge 阶段已经给的判定 + 工具目录引导。
    """
    system = REACT_SYSTEM_PROMPT.replace("{tool_catalog}", _escape(tool_catalog))
    return ChatPromptTemplate.from_messages(
        [
            ("system", system),
            ("user", REACT_USER_TEMPLATE),
        ]
    )


def format_evidence(react_steps: list[dict]) -> str:
    """把已调工具的结果格式化成文本（喂给 LLM）。"""
    if not react_steps:
        return "(尚无工具调用结果)"
    lines = []
    for i, step in enumerate(react_steps, 1):
        tool = step.get("tool", "?")
        args = step.get("args", {})
        result = step.get("result", {})
        lines.append(f"第{i}步 调用 {tool}({args}) → {json.dumps(result, ensure_ascii=False)}")
    return "\n".join(lines)


def format_tools_called(react_steps: list[dict]) -> str:
    """简化的已调工具列表。"""
    if not react_steps:
        return "(无)"
    return ", ".join(s.get("tool", "?") for s in react_steps)
