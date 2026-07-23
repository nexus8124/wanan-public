"""Pydantic 数据模型。

Alert 是整个系统的核心 schema——所有后续模块（预处理 / 研判 / 评测）
都基于这个结构。字段严格对齐赛题"多源安全数据（流量、端点、日志）"要求。
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


Severity = Literal["high", "medium", "low", "info"]
AlertSource = Literal["siem", "edr", "firewall", "ids", "waf", "ips", "ndr"]
Label = Literal["真阳", "假阳", "待查", None]


class Alert(BaseModel):
    """告警事件统一 schema。

    source 字段对齐赛题三类数据源：
      - "流量" → firewall / ids / waf / ips / ndr
      - "端点" → edr
      - "日志" → siem

    label 仅评测时使用，推理流程不传入（避免泄露答案）。
    """

    alert_id: str = Field(..., description="告警唯一 ID")
    timestamp: datetime = Field(..., description="告警时间")
    source: AlertSource = Field(..., description="告警来源设备类型")
    severity: Severity = Field(..., description="严重等级")

    src_ip: str | None = Field(default=None, description="源 IP")
    dst_ip: str | None = Field(default=None, description="目的 IP")
    src_port: int | None = Field(default=None, ge=0, le=65535, description="源端口")
    dst_port: int | None = Field(default=None, ge=0, le=65535, description="目的端口")
    protocol: str | None = Field(default=None, description="协议：TCP/UDP/ICMP/HTTP...")

    rule_name: str = Field(..., description="触发的检测规则名")
    description: str = Field(..., description="告警描述（自然语言）")

    raw_payload: dict[str, Any] = Field(
        default_factory=dict, description="原始数据（保留设备特定字段）"
    )
    label: Label = Field(
        default=None,
        description="真阳/假阳标注。仅评测用，推理时不传入。",
    )


class AlertList(BaseModel):
    """告警列表包装，用于加载 JSON 文件。"""

    alerts: list[Alert]

    def __len__(self) -> int:
        return len(self.alerts)

    def __iter__(self):  # type: ignore[override]
        return iter(self.alerts)


# ============================================================
# LLM 结构化输出模型（节点3 judge 用）
# 赛题贴合：评分要求"准确性"，结构化输出是准确率的基础
# ============================================================


class Judgment(BaseModel):
    """LLM 研判结果的结构化 schema。

    用 with_structured_output(Judgment) 强制 LLM 输出符合此 schema 的 JSON，
    避免自由文本解析困难（方案 5.1 节关键技术决策）。
    """

    cot: list[str] = Field(
        ...,
        description="5 步思维链推理过程，每步一句话。"
        "对应赛题挑战任务要求的'展示完整思维链推理过程'。",
        min_length=1,
    )
    judgment: Literal["真阳", "假阳", "待查"] = Field(
        ..., description="最终判定：真阳(真实攻击) / 假阳(误报) / 待查(信息不足)"
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="置信度 0.0-1.0，0.85 以上为高置信（ReAct 触发阈值参考）",
    )
    reason: str = Field(
        ..., description="简要总结判定理由"
    )


# ============================================================
# ReAct 决策模型（节点5b react_decide 用）
# 赛题贴合："观测、反馈、重新规划的 ReAct 能力"
# ============================================================


class ToolCall(BaseModel):
    """LLM 决定调用的工具及参数。

    next_action=None 表示证据已足够，跳出循环。
    """

    tool: str = Field(..., description="工具名（必须来自工具目录）")
    args: dict[str, Any] = Field(
        default_factory=dict, description="工具参数（键值对）"
    )


class ReactDecision(BaseModel):
    """ReAct 每一步的决策结果（LLM 输出）。

    字段名故意简洁（analysis/judgment/confidence/...），
    避免带前缀（如 updated_）让 LLM 写错字段名。
    """

    analysis: str = Field(
        ..., description="对当前已有证据的分析"
    )
    judgment: Literal["真阳", "假阳", "待查"] = Field(
        ..., description="基于当前证据的判定（必须三选一）"
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="基于当前证据的置信度 0.0-1.0"
    )
    need_more_info: bool = Field(
        ..., description="是否还需要更多信息（调工具）。false=证据足够，跳出循环"
    )
    next_action: ToolCall | None = Field(
        default=None,
        description="下一步要调的工具；need_more_info=false 时必须为 null",
    )
    reasoning: str = Field(
        ..., description="本次决策的推理过程"
    )
    cited_evidence: list[str] = Field(
        default_factory=list,
        description="支撑本次判定的 evidence_id 列表；没有可引用证据时为空",
    )


class Disposition(BaseModel):
    """处置建议（节点6 disposition 输出）。

    赛题贴合："从发现威胁到处置闭环"
    """

    action: Literal[
        "block_and_isolate",  # 真阳：封禁 + 隔离
        "block_ip",           # 仅封禁 IP
        "isolate_host",       # 仅隔离主机
        "whitelist",          # 假阳：加白
        "escalate_human",     # 待查：升级人工
        "monitor",            # 监控
    ] = Field(..., description="处置动作类型")
    summary: str = Field(..., description="处置建议一句话总结")
    tickets: list[dict[str, Any]] = Field(
        default_factory=list, description="生成的工单列表（不执行）"
    )
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(
        ..., description="事件严重等级"
    )
