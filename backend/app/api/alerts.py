"""告警研判 API 路由。

赛题贴合：方案 B7，暴露 POST /api/alerts/judge。
"程序源代码、设计文档...确保可正常运行"——API 是可运行系统的对外入口。
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from app.agent.graph import judge_alert
from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.llm import get_llm, provider_is_configured, validate_model_selection
from app.models.schemas import Alert
from app.operations import record_alert_judgment

logger = get_logger(__name__)

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.post("/judge")
def judge(
    alert: Alert,
    rag: bool | None = None,
    multi_agent: bool = False,
    provider: str | None = None,
    model: str | None = None,
) -> JSONResponse:
    """研判单条告警，返回结构化判定结果 + CoT。

    入参：Alert（Pydantic schema，自动校验）
    出参：
        {
          "alert_id": "...",
          "judgment": "真阳|假阳|待查",
          "confidence": 0.0-1.0,
          "reason": "...",
          "cot_trace": ["步骤1", ...],
          "features": {...}
        }
    """
    settings = get_settings()

    try:
        selected_provider, selected_model = validate_model_selection(
            provider, model, settings=settings
        )
    except ValueError as selection_error:
        raise HTTPException(status_code=400, detail=str(selection_error)) from selection_error

    if not provider_is_configured(settings, selected_provider):
        raise HTTPException(
            status_code=503,
            detail=f"{selected_provider} 未配置 API Key，告警研判不会降级为 Mock 模型",
        )

    try:
        llm = get_llm(
            provider=selected_provider,
            model=selected_model,
            mock=False,
            settings=settings,
        )
        # 不把 label 传给 Agent（推理时不应看到答案）
        truth_label = alert.label
        alert_dict = alert.model_dump(mode="json")
        alert_dict.pop("label", None)
        result = judge_alert(
            alert_dict,
            llm=llm,
            # 多智能体模式不是 ReAct 的替代项：协调器会在每次专业
            # 智能体返回观测后，根据证据和剩余预算重新规划。
            enable_react=True,
            enable_multi_agent=multi_agent,
            force_multi_agent=multi_agent,
            enable_rag=settings.rag_enabled if rag is None else rag,
        )
        try:
            record_alert_judgment(
                alert_dict,
                result,
                truth_label=truth_label,
                channel="interactive",
            )
        except Exception as history_error:
            # Dashboard persistence must never make an otherwise valid judgment fail.
            logger.exception("save operational judgment failed: %s", history_error)
        return JSONResponse(content=result)
    except Exception as e:
        logger.exception("judge API failed: %s", e)
        raise HTTPException(status_code=500, detail=f"judge failed: {e}")


@router.get("/sample")
def get_sample_alert() -> dict:
    """返回一条示例告警，方便前端 / curl 测试。"""
    from app.data.loader import load_alerts

    alerts = load_alerts()
    if not alerts:
        raise HTTPException(status_code=404, detail="no sample alerts available")
    # 返回第一条，去掉 label
    sample = alerts[0].model_dump(mode="json")
    sample.pop("label", None)
    return sample
