"""模型配置 API：读写运行时厂商/模型目录，并提供连接测试。

路由：
    GET    /api/config/models        读取配置（API Key 只返回掩码）
    PUT    /api/config/models        保存配置（立即生效，无需重启）
    DELETE /api/config/models        删除配置文件，回到内置目录 + .env
    POST   /api/config/models/test   用当前表单值测试厂商连通性
"""

from __future__ import annotations

from typing import Any

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.model_config import (
    ModelConfigError,
    get_effective_config,
    mask_key,
    model_config_path,
    reset_model_config,
    save_model_config,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/api/config", tags=["config"])


class ModelEntryIn(BaseModel):
    id: str
    label: str = ""


class ProviderIn(BaseModel):
    id: str
    display_name: str = ""
    base_url: str = ""
    # None/缺省 = 沿用已保存的 key；"" = 清除；非空 = 覆盖
    api_key: str | None = None
    enabled: bool = True
    models: list[ModelEntryIn] = Field(default_factory=list)


class ModelConfigUpdate(BaseModel):
    default_provider: str
    default_model: str = ""
    temperature: float | None = None
    providers: list[ProviderIn]


class ProviderTestRequest(BaseModel):
    provider: str
    base_url: str | None = None
    api_key: str | None = None


def _config_payload() -> dict[str, Any]:
    settings = get_settings()
    config = get_effective_config(settings)
    providers_out: list[dict[str, Any]] = []
    for entry in config.providers:
        api_key = entry.resolved_api_key(settings)
        providers_out.append(
            {
                "id": entry.id,
                "display_name": entry.display_name,
                "base_url": entry.resolved_base_url(settings),
                "enabled": entry.enabled,
                "builtin": entry.builtin,
                "api_key_set": bool(api_key),
                "api_key_preview": mask_key(api_key),
                "api_key_source": "file" if entry.api_key.strip() else ("env" if api_key else "none"),
                "models": [{"id": m.id, "label": m.label} for m in entry.models],
            }
        )
    return {
        "config_file": str(model_config_path(settings)),
        "from_file": config.from_file,
        "defaults": {
            "provider": config.default_provider,
            "model": config.default_model,
            "temperature": (
                config.temperature
                if config.temperature is not None
                else settings.llm_temperature
            ),
        },
        "providers": providers_out,
    }


@router.get("/models")
def read_model_config() -> dict[str, Any]:
    """返回当前生效的模型配置；API Key 只返回掩码与来源，不回传明文。"""
    return _config_payload()


@router.put("/models")
def update_model_config(payload: ModelConfigUpdate) -> dict[str, Any]:
    """保存模型配置，写入 data/model_config.json 并立即生效。"""
    try:
        save_model_config(payload.model_dump())
    except ModelConfigError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except OSError as exc:
        logger.exception("model config write failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"配置写入失败：{exc}") from exc
    return _config_payload()


@router.delete("/models")
def delete_model_config() -> dict[str, Any]:
    """删除配置文件，恢复内置厂商目录 + .env 配置。"""
    reset_model_config()
    return _config_payload()


@router.post("/models/test")
async def test_model_provider(body: ProviderTestRequest) -> dict[str, Any]:
    """测试厂商连通性：GET {base_url}/models，验证网络与 API Key。"""
    settings = get_settings()
    config = get_effective_config(settings)
    entry = config.provider_map.get(body.provider.lower())
    base_url = (body.base_url or "").strip() or (
        entry.resolved_base_url(settings) if entry else ""
    )
    api_key = (body.api_key or "").strip() or (
        entry.resolved_api_key(settings) if entry else ""
    )

    if not base_url:
        raise HTTPException(status_code=400, detail="请先填写 Base URL")
    if not base_url.lower().startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Base URL 必须以 http(s):// 开头")
    if not api_key:
        raise HTTPException(status_code=400, detail="请先配置 API Key")

    url = f"{base_url.rstrip('/')}/models"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                url,
                headers={"Authorization": f"Bearer {api_key}"},
            )
    except httpx.TimeoutException:
        return {"ok": False, "message": "连接超时（10s），请检查 Base URL 或网络"}
    except httpx.HTTPError as exc:
        return {"ok": False, "message": f"无法连接：{exc.__class__.__name__}"}

    if 200 <= response.status_code < 300:
        return {
            "ok": True,
            "verified": True,
            "message": f"连接成功，API Key 有效（HTTP {response.status_code}）",
        }
    if response.status_code in (401, 403):
        return {
            "ok": False,
            "message": f"API Key 无效或无权限（HTTP {response.status_code}）",
        }
    if response.status_code in (404, 405):
        return {
            "ok": True,
            "verified": False,
            "message": (
                "网络连通，但该端点不提供 /models 列表；"
                "Key 有效性将在首次调用时验证"
            ),
        }
    return {
        "ok": False,
        "message": f"服务端返回异常状态（HTTP {response.status_code}）",
    }
