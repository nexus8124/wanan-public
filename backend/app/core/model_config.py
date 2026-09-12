"""运行时模型配置：文件持久化 + .env 回退。

设计要点：
1. 内置厂商目录（原硬编码在 llm.py）搬到这里，作为工厂与配置页的共同数据源
2. ``data/model_config.json`` 保存后在运行时生效（按 mtime 缓存，无需重启）；
   文件不存在时行为与旧版完全一致：内置目录 + .env 的 key/base_url
3. API Key 优先级：配置文件 > .env。文件里为空的字段自动回落 .env，
   因此已有 .env 部署不做任何操作也能继续工作
4. 文件在 .gitignore 中（内含明文 key），只存在本机
"""

from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.config import Settings, get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

CONFIG_VERSION = 1

# provider id 合法格式：小写字母开头，后续字母/数字/下划线/连字符
_PROVIDER_ID_RE = re.compile(r"^[a-z][a-z0-9_-]*$")

# 内置厂商种子目录（与旧版 _PROVIDER_DEFAULTS + _MODEL_CATALOG 保持一致）
BUILTIN_PROVIDERS: list[dict[str, Any]] = [
    {
        "id": "deepseek",
        "display_name": "DeepSeek",
        "base_url": "https://api.deepseek.com",
        "models": [
            {"id": "deepseek-v4-pro", "label": "DeepSeek V4 Pro"},
            {"id": "deepseek-v4-flash", "label": "DeepSeek V4 Flash"},
        ],
    },
    {
        "id": "qwen",
        "display_name": "阿里云百炼",
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "models": [{"id": "qwen3.7-flash", "label": "Qwen3.7 Flash"}],
    },
    {
        "id": "siliconflow",
        "display_name": "SiliconFlow",
        "base_url": "https://api.siliconflow.cn/v1",
        "models": [
            {"id": "Qwen/Qwen3.5-9B", "label": "Qwen3.5 9B (SiliconFlow)"},
            {"id": "Qwen/Qwen3-8B", "label": "Qwen3 8B (SiliconFlow)"},
        ],
    },
    {
        "id": "openai_relay",
        "display_name": "OpenAI 中转",
        "base_url": "https://www.cctq.ai/v1",
        "models": [{"id": "gpt-5.4", "label": "GPT-5.4 (relay)"}],
    },
    {
        # 深信服安全 GPT：平台权限下发前无 base_url，配置页填入后即可用
        "id": "sangfor",
        "display_name": "深信服安全 GPT",
        "base_url": "",
        "models": [{"id": "sangfor-security-gpt", "label": "深信服安全 GPT"}],
    },
]

_BUILTIN_IDS = {item["id"] for item in BUILTIN_PROVIDERS}

# provider id → (Settings 的 key 字段, base_url 字段, 缺 key 时的报错提示)
# 自定义厂商不在表中：key 只能来自配置文件
ENV_PROVIDER_FIELDS: dict[str, tuple[str, str, str]] = {
    "deepseek": ("deepseek_api_key", "deepseek_base_url", "DEEPSEEK_API_KEY"),
    "qwen": ("qwen_api_key", "qwen_base_url", "QWEN_API_KEY"),
    "siliconflow": (
        "siliconflow_api_key",
        "siliconflow_base_url",
        "SILICONFLOW_API_KEY",
    ),
    "openai_relay": (
        "openai_relay_api_key",
        "openai_relay_base_url",
        "OPENAI_RELAY_API_KEY",
    ),
    "sangfor": ("sangfor_api_key", "sangfor_base_url", "SANGFOR_API_KEY"),
}


def env_key_hint(provider_id: str) -> str:
    entry = ENV_PROVIDER_FIELDS.get(provider_id)
    return entry[2] if entry else f"Provider {provider_id!r} API key"


@dataclass
class ModelEntry:
    id: str
    label: str


@dataclass
class ProviderConfig:
    """一个厂商的生效配置（文件值 + .env 回退后的视图）。"""

    id: str
    display_name: str
    base_url: str = ""  # 配置文件保存的 base_url；无文件时为空
    api_key: str = ""  # 仅配置文件里保存的 key；.env 的 key 不落盘
    enabled: bool = True
    builtin: bool = False
    models: list[ModelEntry] = field(default_factory=list)
    # 内置目录里的兜底 base_url（厂商官方地址），持久化时忽略
    fallback_base_url: str = ""

    # ----- 解析优先级：配置文件 > .env > 内置默认 -----
    def env_api_key(self, settings: Settings) -> str:
        entry = ENV_PROVIDER_FIELDS.get(self.id)
        if not entry:
            return ""
        return str(getattr(settings, entry[0]) or "").strip()

    def env_base_url(self, settings: Settings) -> str:
        entry = ENV_PROVIDER_FIELDS.get(self.id)
        if not entry:
            return ""
        return str(getattr(settings, entry[1]) or "").strip()

    def resolved_api_key(self, settings: Settings) -> str:
        return self.api_key.strip() or self.env_api_key(settings)

    def resolved_base_url(self, settings: Settings) -> str:
        return (
            self.base_url.strip()
            or self.env_base_url(settings)
            or self.fallback_base_url
        )

    @property
    def api_key_source(self) -> str:
        # 调用方需要区分 key 来源时由 resolved 结果推断，这里只报文件态
        return "file" if self.api_key.strip() else "none"


@dataclass
class ModelRuntimeConfig:
    """全量生效配置：厂商列表 + 全局默认。"""

    providers: list[ProviderConfig] = field(default_factory=list)
    default_provider: str = ""
    default_model: str = ""
    temperature: float | None = None
    from_file: bool = False

    @property
    def provider_map(self) -> dict[str, ProviderConfig]:
        return {p.id: p for p in self.providers}

    def default_model_for(self, provider_id: str) -> str:
        if (
            provider_id == self.default_provider
            and self.default_model
        ):
            provider = self.provider_map.get(provider_id)
            if provider and any(m.id == self.default_model for m in provider.models):
                return self.default_model
        provider = self.provider_map.get(provider_id)
        if provider and provider.models:
            return provider.models[0].id
        return ""


# ------------------------------------------------------------
# 文件读写（mtime 缓存，保存后立即生效）
# ------------------------------------------------------------

_cache_lock = threading.Lock()
_cache: dict[str, tuple[tuple[int, int], dict[str, Any] | None]] = {}


def model_config_path(settings: Settings | None = None) -> Path:
    s = settings or get_settings()
    return s.model_config_path


def _read_stored_config(settings: Settings) -> dict[str, Any] | None:
    path = model_config_path(settings)
    key = str(path)
    try:
        stat = path.stat()
        stamp = (stat.st_mtime_ns, stat.st_size)
    except OSError:
        with _cache_lock:
            _cache.pop(key, None)
        return None

    with _cache_lock:
        cached = _cache.get(key)
        if cached and cached[0] == stamp:
            return cached[1]

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        stored = raw if isinstance(raw, dict) else None
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("model config file unreadable, falling back to defaults: %s", exc)
        stored = None

    with _cache_lock:
        _cache[key] = (stamp, stored)
    return stored


def invalidate_config_cache(settings: Settings | None = None) -> None:
    path = model_config_path(settings or get_settings())
    with _cache_lock:
        _cache.pop(str(path), None)


def _provider_from_raw(
    raw: dict[str, Any], *, builtin_hint: dict[str, Any] | None = None
) -> ProviderConfig:
    hint = builtin_hint or {}
    models_raw = raw.get("models") or []
    models = [
        ModelEntry(
            id=str(item.get("id", "")).strip(),
            label=str(item.get("label", "")).strip(),
        )
        for item in models_raw
        if isinstance(item, dict) and str(item.get("id", "")).strip()
    ]
    models = [
        ModelEntry(id=m.id, label=m.label or m.id) for m in models
    ]
    return ProviderConfig(
        id=str(raw.get("id", "")).strip(),
        display_name=str(raw.get("display_name", "")).strip()
        or str(hint.get("display_name", ""))
        or str(raw.get("id", "")).strip(),
        # base_url 只存文件值；hint 仅作内置兜底，让 .env 覆盖值保持优先
        base_url=str(raw.get("base_url", "")).strip(),
        api_key=str(raw.get("api_key", "") or ""),
        enabled=bool(raw.get("enabled", True)),
        builtin=bool(raw.get("builtin", False)) or raw.get("id") in _BUILTIN_IDS,
        models=models,
        fallback_base_url=str(hint.get("base_url", "")),
    )


def get_effective_config(settings: Settings | None = None) -> ModelRuntimeConfig:
    """返回生效配置：有配置文件用文件，否则用内置目录 + .env 默认值。"""
    s = settings or get_settings()
    stored = _read_stored_config(s)

    if stored and isinstance(stored.get("providers"), list):
        hints = {item["id"]: item for item in BUILTIN_PROVIDERS}
        providers = [
            _provider_from_raw(item, builtin_hint=hints.get(str(item.get("id", ""))))
            for item in stored["providers"]
            if isinstance(item, dict)
        ]
        providers = [p for p in providers if p.id]
        config = ModelRuntimeConfig(
            providers=providers,
            default_provider=str(stored.get("default_provider", "")).strip(),
            default_model=str(stored.get("default_model", "")).strip(),
            temperature=(
                float(stored["temperature"])
                if stored.get("temperature") is not None
                else None
            ),
            from_file=True,
        )
        _repair_defaults(config, s)
        return config

    # 无文件：内置目录 + Settings 默认（与旧版行为一致）。
    # base_url 置空以保留 .env 覆盖的优先级，内置地址只作兜底。
    providers = [
        _provider_from_raw({**item, "base_url": ""}, builtin_hint=item)
        for item in BUILTIN_PROVIDERS
    ]
    config = ModelRuntimeConfig(
        providers=providers,
        default_provider=s.llm_provider.lower(),
        default_model=s.llm_model.strip(),
        temperature=None,
        from_file=False,
    )
    provider = config.provider_map.get(config.default_provider)
    if not provider or not any(
        m.id == config.default_model for m in provider.models
    ):
        config.default_model = provider.models[0].id if provider and provider.models else ""
    return config


def _repair_defaults(config: ModelRuntimeConfig, settings: Settings) -> None:
    """配置文件里的默认 provider/model 失效时回落到第一个可用厂商。"""
    provider = config.provider_map.get(config.default_provider)
    if provider and any(m.id == config.default_model for m in provider.models):
        return
    fallback = next(
        (p for p in config.providers if p.enabled and p.models),
        None,
    )
    if fallback:
        config.default_provider = fallback.id
        config.default_model = fallback.models[0].id
    elif config.providers:
        first = config.providers[0]
        config.default_provider = first.id
        config.default_model = first.models[0].id if first.models else ""


# ------------------------------------------------------------
# 保存（配置页提交）
# ------------------------------------------------------------

class ModelConfigError(ValueError):
    """配置校验失败，message 直接展示给前端。"""


def _validate_providers(payload_providers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not payload_providers:
        raise ModelConfigError("至少需要一个模型厂商")
    seen_ids: set[str] = set()
    cleaned: list[dict[str, Any]] = []
    for item in payload_providers:
        pid = str(item.get("id", "")).strip()
        if not _PROVIDER_ID_RE.match(pid):
            raise ModelConfigError(
                f"厂商标识 {pid!r} 不合法：需以小写字母开头，仅含小写字母/数字/下划线/连字符"
            )
        if pid in seen_ids:
            raise ModelConfigError(f"厂商标识重复：{pid}")
        seen_ids.add(pid)

        models_raw = item.get("models") or []
        models: list[dict[str, str]] = []
        seen_models: set[str] = set()
        for m in models_raw:
            mid = str(m.get("id", "")).strip()
            if not mid:
                continue
            if mid in seen_models:
                raise ModelConfigError(f"厂商 {pid} 的模型名重复：{mid}")
            seen_models.add(mid)
            models.append({"id": mid, "label": str(m.get("label", "")).strip() or mid})
        if not models:
            raise ModelConfigError(f"厂商 {pid} 至少需要一个模型")

        base_url = str(item.get("base_url", "")).strip()
        enabled = bool(item.get("enabled", True))
        if enabled and base_url and not base_url.lower().startswith(("http://", "https://")):
            raise ModelConfigError(f"厂商 {pid} 的 Base URL 必须以 http(s):// 开头")

        raw_key = item.get("api_key")
        cleaned.append(
            {
                "id": pid,
                "display_name": str(item.get("display_name", "")).strip() or pid,
                "base_url": base_url,
                # None = 沿用已保存的 key（由 save_model_config 回填），"" = 清除
                "api_key": None if raw_key is None else str(raw_key),
                "enabled": enabled,
                "builtin": bool(item.get("builtin", False)) or pid in _BUILTIN_IDS,
                "models": models,
            }
        )
    return cleaned


def save_model_config(
    payload: dict[str, Any], settings: Settings | None = None
) -> ModelRuntimeConfig:
    """校验并落盘配置；api_key 为 None 表示沿用已保存的 key。

    前端约定：
    - ``api_key`` 缺省/None → 保留文件里已有的 key
    - ``api_key`` 为 ""     → 清除已保存的 key（.env 的 key 仍会生效）
    - ``api_key`` 非空      → 覆盖保存
    """
    s = settings or get_settings()
    existing = _read_stored_config(s) or {}
    existing_keys = {
        str(p.get("id", "")): str(p.get("api_key", "") or "")
        for p in existing.get("providers", [])
        if isinstance(p, dict)
    }

    providers_raw = payload.get("providers")
    if not isinstance(providers_raw, list):
        raise ModelConfigError("providers 必须是列表")

    providers = _validate_providers(providers_raw)
    for provider in providers:
        if provider["api_key"] is None:
            provider["api_key"] = existing_keys.get(provider["id"], "")

    default_provider = str(payload.get("default_provider", "")).strip()
    default_model = str(payload.get("default_model", "")).strip()
    provider_map = {p["id"]: p for p in providers}
    target = provider_map.get(default_provider)
    if not target:
        raise ModelConfigError(f"默认厂商 {default_provider!r} 不在厂商列表中")
    if default_model and not any(
        m["id"] == default_model for m in target["models"]
    ):
        raise ModelConfigError(
            f"默认模型 {default_model!r} 不属于厂商 {default_provider!r}"
        )
    if not default_model:
        default_model = target["models"][0]["id"]

    temperature_raw = payload.get("temperature")
    temperature: float | None = None
    if temperature_raw is not None:
        try:
            temperature = float(temperature_raw)
        except (TypeError, ValueError) as exc:
            raise ModelConfigError("temperature 必须是数字") from exc
        if not 0.0 <= temperature <= 2.0:
            raise ModelConfigError("temperature 需在 0 到 2 之间")

    doc = {
        "version": CONFIG_VERSION,
        "default_provider": default_provider,
        "default_model": default_model,
        "temperature": temperature,
        "providers": providers,
    }

    path = model_config_path(s)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(
        json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    os.replace(tmp, path)
    invalidate_config_cache(s)

    logger.info(
        "model config saved: %d providers, default=%s/%s",
        len(providers),
        default_provider,
        default_model,
    )
    return get_effective_config(s)


def reset_model_config(settings: Settings | None = None) -> bool:
    """删除配置文件，回到内置目录 + .env。返回文件是否原本存在。"""
    s = settings or get_settings()
    path = model_config_path(s)
    existed = path.exists()
    if existed:
        path.unlink()
    invalidate_config_cache(s)
    return existed


def mask_key(key: str) -> str:
    key = key.strip()
    if not key:
        return ""
    if len(key) <= 8:
        return "***"
    return f"{key[:3]}***{key[-4:]}"
