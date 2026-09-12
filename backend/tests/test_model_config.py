"""模型配置模块测试：文件持久化、.env 回退、工厂接入、API 往返。"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.model_config import (
    ModelConfigError,
    get_effective_config,
    mask_key,
    model_config_path,
    reset_model_config,
    save_model_config,
)


def fresh_settings(**kwargs) -> Settings:
    """每个用例独立的 Settings（继承 conftest 注入的隔离 MODEL_CONFIG_PATH）。"""
    return Settings(_env_file=None, **kwargs)


@pytest.fixture(autouse=True)
def clean_config_file():
    """每条用例前清掉隔离目录里的配置文件，避免用例间串扰。"""
    path = model_config_path(fresh_settings())
    path.unlink(missing_ok=True)
    yield
    path.unlink(missing_ok=True)


def _payload(**overrides) -> dict:
    payload = {
        "default_provider": "deepseek",
        "default_model": "deepseek-v4-pro",
        "temperature": 0.2,
        "providers": [
            {
                "id": "deepseek",
                "display_name": "DeepSeek",
                "base_url": "https://api.deepseek.com",
                "api_key": "sk-file-key-123456",
                "enabled": True,
                "models": [
                    {"id": "deepseek-v4-pro", "label": "DeepSeek V4 Pro"},
                ],
            }
        ],
    }
    payload.update(overrides)
    return payload


# ------------------------------------------------------------
# 无配置文件：与旧版行为一致
# ------------------------------------------------------------

def test_builtin_catalog_used_when_no_file():
    settings = fresh_settings()
    config = get_effective_config(settings)
    ids = [p.id for p in config.providers]
    assert {"deepseek", "qwen", "siliconflow", "openai_relay", "sangfor"} <= set(ids)
    assert config.from_file is False
    deepseek = config.provider_map["deepseek"]
    assert deepseek.resolved_base_url(settings) == "https://api.deepseek.com"
    assert deepseek.resolved_api_key(settings) == ""  # env 也未配置


def test_env_key_fallback_without_file():
    settings = fresh_settings(DEEPSEEK_API_KEY="sk-env-key")
    config = get_effective_config(settings)
    assert config.provider_map["deepseek"].resolved_api_key(settings) == "sk-env-key"


# ------------------------------------------------------------
# 保存 + 生效
# ------------------------------------------------------------

def test_save_and_reload_custom_provider():
    settings = fresh_settings()
    payload = _payload(
        providers=[
            {
                "id": "my_relay",
                "display_name": "我的中转",
                "base_url": "https://relay.example/v1",
                "api_key": "rk-1234567890",
                "enabled": True,
                "models": [{"id": "gpt-x", "label": "GPT X"}],
            }
        ],
        default_provider="my_relay",
        default_model="gpt-x",
    )
    save_model_config(payload, settings)

    config = get_effective_config(settings)
    assert config.from_file is True
    entry = config.provider_map["my_relay"]
    assert entry.resolved_api_key(settings) == "rk-1234567890"
    assert config.default_model_for("my_relay") == "gpt-x"

    # 自定义厂商 + 自定义模型直接进入工厂，无需改代码
    from app.models.llm import get_llm

    llm = get_llm(provider="my_relay", model="gpt-x", settings=settings)
    assert llm.model_name == "gpt-x"
    assert str(llm.openai_api_base).rstrip("/") == "https://relay.example/v1"


def test_file_key_overrides_env_key_and_none_keeps_existing():
    settings = fresh_settings(DEEPSEEK_API_KEY="sk-env-key")
    save_model_config(_payload(), settings)
    assert (
        get_effective_config(settings).provider_map["deepseek"].api_key
        == "sk-file-key-123456"
    )

    # 再次保存时 api_key=None → 沿用文件里的 key
    payload = _payload(
        providers=[
            {
                "id": "deepseek",
                "display_name": "DeepSeek",
                "base_url": "https://api.deepseek.com",
                "api_key": None,
                "models": [{"id": "deepseek-v4-pro", "label": "Pro"}],
            }
        ]
    )
    save_model_config(payload, settings)
    assert (
        get_effective_config(settings).provider_map["deepseek"].api_key
        == "sk-file-key-123456"
    )

    # api_key="" → 清除文件 key，回落 env
    payload["providers"][0]["api_key"] = ""
    save_model_config(payload, settings)
    entry = get_effective_config(settings).provider_map["deepseek"]
    assert entry.api_key == ""
    assert entry.resolved_api_key(settings) == "sk-env-key"


def test_custom_provider_temperature_from_file():
    settings = fresh_settings()
    save_model_config(_payload(temperature=0.7), settings)
    from app.models.llm import get_llm

    llm = get_llm(provider="deepseek", settings=settings)
    assert llm.temperature == 0.7


def test_reset_restores_builtin_defaults():
    settings = fresh_settings()
    save_model_config(_payload(), settings)
    assert model_config_path(settings).exists()
    reset_model_config(settings)
    config = get_effective_config(settings)
    assert config.from_file is False
    assert "my_relay" not in config.provider_map


def test_invalid_config_rejected():
    settings = fresh_settings()

    with pytest.raises(ModelConfigError, match="不合法"):
        save_model_config(
            _payload(
                providers=[
                    {
                        "id": "Bad Id",
                        "display_name": "x",
                        "base_url": "https://x.example",
                        "models": [{"id": "m"}],
                    }
                ]
            ),
            settings,
        )

    with pytest.raises(ModelConfigError, match="至少需要一个模型"):
        save_model_config(
            _payload(
                providers=[
                    {
                        "id": "deepseek",
                        "display_name": "x",
                        "base_url": "https://x.example",
                        "models": [],
                    }
                ]
            ),
            settings,
        )

    with pytest.raises(ModelConfigError, match="默认厂商"):
        save_model_config(_payload(default_provider="ghost"), settings)


def test_validate_model_selection_uses_saved_catalog():
    from app.models.llm import validate_model_selection

    settings = fresh_settings()
    save_model_config(_payload(), settings)

    provider, model = validate_model_selection(
        provider="deepseek", model="deepseek-v4-pro", settings=settings
    )
    assert (provider, model) == ("deepseek", "deepseek-v4-pro")

    with pytest.raises(ValueError, match="does not belong to provider"):
        validate_model_selection(
            provider="deepseek", model="gpt-5.4", settings=settings
        )


def test_mask_key():
    assert mask_key("") == ""
    assert mask_key("short") == "***"
    assert mask_key("sk-abcdef123456") == "sk-***3456"


# ------------------------------------------------------------
# API 往返（GET 返回掩码，PUT 立即生效）
# ------------------------------------------------------------

def test_config_api_round_trip():
    from app.main import app

    client = TestClient(app)

    initial = client.get("/api/config/models").json()
    assert initial["from_file"] is False
    deepseek = next(p for p in initial["providers"] if p["id"] == "deepseek")
    assert "api_key" not in deepseek

    saved = client.put(
        "/api/config/models",
        json={
            "default_provider": "deepseek",
            "default_model": "deepseek-v4-pro",
            "temperature": 0.3,
            "providers": [
                {
                    "id": "deepseek",
                    "display_name": "DeepSeek",
                    "base_url": "https://api.deepseek.com",
                    "api_key": "sk-api-test-9999",
                    "models": [{"id": "deepseek-v4-pro", "label": "Pro"}],
                }
            ],
        },
    )
    assert saved.status_code == 200
    body = saved.json()
    assert body["from_file"] is True
    entry = body["providers"][0]
    assert entry["api_key_set"] is True
    assert entry["api_key_source"] == "file"
    assert "sk-api-test-9999" not in json.dumps(body)
    assert entry["api_key_preview"] == mask_key("sk-api-test-9999")

    # /api/models（顶栏目录）立即反映新配置
    models = client.get("/api/models").json()
    assert models["providers"][0]["configured"] is True

    reset = client.delete("/api/config/models")
    assert reset.status_code == 200
    assert reset.json()["from_file"] is False
