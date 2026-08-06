"""LLM 工厂测试（不耗 token，全部走 mock 路径）。"""

from __future__ import annotations

import pytest

from app.models.llm import get_llm
from app.models.schemas import Judgment, ReactDecision


def test_mock_llm_returns_chat_model():
    """mock=True 必须返回可调用的 BaseChatModel。"""
    llm = get_llm(mock=True)
    assert llm is not None
    # invoke 应返回带 content 属性的消息
    result = llm.invoke("anything")
    assert hasattr(result, "content")
    assert isinstance(result.content, str)


def test_mock_llm_supports_react_decision_schema():
    """Mock ReAct 输出必须满足 ReactDecision，防止复现字段缺失漏洞。"""
    llm = get_llm(mock=True)
    structured_llm = llm.with_structured_output(ReactDecision)

    result = structured_llm.invoke("健康检查告警")

    assert isinstance(result, ReactDecision)
    assert result.need_more_info is False
    assert result.next_action is None
    assert result.analysis
    assert result.reasoning


def test_structured_schemas_accept_detailed_security_reasoning():
    """Provider output must not fail merely because a useful analysis exceeds 300 chars."""
    long_text = "跨检测器证据与端点行为需要综合分析。" * 50
    decision = ReactDecision(
        analysis=long_text,
        judgment="待查",
        confidence=0.6,
        need_more_info=False,
        next_action=None,
        reasoning=long_text,
    )
    judgment = Judgment(
        cot=["综合多源证据。"],
        judgment="真阳",
        confidence=0.9,
        reason="关联案例判定说明。" * 30,
    )
    assert len(decision.analysis) > 300
    assert len(decision.reasoning) > 300
    assert len(judgment.reason) > 200


def test_unknown_provider_raises():
    """未知 provider 必须报 ValueError。"""
    with pytest.raises(ValueError, match="Unknown LLM provider"):
        get_llm(provider="nonexistent", mock=False)


def test_sangfor_not_implemented():
    """深信服适配点未实现时必须抛 NotImplementedError（接口已对齐）。

    赛题合规性硬指标：接口必须存在，便于平台权限下发后接入。
    """
    with pytest.raises(NotImplementedError, match="Sangfor"):
        get_llm(provider="sangfor", mock=False)


def test_deepseek_without_key_raises(monkeypatch):
    """无 key 调 deepseek 必须报明确错误（而不是让 OpenAI SDK 报模糊错误）。

    注意：用 _env_file=None 禁止 Settings 读 .env，否则在配了真实 .env
    的开发机上空 key 会被 .env 的真实值覆盖，测试失效。
    """
    from app.core.config import Settings

    fake_settings = Settings(_env_file=None, deepseek_api_key="", llm_provider="deepseek")
    with pytest.raises(RuntimeError, match="DEEPSEEK_API_KEY not set"):
        get_llm(provider="deepseek", mock=False, settings=fake_settings)


def test_deepseek_client_uses_global_timeout_as_fallback():
    from app.core.config import Settings

    settings = Settings(
        _env_file=None,
        DEEPSEEK_API_KEY="test-key",
        DEEPSEEK_BASE_URL="https://example.invalid/v1",
        LLM_PROVIDER="deepseek",
        REACT_GLOBAL_TIMEOUT_S=17.5,
    )
    llm = get_llm(provider="deepseek", settings=settings)
    assert llm.request_timeout == 17.5


def test_model_catalog_is_safe_and_contains_comparison_models():
    from app.core.config import Settings
    from app.models.llm import get_model_catalog

    settings = Settings(
        _env_file=None,
        SILICONFLOW_API_KEY="silicon-test",
        OPENAI_RELAY_API_KEY="relay-test",
    )
    catalog = get_model_catalog(settings)
    by_provider = {item["provider"]: item for item in catalog}
    assert {item["id"] for item in by_provider["deepseek"]["models"]} == {
        "deepseek-v4-pro",
        "deepseek-v4-flash",
    }
    assert by_provider["siliconflow"]["configured"] is True
    assert by_provider["openai_relay"]["configured"] is True
    assert by_provider["openai_relay"]["default_model"] == "gpt-5.4"
    assert {item["id"] for item in by_provider["openai_relay"]["models"]} == {"gpt-5.4"}
    assert by_provider["qwen"]["display_name"] == "阿里云百炼"
    assert by_provider["qwen"]["default_model"] == "qwen3.7-flash"
    assert all("api_key" not in item for item in catalog)


def test_siliconflow_client_uses_openai_compatible_settings():
    from app.core.config import Settings

    settings = Settings(
        _env_file=None,
        SILICONFLOW_API_KEY="test-key",
        SILICONFLOW_BASE_URL="https://silicon.example/v1/",
        REACT_GLOBAL_TIMEOUT_S=19.0,
    )
    llm = get_llm(provider="siliconflow", settings=settings)
    assert llm.model_name == "Qwen/Qwen3.5-9B"
    assert str(llm.openai_api_base).rstrip("/") == "https://silicon.example/v1"
    assert llm.request_timeout == 19.0


def test_qwen_client_uses_dashscope_settings():
    from app.core.config import Settings

    settings = Settings(
        _env_file=None,
        QWEN_API_KEY="test-key",
        QWEN_BASE_URL="https://dashscope.example/v1/",
    )
    llm = get_llm(provider="qwen", settings=settings)
    assert llm.model_name == "qwen3.7-flash"
    assert str(llm.openai_api_base).rstrip("/") == "https://dashscope.example/v1"


def test_openai_relay_client_accepts_per_provider_model_override():
    from app.core.config import Settings

    settings = Settings(
        _env_file=None,
        OPENAI_RELAY_API_KEY="test-key",
        OPENAI_RELAY_BASE_URL="https://relay.example/v1",
    )
    llm = get_llm(
        provider="openai_relay",
        model="gpt-5.4",
        settings=settings,
    )
    assert llm.model_name == "gpt-5.4"
    assert str(llm.openai_api_base).rstrip("/") == "https://relay.example/v1"


@pytest.mark.parametrize(
    ("provider", "message"),
    [
        ("siliconflow", "SILICONFLOW_API_KEY not set"),
        ("openai_relay", "OPENAI_RELAY_API_KEY not set"),
    ],
)
def test_new_provider_without_key_raises(provider, message):
    from app.core.config import Settings

    settings = Settings(_env_file=None, llm_provider=provider)
    with pytest.raises(RuntimeError, match=message):
        get_llm(provider=provider, settings=settings)
