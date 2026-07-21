"""LLM 工厂测试（不耗 token，全部走 mock 路径）。"""

from __future__ import annotations

import pytest

from app.models.llm import get_llm
from app.models.schemas import ReactDecision


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
