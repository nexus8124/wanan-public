"""LLM 抽象工厂。

赛题贴合（合规性硬指标）：
- "基于深信服 AI 安全平台" → 三 provider 工厂，预留 `sangfor` 适配接口
- "集成 DeepSeek、Qwen 及深信服自研安全 GPT" → 三者皆支持切换

设计要点：
1. DeepSeek / Qwen 都兼容 OpenAI 接口，统一用 `ChatOpenAI`
2. 深信服安全 GPT（运营 GPT / 检测 GPT）暂未拿到权限，留 NotImplementedError 但接口已对齐
3. `mock=True` 返回 FakeJudgeLLM，让无 key / CI 环境也能跑通测试，不耗 token
"""

from __future__ import annotations

from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_openai import ChatOpenAI

from app.core.config import Settings, get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# 各 provider 的默认配置
# 注：DeepSeek、Qwen 均 OpenAI 兼容，base_url 不同
_PROVIDER_DEFAULTS: dict[str, dict[str, Any]] = {
    "deepseek": {
        # deepseek-v4-flash 是 V4 主力；deepseek-chat 已于 2026/07/24 弃用
        "model": "deepseek-v4-flash",
        "base_url": "https://api.deepseek.com",
    },
    "qwen": {
        "model": "qwen-plus",
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
    },
    "sangfor": {
        # 深信服安全 GPT：base_url 待平台权限下发后填入 .env
        "model": "sangfor-security-gpt",
        "base_url": "",  # 占位，从 settings.sangfor_base_url 读
    },
}


def _make_mock_llm() -> "FakeJudgeLLM":
    """返回一个不耗 token 的假 LLM，用于测试和无 key 环境。

    基于规则给出确定性研判（不动用真实模型），让 CI / 无 key 环境也能跑通
    preprocess → judge → output 完整链路。规则见 FakeJudgeLLM。
    """
    return FakeJudgeLLM()


class FakeJudgeLLM(BaseChatModel):
    """测试用 mock LLM。

    用关键词规则模拟研判（不调真实模型），支持 with_structured_output。
    规则：alert 描述里出现 attack_keyword → 真阳；出现 benign_keyword → 假阳。

    目的：让无 DeepSeek key 时也能跑通完整 Agent 图 + 评测脚本，
    验证工程链路正确（不验证业务准确率——那是真实 LLM 的活）。
    """

    # 真阳关键词（出现任一即判真阳）
    # 注：避免宽泛词（如"横向""外连"）误伤 features 里的方向字段，
    # 只用攻击动作专有词。
    attack_keywords: list[str] = [
        "reverse shell", "known c2", "c2 server", "lateral movement",
        "横向移动", "横向扩散", "psexec", "encoded command",
        "sql injection", "sqli", "brute force", "暴破", "暴力破解",
        "regsvr32", "powershell.exe", "钓鱼", "phishing", "malicious",
    ]
    # 假阳关键词
    benign_keywords: list[str] = [
        "health check", "健康检查", "cdn", "nightly",
        "monitor", "cron", "定时", "监控", "探针",
        "签名验证通过", "可用性探针", "availability probe",
    ]

    @property
    def _llm_type(self) -> str:
        return "fake-judge"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):  # type: ignore[override]
        from langchain_core.outputs import ChatGeneration, ChatResult

        # 取最后一条 user message 的文本（含告警 JSON）
        text = ""
        for m in reversed(messages):
            content = getattr(m, "content", "")
            if content:
                text = content.lower() if isinstance(content, str) else str(content).lower()
                break
        judgment = self._rule_judge(text)
        msg = AIMessage(content=_compact_json(judgment))
        return ChatResult(generations=[ChatGeneration(message=msg)])

    def _rule_judge(self, text: str) -> dict:
        """基于关键词的规则研判，返回 Judgment schema 兼容 dict。"""
        is_attack = any(k in text for k in self.attack_keywords)
        is_benign = any(k in text for k in self.benign_keywords)
        if is_attack and not is_benign:
            return {
                "cot": [
                    "流量特征：mock 规则命中攻击关键词。",
                    "行为意图：符合已知攻击模式特征。",
                    "关联上下文：源/目的地址或载荷可疑。",
                    "历史模式：不匹配已知业务行为。",
                    "综合判定：判真阳（mock）。",
                ],
                "judgment": "真阳",
                "confidence": 0.85,
                "reason": "mock LLM: 命中攻击关键词",
            }
        if is_benign and not is_attack:
            return {
                "cot": [
                    "流量特征：mock 规则命中业务关键词。",
                    "行为意图：符合已知业务模式。",
                    "关联上下文：源/目的合理。",
                    "历史模式：匹配定时/监控任务特征。",
                    "综合判定：判假阳（mock）。",
                ],
                "judgment": "假阳",
                "confidence": 0.82,
                "reason": "mock LLM: 命中业务关键词",
            }
        return {
            "cot": ["mock 规则未命中明确关键词，进入待查。"],
            "judgment": "待查",
            "confidence": 0.5,
            "reason": "mock LLM: 关键词不明确",
        }

    def with_structured_output(self, schema, **kwargs):  # type: ignore[override]
        """支持结构化输出：根据目标 schema 构造对应的 mock 数据。"""
        from langchain_core.runnables import RunnableLambda

        def _invoke(inp, config=None, **kw):
            # inp 可能是 dict（chain 直调）/ str / ChatPromptValue（prompt | llm 链式）
            text = _extract_text(inp)

            # 原实现保留：它只会生成 Judgment 所需的字段，直接用于
            # ReactDecision 时会缺少 analysis/need_more_info/reasoning。
            # data = self._rule_judge(text)

            judgment_data = self._rule_judge(text)
            if schema.__name__ == "ReactDecision":
                data = {
                    "analysis": judgment_data["reason"],
                    "judgment": judgment_data["judgment"],
                    "confidence": judgment_data["confidence"],
                    "need_more_info": False,
                    "next_action": None,
                    "reasoning": "mock ReAct：当前证据已足够，停止工具调用。",
                }
            else:
                data = judgment_data

            return schema.model_validate(data)

        return RunnableLambda(_invoke)


def _extract_text(inp: Any) -> str:
    """从多种输入类型提取纯文本（用于 mock 关键词匹配）。

    关键：当输入是 ChatPromptValue（prompt | llm 链式调用）时，
    只取【最后一条 user message】——因为前面的 few-shot 示例也会含
    attack/benign 关键词，会导致规则误判。
    """
    # ChatPromptValue
    messages = getattr(inp, "messages", None)
    if messages is not None:
        # 倒序找最后一条 content 非空的 message
        for m in reversed(messages):
            c = getattr(m, "content", "")
            if isinstance(c, str) and c.strip():
                return c.lower()
        return ""
    if isinstance(inp, dict):
        # 直调场景：优先看告警 + 特征
        return (
            str(inp.get("alert_json", ""))
            + " "
            + str(inp.get("features_text", ""))
        ).lower()
    if isinstance(inp, str):
        return inp.lower()
    return str(inp).lower()


def _compact_json(obj: Any) -> str:
    import json

    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def get_llm(
    provider: str | None = None,
    *,
    model: str | None = None,
    temperature: float | None = None,
    mock: bool = False,
    settings: Settings | None = None,
) -> BaseChatModel:
    """LLM 工厂入口。

    参数：
        provider: "deepseek" | "qwen" | "sangfor"；None 则读 settings.llm_provider
        model:    模型名；None 则用 provider 默认值
        temperature: 温度；None 则读 settings.llm_temperature
        mock:     True 时返回不耗 token 的假模型（测试 / 无 key 环境用）
        settings: 注入配置（测试用），None 则读全局单例

    返回：BaseChatModel 实例

    用法：
        llm = get_llm()                          # 默认 DeepSeek
        llm = get_llm(provider="qwen")           # 切换 Qwen
        llm = get_llm(mock=True)                 # 测试不耗 token
    """
    if mock:
        logger.info("LLM factory: returning mock LLM (no token cost)")
        return _make_mock_llm()

    s = settings or get_settings()
    provider = (provider or s.llm_provider).lower()
    if provider not in _PROVIDER_DEFAULTS:
        raise ValueError(
            f"Unknown LLM provider: {provider!r}. "
            f"Expected one of {list(_PROVIDER_DEFAULTS)}"
        )

    defaults = _PROVIDER_DEFAULTS[provider]
    model_name = model or s.llm_model or defaults["model"]
    temp = temperature if temperature is not None else s.llm_temperature

    if provider == "deepseek":
        if not s.deepseek_api_key:
            raise RuntimeError(
                "DEEPSEEK_API_KEY not set. Fill it in .env "
                "(see .env.example), or use get_llm(mock=True) for testing."
            )
        # DeepSeek V4 默认开启 thinking 模式（思考链）。
        # 我们的研判 Prompt 已在内容层强制 5 步 CoT，不需要模型内部再 think，
        # 而且 thinking 模式与 tool_choice/function_calling 有兼容问题
        # （会报 "Thinking mode does not support this tool_choice"）。
        # 所以默认关闭 thinking，需要时单独开启。
        # return ChatOpenAI(
        #     model=model_name,
        #     api_key=s.deepseek_api_key,
        #     base_url=defaults["base_url"],
        #     temperature=temp,
        #     extra_body={"thinking": {"type": "disabled"}},
        # )
        deepseek_kwargs: dict[str, Any] = {
            "model": model_name,
            "api_key": s.deepseek_api_key,
            "base_url": s.deepseek_base_url.rstrip("/"),
            "temperature": temp,
            "default_headers": {
                "User-Agent": "Mozilla/5.0",
            },
        }

        if s.deepseek_send_thinking:
            deepseek_kwargs["extra_body"] = {
                "thinking": {"type": "disabled"}
            }

        return ChatOpenAI(**deepseek_kwargs)
        

    if provider == "qwen":
        if not s.qwen_api_key:
            raise RuntimeError(
                "QWEN_API_KEY not set. Fill it in .env or use mock=True."
            )
        return ChatOpenAI(
            model=model_name,
            api_key=s.qwen_api_key,
            base_url=defaults["base_url"],
            temperature=temp,
        )

    if provider == "sangfor":
        # ⚠️ 深信服安全 GPT 适配点：平台权限下发后在此实现
        # 当前只对齐接口签名，保证主流程不受影响
        raise NotImplementedError(
            "Sangfor Security GPT adapter not yet implemented. "
            "Waiting for platform access (contact the project administrator). "
            "Interface is reserved for compliance — switch provider to "
            "'deepseek' or 'qwen' for now."
        )

    # 不可达：前面已校验 provider
    raise AssertionError(f"unhandled provider: {provider}")
