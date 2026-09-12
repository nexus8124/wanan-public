"""LLM 抽象工厂。

赛题贴合（合规性硬指标）：
- "基于深信服 AI 安全平台" → 多 provider 工厂，预留 `sangfor` 适配接口
- "集成 DeepSeek、Qwen 及深信服自研安全 GPT" → 皆支持切换

设计要点：
1. 厂商/模型目录来自 app.core.model_config：内置目录 + 配置页写入的
   data/model_config.json（运行时生效，无需重启），全部走 OpenAI 兼容接口
2. 深信服安全 GPT 未配置 base_url/key 时抛 NotImplementedError，接口已对齐；
   在配置页填入后即可通过通用路径调用
3. `mock=True` 返回 FakeJudgeLLM，让无 key / CI 环境也能跑通测试，不耗 token
"""

from __future__ import annotations

from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_openai import ChatOpenAI

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.core.model_config import (
    env_key_hint,
    get_effective_config,
)

logger = get_logger(__name__)

# 厂商默认配置已迁移到 app.core.model_config：
# 内置目录 + 配置页写入的 data/model_config.json 共同决定生效的 provider/model。


def provider_is_configured(settings: Settings, provider: str | None = None) -> bool:
    """Return whether the selected provider has a usable API key."""
    config = get_effective_config(settings)
    name = (provider or settings.llm_provider).lower()
    entry = config.provider_map.get(name)
    return bool(entry and entry.resolved_api_key(settings))


def get_model_catalog(settings: Settings | None = None) -> list[dict[str, Any]]:
    """Return safe provider/model metadata without exposing API keys."""
    s = settings or get_settings()
    config = get_effective_config(s)
    return [
        {
            "provider": provider.id,
            "display_name": provider.display_name,
            "models": [
                {"id": m.id, "label": m.label} for m in provider.models
            ],
            "configured": bool(provider.resolved_api_key(s)),
            "default_model": config.default_model_for(provider.id),
        }
        for provider in config.providers
    ]


def validate_model_selection(
    provider: str | None = None,
    model: str | None = None,
    *,
    settings: Settings | None = None,
) -> tuple[str, str]:
    """Resolve and validate a provider/model pair exposed by the public API."""
    s = settings or get_settings()
    config = get_effective_config(s)
    provider_name = (provider or s.llm_provider).lower()
    entry = config.provider_map.get(provider_name)
    if entry is None:
        raise ValueError(
            f"Unknown LLM provider: {provider_name!r}. "
            f"Expected one of {list(config.provider_map)}"
        )

    configured_model = (
        s.llm_model
        if provider is None or provider_name == s.llm_provider.lower()
        else ""
    )
    model_name = (
        model or configured_model or config.default_model_for(provider_name)
    )
    allowed_models = {m.id for m in entry.models}
    if not allowed_models:
        raise ValueError(
            f"Provider {provider_name!r} has no models configured. "
            "Add one on the model settings page."
        )
    if model_name not in allowed_models:
        raise ValueError(
            f"Model {model_name!r} does not belong to provider {provider_name!r}. "
            f"Expected one of {sorted(allowed_models)}"
        )
    return provider_name, model_name


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
            elif schema.__name__ == "MultiAgentPlan":
                import re

                ips = list(dict.fromkeys(re.findall(
                    r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text
                )))
                target = ips[0] if ips else ""
                tasks = [{
                    "agent": "context_agent",
                    "tool": "inspect_alert_context",
                    "args": {},
                    "purpose": "先核验告警上下文和真实可用的数据源",
                    "success_criteria": "取得检测器上下文或证据源说明",
                }]
                if target and "endpoint_logs" in text:
                    tasks.append({
                        "agent": "endpoint_agent",
                        "tool": "fetch_endpoint_logs",
                        "args": {"host_ip": target},
                        "purpose": "核验告警主机上的进程和认证行为",
                        "success_criteria": "取得与主机和时间一致的端点记录",
                    })
                if target and any(
                    capability in text
                    for capability in ("network_alerts", "network_flows", "netflow")
                ):
                    tasks.append({
                        "agent": "network_agent",
                        "tool": "fetch_network_flows",
                        "args": {"host_ip": target, "window_min": 30},
                        "purpose": "核验同一目标的网络连接和流量证据",
                        "success_criteria": "取得与告警时间一致的网络记录",
                    })
                data = {
                    "objective": "用最少的跨源查询验证当前告警判断",
                    "rationale": "mock 协调器根据证据能力和真实目标自主生成调查顺序。",
                    "tasks": tasks[:3],
                }
            elif schema.__name__ == "MultiAgentReplan":
                import json

                remaining: list[dict[str, Any]] = []
                marker = "【尚未执行的候选任务】"
                if marker in text:
                    tail = text.split(marker, 1)[1]
                    start = tail.find("[")
                    if start >= 0:
                        try:
                            parsed, _ = json.JSONDecoder().raw_decode(tail[start:])
                            if isinstance(parsed, list):
                                remaining = [
                                    item for item in parsed if isinstance(item, dict)
                                ]
                        except ValueError:
                            remaining = []
                data = {
                    "observation": "mock 重规划器已读取最新工具观测。",
                    "decision": "continue" if remaining else "verify",
                    "rationale": (
                        "仍有未核验的真实证据源，继续执行价值最高的下一项。"
                        if remaining else "计划中的证据源已经核验，进入最终验证。"
                    ),
                    "tasks": remaining[:3],
                }
            elif schema.__name__ == "MultiAgentVerdict":
                import re

                evidence_ids = list(dict.fromkeys(re.findall(r"EV-[A-Za-z0-9-]+", text)))
                knowledge_ids = list(dict.fromkeys(re.findall(r"KB-[A-Za-z0-9-]+", text)))
                data = {
                    "analysis": "mock 多智能体验证：已复核各专业智能体的结构化发现。",
                    "judgment": judgment_data["judgment"],
                    "confidence": judgment_data["confidence"],
                    "reason": f"mock 多智能体：{judgment_data['reason']}",
                    "cited_evidence": evidence_ids[:3],
                    "cited_knowledge": knowledge_ids[:3],
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
        provider: 内置厂商或配置页添加的自定义厂商；None 则读默认配置
        model:    模型名；None 则用 provider 默认值
        temperature: 温度；None 则依次读配置文件、settings.llm_temperature
        mock:     True 时返回不耗 token 的假模型（测试 / 无 key 环境用）
        settings: 注入配置（测试用），None 则读全局单例

    返回：BaseChatModel 实例

    用法：
        llm = get_llm()                          # 默认 DeepSeek
        llm = get_llm(provider="qwen")           # 切换 Qwen
        llm = get_llm(mock=True)                 # 测试不耗 token
    """
    s = settings or get_settings()
    provider, model_name = validate_model_selection(provider, model, settings=s)

    if mock:
        logger.info("LLM factory: returning mock LLM (no token cost)")
        return _make_mock_llm()

    config = get_effective_config(s)
    entry = config.provider_map[provider]
    api_key = entry.resolved_api_key(s)
    base_url = entry.resolved_base_url(s)
    temp = (
        temperature
        if temperature is not None
        else (
            config.temperature
            if config.temperature is not None
            else s.llm_temperature
        )
    )

    if provider == "sangfor" and not (api_key and base_url):
        # ⚠️ 深信服安全 GPT 适配点：平台权限未下发（无 base_url/key）时保持占位。
        # 在模型配置页填入 base_url 和 API Key 后即可通过通用 OpenAI 兼容路径调用。
        raise NotImplementedError(
            "Sangfor Security GPT adapter not yet implemented. "
            "Waiting for platform access (contact the project administrator), "
            "or configure its base_url and API key on the model settings page. "
            "Interface is reserved for compliance — switch provider to "
            "'deepseek' or 'qwen' for now."
        )

    if not api_key:
        raise RuntimeError(
            f"{env_key_hint(provider)} not set. Fill it in .env "
            "(see .env.example), configure it on the model settings page, "
            "or use get_llm(mock=True) for testing."
        )
    if not base_url:
        raise RuntimeError(
            f"Provider {provider!r} has no base_url configured. "
            "Set one on the model settings page."
        )

    client_kwargs: dict[str, Any] = {
        "model": model_name,
        "api_key": api_key,
        "base_url": base_url.rstrip("/"),
        "temperature": temp,
        # Node calls pass the remaining global budget dynamically; this is
        # the client-level fallback for direct/non-graph invocations.
        "timeout": s.react_global_timeout_s,
    }

    if provider == "deepseek":
        # DeepSeek V4 默认开启 thinking 模式，与研判 Prompt 的显式 5 步 CoT
        # 重复，且与 tool_choice/function_calling 有兼容问题，默认关闭。
        client_kwargs["default_headers"] = {"User-Agent": "Mozilla/5.0"}
        if s.deepseek_send_thinking:
            client_kwargs["extra_body"] = {"thinking": {"type": "disabled"}}

    return ChatOpenAI(**client_kwargs)
