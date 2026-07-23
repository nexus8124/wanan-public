"""应用配置：从 .env 读取，pydantic-settings 校验。

赛题贴合：
- "基于深信服 AI 安全平台" → Settings 预留 sangfor 相关字段
- "可正常运行" → 统一配置入口，方便部署
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/ 目录（pyproject.toml 所在）
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
# 项目根目录（含 README.md、.env）
PROJECT_ROOT = BACKEND_DIR.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ----- LLM Providers -----
    deepseek_api_key: str = Field(default="", alias="DEEPSEEK_API_KEY")
    deepseek_base_url: str = Field(
    default="https://api.deepseek.com",
    alias="DEEPSEEK_BASE_URL",
    )
    deepseek_send_thinking: bool = Field(
    default=False,
    alias="DEEPSEEK_SEND_THINKING",
    )
    qwen_api_key: str = Field(default="", alias="QWEN_API_KEY")
    sangfor_api_key: str = Field(default="", alias="SANGFOR_API_KEY")
    sangfor_base_url: str = Field(default="", alias="SANGFOR_BASE_URL")

    # ----- LLM 调用参数 -----
    llm_provider: str = Field(default="deepseek", alias="LLM_PROVIDER")
    llm_model: str = Field(default="", alias="LLM_MODEL")
    llm_temperature: float = Field(default=0.1, alias="LLM_TEMPERATURE")

    # ----- 应用 -----
    app_env: str = Field(default="dev", alias="APP_ENV")
    app_port: int = Field(default=8000, alias="APP_PORT")
    eval_dataset_path: str = Field(default="", alias="EVAL_DATASET_PATH")

    # ----- ReAct 执行护栏（第二阶段） -----
    react_max_steps: int = Field(default=3, ge=1, le=10, alias="REACT_MAX_STEPS")
    react_tool_timeout_s: float = Field(
        default=10.0, gt=0, le=120, alias="REACT_TOOL_TIMEOUT_S"
    )
    react_global_timeout_s: float = Field(
        default=120.0, gt=0, le=900, alias="REACT_GLOBAL_TIMEOUT_S"
    )
    react_tool_retries: int = Field(
        default=1, ge=0, le=3, alias="REACT_TOOL_RETRIES"
    )
    react_max_llm_calls: int = Field(
        default=5, ge=1, le=20, alias="REACT_MAX_LLM_CALLS"
    )
    react_max_estimated_tokens: int = Field(
        default=30_000, ge=1000, alias="REACT_MAX_ESTIMATED_TOKENS"
    )
    react_max_no_evidence: int = Field(
        default=2, ge=1, le=10, alias="REACT_MAX_NO_EVIDENCE"
    )

    @property
    def data_dir(self) -> Path:
        """数据根目录（datasets、chroma_db 等）"""
        return PROJECT_ROOT / "data"


@lru_cache
def get_settings() -> Settings:
    """单例配置。用 lru_cache 避免重复读 .env。"""
    return Settings()
