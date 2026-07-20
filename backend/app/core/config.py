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

    @property
    def data_dir(self) -> Path:
        """数据根目录（datasets、chroma_db 等）"""
        return PROJECT_ROOT / "data"


@lru_cache
def get_settings() -> Settings:
    """单例配置。用 lru_cache 避免重复读 .env。"""
    return Settings()
