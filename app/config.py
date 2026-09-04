from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    bot_token: str
    admin_ids: List[int] = Field(default_factory=list)

    openrouter_api_key: str = ""
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    llm_model: str = "openai/gpt-4o-mini"
    llm_enabled: bool = True

    virustotal_api_key: str = ""

    nuclei_path: str = "nuclei"
    semgrep_path: str = "semgrep"
    trivy_path: str = "trivy"
    nuclei_templates_dir: str = "~/nuclei-templates"

    allowed_domains: List[str] = Field(default_factory=list)
    allowed_github_orgs: List[str] = Field(default_factory=list)
    max_concurrent_scans: int = 2
    scan_timeout_seconds: int = 1800

    database_url: str = "sqlite+aiosqlite:///./data/bot.db"
    redis_url: str | None = None

    webhook_url: str | None = None
    webhook_path: str = "/webhook"
    port: int = 8080

    log_level: str = "INFO"
    environment: str = "development"

    @field_validator("admin_ids", mode="before")
    @classmethod
    def parse_admin_ids(cls, v):
        if isinstance(v, str):
            return [int(x.strip()) for x in v.split(",") if x.strip()]
        return v or []

    @field_validator("allowed_domains", "allowed_github_orgs", mode="before")
    @classmethod
    def parse_list(cls, v):
        if isinstance(v, str):
            return [x.strip().lower() for x in v.split(",") if x.strip()]
        return v or []


@lru_cache
def get_settings() -> Settings:
    return Settings()
