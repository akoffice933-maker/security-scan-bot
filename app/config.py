from functools import lru_cache
from typing import Annotated, Any, List

from pydantic import BeforeValidator, Field
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


def _split_ints(value: Any) -> list[int]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [int(x) for x in value]
    if isinstance(value, str):
        return [int(x.strip()) for x in value.split(",") if x.strip()]
    return []


def _split_strs(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(x).strip().lower() for x in value if str(x).strip()]
    if isinstance(value, str):
        return [x.strip().lower() for x in value.split(",") if x.strip()]
    return []


AdminIds = Annotated[List[int], NoDecode, BeforeValidator(_split_ints)]
StrList = Annotated[List[str], NoDecode, BeforeValidator(_split_strs)]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    bot_token: str = ""
    admin_ids: AdminIds = Field(default_factory=list)

    openrouter_api_key: str = ""
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    llm_model: str = "openai/gpt-4o-mini"
    llm_enabled: bool = True

    virustotal_api_key: str = ""

    nuclei_path: str = "nuclei"
    semgrep_path: str = "semgrep"
    trivy_path: str = "trivy"
    clamscan_path: str = "clamscan"
    bandit_path: str = "bandit"
    git_path: str = "git"
    nuclei_templates_dir: str = ""

    allowed_domains: StrList = Field(default_factory=list)
    allowed_ips: StrList = Field(default_factory=list)
    allowed_github_orgs: StrList = Field(default_factory=list)
    allowed_docker_registries: StrList = Field(default_factory=list)
    max_concurrent_scans: int = 2
    scan_timeout_seconds: int = 1800
    max_archive_size_mb: int = 20

    database_url: str = "sqlite+aiosqlite:///./data/bot.db"
    redis_url: str | None = None

    webhook_url: str | None = None
    webhook_path: str = "/webhook"
    webhook_secret: str = ""
    port: int = 8080

    log_level: str = "INFO"
    environment: str = "development"

    reports_dir: str = "./data/reports"
    uploads_dir: str = "./data/uploads"
    work_dir: str = "./data/work"
    scan_tmp_dir: str = "./data/scans"
    disk_warn_percent: int = 85
    scan_tmp_max_age_hours: int = 24

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()


def clear_settings_cache() -> None:
    get_settings.cache_clear()
