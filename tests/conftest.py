from __future__ import annotations

import os

os.environ.setdefault("BOT_TOKEN", "123456:TESTTOKEN")
os.environ.setdefault("ADMIN_IDS", "111")
os.environ.setdefault("ALLOWED_DOMAINS", "example.com,myproject.dev,localhost,127.0.0.1")
os.environ.setdefault("ALLOWED_GITHUB_ORGS", "myusername,myorg")
os.environ.setdefault("ALLOWED_DOCKER_REGISTRIES", "docker.io,ghcr.io,localhost")
os.environ.setdefault("LLM_ENABLED", "false")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

import pytest

from app.config import clear_settings_cache
from app.db.session import init_db_sync, reset_engine


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path}/test.db")
    clear_settings_cache()
    reset_engine()
    init_db_sync()
    yield
    reset_engine()
    clear_settings_cache()
