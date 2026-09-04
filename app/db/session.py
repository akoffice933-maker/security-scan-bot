from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings
from app.db.models import Base

logger = logging.getLogger(__name__)

_engine = None
_SessionLocal: sessionmaker | None = None


def to_sync_url(url: str) -> str:
    return (
        url.replace("sqlite+aiosqlite://", "sqlite://")
        .replace("postgresql+asyncpg://", "postgresql+psycopg://")
    )


def _ensure_sqlite_dir(url: str) -> None:
    if not url.startswith("sqlite"):
        return
    # sqlite:////abs or sqlite:///./rel
    path = url.split("sqlite:///", 1)[-1]
    if path in {":memory:", ""}:
        return
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def get_sync_engine():
    global _engine, _SessionLocal
    if _engine is None:
        settings = get_settings()
        url = to_sync_url(settings.database_url)
        _ensure_sqlite_dir(url)
        kwargs: dict = {"echo": False, "future": True}
        if url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
        _engine = create_engine(url, **kwargs)
        if url.startswith("sqlite"):

            @event.listens_for(_engine, "connect")
            def _sqlite_pragmas(dbapi_connection, _connection_record):  # noqa: ANN001
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA busy_timeout=5000")
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()

        _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False, class_=Session)
        logger.info("DB engine ready: %s", url.split("://")[0])
    return _engine


def get_session() -> Session:
    get_sync_engine()
    assert _SessionLocal is not None
    return _SessionLocal()


def reset_engine() -> None:
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None


def init_db_sync() -> None:
    engine = get_sync_engine()
    Base.metadata.create_all(engine)
    settings = get_settings()
    Path(settings.reports_dir).mkdir(parents=True, exist_ok=True)
    Path(settings.uploads_dir).mkdir(parents=True, exist_ok=True)
    Path(settings.work_dir).mkdir(parents=True, exist_ok=True)


async def init_db() -> None:
    await asyncio.to_thread(init_db_sync)
