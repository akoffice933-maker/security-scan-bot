import asyncio

from aiogram.types import User

from app.config import clear_settings_cache
from app.middlewares.access import AccessMiddleware


class DummyMessage:
    def __init__(self):
        self.answers: list[str] = []

    async def answer(self, text, **kwargs):
        self.answers.append(text)


def test_empty_admin_ids_denies(monkeypatch):
    monkeypatch.setenv("ADMIN_IDS", "")
    monkeypatch.setenv("BOT_TOKEN", "t")
    clear_settings_cache()
    mw = AccessMiddleware()
    called = {"ok": False}

    async def handler(_event, _data):
        called["ok"] = True

    asyncio.run(
        mw(handler, DummyMessage(), {"event_from_user": User(id=1, is_bot=False, first_name="A")})
    )
    assert called["ok"] is False
    clear_settings_cache()


def test_admin_passes(monkeypatch):
    monkeypatch.setenv("ADMIN_IDS", "42")
    monkeypatch.setenv("BOT_TOKEN", "t")
    clear_settings_cache()
    mw = AccessMiddleware()
    called = {"ok": False}

    async def handler(_event, _data):
        called["ok"] = True

    asyncio.run(
        mw(
            handler,
            DummyMessage(),
            {"event_from_user": User(id=42, is_bot=False, first_name="Admin")},
        )
    )
    assert called["ok"] is True
    clear_settings_cache()


def test_stranger_denied(monkeypatch):
    monkeypatch.setenv("ADMIN_IDS", "42")
    monkeypatch.setenv("BOT_TOKEN", "t")
    clear_settings_cache()
    mw = AccessMiddleware()
    called = {"ok": False}

    async def handler(_event, _data):
        called["ok"] = True

    asyncio.run(
        mw(
            handler,
            DummyMessage(),
            {"event_from_user": User(id=7, is_bot=False, first_name="Nope")},
        )
    )
    assert called["ok"] is False
    clear_settings_cache()
