from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.fsm.storage.memory import MemoryStorage

from app.config import get_settings


def create_bot() -> Bot:
    settings = get_settings()
    if not settings.bot_token:
        raise RuntimeError("BOT_TOKEN is required to start the Telegram bot")
    return Bot(
        token=settings.bot_token,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )


def create_dispatcher() -> Dispatcher:
    settings = get_settings()
    if settings.redis_url:
        try:
            from aiogram.fsm.storage.redis import RedisStorage

            return Dispatcher(storage=RedisStorage.from_url(settings.redis_url))
        except Exception:
            pass
    return Dispatcher(storage=MemoryStorage())
