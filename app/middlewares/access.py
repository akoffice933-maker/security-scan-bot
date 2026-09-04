from typing import Any, Awaitable, Callable, Dict

from aiogram import BaseMiddleware
from aiogram.types import TelegramObject, Message

from app.config import get_settings


class AccessMiddleware(BaseMiddleware):
    """Простая проверка: только admin_ids могут использовать бота."""

    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any],
    ) -> Any:
        settings = get_settings()
        if not settings.admin_ids:
            return await handler(event, data)

        user = data.get("event_from_user")
        if user and user.id in settings.admin_ids:
            return await handler(event, data)

        if isinstance(event, Message):
            await event.answer("⛔ У тебя нет доступа к этому боту.")
        return None
