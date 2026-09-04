from typing import Any, Awaitable, Callable, Dict
import logging

from aiogram import BaseMiddleware
from aiogram.types import TelegramObject, Message, CallbackQuery

from app.config import get_settings

logger = logging.getLogger(__name__)


class AccessMiddleware(BaseMiddleware):
    """Fail-closed: only ADMIN_IDS may use the bot. Empty list = deny all."""

    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any],
    ) -> Any:
        settings = get_settings()
        user = data.get("event_from_user")

        if not settings.admin_ids:
            logger.error("ADMIN_IDS is empty — denying all access (fail-closed)")
            if isinstance(event, Message):
                await event.answer("⛔ Бот не настроен: ADMIN_IDS пуст.")
            elif isinstance(event, CallbackQuery):
                await event.answer("Бот не настроен", show_alert=True)
            return None

        if user and user.id in settings.admin_ids:
            return await handler(event, data)

        logger.warning("Access denied for user_id=%s", getattr(user, "id", None))
        if isinstance(event, Message):
            await event.answer("⛔ У тебя нет доступа к этому боту.")
        elif isinstance(event, CallbackQuery):
            await event.answer("Нет доступа", show_alert=True)
        return None
