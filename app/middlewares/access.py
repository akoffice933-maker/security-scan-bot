from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable, Dict
import logging

from aiogram import BaseMiddleware
from aiogram.types import CallbackQuery, Message, TelegramObject

from app.config import get_settings

logger = logging.getLogger(__name__)


class AccessMiddleware(BaseMiddleware):
    """Fail-closed: only admin_ids may use the bot. Empty list denies everyone."""

    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any],
    ) -> Any:
        settings = get_settings()
        user = data.get("event_from_user")
        user_id = getattr(user, "id", None)

        if not settings.admin_ids:
            logger.error("ADMIN_IDS is empty — denying user_id=%s (fail-closed)", user_id)
            await self._deny(event, "Бот не настроен: пустой ADMIN_IDS.")
            return None

        if user_id is not None and user_id in settings.admin_ids:
            return await handler(event, data)

        logger.warning("Access denied for user_id=%s", user_id)
        await self._deny(event, "⛔ У тебя нет доступа к этому боту.")
        return None

    @staticmethod
    async def _deny(event: TelegramObject, text: str) -> None:
        if isinstance(event, CallbackQuery):
            await event.answer(text, show_alert=True)
        elif isinstance(event, Message):
            await event.answer(text)
