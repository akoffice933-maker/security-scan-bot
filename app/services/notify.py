from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from app.config import get_settings
from app.keyboards.menu import after_scan_kb
from app.services.textutil import escape_html, split_message

logger = logging.getLogger(__name__)


async def _notify(
    chat_id: int,
    text: str,
    files: list[Path] | None = None,
    message_id: int | None = None,
) -> None:
    from aiogram import Bot
    from aiogram.client.default import DefaultBotProperties
    from aiogram.enums import ParseMode
    from aiogram.types import FSInputFile

    settings = get_settings()
    if not settings.bot_token or not chat_id:
        return
    bot = Bot(
        token=settings.bot_token,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    try:
        chunks = split_message(text)
        first = chunks[0]
        if message_id:
            try:
                await bot.edit_message_text(
                    chat_id=chat_id,
                    message_id=message_id,
                    text=first,
                    reply_markup=after_scan_kb(),
                )
            except Exception:
                await bot.send_message(
                    chat_id, first, reply_markup=after_scan_kb()
                )
        else:
            await bot.send_message(chat_id, first, reply_markup=after_scan_kb())
        for chunk in chunks[1:]:
            await bot.send_message(chat_id, chunk)
        for path in files or []:
            if path.is_file():
                await bot.send_document(chat_id, FSInputFile(path))
    except Exception:
        logger.exception("Failed to notify chat_id=%s", chat_id)
    finally:
        await bot.session.close()


def notify_sync(
    chat_id: int | None,
    text: str,
    files: list[Path] | None = None,
    message_id: int | None = None,
) -> None:
    if not chat_id:
        return
    asyncio.run(_notify(chat_id, text, files=files, message_id=message_id))


def format_chat_report(summary: str, important_lines: list[str]) -> str:
    parts = ["<b>Результат проверки</b>", "", escape_html(summary)]
    if important_lines:
        parts.append("")
        parts.append("<b>Важные находки</b>")
        for line in important_lines[:15]:
            parts.append("• " + escape_html(line))
    return "\n".join(parts)
