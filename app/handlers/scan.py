from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from aiogram import F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from app.config import get_settings
from app.handlers.states import ScanStates
from app.keyboards.menu import (
    BTN_ARCHIVE,
    BTN_DOCKER,
    BTN_REPO,
    BTN_SITE,
    cancel_kb,
    main_menu_kb,
    nuclei_profile_kb,
)
from app.services import history
from app.services.archive import is_allowed_archive
from app.services.policy import allow_image, allow_repo, allow_url
from app.services.queue import enqueue_scan
from app.services.textutil import escape_html

logger = logging.getLogger(__name__)
router = Router(name="scan")


async def _ensure_capacity(message: Message, user_id: int) -> bool:
    settings = get_settings()
    running = await asyncio.to_thread(history.count_running, user_id)
    if running >= settings.max_concurrent_scans:
        await message.answer(
            f"Уже запущено {running} проверок (лимит {settings.max_concurrent_scans}). "
            "Подожди окончания."
        )
        return False
    return True


async def _start_scan(
    message: Message,
    user_id: int,
    scan_type: str,
    target: str,
    options: dict | None = None,
    file_path: str | None = None,
) -> None:
    if not await _ensure_capacity(message, user_id):
        return
    scan_id = await asyncio.to_thread(history.create_scan, user_id, scan_type, target)
    progress = await message.answer(
        f"⏳ Проверка #{scan_id} запущена.\nЦель: <code>{escape_html(target)}</code>\n"
        "Это может занять несколько минут."
    )
    payload = {
        "scan_id": scan_id,
        "user_id": user_id,
        "chat_id": message.chat.id,
        "scan_type": scan_type,
        "target": target,
        "options": options or {},
        "progress_message_id": progress.message_id,
        "file_path": file_path,
    }
    mode = await asyncio.to_thread(enqueue_scan, payload)
    logger.info("enqueued scan %s via %s", scan_id, mode)


@router.message(F.text == BTN_SITE)
async def start_site(message: Message, state: FSMContext) -> None:
    await state.set_state(ScanStates.waiting_url)
    await message.answer(
        "Пришли URL (только http/https и домен из whitelist).\n"
        "Чужие сайты сканировать нельзя.",
        reply_markup=cancel_kb(),
    )


@router.message(ScanStates.waiting_url, F.text)
async def got_url(message: Message, state: FSMContext) -> None:
    url = (message.text or "").strip()
    ok, reason = allow_url(url)
    if not ok:
        await message.answer(f"⛔ {reason}", reply_markup=cancel_kb())
        return
    await state.update_data(url=url)
    await state.set_state(ScanStates.waiting_nuclei_profile)
    await message.answer("Какой профиль Nuclei?", reply_markup=nuclei_profile_kb())


@router.callback_query(ScanStates.waiting_nuclei_profile, F.data.startswith("nuclei_profile:"))
async def got_profile(callback: CallbackQuery, state: FSMContext) -> None:
    await callback.answer()
    profile = (callback.data or "").split(":", 1)[1]
    data = await state.get_data()
    url = data.get("url")
    await state.clear()
    if not url or not callback.message or not callback.from_user:
        return
    await _start_scan(
        callback.message,
        callback.from_user.id,
        "url",
        url,
        options={"profile": profile},
    )


@router.message(F.text == BTN_REPO)
async def start_repo(message: Message, state: FSMContext) -> None:
    await state.set_state(ScanStates.waiting_repo)
    await message.answer(
        "Пришли <code>owner/repo</code> или https://github.com/owner/repo\n"
        "Владелец должен быть в ALLOWED_GITHUB_ORGS.",
        reply_markup=cancel_kb(),
    )


@router.message(ScanStates.waiting_repo, F.text)
async def got_repo(message: Message, state: FSMContext) -> None:
    repo = (message.text or "").strip()
    ok, reason = allow_repo(repo)
    if not ok:
        await message.answer(f"⛔ {reason}", reply_markup=cancel_kb())
        return
    await state.clear()
    if not message.from_user:
        return
    await _start_scan(message, message.from_user.id, "repo", repo)


@router.message(F.text == BTN_DOCKER)
async def start_docker(message: Message, state: FSMContext) -> None:
    await state.set_state(ScanStates.waiting_docker)
    await message.answer(
        "Пришли имя образа, например <code>nginx:1.27</code> или "
        "<code>ghcr.io/myorg/app:latest</code>.\n"
        "Registry должен быть в ALLOWED_DOCKER_REGISTRIES.",
        reply_markup=cancel_kb(),
    )


@router.message(ScanStates.waiting_docker, F.text)
async def got_docker(message: Message, state: FSMContext) -> None:
    image = (message.text or "").strip()
    ok, reason = allow_image(image)
    if not ok:
        await message.answer(f"⛔ {reason}", reply_markup=cancel_kb())
        return
    await state.clear()
    if not message.from_user:
        return
    await _start_scan(message, message.from_user.id, "docker", image)


@router.message(F.text == BTN_ARCHIVE)
async def start_archive(message: Message, state: FSMContext) -> None:
    await state.set_state(ScanStates.waiting_archive)
    settings = get_settings()
    await message.answer(
        f"Пришли zip/tar архив (до {settings.max_archive_size_mb} МБ).\n"
        "Распаковка с защитой от zip-slip. Не загружай чужие исходники.",
        reply_markup=cancel_kb(),
    )


@router.message(ScanStates.waiting_archive, F.document)
async def got_archive(message: Message, state: FSMContext) -> None:
    document = message.document
    if not document or not message.from_user:
        return
    name = document.file_name or "archive.zip"
    if not is_allowed_archive(name):
        await message.answer("Нужен zip или tar-архив.", reply_markup=cancel_kb())
        return
    settings = get_settings()
    max_bytes = settings.max_archive_size_mb * 1024 * 1024
    if (document.file_size or 0) > max_bytes:
        await message.answer(f"Файл больше {settings.max_archive_size_mb} МБ.")
        return
    dest_dir = Path(settings.uploads_dir) / f"upload-{message.from_user.id}-{document.file_unique_id}"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / name
    await message.bot.download(document, destination=dest)
    await state.clear()
    await _start_scan(
        message,
        message.from_user.id,
        "archive",
        name,
        options={"virustotal": bool(settings.virustotal_api_key)},
        file_path=str(dest),
    )


@router.message(ScanStates.waiting_archive)
async def archive_not_file(message: Message) -> None:
    await message.answer("Пришли именно файл-архив, не текст.", reply_markup=cancel_kb())


@router.message(F.text & ~F.text.startswith("/"))
async def unknown_text(message: Message) -> None:
    await message.answer("Не понял. Выбери пункт меню.", reply_markup=main_menu_kb())
