from __future__ import annotations

import asyncio

from aiogram import F, Router
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from app.keyboards.menu import (
    BTN_HELP,
    BTN_HISTORY,
    after_scan_kb,
    history_kb,
    main_menu_kb,
)
from app.services import history
from app.services.textutil import escape_html, truncate

router = Router(name="common")

WELCOME = (
    "Привет. Я проверяю <b>только твои</b> проекты.\n\n"
    "Сканировать чужие сайты, репозитории и образы — нельзя и, скорее всего, незаконно.\n"
    "Можно: домен из <code>ALLOWED_DOMAINS</code>, IP из <code>ALLOWED_IPS</code> "
    "(или тот же IP в списке доменов), GitHub-орг и Docker-registry из whitelist.\n\n"
    "Выбери, что проверить."
)

HELP = (
    "<b>Как пользоваться</b>\n"
    "• Сайт / IP — Nuclei по URL <b>или по IP</b> из whitelist "
    "(голый адрес, например <code>10.0.0.5</code>, или <code>https://10.0.0.5/</code>)\n"
    "• GitHub — clone + Semgrep + Trivy + Bandit + ClamAV\n"
    "• Архив — распаковка с защитой от zip-slip, те же сканеры\n"
    "• Docker — Trivy image по registry из whitelist\n\n"
    "127.0.0.1 и cloud metadata нельзя даже из списка. Чужие хосты — нельзя.\n"
    "В чат попадают важные находки. Полный отчёт — PDF / HTML / Markdown / JSON.\n"
    "/cancel — отменить текущий шаг."
)


@router.message(CommandStart())
async def cmd_start(message: Message, state: FSMContext) -> None:
    await state.clear()
    await message.answer(WELCOME, reply_markup=main_menu_kb())


@router.message(Command("help"))
@router.message(F.text == BTN_HELP)
async def cmd_help(message: Message) -> None:
    await message.answer(HELP, reply_markup=main_menu_kb())


@router.message(Command("cancel"))
async def cmd_cancel(message: Message, state: FSMContext) -> None:
    await state.clear()
    await message.answer("Отменил. Можно начать заново.", reply_markup=main_menu_kb())


@router.callback_query(F.data == "cancel_scan")
async def cb_cancel(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await callback.answer("Отменено")
    if callback.message:
        await callback.message.answer("Отменил. Можно начать заново.", reply_markup=main_menu_kb())


@router.callback_query(F.data == "back_to_menu")
async def cb_menu(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await callback.answer()
    if callback.message:
        await callback.message.answer("Меню:", reply_markup=main_menu_kb())


@router.message(F.text == BTN_HISTORY)
@router.callback_query(F.data == "show_history")
async def show_history(event: Message | CallbackQuery) -> None:
    user = event.from_user
    if not user:
        return
    rows = await asyncio.to_thread(history.get_user_history, user.id, 10)
    if isinstance(event, CallbackQuery):
        await event.answer()
        message = event.message
    else:
        message = event
    if not message:
        return
    if not rows:
        await message.answer("История пустая.", reply_markup=after_scan_kb())
        return
    items = []
    text_lines = ["<b>Последние проверки</b>"]
    for row in rows:
        label = f"#{row.id} {row.status} {row.scan_type} {truncate(row.target, 40)}"
        items.append((row.id, label))
        text_lines.append(escape_html(label))
    await message.answer("\n".join(text_lines), reply_markup=history_kb(items))


@router.callback_query(F.data.startswith("history:"))
async def cb_history_item(callback: CallbackQuery) -> None:
    await callback.answer()
    try:
        scan_id = int((callback.data or "").split(":", 1)[1])
    except (ValueError, IndexError):
        return
    row = await asyncio.to_thread(history.get_scan, scan_id)
    if not row or not callback.from_user or row.user_id != callback.from_user.id:
        if callback.message:
            await callback.message.answer("Запись не найдена.")
        return
    body = (
        f"<b>Проверка #{row.id}</b>\n"
        f"Тип: {escape_html(row.scan_type)}\n"
        f"Цель: <code>{escape_html(row.target)}</code>\n"
        f"Статус: {escape_html(row.status)}\n\n"
        f"{escape_html(row.summary or 'нет описания')}"
    )
    if callback.message:
        await callback.message.answer(body, reply_markup=after_scan_kb())
