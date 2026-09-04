from aiogram.types import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    KeyboardButton,
    ReplyKeyboardMarkup,
)

BTN_SITE = "🔍 Проверить сайт / IP"
BTN_REPO = "📁 Проверить код (GitHub)"
BTN_ARCHIVE = "📦 Проверить архив с кодом"
BTN_DOCKER = "🐳 Проверить Docker-образ"
BTN_HISTORY = "📜 Мои проверки"
BTN_HELP = "❓ Помощь"


def main_menu_kb() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text=BTN_SITE)],
            [KeyboardButton(text=BTN_REPO)],
            [KeyboardButton(text=BTN_ARCHIVE)],
            [KeyboardButton(text=BTN_DOCKER)],
            [KeyboardButton(text=BTN_HISTORY), KeyboardButton(text=BTN_HELP)],
        ],
        resize_keyboard=True,
        input_field_placeholder="Выбери, что хочешь проверить",
    )


def nuclei_profile_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🔥 Известные уязвимости (CVE)", callback_data="nuclei_profile:cve")],
            [InlineKeyboardButton(text="⚙️ Ошибки настройки", callback_data="nuclei_profile:misconfig")],
            [InlineKeyboardButton(text="📂 Утечки и открытые панели", callback_data="nuclei_profile:exposures")],
            [InlineKeyboardButton(text="🌐 Полная проверка", callback_data="nuclei_profile:all")],
            [InlineKeyboardButton(text="« Назад", callback_data="cancel_scan")],
        ]
    )


def after_scan_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🔄 Проверить что-то ещё", callback_data="back_to_menu")],
            [InlineKeyboardButton(text="📜 История проверок", callback_data="show_history")],
        ]
    )


def cancel_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text="« Отмена", callback_data="cancel_scan")]]
    )


def history_kb(items: list[tuple[int, str]]) -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton(text=label[:60], callback_data=f"history:{scan_id}")]
        for scan_id, label in items
    ]
    rows.append([InlineKeyboardButton(text="« Меню", callback_data="back_to_menu")])
    return InlineKeyboardMarkup(inline_keyboard=rows)
