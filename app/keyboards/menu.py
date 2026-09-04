from aiogram.types import (
    InlineKeyboardMarkup,
    InlineKeyboardButton,
    ReplyKeyboardMarkup,
    KeyboardButton,
)


def main_menu_kb() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="🔍 Проверить сайт")],
            [KeyboardButton(text="📁 Проверить код (GitHub)")],
            [KeyboardButton(text="📦 Проверить архив с кодом")],
            [KeyboardButton(text="🐳 Проверить Docker-образ")],
            [KeyboardButton(text="📜 Мои проверки"), KeyboardButton(text="❓ Помощь")],
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
        inline_keyboard=[
            [InlineKeyboardButton(text="« Отмена", callback_data="cancel_scan")]
        ]
    )
