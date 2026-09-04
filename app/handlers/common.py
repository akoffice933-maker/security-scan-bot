from aiogram import Router, F
from aiogram.filters import Command, CommandStart
from aiogram.types import Message, CallbackQuery
from aiogram.fsm.context import FSMContext

from app.config import get_settings
from app.keyboards.menu import main_menu_kb

router = Router(name="common")


WELCOME_TEXT = """
🛡 <b>Привет! Я бот для проверки безопасности твоих проектов.</b>

Я умею находить:
• уязвимости на сайтах
• проблемы и слабые места в коде
• <b>вирусы и вредоносное ПО</b> (ClamAV + VirusTotal)
• случайно оставленные пароли и ключи
• ошибки в Docker и конфигурациях

<b>Как это работает:</b>
1. Выбираешь, что проверить
2. Отправляешь ссылку или файл
3. Я всё проверяю и объясняю простым языком
4. Присылаю понятный отчёт

Нажимай кнопки ниже — я подскажу каждый шаг.
""".strip()


HELP_TEXT = """
❓ <b>Как пользоваться ботом</b>

🔍 <b>Проверить сайт</b>
Проверка на известные уязвимости и ошибки настройки.

📁 <b>Проверить код (GitHub)</b> и 📦 <b>Архив</b>
• вирусы (ClamAV + VirusTotal)
• уязвимости в коде
• секреты (пароли, токены)
• ошибки конфигурации

🐳 <b>Проверить Docker-образ</b>
Поиск известных уязвимостей в образе.

После проверки ты получишь:
• простое объяснение результатов
• только важные находки
• подробные отчёты (PDF, HTML и др.)

Проверяй только <b>свои</b> проекты.
""".strip()


@router.message(CommandStart())
async def cmd_start(message: Message, state: FSMContext) -> None:
    await state.clear()
    await message.answer(WELCOME_TEXT, reply_markup=main_menu_kb())


@router.message(F.text.in_({"❓ Помощь", "помощь", "Помощь", "/help"}))
@router.message(Command("help"))
async def cmd_help(message: Message, state: FSMContext) -> None:
    await state.clear()
    await message.answer(HELP_TEXT, reply_markup=main_menu_kb())


@router.message(Command("status"))
async def cmd_status(message: Message) -> None:
    settings = get_settings()
    text = (
        "🤖 Бот работает.\n\n"
        f"Умный анализ: {'включён' if settings.llm_enabled else 'выключен'}\n"
        "Можешь начинать проверку кнопками ниже."
    )
    await message.answer(text, reply_markup=main_menu_kb())


@router.callback_query(F.data == "back_to_menu")
async def back_to_menu(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await callback.message.answer("Выбери, что хочешь проверить:", reply_markup=main_menu_kb())
    await callback.answer()
