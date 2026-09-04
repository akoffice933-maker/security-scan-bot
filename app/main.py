import asyncio
import logging
import sys

from aiohttp import web
from aiogram import Dispatcher
from aiogram.webhook.aiohttp_server import SimpleRequestHandler, setup_application

from app.bot import create_bot, create_dispatcher
from app.config import get_settings
from app.db.session import init_db
from app.handlers import common, scan
from app.middlewares.access import AccessMiddleware


def setup_logging() -> None:
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        stream=sys.stdout,
    )


async def on_startup(bot) -> None:
    await init_db()
    settings = get_settings()
    if settings.environment == "production" and getattr(settings, "webhook_url", None):
        await bot.set_webhook(
            url=settings.webhook_url,
            drop_pending_updates=True,
            allowed_updates=["message", "callback_query"],
        )


async def on_shutdown(bot) -> None:
    settings = get_settings()
    if getattr(settings, "webhook_url", None):
        await bot.delete_webhook()


def main() -> None:
    setup_logging()
    logger = logging.getLogger(__name__)
    settings = get_settings()

    bot = create_bot()
    dp = create_dispatcher()

    dp.message.middleware(AccessMiddleware())
    dp.callback_query.middleware(AccessMiddleware())

    dp.include_router(common.router)
    dp.include_router(scan.router)

    dp.startup.register(on_startup)
    dp.shutdown.register(on_shutdown)

    webhook_url = getattr(settings, "webhook_url", None) or ""
    webhook_path = getattr(settings, "webhook_path", "/webhook")

    if settings.environment == "production" and webhook_url:
        logger.info("Starting in WEBHOOK mode: %s", webhook_url)
        app = web.Application()
        webhook_requests_handler = SimpleRequestHandler(dispatcher=dp, bot=bot)
        webhook_requests_handler.register(app, path=webhook_path)
        setup_application(app, dp, bot=bot)
        web.run_app(app, host="0.0.0.0", port=int(getattr(settings, "port", 8080)))
    else:
        logger.info("Starting in POLLING mode...")
        logger.info("LLM enabled: %s | model: %s", settings.llm_enabled, settings.llm_model)
        asyncio.run(dp.start_polling(bot))


if __name__ == "__main__":
    main()
