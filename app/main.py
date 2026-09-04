from __future__ import annotations

import asyncio
import logging
import sys

from aiohttp import web
from aiogram.webhook.aiohttp_server import SimpleRequestHandler, setup_application

from app.bot import create_bot, create_dispatcher
from app.config import get_settings
from app.db.session import init_db
from app.handlers import setup_routers
from app.middlewares.access import AccessMiddleware

logger = logging.getLogger(__name__)


def setup_logging() -> None:
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        stream=sys.stdout,
    )


def validate_bot_settings() -> None:
    settings = get_settings()
    if not settings.bot_token:
        raise SystemExit("BOT_TOKEN is required")
    if not settings.admin_ids:
        raise SystemExit("ADMIN_IDS is empty — refusing to start (fail-closed)")
    if settings.is_production:
        if not settings.allowed_domains and not settings.allowed_github_orgs:
            raise SystemExit("production requires a non-empty whitelist")
        if settings.webhook_url and not settings.webhook_secret:
            raise SystemExit("WEBHOOK_SECRET is required in production webhook mode")


async def on_startup(bot) -> None:  # noqa: ANN001
    await init_db()
    settings = get_settings()
    if settings.is_production and settings.webhook_url:
        kwargs = {
            "url": settings.webhook_url,
            "drop_pending_updates": True,
            "allowed_updates": ["message", "callback_query"],
        }
        if settings.webhook_secret:
            kwargs["secret_token"] = settings.webhook_secret
        await bot.set_webhook(**kwargs)


async def on_shutdown(bot) -> None:  # noqa: ANN001
    settings = get_settings()
    if settings.webhook_url:
        await bot.delete_webhook()
    await bot.session.close()


def main() -> None:
    setup_logging()
    validate_bot_settings()
    settings = get_settings()

    bot = create_bot()
    dp = create_dispatcher()
    dp.message.middleware(AccessMiddleware())
    dp.callback_query.middleware(AccessMiddleware())
    setup_routers(dp)
    dp.startup.register(on_startup)
    dp.shutdown.register(on_shutdown)

    if settings.is_production and settings.webhook_url:
        logger.info("Starting in WEBHOOK mode: %s", settings.webhook_url)
        app = web.Application()
        handler = SimpleRequestHandler(
            dispatcher=dp,
            bot=bot,
            secret_token=settings.webhook_secret or None,
        )
        handler.register(app, path=settings.webhook_path)
        setup_application(app, dp, bot=bot)
        web.run_app(app, host="0.0.0.0", port=int(settings.port))
    else:
        logger.info("Starting in POLLING mode...")
        logger.info("LLM enabled: %s | model: %s", settings.llm_enabled, settings.llm_model)
        asyncio.run(dp.start_polling(bot, allowed_updates=["message", "callback_query"]))


if __name__ == "__main__":
    main()
