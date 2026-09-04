from aiogram import Dispatcher

from app.handlers import common, scan


def setup_routers(dp: Dispatcher) -> None:
    dp.include_router(common.router)
    dp.include_router(scan.router)


__all__ = ["common", "scan", "setup_routers"]
