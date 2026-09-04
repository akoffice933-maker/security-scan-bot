from __future__ import annotations

import logging
import threading

from app.config import get_settings

logger = logging.getLogger(__name__)


def enqueue_scan(payload: dict) -> str:
    """Queue via Celery when Redis is configured, otherwise a daemon thread."""
    settings = get_settings()
    if settings.redis_url:
        try:
            from app.tasks.scan_tasks import run_scan

            run_scan.delay(payload)
            return "celery"
        except Exception:
            logger.exception("Celery enqueue failed, falling back to thread")

    from app.services.pipeline import execute_scan

    thread = threading.Thread(
        target=execute_scan,
        args=(payload,),
        name=f"scan-{payload.get('scan_id')}",
        daemon=True,
    )
    thread.start()
    return "thread"
