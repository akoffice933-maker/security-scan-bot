from __future__ import annotations

from app.celery_app import celery_app


@celery_app.task(name="app.tasks.scan_tasks.run_scan")
def run_scan(payload: dict) -> dict:
    from app.services.pipeline import execute_scan

    return execute_scan(payload)
