"""Disk and queue health. Warns before scans fill the host."""

from __future__ import annotations

import logging
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

from app.config import get_settings

logger = logging.getLogger(__name__)


@dataclass
class HealthStatus:
    disk_free_mb: float
    disk_used_pct: float
    work_dir_mb: float
    reports_dir_mb: float
    scan_tmp_mb: float
    celery_queue: int | None
    ok: bool
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "disk_free_mb": round(self.disk_free_mb, 1),
            "disk_used_pct": round(self.disk_used_pct, 1),
            "work_dir_mb": round(self.work_dir_mb, 1),
            "reports_dir_mb": round(self.reports_dir_mb, 1),
            "scan_tmp_mb": round(self.scan_tmp_mb, 1),
            "celery_queue": self.celery_queue,
            "ok": self.ok,
            "warnings": self.warnings,
        }


def _dir_mb(path: Path) -> float:
    if not path.exists():
        return 0.0
    total = 0
    for item in path.rglob("*"):
        try:
            if item.is_file():
                total += item.stat().st_size
        except OSError:
            continue
    return total / (1024 * 1024)


def celery_depth(redis_url: str | None) -> int | None:
    if not redis_url:
        return None
    try:
        import redis as redis_lib

        client = redis_lib.Redis.from_url(redis_url, socket_timeout=1)
        return int(client.llen("celery"))
    except Exception:
        return None


def collect() -> HealthStatus:
    settings = get_settings()
    work = Path(settings.work_dir)
    reports = Path(settings.reports_dir)
    scan_tmp = Path(settings.scan_tmp_dir)
    usage = shutil.disk_usage(str(work if work.exists() else Path(".")))
    used_pct = (usage.used / usage.total) * 100 if usage.total else 0.0
    free_mb = usage.free / (1024 * 1024)
    warnings: list[str] = []
    if used_pct >= settings.disk_warn_percent:
        warnings.append(f"диск занят на {used_pct:.0f}%")
    if free_mb < 256:
        warnings.append(f"свободно только {free_mb:.0f} МБ")
    queue = celery_depth(settings.redis_url)
    if queue is not None and queue > 20:
        warnings.append(f"очередь Celery: {queue} задач")
    ok = used_pct < 95 and free_mb >= 128
    return HealthStatus(
        disk_free_mb=free_mb,
        disk_used_pct=used_pct,
        work_dir_mb=_dir_mb(work),
        reports_dir_mb=_dir_mb(reports),
        scan_tmp_mb=_dir_mb(scan_tmp),
        celery_queue=queue,
        ok=ok,
        warnings=warnings,
    )


def cleanup_stale(max_age_hours: int | None = None) -> int:
    settings = get_settings()
    hours = max_age_hours if max_age_hours is not None else settings.scan_tmp_max_age_hours
    cutoff = time.time() - hours * 3600
    removed = 0
    for root in (Path(settings.work_dir), Path(settings.scan_tmp_dir), Path(settings.uploads_dir)):
        if not root.exists():
            continue
        for child in root.iterdir():
            try:
                if child.stat().st_mtime < cutoff:
                    if child.is_dir():
                        shutil.rmtree(child, ignore_errors=True)
                    else:
                        child.unlink(missing_ok=True)
                    removed += 1
            except OSError:
                continue
    if removed:
        logger.info("health: removed %s stale scan artifacts", removed)
    return removed


def log_status() -> HealthStatus:
    status = collect()
    if status.warnings:
        logger.warning("health: %s", "; ".join(status.warnings))
    else:
        logger.info(
            "health: disk=%.0f%% free=%.0fMB queue=%s work=%.1fMB tmp=%.1fMB",
            status.disk_used_pct,
            status.disk_free_mb,
            status.celery_queue,
            status.work_dir_mb,
            status.scan_tmp_mb,
        )
    return status
