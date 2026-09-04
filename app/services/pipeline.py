from __future__ import annotations

import json
import logging
from pathlib import Path

from app.config import get_settings
from app.services import audit, health, history, scanner
from app.services.findings import ScanResult
from app.services.export import export_all_formats
from app.services.llm import summarize_sync
from app.services.notify import format_chat_report, notify_sync
from app.services.policy import allow_scan
from app.services.textutil import mask_secrets

logger = logging.getLogger(__name__)


def execute_scan(payload: dict) -> dict:
    scan_id = int(payload["scan_id"])
    scan_type = str(payload["scan_type"])
    target = str(payload["target"])
    user_id = int(payload.get("user_id") or 0)
    chat_id = payload.get("chat_id")
    options = payload.get("options") or {}
    progress_message_id = payload.get("progress_message_id")
    file_path = payload.get("file_path")

    ok, reason = allow_scan(scan_type, target)
    if not ok:
        history.finish_scan(scan_id, "denied", summary=reason)
        audit.write_event(user_id, "scan_denied", scan_type, target, scan_id, reason)
        notify_sync(
            chat_id,
            f"⛔ Сканирование отклонено: {reason}",
            message_id=progress_message_id,
        )
        return {"status": "denied", "reason": reason}

    status = health.log_status()
    health.cleanup_stale()
    if not status.ok:
        reason = "диск переполнен — скан отклонён"
        history.finish_scan(scan_id, "failed", summary=reason)
        audit.write_event(user_id, "scan_failed", scan_type, target, scan_id, reason)
        notify_sync(chat_id, f"⛔ {reason}", message_id=progress_message_id)
        return {"status": "failed", "reason": reason}

    try:
        result = _dispatch(scan_type, target, options, file_path)
        summary = summarize_sync(result, scan_type, target)
        status = "completed" if result.success else "failed"
        raw = mask_secrets(json.dumps(result.to_dict(), ensure_ascii=False))
        history.finish_scan(scan_id, status, raw_report=raw, summary=summary)
        audit.write_event(
            user_id,
            "scan_completed" if status == "completed" else "scan_failed",
            scan_type,
            target,
            scan_id,
            f"findings={len(result.findings)} status={status}",
        )

        settings = get_settings()
        out_dir = Path(settings.reports_dir) / f"scan-{scan_id}"
        files = export_all_formats(scan_id, scan_type, target, result, summary, out_dir)

        important_lines = [
            f"[{f.severity}] {f.scanner}: {f.title}"
            for f in result.important()
        ]
        text = format_chat_report(summary, important_lines)
        notify_sync(
            chat_id,
            text,
            files=list(files.values()),
            message_id=progress_message_id,
        )
        _cleanup_upload(file_path)
        return {"status": status, "findings": len(result.findings)}
    except Exception as exc:
        logger.exception("scan %s failed", scan_id)
        history.finish_scan(scan_id, "failed", summary=str(exc)[:1000])
        audit.write_event(user_id, "scan_failed", scan_type, target, scan_id, str(exc)[:1000])
        notify_sync(
            chat_id,
            f"❌ Проверка сломалась: {exc}",
            message_id=progress_message_id,
        )
        return {"status": "failed", "error": str(exc)}


def _dispatch(scan_type: str, target: str, options: dict, file_path: str | None) -> ScanResult:
    if scan_type == "url":
        return scanner.scan_url(target, profile=options.get("profile") or "cve")
    if scan_type in {"repo", "github"}:
        return scanner.scan_repo(target)
    if scan_type == "archive":
        if not file_path:
            return ScanResult(success=False, error="нет файла архива")
        return scanner.scan_archive(file_path, with_virustotal=bool(options.get("virustotal")))
    if scan_type in {"docker", "image"}:
        return scanner.scan_docker(target)
    if scan_type == "file_vt":
        if not file_path:
            return ScanResult(success=False, error="нет файла")
        return scanner.scan_file_virustotal(file_path)
    return ScanResult(success=False, error=f"unknown scan type {scan_type}")


def _cleanup_upload(file_path: str | None) -> None:
    if not file_path:
        return
    path = Path(file_path)
    try:
        if path.is_file():
            path.unlink()
        if path.parent.is_dir() and path.parent.name.startswith("upload-"):
            path.parent.rmdir()
    except OSError:
        logger.warning("failed to cleanup %s", path)
