from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path

import httpx
from tenacity import retry, stop_after_attempt, wait_fixed

from app.config import get_settings
from app.services.findings import Finding, ScanResult

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"


def _headers() -> dict[str, str]:
    key = get_settings().virustotal_api_key
    return {"x-apikey": key, "accept": "application/json"}


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@retry(stop=stop_after_attempt(3), wait=wait_fixed(2), reraise=True)
def _get(path: str) -> httpx.Response:
    with httpx.Client(timeout=30.0) as client:
        return client.get(f"{VT_BASE}{path}", headers=_headers())


def scan_file(path: str | Path, upload_if_unknown: bool = False) -> ScanResult:
    settings = get_settings()
    if not settings.virustotal_api_key:
        return ScanResult(success=True, notes=["VirusTotal не настроен — шаг пропущен"])

    file_path = Path(path)
    digest = sha256_file(file_path)
    result = ScanResult(success=True, stats={"sha256": digest})
    try:
        response = _get(f"/files/{digest}")
    except Exception as exc:  # noqa: BLE001
        logger.warning("VirusTotal lookup failed: %s", exc)
        return ScanResult(success=True, notes=[f"VirusTotal недоступен: {exc}"])

    if response.status_code == 404:
        if not upload_if_unknown:
            result.notes.append("файла нет в VirusTotal (загрузка отключена)")
            return result
        if file_path.stat().st_size > 32 * 1024 * 1024:
            result.notes.append("файл больше 32 МБ — VirusTotal не принимает без premium")
            return result
        return _upload_and_wait(file_path, digest)

    if response.status_code != 200:
        result.notes.append(f"VirusTotal HTTP {response.status_code}")
        return result

    _fill_from_report(result, response.json(), digest)
    return result


def _upload_and_wait(file_path: Path, digest: str) -> ScanResult:
    result = ScanResult(success=True, stats={"sha256": digest})
    try:
        with httpx.Client(timeout=120.0) as client, open(file_path, "rb") as fh:
            uploaded = client.post(
                f"{VT_BASE}/files",
                headers=_headers(),
                files={"file": (file_path.name, fh)},
            )
        if uploaded.status_code not in {200, 201}:
            result.notes.append(f"VirusTotal upload HTTP {uploaded.status_code}")
            return result
        analysis_id = (uploaded.json().get("data") or {}).get("id")
        if not analysis_id:
            result.notes.append("VirusTotal не вернул analysis id")
            return result
        for _ in range(8):
            time.sleep(3)
            report = _get(f"/analyses/{analysis_id}")
            if report.status_code != 200:
                continue
            status = (report.json().get("data") or {}).get("attributes", {}).get("status")
            if status == "completed":
                file_report = _get(f"/files/{digest}")
                if file_report.status_code == 200:
                    _fill_from_report(result, file_report.json(), digest)
                return result
        result.notes.append("VirusTotal: анализ не успел завершиться, проверь хеш позже")
    except Exception as exc:  # noqa: BLE001
        logger.warning("VirusTotal upload failed: %s", exc)
        result.notes.append(f"VirusTotal upload error: {exc}")
    return result


def _fill_from_report(result: ScanResult, payload: dict, digest: str) -> None:
    stats = ((payload.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    result.stats.update({"malicious": malicious, "suspicious": suspicious, "sha256": digest})
    if malicious or suspicious:
        result.findings.append(
            Finding(
                scanner="virustotal",
                severity="critical" if malicious else "high",
                title="VirusTotal detections",
                description=f"malicious={malicious}, suspicious={suspicious}",
                location=digest,
            )
        )
    result.sort()
