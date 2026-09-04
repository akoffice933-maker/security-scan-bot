"""High-level scan orchestration for URL / repo / archive / docker."""

from __future__ import annotations

import logging
import shutil
import tempfile
from pathlib import Path

from app.config import get_settings
from app.services import scanners, virustotal
from app.services.archive import extract_archive
from app.services.findings import Finding, ScanResult
from app.services.policy import allow_image, allow_repo, allow_url, parse_github_repo
from app.services.sandbox import run_cmd

logger = logging.getLogger(__name__)


def _merge(parts: list[ScanResult]) -> ScanResult:
    merged = ScanResult(success=True)
    for part in parts:
        merged.findings.extend(part.findings)
        merged.notes.extend(part.notes)
        merged.stats.update(part.stats)
        if part.error:
            merged.notes.append(part.error)
        if not part.success and part.error:
            # one missing optional scanner shouldn't fail the whole job
            if part.error and "не установлен" not in part.error:
                merged.success = merged.success and part.success
    merged.sort()
    merged.stats["total"] = len(merged.findings)
    merged.stats["important"] = len(merged.important())
    return merged


def scan_url(url: str, profile: str = "cve") -> ScanResult:
    ok, reason = allow_url(url)
    if not ok:
        return ScanResult(success=False, error=reason)
    timeout = get_settings().scan_timeout_seconds
    return scanners.scan_nuclei(url, profile=profile, timeout=timeout)


def scan_repo(repo: str) -> ScanResult:
    ok, reason = allow_repo(repo)
    if not ok:
        return ScanResult(success=False, error=reason)
    parsed = parse_github_repo(repo)
    if not parsed:
        return ScanResult(success=False, error="некорректный репозиторий")
    owner, name = parsed
    clone_url = f"https://github.com/{owner}/{name}.git"
    settings = get_settings()
    Path(settings.work_dir).mkdir(parents=True, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="repo-", dir=settings.work_dir)
    try:
        git = run_cmd(
            [settings.git_path, "clone", "--depth", "1", "--single-branch", "--", clone_url, tmp],
            timeout=min(300, settings.scan_timeout_seconds),
        )
        if git.not_found:
            return ScanResult(success=False, error="git не установлен")
        if git.returncode != 0:
            return ScanResult(
                success=False,
                error=f"git clone не удался: {(git.stderr or git.stdout)[:400]}",
            )
        return _scan_workdir(tmp, remaining=settings.scan_timeout_seconds)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def scan_archive(archive_path: str, with_virustotal: bool = False) -> ScanResult:
    settings = get_settings()
    path = Path(archive_path)
    if not path.is_file():
        return ScanResult(success=False, error="файл архива не найден")
    max_bytes = settings.max_archive_size_mb * 1024 * 1024
    if path.stat().st_size > max_bytes:
        return ScanResult(success=False, error=f"архив больше {settings.max_archive_size_mb} МБ")
    Path(settings.work_dir).mkdir(parents=True, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="arch-", dir=settings.work_dir)
    try:
        extract_archive(path, tmp)
        parts = [_scan_workdir(tmp, remaining=settings.scan_timeout_seconds)]
        if with_virustotal:
            parts.append(virustotal.scan_file(path, upload_if_unknown=False))
        return _merge(parts)
    except Exception as exc:  # noqa: BLE001
        return ScanResult(success=False, error=str(exc))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def scan_docker(image: str) -> ScanResult:
    ok, reason = allow_image(image)
    if not ok:
        return ScanResult(success=False, error=reason)
    timeout = get_settings().scan_timeout_seconds
    return scanners.scan_trivy_image(image, timeout=timeout)


def scan_file_virustotal(path: str) -> ScanResult:
    file_path = Path(path)
    if not file_path.is_file():
        return ScanResult(success=False, error="файл не найден")
    # local hash lookup only — never auto-upload from MCP without an explicit flag
    return virustotal.scan_file(file_path, upload_if_unknown=False)


def _scan_workdir(workdir: str, remaining: int) -> ScanResult:
    slice_timeout = max(60, remaining // 3)
    parts = [
        scanners.scan_semgrep(workdir, timeout=slice_timeout),
        scanners.scan_trivy_fs(workdir, timeout=slice_timeout),
        scanners.scan_bandit(workdir, timeout=min(120, slice_timeout)),
        scanners.scan_clamav(workdir, timeout=min(180, slice_timeout)),
    ]
    return _merge(parts)


def empty_result_with_note(note: str) -> ScanResult:
    return ScanResult(success=True, notes=[note], findings=[Finding(
        scanner="system",
        severity="info",
        title="no-op",
        description=note,
    )])
