"""Wrappers around Nuclei, Semgrep, Trivy, ClamAV, Bandit. No shell=True."""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path

from app.config import get_settings
from app.services.findings import Finding, ScanResult, normalize_severity
from app.services.sandbox import run_cmd

logger = logging.getLogger(__name__)

NUCLEI_TAGS = {
    "cve": ["cve"],
    "misconfig": ["misconfig", "misconfiguration"],
    "exposures": ["exposure", "panel"],
    "all": [],
}


def tool_available(path: str) -> bool:
    return shutil.which(path) is not None


def capabilities() -> dict[str, bool]:
    s = get_settings()
    return {
        "nuclei": tool_available(s.nuclei_path),
        "semgrep": tool_available(s.semgrep_path),
        "trivy": tool_available(s.trivy_path),
        "clamav": tool_available(s.clamscan_path),
        "bandit": tool_available(s.bandit_path),
        "git": tool_available(s.git_path),
        "virustotal": bool(s.virustotal_api_key),
        "llm": bool(s.llm_enabled and s.openrouter_api_key),
    }


def _budget(remaining: int, default: int = 120) -> int:
    return max(30, min(remaining, default))


def scan_nuclei(url: str, profile: str, timeout: int) -> ScanResult:
    s = get_settings()
    if not tool_available(s.nuclei_path):
        return ScanResult(success=False, error="Nuclei не установлен", notes=["nuclei not found"])
    argv = [
        s.nuclei_path,
        "-u",
        url,
        "-jsonl",
        "-silent",
        "-nc",
        "-severity",
        "critical,high,medium,low",
        "-timeout",
        "10",
        "-retries",
        "1",
    ]
    tags = NUCLEI_TAGS.get(profile, NUCLEI_TAGS["cve"])
    if tags:
        argv.extend(["-tags", ",".join(tags)])
    templates = (s.nuclei_templates_dir or "").replace("~", "")
    if templates and Path(templates).expanduser().exists():
        argv.extend(["-t", str(Path(templates).expanduser())])

    proc = run_cmd(argv, timeout=timeout)
    result = ScanResult(success=not proc.not_found and not proc.timed_out)
    if proc.not_found:
        result.error = "Nuclei не найден"
        return result
    if proc.timed_out:
        result.notes.append("Nuclei превысил таймаут, показаны частичные результаты")
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = item.get("info") or {}
        result.findings.append(
            Finding(
                scanner="nuclei",
                severity=normalize_severity(info.get("severity")),
                title=str(info.get("name") or info.get("id") or "nuclei finding"),
                description=str(info.get("description") or "")[:2000],
                location=str(item.get("matched-at") or item.get("host") or url),
                extra={"template": info.get("id") or item.get("template-id")},
            )
        )
    if proc.returncode not in {0, 1} and not result.findings:
        result.success = False
        result.error = (proc.stderr or "nuclei failed")[:500]
    result.sort()
    result.stats["nuclei"] = len(result.findings)
    return result


def scan_semgrep(target: str, timeout: int) -> ScanResult:
    s = get_settings()
    if not tool_available(s.semgrep_path):
        return ScanResult(success=True, notes=["Semgrep не установлен — шаг пропущен"])
    argv = [
        s.semgrep_path,
        "scan",
        "--config",
        "p/ci",
        "--json",
        "--quiet",
        "--metrics=off",
        "--disable-version-check",
        target,
    ]
    proc = run_cmd(argv, timeout=timeout)
    result = ScanResult(success=True)
    if proc.timed_out:
        result.notes.append("Semgrep превысил таймаут")
    payload = {}
    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        result.notes.append("Semgrep вернул не-JSON")
    for item in payload.get("results") or []:
        extra = item.get("extra") or {}
        result.findings.append(
            Finding(
                scanner="semgrep",
                severity=normalize_severity(extra.get("severity")),
                title=str(item.get("check_id") or "semgrep"),
                description=str(extra.get("message") or "")[:2000],
                location=f"{item.get('path', '')}:{item.get('start', {}).get('line', '')}",
            )
        )
    result.sort()
    result.stats["semgrep"] = len(result.findings)
    return result


def scan_bandit(target: str, timeout: int) -> ScanResult:
    s = get_settings()
    if not tool_available(s.bandit_path):
        return ScanResult(success=True, notes=["Bandit не установлен — шаг пропущен"])
    py_files = list(Path(target).rglob("*.py"))
    if not py_files:
        return ScanResult(success=True, notes=["Python-файлов нет, Bandit пропущен"])
    argv = [s.bandit_path, "-r", target, "-f", "json", "-q"]
    tests_dir = Path(target) / "tests"
    if tests_dir.is_dir():
        argv.extend(["-x", str(tests_dir)])
    proc = run_cmd(argv, timeout=timeout)
    result = ScanResult(success=True)
    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return result
    for item in payload.get("results") or []:
        result.findings.append(
            Finding(
                scanner="bandit",
                severity=normalize_severity(item.get("issue_severity")),
                title=str(item.get("test_id") or item.get("test_name") or "bandit"),
                description=str(item.get("issue_text") or "")[:2000],
                location=f"{item.get('filename', '')}:{item.get('line_number', '')}",
            )
        )
    result.sort()
    result.stats["bandit"] = len(result.findings)
    return result


def scan_trivy_fs(target: str, timeout: int) -> ScanResult:
    s = get_settings()
    if not tool_available(s.trivy_path):
        return ScanResult(success=True, notes=["Trivy не установлен — шаг пропущен"])
    argv = [
        s.trivy_path,
        "fs",
        "--format",
        "json",
        "--quiet",
        "--scanners",
        "vuln,secret,misconfig",
        target,
    ]
    return _parse_trivy(run_cmd(argv, timeout=timeout), label="trivy-fs")


def scan_trivy_image(image: str, timeout: int) -> ScanResult:
    s = get_settings()
    if not tool_available(s.trivy_path):
        return ScanResult(success=False, error="Trivy не установлен")
    argv = [
        s.trivy_path,
        "image",
        "--format",
        "json",
        "--quiet",
        image,
    ]
    return _parse_trivy(run_cmd(argv, timeout=timeout), label="trivy-image")


def _parse_trivy(proc, label: str) -> ScanResult:
    result = ScanResult(success=not proc.not_found)
    if proc.not_found:
        result.error = "Trivy не найден"
        return result
    if proc.timed_out:
        result.notes.append("Trivy превысил таймаут")
    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        result.notes.append("Trivy вернул не-JSON")
        if proc.returncode not in {0, 1}:
            result.success = False
            result.error = (proc.stderr or "trivy failed")[:500]
        return result
    for block in payload.get("Results") or []:
        target = block.get("Target") or ""
        for vuln in block.get("Vulnerabilities") or []:
            result.findings.append(
                Finding(
                    scanner=label,
                    severity=normalize_severity(vuln.get("Severity")),
                    title=str(vuln.get("VulnerabilityID") or vuln.get("Title") or "CVE"),
                    description=str(vuln.get("Title") or vuln.get("Description") or "")[:2000],
                    location=f"{target} {vuln.get('PkgName', '')}@{vuln.get('InstalledVersion', '')}".strip(),
                )
            )
        for secret in block.get("Secrets") or []:
            result.findings.append(
                Finding(
                    scanner=label,
                    severity=normalize_severity(secret.get("Severity") or "high"),
                    title=str(secret.get("Title") or secret.get("RuleID") or "secret"),
                    description="Найден секрет (значение скрыто)",
                    location=f"{target}:{secret.get('StartLine', '')}",
                )
            )
        for mis in block.get("Misconfigurations") or []:
            result.findings.append(
                Finding(
                    scanner=label,
                    severity=normalize_severity(mis.get("Severity")),
                    title=str(mis.get("ID") or mis.get("Title") or "misconfig"),
                    description=str(mis.get("Title") or "")[:2000],
                    location=target,
                )
            )
    result.sort()
    result.stats[label] = len(result.findings)
    return result


def scan_clamav(target: str, timeout: int) -> ScanResult:
    s = get_settings()
    if not tool_available(s.clamscan_path):
        return ScanResult(success=True, notes=["ClamAV не установлен — шаг пропущен"])
    argv = [s.clamscan_path, "-r", "--no-summary", "--infected", target]
    proc = run_cmd(argv, timeout=timeout)
    result = ScanResult(success=True)
    if proc.timed_out:
        result.notes.append("ClamAV превысил таймаут")
    for line in (proc.stdout or "").splitlines():
        if " FOUND" in line:
            path, _, sig = line.partition(":")
            result.findings.append(
                Finding(
                    scanner="clamav",
                    severity="critical",
                    title="malware",
                    description=sig.replace("FOUND", "").strip() or "infected",
                    location=path.strip(),
                )
            )
    result.stats["clamav"] = len(result.findings)
    return result
