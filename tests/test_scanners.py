import json

from app.services.sandbox import SandboxResult
from app.services import scanners


def _always_available(_path: str) -> bool:
    return True


def test_nuclei_argv_timeout_and_parse(monkeypatch):
    monkeypatch.setattr(scanners, "tool_available", _always_available)
    captured: dict = {}

    def fake_run(argv, timeout, cwd=None, extra_env=None):
        captured["argv"] = argv
        captured["timeout"] = timeout
        line = json.dumps(
            {
                "info": {"name": "CVE-1", "severity": "high", "description": "xss"},
                "matched-at": "https://example.com/x",
            }
        )
        return SandboxResult(0, line + "\n", "")

    monkeypatch.setattr(scanners, "run_cmd", fake_run)
    result = scanners.scan_nuclei("https://example.com", "cve", timeout=90)
    assert captured["timeout"] == 90
    assert captured["argv"][0] == "nuclei"
    assert "-u" in captured["argv"]
    assert "https://example.com" in captured["argv"]
    assert "-jsonl" in captured["argv"]
    assert all(";" not in a and "|" not in a for a in captured["argv"])
    assert result.success is True
    assert result.findings[0].severity == "high"
    assert result.findings[0].title == "CVE-1"


def test_nuclei_timeout_note(monkeypatch):
    monkeypatch.setattr(scanners, "tool_available", _always_available)
    monkeypatch.setattr(
        scanners,
        "run_cmd",
        lambda *a, **k: SandboxResult(124, "", "timeout", timed_out=True),
    )
    result = scanners.scan_nuclei("https://example.com", "cve", timeout=5)
    assert any("таймаут" in n.lower() for n in result.notes)


def test_nuclei_nonzero_exit_without_findings(monkeypatch):
    monkeypatch.setattr(scanners, "tool_available", _always_available)
    monkeypatch.setattr(
        scanners,
        "run_cmd",
        lambda *a, **k: SandboxResult(2, "", "nuclei crashed"),
    )
    result = scanners.scan_nuclei("https://example.com", "all", timeout=5)
    assert result.success is False
    assert "crashed" in (result.error or "")


def test_semgrep_parses_warning(monkeypatch):
    monkeypatch.setattr(scanners, "tool_available", _always_available)
    payload = {
        "results": [
            {
                "check_id": "python.lang.security.audit.eval",
                "path": "app.py",
                "start": {"line": 12},
                "extra": {"severity": "WARNING", "message": "eval"},
            }
        ]
    }
    captured: dict = {}

    def fake_run(argv, timeout, cwd=None, extra_env=None):
        captured["argv"] = argv
        return SandboxResult(0, json.dumps(payload), "")

    monkeypatch.setattr(scanners, "run_cmd", fake_run)
    result = scanners.scan_semgrep("/tmp/src", timeout=30)
    assert "--json" in captured["argv"]
    assert captured["argv"][-1] == "/tmp/src"
    assert result.findings[0].severity == "medium"
    assert "app.py:12" in result.findings[0].location


def test_trivy_parses_cve_and_secret(monkeypatch):
    monkeypatch.setattr(scanners, "tool_available", _always_available)
    payload = {
        "Results": [
            {
                "Target": "package-lock.json",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-1",
                        "Severity": "HIGH",
                        "Title": "DoS",
                        "PkgName": "qs",
                        "InstalledVersion": "6.0.0",
                    }
                ],
                "Secrets": [{"Severity": "HIGH", "Title": "aws-key", "StartLine": 4}],
            }
        ]
    }
    monkeypatch.setattr(
        scanners,
        "run_cmd",
        lambda *a, **k: SandboxResult(0, json.dumps(payload), ""),
    )
    result = scanners.scan_trivy_fs("/tmp/src", timeout=40)
    titles = {f.title for f in result.findings}
    assert "CVE-2026-1" in titles
    assert "aws-key" in titles
    assert all("значение скрыто" in f.description or f.title.startswith("CVE") for f in result.findings)


def test_bandit_excludes_tests_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(scanners, "tool_available", _always_available)
    (tmp_path / "tests").mkdir()
    (tmp_path / "app.py").write_text("x = 1\n")
    captured: dict = {}

    def fake_run(argv, timeout, cwd=None, extra_env=None):
        captured["argv"] = argv
        return SandboxResult(0, "{}", "")

    monkeypatch.setattr(scanners, "run_cmd", fake_run)
    scanners.scan_bandit(str(tmp_path), timeout=10)
    assert "-x" in captured["argv"]
    assert str(tmp_path / "tests") in captured["argv"]


def test_clamav_found_is_critical(monkeypatch):
    monkeypatch.setattr(scanners, "tool_available", _always_available)
    monkeypatch.setattr(
        scanners,
        "run_cmd",
        lambda *a, **k: SandboxResult(1, "/tmp/eicar: Eicar-Test-Signature FOUND\n", ""),
    )
    result = scanners.scan_clamav("/tmp/eicar", timeout=10)
    assert result.findings[0].severity == "critical"
    assert "Eicar" in result.findings[0].description
