from app.services.explain import enrich_result, explain_danger
from app.services.findings import Finding, ScanResult


def test_malware_and_secret():
    malware = explain_danger(Finding("clamav", "critical", "malware", "Eicar FOUND", "/tmp/x"))
    assert "вредонос" in malware.lower() or "код" in malware.lower()
    secret = explain_danger(Finding("trivy-fs", "high", "aws-key", "secret found", "app.py:4"))
    assert "секрет" in secret.lower() or "ключ" in secret.lower()


def test_dos_and_xss_and_gha():
    dos = explain_danger(
        Finding("trivy-fs", "high", "CVE-1", "nanoid: Denial of Service via infinite loop", "lock")
    )
    assert "отказ" in dos.lower() or "dos" in dos.lower() or "завис" in dos.lower()
    xss = explain_danger(
        Finding("trivy-fs", "medium", "CVE-2", "PostCSS: Cross-Site Scripting (XSS)", "lock")
    )
    assert "xss" in xss.lower() or "скрипт" in xss.lower()
    gha = explain_danger(
        Finding(
            "semgrep",
            "medium",
            "yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag",
            "mutable tag",
            "ci.yml",
        )
    )
    assert "тег" in gha.lower() or "supply" in gha.lower() or "экшен" in gha.lower()


def test_php_eol_and_hsts():
    php = explain_danger(
        Finding("httpcheck", "high", "Outdated PHP (EOL)", "PHP 5.3.29", "https://example.com")
    )
    assert "php" in php.lower()
    hsts = explain_danger(
        Finding("httpcheck", "medium", "Missing HSTS", "no Strict-Transport-Security", "https://x")
    )
    assert "hsts" in hsts.lower() or "https" in hsts.lower()


def test_enrich_fills_impact():
    result = ScanResult(
        success=True,
        findings=[Finding("bandit", "high", "B307", "Use of eval", "vuln.py:5")],
    )
    enrich_result(result)
    assert result.findings[0].impact
    assert "код" in result.findings[0].impact.lower() or "сервер" in result.findings[0].impact.lower()
