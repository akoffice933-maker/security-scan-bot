from email.message import Message

from app.services.httpcheck import findings_from_headers, scan_http
from app.services.scanner import scan_url


def _headers(**kwargs: str) -> Message:
    msg = Message()
    for key, value in kwargs.items():
        msg[key.replace("_", "-")] = value
    return msg


def test_php53_is_high_eol():
    items = findings_from_headers(
        "https://example.com/",
        _headers(X_Powered_By="PHP/5.3.29-pl0-gentoo", Server="nginx/1.31.3"),
        https=True,
    )
    titles = {f.title: f for f in items}
    assert titles["Outdated PHP (EOL)"].severity == "high"
    assert "5.3.29" in titles["Outdated PHP (EOL)"].description
    assert titles["X-Powered-By disclosure"].severity == "low"
    assert titles["Server version disclosure"].severity == "low"
    assert titles["Missing HSTS"].severity == "medium"


def test_php84_no_eol():
    items = findings_from_headers(
        "https://example.com/",
        _headers(X_Powered_By="PHP/8.4.1", **{"Strict-Transport-Security": "max-age=31536000"}),
        https=True,
    )
    titles = {f.title for f in items}
    assert "Outdated PHP (EOL)" not in titles
    assert "Missing HSTS" not in titles
    assert "X-Powered-By disclosure" in titles


def test_scan_http_denied():
    result = scan_http("https://evil.example/")
    assert result.success is False


def test_scan_url_merges_headers(monkeypatch):
    from app.services import httpcheck, scanners
    from app.services.findings import Finding, ScanResult
    from app.services import scanner as scan_mod

    monkeypatch.setattr(scan_mod, "assert_url_safe_to_connect", lambda url: (True, ""))

    monkeypatch.setattr(
        httpcheck,
        "scan_http",
        lambda url, timeout=15: ScanResult(
            success=True,
            findings=[Finding("httpcheck", "high", "Outdated PHP (EOL)", "PHP 5.3", url)],
        ),
    )
    monkeypatch.setattr(
        scanners,
        "scan_nuclei",
        lambda url, profile, timeout: ScanResult(
            success=True,
            findings=[Finding("nuclei", "high", "Joomla SQLi", "cve", url)],
        ),
    )
    result = scan_url("https://example.com/", profile="cve")
    titles = {f.title for f in result.findings}
    assert "Outdated PHP (EOL)" in titles
    assert "Joomla SQLi" in titles
    assert result.stats["important"] == 2
