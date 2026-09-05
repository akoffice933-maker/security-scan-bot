"""Passive HTTP header checks. No payloads, allowlisted URL only."""

from __future__ import annotations

import logging
import re
import ssl
import urllib.error
import urllib.request
from email.message import Message
from urllib.parse import urlparse

from app.services.findings import Finding, ScanResult
from app.services.policy import assert_url_safe_to_connect, normalize_http_target

logger = logging.getLogger(__name__)

USER_AGENT = "security-scan-bot/0.3"
PHP_RE = re.compile(r"PHP/(\d+)\.(\d+)(?:\.(\d+))?", re.I)
SERVER_VER_RE = re.compile(r"/[\d.]+")

# As of 2026-09: PHP < 8.2 is EOL. 8.2 is security-only until 2026-12-31.
PHP_EOL_BEFORE = (8, 2)
PHP_SECURITY_ONLY = {(8, 2)}


class _AllowlistRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        ok, _ = assert_url_safe_to_connect(newurl)
        if not ok:
            logger.info("httpcheck: stop redirect to non-allowlisted %s", newurl)
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _header(headers: Message | dict, name: str) -> str:
    getter = getattr(headers, "get", None)
    if getter is None:
        return ""
    value = getter(name) or getter(name.lower()) or ""
    return str(value).strip()


def _php_findings(powered: str, url: str) -> list[Finding]:
    out: list[Finding] = []
    if not powered:
        return out
    out.append(
        Finding(
            scanner="httpcheck",
            severity="low",
            title="X-Powered-By disclosure",
            description=f"Сервер отдаёт заголовок X-Powered-By: {powered[:120]}",
            location=url,
            extra={"header": "X-Powered-By"},
        )
    )
    match = PHP_RE.search(powered)
    if not match:
        return out
    major, minor = int(match.group(1)), int(match.group(2))
    patch = match.group(3) or "0"
    version = f"{major}.{minor}.{patch}"
    key = (major, minor)
    if key < PHP_EOL_BEFORE:
        out.append(
            Finding(
                scanner="httpcheck",
                severity="high",
                title="Outdated PHP (EOL)",
                description=(
                    f"PHP {version} давно без обновлений безопасности. "
                    "Нужно 8.2+ (лучше 8.3/8.4)."
                ),
                location=url,
                extra={"php": version},
            )
        )
    elif key in PHP_SECURITY_ONLY:
        out.append(
            Finding(
                scanner="httpcheck",
                severity="medium",
                title="PHP security-only",
                description=(
                    f"PHP {version} только на security-support (EOL 31.12.2026). "
                    "Запланировать переход на 8.3/8.4."
                ),
                location=url,
                extra={"php": version},
            )
        )
    return out


def findings_from_headers(url: str, headers: Message | dict, https: bool) -> list[Finding]:
    items: list[Finding] = []
    powered = _header(headers, "X-Powered-By")
    items.extend(_php_findings(powered, url))

    server = _header(headers, "Server")
    if server and SERVER_VER_RE.search(server):
        items.append(
            Finding(
                scanner="httpcheck",
                severity="low",
                title="Server version disclosure",
                description=f"Заголовок Server выдаёт стек: {server[:120]}",
                location=url,
                extra={"header": "Server"},
            )
        )

    if https and not _header(headers, "Strict-Transport-Security"):
        items.append(
            Finding(
                scanner="httpcheck",
                severity="medium",
                title="Missing HSTS",
                description="Нет Strict-Transport-Security — браузер не закрепит HTTPS.",
                location=url,
                extra={"header": "Strict-Transport-Security"},
            )
        )
    return items


def _ssl_context(*, insecure: bool) -> ssl.SSLContext:
    if insecure:
        ctx = ssl._create_unverified_context()
        ctx.check_hostname = False
        return ctx
    return ssl.create_default_context()


def _is_tls_trust_error(exc: BaseException) -> bool:
    reason = getattr(exc, "reason", None)
    parts = [str(exc), type(exc).__name__]
    if reason is not None:
        parts.append(str(reason))
        parts.append(type(reason).__name__)
    text = " ".join(parts).lower()
    markers = (
        "certificate_verify_failed",
        "certificate verify failed",
        "self-signed",
        "sslcerterror",
        "sslcertverificationerror",
    )
    if any(m in text for m in markers):
        return True
    return isinstance(exc, ssl.SSLError) or isinstance(reason, ssl.SSLError)


def fetch_headers(url: str, timeout: int = 15, *, insecure: bool = False) -> tuple[Message, str]:
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
    )
    https = urllib.request.HTTPSHandler(context=_ssl_context(insecure=insecure))
    opener = urllib.request.build_opener(https, _AllowlistRedirect())
    with opener.open(req, timeout=timeout) as resp:  # nosec B310 — allowlisted http(s) only
        final = str(getattr(resp, "url", url) or url)
        headers = resp.headers
        return headers, final


def scan_http(url: str, timeout: int = 15) -> ScanResult:
    url = normalize_http_target(url)
    ok, reason = assert_url_safe_to_connect(url)
    if not ok:
        return ScanResult(success=False, error=reason)
    result = ScanResult(success=True)
    wait = max(5, min(timeout, 30))
    try:
        try:
            headers, final = fetch_headers(url, timeout=wait, insecure=False)
        except Exception as exc:
            if urlparse(url).scheme != "https" or not _is_tls_trust_error(exc):
                raise
            logger.info("httpcheck: retry without TLS verify after %s", exc)
            result.findings.append(
                Finding(
                    scanner="httpcheck",
                    severity="medium",
                    title="Untrusted TLS certificate",
                    description=(
                        "Сертификат не проходит проверку (self-signed или просрочен). "
                        "Заголовки сняты без проверки цепочки — только для allowlisted цели."
                    ),
                    location=url,
                )
            )
            result.notes.append("TLS: сертификат не доверен, заголовки сняты повторным запросом")
            headers, final = fetch_headers(url, timeout=wait, insecure=True)
        https = urlparse(final).scheme == "https"
        result.findings.extend(findings_from_headers(final, headers, https=https))
    except urllib.error.HTTPError as exc:
        https = urlparse(url).scheme == "https"
        result.findings.extend(findings_from_headers(url, exc.headers or Message(), https=https))
        result.notes.append(f"HTTP {exc.code} при проверке заголовков")
    except Exception as exc:  # noqa: BLE001
        logger.info("httpcheck failed: %s", exc)
        result.notes.append(f"заголовки не сняты: {str(exc)[:200]}")
    result.sort()
    result.stats["httpcheck"] = len(result.findings)
    return result
