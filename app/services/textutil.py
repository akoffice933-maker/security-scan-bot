from __future__ import annotations

import html
import re

SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA***"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "ghp_***"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), "github_pat_***"),
    (re.compile(r"sk-or-v1-[A-Za-z0-9]{20,}"), "sk-or-***"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "sk-***"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "xox***"),
    (re.compile(r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----"), "***PRIVATE KEY***"),
    (re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*\S+"), r"\1=***"),
]


def mask_secrets(text: str) -> str:
    if not text:
        return text
    masked = text
    for pattern, repl in SECRET_PATTERNS:
        masked = pattern.sub(repl, masked)
    return masked


def escape_html(text: str) -> str:
    return html.escape(text or "", quote=False)


def truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)] + "…"


def split_message(text: str, limit: int = 3900) -> list[str]:
    if len(text) <= limit:
        return [text]
    chunks: list[str] = []
    rest = text
    while rest:
        chunks.append(rest[:limit])
        rest = rest[limit:]
    return chunks
