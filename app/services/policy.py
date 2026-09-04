"""Fail-closed target policy. Empty allowlist means deny, not allow."""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
from urllib.parse import urlparse

from app.config import get_settings

logger = logging.getLogger(__name__)

METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.gke.internal",
    "metadata.internal",
}

MAX_URL_LENGTH = 2048
GITHUB_RE = re.compile(
    r"^(?:https://github\.com/)?([A-Za-z0-9][A-Za-z0-9_.-]*)/([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\.git)?/?$",
    re.IGNORECASE,
)
IMAGE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\-/:@]{0,255}$")
REPO_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _canonical_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    ip = ipaddress.ip_address(value)
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped if mapped is not None else ip


def ip_is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Deny loopback, private, link-local, CGNAT, metadata — anything not global."""
    if str(ip) in METADATA_HOSTS:
        return True
    return not ip.is_global


def resolve_host_ips(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    seen: list[str] = []
    for info in infos:
        addr = info[4][0]
        text = str(_canonical_ip(addr))
        if text not in seen:
            seen.append(text)
    return seen


def assert_host_public(host: str) -> tuple[bool, str]:
    """Resolve (if needed) and reject non-public addresses. Closes DNS-rebinding TOCTOU."""
    host = (host or "").lower().rstrip(".")
    if not host:
        return False, "в URL нет хоста"
    if _is_ip(host):
        ip = _canonical_ip(host)
        if ip_is_blocked(ip):
            return False, "этот IP заблокирован (не публичный)"
        return True, ""
    try:
        ips = resolve_host_ips(host)
    except OSError:
        return False, f"не удалось разрешить DNS для {host}"
    if not ips:
        return False, f"нет адресов для {host}"
    for text in ips:
        ip = _canonical_ip(text)
        if ip_is_blocked(ip):
            logger.info("blocked internal resolution host=%s ip=%s", host, ip)
            return False, f"хост {host} указывает на внутреннюю сеть — скан отклонён"
    return True, ""


def assert_url_safe_to_connect(url: str) -> tuple[bool, str]:
    ok, reason = allow_url(url)
    if not ok:
        return ok, reason
    host = (urlparse(url).hostname or "").lower().rstrip(".")
    return assert_host_public(host)


def _host_matches(host: str, allowed: str) -> bool:
    host = host.lower().rstrip(".")
    allowed = allowed.lower().rstrip(".")
    if not host or not allowed:
        return False
    if host == allowed:
        return True
    if _is_ip(allowed) or _is_ip(host):
        return False
    return host.endswith("." + allowed)


def host_in_allowlist(host: str, allowed_domains: list[str]) -> bool:
    return any(_host_matches(host, item) for item in allowed_domains)


def allow_url(
    url: str,
    allowed_domains: list[str] | None = None,
) -> tuple[bool, str]:
    domains = (
        allowed_domains
        if allowed_domains is not None
        else get_settings().allowed_domains
    )
    if not domains:
        return False, "whitelist доменов пуст — сканирование URL запрещено"
    if not url or not isinstance(url, str):
        return False, "нужен http(s) URL"
    url = url.strip()
    if len(url) > MAX_URL_LENGTH:
        return False, "URL слишком длинный"
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False, "разрешены только http и https"
    if parsed.username or parsed.password:
        return False, "URL с логином/паролем не принимается"
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return False, "в URL нет хоста"
    if host in METADATA_HOSTS or host.endswith(".internal"):
        return False, "этот хост заблокирован (cloud metadata)"
    if _is_ip(host):
        ip = _canonical_ip(host)
        if ip_is_blocked(ip):
            return False, "этот IP заблокирован (не публичный)"
    if not host_in_allowlist(host, domains):
        return False, f"хост {host} не в whitelist доменов"
    return True, ""


def parse_github_repo(value: str) -> tuple[str, str] | None:
    if not value or not isinstance(value, str):
        return None
    raw = value.strip()
    if raw.startswith("git@"):
        return None
    if "://" in raw and not raw.lower().startswith("https://github.com/"):
        return None
    match = GITHUB_RE.fullmatch(raw)
    if not match:
        return None
    owner, repo = match.group(1), match.group(2)
    if repo.endswith(".git"):
        repo = repo[: -len(".git")]
    if repo in {".", ".."} or repo.startswith("-") or owner.startswith("-"):
        return None
    if not REPO_NAME_RE.fullmatch(repo):
        return None
    return owner, repo


def allow_repo(
    value: str,
    allowed_orgs: list[str] | None = None,
) -> tuple[bool, str]:
    orgs = (
        allowed_orgs
        if allowed_orgs is not None
        else get_settings().allowed_github_orgs
    )
    if not orgs:
        return False, "whitelist GitHub-организаций пуст — сканирование репозиториев запрещено"
    parsed = parse_github_repo(value)
    if not parsed:
        return False, "нужен репозиторий вида owner/repo или https://github.com/owner/repo"
    owner, repo = parsed
    if owner.lower() not in {o.lower() for o in orgs}:
        return False, f"организация/пользователь {owner} не в whitelist"
    return True, ""


def extract_docker_registry(image: str) -> str:
    """Best-effort registry from a docker image reference."""
    ref = image.split("@", 1)[0]
    # strip tag only if it's on the last path component
    name = ref
    if "/" in ref:
        first, rest = ref.split("/", 1)
        if "." in first or ":" in first or first == "localhost":
            registry = first
            return registry.lower()
        return "docker.io"
    # no slash: official image on docker.io (nginx:latest)
    return "docker.io"


def allow_image(
    image: str,
    allowed_registries: list[str] | None = None,
) -> tuple[bool, str]:
    registries = (
        allowed_registries
        if allowed_registries is not None
        else get_settings().allowed_docker_registries
    )
    if not registries:
        return False, "whitelist Docker-registry пуст — сканирование образов запрещено"
    if not image or not isinstance(image, str):
        return False, "нужно имя образа"
    image = image.strip()
    if not IMAGE_RE.fullmatch(image):
        return False, "некорректное имя образа"
    registry = extract_docker_registry(image)
    allowed = {r.lower().rstrip("/") for r in registries}
    registry_host = registry.split(":", 1)[0]
    if registry.lower() not in allowed and registry_host not in allowed:
        return False, f"registry {registry} не в whitelist"
    return True, ""


def allow_scan(scan_type: str, target: str) -> tuple[bool, str]:
    if scan_type == "url":
        return allow_url(target)
    if scan_type in {"repo", "github"}:
        return allow_repo(target)
    if scan_type in {"docker", "image"}:
        return allow_image(target)
    if scan_type in {"archive", "file", "file_vt"}:
        # local files the bot already downloaded; path traversal checked elsewhere
        return True, ""
    return False, f"неизвестный тип сканирования: {scan_type}"
