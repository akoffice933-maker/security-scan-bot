from __future__ import annotations

import json
import logging
import os

from app.db.session import init_db_sync
from app.services import scanner as scan_svc
from app.services.policy import allow_image, allow_repo, allow_url
from app.services.scanners import capabilities
from app.services.textutil import mask_secrets

logger = logging.getLogger(__name__)


def _dump(result) -> str:  # noqa: ANN001
    return mask_secrets(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))


def _mcp_class():
    try:
        from mcp.server.mcpserver import MCPServer

        return MCPServer
    except ImportError:  # mcp 1.x
        from mcp.server.fastmcp import FastMCP

        return FastMCP


def create_mcp():
    mcp_cls = _mcp_class()
    mcp = mcp_cls(
        "security-scan-bot",
        instructions=(
            "Scan only allowlisted targets you own. "
            "Refuse anything outside ALLOWED_DOMAINS / ALLOWED_GITHUB_ORGS / "
            "ALLOWED_DOCKER_REGISTRIES. Never scan third-party systems."
        ),
    )

    @mcp.tool()
    def scan_url(url: str, profile: str = "cve") -> str:
        """Scan an allowlisted URL with Nuclei. profile: cve|misconfig|exposures|all."""
        ok, reason = allow_url(url)
        if not ok:
            return json.dumps({"success": False, "error": reason})
        return _dump(scan_svc.scan_url(url, profile=profile))

    @mcp.tool()
    def scan_repo(repo: str) -> str:
        """Scan an allowlisted GitHub repo (owner/repo) with Semgrep, Trivy, Bandit, ClamAV."""
        ok, reason = allow_repo(repo)
        if not ok:
            return json.dumps({"success": False, "error": reason})
        return _dump(scan_svc.scan_repo(repo))

    @mcp.tool()
    def scan_docker(image: str) -> str:
        """Scan a Docker image from an allowlisted registry with Trivy."""
        ok, reason = allow_image(image)
        if not ok:
            return json.dumps({"success": False, "error": reason})
        return _dump(scan_svc.scan_docker(image))

    @mcp.tool()
    def scan_file_virustotal(path: str) -> str:
        """Look up a local file hash on VirusTotal. Does not upload the file."""
        return _dump(scan_svc.scan_file_virustotal(path))

    @mcp.tool()
    def scan_archive(path: str) -> str:
        """Scan a local zip/tar archive with Semgrep, Trivy, Bandit, ClamAV."""
        return _dump(scan_svc.scan_archive(path, with_virustotal=False))

    @mcp.tool()
    def get_scan_capabilities() -> str:
        """Installed scanners and whitelist sizes. Does not return secrets."""
        from app.config import get_settings

        caps = capabilities()
        settings = get_settings()
        caps["whitelist"] = {
            "domains": len(settings.allowed_domains),
            "github_orgs": len(settings.allowed_github_orgs),
            "docker_registries": len(settings.allowed_docker_registries),
        }
        return json.dumps(caps, indent=2)

    return mcp


def refuse_non_stdio() -> None:
    """MCP is stdio-only. Refuse if someone wraps it in HTTP/SSE."""
    transport = (os.environ.get("MCP_TRANSPORT") or "stdio").strip().lower()
    if transport not in {"stdio", ""}:
        raise SystemExit("MCP только stdio. HTTP/SSE транспорт запрещён.")
    for key in ("FASTMCP_HOST", "MCP_HTTP", "MCP_SSE"):
        if os.environ.get(key):
            raise SystemExit(f"MCP только stdio ({key} задан — отказ).")


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    refuse_non_stdio()
    init_db_sync()
    mcp = create_mcp()
    mcp.run(transport="stdio")
