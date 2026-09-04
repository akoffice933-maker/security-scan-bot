#!/usr/bin/env python3
"""CLI: scan an allowlisted URL (headers + Nuclei) and write reports."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.config import clear_settings_cache, get_settings  # noqa: E402
from app.db.session import init_db_sync  # noqa: E402
from app.services import audit, history  # noqa: E402
from app.services.pipeline import execute_scan  # noqa: E402
from app.services.policy import allow_url, normalize_http_target  # noqa: E402
from app.services.scanners import capabilities  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan an allowlisted website URL")
    parser.add_argument("url", help="https://example.com/ or a public IP from ALLOWED_IPS")
    parser.add_argument(
        "--profile",
        default="all",
        choices=("cve", "misconfig", "exposures", "all"),
        help="Nuclei profile (default: all)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    )
    clear_settings_cache()
    init_db_sync()

    print("Capabilities:", json.dumps(capabilities(), indent=2))
    ok, reason = allow_url(args.url)
    if not ok:
        audit.write_event(0, "scan_denied", "url", args.url, None, reason)
        print(f"DENIED: {reason}", file=sys.stderr)
        return 2

    scan_id = history.create_scan(0, "url", args.url)
    audit.write_event(0, "scan_requested", "url", args.url, scan_id, "cli")
    result = execute_scan(
        {
            "scan_id": scan_id,
            "user_id": 0,
            "scan_type": "url",
            "target": args.url,
            "chat_id": None,
            "options": {"profile": args.profile},
        }
    )
    row = history.get_scan(scan_id)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if row and row.summary:
        print("\n===== SUMMARY =====\n")
        print(row.summary)
    reports = Path(get_settings().reports_dir) / f"scan-{scan_id}"
    print(f"\nReports: {reports}")
    if reports.exists():
        for p in sorted(reports.iterdir()):
            print(" -", p)
    return 0 if result.get("status") in {"completed", "failed"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
