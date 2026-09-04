#!/usr/bin/env python3
"""CLI: scan an allowlisted GitHub repo and write reports under data/reports/."""

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
from app.services import history  # noqa: E402
from app.services.export import export_all_formats  # noqa: E402
from app.services.llm import summarize_sync  # noqa: E402
from app.services.pipeline import execute_scan  # noqa: E402
from app.services.policy import allow_repo  # noqa: E402
from app.services.scanners import capabilities  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan an allowlisted GitHub repository")
    parser.add_argument("repo", help="owner/repo or https://github.com/owner/repo")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    )
    clear_settings_cache()
    init_db_sync()

    print("Capabilities:", json.dumps(capabilities(), indent=2))
    ok, reason = allow_repo(args.repo)
    if not ok:
        audit.write_event(0, "scan_denied", "repo", args.repo, None, reason)
        print(f"DENIED: {reason}", file=sys.stderr)
        return 2

    scan_id = history.create_scan(0, "repo", args.repo)
    audit.write_event(0, "scan_requested", "repo", args.repo, scan_id, "cli")
    result = execute_scan(
        {
            "scan_id": scan_id,
            "user_id": 0,
            "scan_type": "repo",
            "target": args.repo,
            "chat_id": None,
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
