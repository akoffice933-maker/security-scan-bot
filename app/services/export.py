from __future__ import annotations

import json
import logging
from pathlib import Path

from app.services.findings import ScanResult
from app.services.pdf_report import generate_pdf_report
from app.services.textutil import mask_secrets

logger = logging.getLogger(__name__)


def _md(result: ScanResult, scan_type: str, target: str, summary: str) -> str:
    lines = [
        f"# Отчёт по проверке",
        f"",
        f"- Тип: `{scan_type}`",
        f"- Цель: `{target}`",
        f"- Находок: {len(result.findings)} (важных: {len(result.important())})",
        f"",
        f"## Кратко",
        f"",
        summary,
        f"",
        f"## Находки",
        f"",
    ]
    if not result.findings:
        lines.append("Пусто.")
    for item in result.findings:
        lines.append(f"### [{item.severity}] {item.title}")
        lines.append(f"- Сканер: {item.scanner}")
        if item.location:
            lines.append(f"- Где: `{item.location}`")
        if item.description:
            lines.append(f"- {item.description}")
        lines.append("")
    if result.notes:
        lines.append("## Заметки")
        for note in result.notes:
            lines.append(f"- {note}")
    return mask_secrets("\n".join(lines))


def _html(result: ScanResult, scan_type: str, target: str, summary: str) -> str:
    from html import escape

    rows = []
    colors = {
        "critical": "#7f1d1d",
        "high": "#b91c1c",
        "medium": "#c2410c",
        "low": "#a3a3a3",
        "info": "#64748b",
    }
    for item in result.findings:
        color = colors.get(item.severity, "#334155")
        rows.append(
            "<tr>"
            f"<td style='color:{color};font-weight:700'>{escape(item.severity)}</td>"
            f"<td>{escape(item.scanner)}</td>"
            f"<td>{escape(item.title)}</td>"
            f"<td>{escape(item.location or '')}</td>"
            f"<td>{escape((item.description or '')[:400])}</td>"
            "</tr>"
        )
    table = "\n".join(rows) or "<tr><td colspan='5'>Находок нет</td></tr>"
    return f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<title>Scan report</title>
<style>
body {{ font-family: sans-serif; background:#0f172a; color:#e2e8f0; margin:24px; }}
h1,h2 {{ color:#f8fafc; }}
.card {{ background:#1e293b; padding:16px 20px; border-radius:12px; }}
table {{ width:100%; border-collapse:collapse; margin-top:12px; }}
th,td {{ text-align:left; padding:8px; border-bottom:1px solid #334155; vertical-align:top; }}
code {{ color:#93c5fd; }}
pre {{ white-space:pre-wrap; }}
</style></head>
<body>
<div class="card">
<h1>Отчёт по проверке</h1>
<p>Тип: <code>{escape(scan_type)}</code><br>Цель: <code>{escape(target)}</code></p>
<h2>Кратко</h2>
<pre>{escape(summary)}</pre>
<h2>Находки ({len(result.findings)})</h2>
<table>
<thead><tr><th>Severity</th><th>Сканер</th><th>Title</th><th>Где</th><th>Описание</th></tr></thead>
<tbody>{table}</tbody>
</table>
</div>
</body></html>
"""


def export_all_formats(
    scan_id: int,
    scan_type: str,
    target: str,
    result: ScanResult,
    summary: str,
    out_dir: str | Path,
) -> dict[str, Path]:
    dest = Path(out_dir)
    dest.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}

    md_path = dest / f"scan-{scan_id}.md"
    md_path.write_text(_md(result, scan_type, target, summary), encoding="utf-8")
    paths["md"] = md_path

    html_path = dest / f"scan-{scan_id}.html"
    html_path.write_text(_html(result, scan_type, target, summary), encoding="utf-8")
    paths["html"] = html_path

    json_path = dest / f"scan-{scan_id}.json"
    payload = {
        "scan_id": scan_id,
        "scan_type": scan_type,
        "target": target,
        "summary": summary,
        "result": result.to_dict(),
    }
    json_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    paths["json"] = json_path

    pdf_path = dest / f"scan-{scan_id}.pdf"
    try:
        generate_pdf_report(pdf_path, scan_id, scan_type, target, summary, result)
        paths["pdf"] = pdf_path
    except Exception:
        logger.exception("PDF generation failed")

    return paths
