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
        "# Отчёт по проверке",
        "",
        f"- Тип: `{scan_type}`",
        f"- Цель: `{target}`",
        f"- Находок: {len(result.findings)} (важных: {len(result.important())})",
        "",
        "## Кратко",
        "",
        summary,
        "",
        "## Находки",
        "",
    ]
    if not result.findings:
        lines.append("Пусто.")
    for item in result.findings:
        lines.append(f"### [{item.severity}] {item.title}")
        lines.append(f"- Сканер: {item.scanner}")
        if item.location:
            lines.append(f"- Где: `{item.location}`")
        if item.description:
            lines.append(f"- Суть: {item.description}")
        if item.impact:
            lines.append(f"- **Чем опасно:** {item.impact}")
        lines.append("")
    if result.notes:
        lines.append("## Заметки")
        for note in result.notes:
            lines.append(f"- {note}")
    return mask_secrets("\n".join(lines))


def _html(result: ScanResult, scan_type: str, target: str, summary: str) -> str:
    from html import escape

    colors = {
        "critical": "#7f1d1d",
        "high": "#b91c1c",
        "medium": "#c2410c",
        "low": "#64748b",
        "info": "#475569",
    }
    cards = []
    for item in result.findings:
        color = colors.get(item.severity, "#334155")
        impact = (
            f"<p class='danger'><b>Чем опасно:</b> {escape(item.impact)}</p>"
            if item.impact
            else ""
        )
        desc = f"<p>{escape(item.description)}</p>" if item.description else ""
        loc = f"<code>{escape(item.location)}</code>" if item.location else ""
        cards.append(
            "<article class='finding'>"
            f"<div class='sev' style='background:{color}'>{escape(item.severity)}</div>"
            f"<h3>{escape(item.title)}</h3>"
            f"<p class='meta'>{escape(item.scanner)} · {loc}</p>"
            f"{desc}{impact}"
            "</article>"
        )
    body = "\n".join(cards) or "<p>Находок нет</p>"
    return f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<title>Scan report</title>
<style>
body {{ font-family: sans-serif; background:#0f172a; color:#e2e8f0; margin:24px; }}
h1,h2,h3 {{ color:#f8fafc; margin:0 0 8px; }}
.card {{ background:#1e293b; padding:16px 20px; border-radius:12px; }}
.finding {{ background:#0f172a; border:1px solid #334155; border-radius:10px; padding:14px 16px; margin:12px 0; }}
.sev {{ display:inline-block; color:#fff; font-size:12px; font-weight:700; padding:2px 8px; border-radius:6px; text-transform:uppercase; }}
.meta {{ color:#94a3b8; font-size:13px; }}
.danger {{ color:#fecaca; background:#7f1d1d33; padding:10px 12px; border-radius:8px; }}
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
{body}
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
