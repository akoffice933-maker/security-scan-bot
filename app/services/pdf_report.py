from __future__ import annotations

from pathlib import Path

from app.services.findings import ScanResult
from app.services.textutil import mask_secrets

FONT_CANDIDATES = [
    Path(__file__).resolve().parents[1] / "assets" / "DejaVuSans.ttf",
    Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
    Path("/usr/share/fonts/dejavu/DejaVuSans.ttf"),
]


def _font_path() -> Path | None:
    for candidate in FONT_CANDIDATES:
        if candidate.is_file():
            return candidate
    return None


def generate_pdf_report(
    path: str | Path,
    scan_id: int,
    scan_type: str,
    target: str,
    summary: str,
    result: ScanResult,
) -> Path:
    from fpdf import FPDF

    out = Path(path)
    font_path = _font_path()
    pdf = FPDF(format="A4", unit="mm")
    pdf.set_margins(15, 15, 15)
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    if font_path:
        pdf.add_font("DejaVu", fname=str(font_path))
        family = "DejaVu"
        unicode_ok = True
    else:
        family = "Helvetica"
        unicode_ok = False

    def write(text: str, size: int = 11) -> None:
        pdf.set_font(family, size=size)
        raw = mask_secrets(text or "")
        if not unicode_ok:
            raw = raw.encode("latin-1", "replace").decode("latin-1")
        width = pdf.epw
        if width <= 0:
            width = 180
        pdf.multi_cell(width, 6, raw)

    write(f"Security scan #{scan_id}", size=16)
    write(f"Type: {scan_type}")
    write(f"Target: {target}")
    write(f"Findings: {len(result.findings)} (important: {len(result.important())})")
    pdf.ln(3)
    write("Summary", size=13)
    write(summary or "")
    pdf.ln(3)
    write("Findings", size=13)
    if not result.findings:
        write("None.")
    for item in result.findings[:80]:
        write(f"[{item.severity}] {item.scanner}: {item.title}")
        if item.location:
            write(f"  {item.location}")
        if item.description:
            write(f"  {item.description[:500]}")
        pdf.ln(1)
    pdf.output(str(out))
    return out
