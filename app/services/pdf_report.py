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
    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    if font_path:
        pdf.add_font("DejaVu", "", str(font_path))
        pdf.add_font("DejaVu", "B", str(font_path))
        font = "DejaVu"
    else:
        font = "Helvetica"

    def write(text: str, size: int = 11, bold: bool = False) -> None:
        pdf.set_font(font, "B" if bold and font == "Helvetica" else "", size)
        if font == "DejaVu":
            pdf.set_font(font, "", size)
        safe = mask_secrets(text).encode("latin-1", "replace").decode("latin-1") if font == "Helvetica" else mask_secrets(text)
        pdf.multi_cell(0, 6, safe)

    write(f"Security scan #{scan_id}", size=16, bold=True)
    write(f"Type: {scan_type}")
    write(f"Target: {target}")
    write(f"Findings: {len(result.findings)} (important: {len(result.important())})")
    pdf.ln(4)
    write("Summary", size=13, bold=True)
    write(summary)
    pdf.ln(4)
    write("Findings", size=13, bold=True)
    if not result.findings:
        write("None.")
    for item in result.findings[:80]:
        write(f"[{item.severity}] {item.scanner}: {item.title}", bold=True)
        if item.location:
            write(f"  {item.location}")
        if item.description:
            write(f"  {item.description[:500]}")
        pdf.ln(1)
    pdf.output(str(out))
    return out
