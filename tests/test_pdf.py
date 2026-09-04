from app.services.findings import Finding, ScanResult
from app.services.pdf_report import generate_pdf_report


def test_pdf_writes_file_with_cyrillic(tmp_path):
    result = ScanResult(
        success=True,
        findings=[
            Finding("trivy-fs", "high", "CVE-1", "DoS in qs", "package-lock.json"),
        ],
    )
    out = tmp_path / "scan.pdf"
    generate_pdf_report(out, 7, "repo", "akoffice933-maker/agent-Mr", "Кратко: две находки", result)
    assert out.is_file()
    assert out.stat().st_size > 200
    assert out.read_bytes()[:4] == b"%PDF"
