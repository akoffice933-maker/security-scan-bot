from app.services.findings import Finding, ScanResult, normalize_severity


def test_normalize_severity():
    assert normalize_severity("ERROR") == "high"
    assert normalize_severity("WARNING") == "medium"
    assert normalize_severity("CRITICAL") == "critical"
    assert normalize_severity(None) == "info"


def test_important_filter_and_sort():
    result = ScanResult(
        success=True,
        findings=[
            Finding("n", "low", "l"),
            Finding("n", "critical", "c"),
            Finding("n", "medium", "m"),
        ],
    )
    result.sort()
    assert result.findings[0].severity == "critical"
    assert [f.severity for f in result.important()] == ["critical", "medium"]
