from app.services import history
from app.services.pipeline import execute_scan


def test_denied_url_does_not_scan(db):
    scan_id = history.create_scan(111, "url", "https://evil.example")
    out = execute_scan(
        {
            "scan_id": scan_id,
            "scan_type": "url",
            "target": "https://evil.example",
            "chat_id": None,
        }
    )
    assert out["status"] == "denied"
    row = history.get_scan(scan_id)
    assert row is not None
    assert row.status == "denied"
