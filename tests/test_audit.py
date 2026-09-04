from app.services import audit, history
from app.services.pipeline import execute_scan


def test_audit_write_and_recent(db):
    event_id = audit.write_event(111, "scan_requested", "repo", "myorg/app", 1, "cli")
    assert event_id > 0
    rows = audit.recent(user_id=111, limit=10)
    assert len(rows) == 1
    assert rows[0].action == "scan_requested"
    assert rows[0].target == "myorg/app"


def test_pipeline_denied_writes_audit(db):
    scan_id = history.create_scan(111, "url", "https://evil.example")
    out = execute_scan(
        {
            "scan_id": scan_id,
            "user_id": 111,
            "scan_type": "url",
            "target": "https://evil.example",
            "chat_id": None,
        }
    )
    assert out["status"] == "denied"
    actions = [e.action for e in audit.recent(user_id=111)]
    assert "scan_denied" in actions
