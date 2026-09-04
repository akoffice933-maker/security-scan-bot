from app.services import history


def test_create_finish_and_list(db):
    scan_id = history.create_scan(111, "url", "https://example.com")
    assert history.count_running(111) == 1
    assert history.finish_scan(scan_id, "completed", raw_report="{}", summary="ok")
    assert history.count_running(111) == 0
    rows = history.get_user_history(111, limit=5)
    assert len(rows) == 1
    assert rows[0].status == "completed"
    assert history.get_scan(scan_id).summary == "ok"


def test_fail_stale_running(db):
    scan_id = history.create_scan(111, "url", "https://example.com")
    assert history.count_running(111) == 1
    n = history.fail_stale_running(max_age_seconds=-1)
    assert n == 1
    row = history.get_scan(scan_id)
    assert row is not None
    assert row.status == "failed"
    assert history.count_running(111) == 0


def test_finish_missing(db):
    assert history.finish_scan(999999, "failed") is False
