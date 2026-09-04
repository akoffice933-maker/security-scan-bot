from pathlib import Path

from app.config import clear_settings_cache
from app.db.session import to_sync_url
from app.services import health


def test_to_sync_url_keeps_psycopg():
    assert to_sync_url("sqlite+aiosqlite:///./data/bot.db") == "sqlite:///./data/bot.db"
    assert (
        to_sync_url("postgresql+psycopg://scanbot:scanbot@postgres:5432/scanbot")
        == "postgresql+psycopg://scanbot:scanbot@postgres:5432/scanbot"
    )
    assert to_sync_url("postgresql+asyncpg://u:p@h/db") == "postgresql+psycopg://u:p@h/db"


def test_collect_and_cleanup(tmp_path, monkeypatch):
    work = tmp_path / "work"
    tmp = tmp_path / "scans"
    uploads = tmp_path / "uploads"
    reports = tmp_path / "reports"
    work.mkdir()
    tmp.mkdir()
    uploads.mkdir()
    reports.mkdir()
    stale = work / "old"
    stale.mkdir()
    (stale / "x.txt").write_text("x")

    monkeypatch.setenv("WORK_DIR", str(work))
    monkeypatch.setenv("SCAN_TMP_DIR", str(tmp))
    monkeypatch.setenv("UPLOADS_DIR", str(uploads))
    monkeypatch.setenv("REPORTS_DIR", str(reports))
    monkeypatch.setenv("BOT_TOKEN", "t")
    monkeypatch.setenv("ADMIN_IDS", "1")
    clear_settings_cache()

    status = health.collect()
    assert status.disk_free_mb > 0
    assert isinstance(status.ok, bool)
    removed = health.cleanup_stale(max_age_hours=0)
    assert removed >= 1
    assert not stale.exists()
    clear_settings_cache()
