from app.config import Settings


def test_parse_csv_lists(monkeypatch):
    monkeypatch.setenv("ADMIN_IDS", "1, 2,3")
    monkeypatch.setenv("ALLOWED_DOMAINS", "Example.COM, localhost")
    monkeypatch.setenv("ALLOWED_IPS", "8.8.8.8, 1.1.1.1")
    monkeypatch.setenv("ALLOWED_GITHUB_ORGS", "MyOrg")
    monkeypatch.setenv("ALLOWED_DOCKER_REGISTRIES", "GHCR.IO,docker.io")
    monkeypatch.setenv("BOT_TOKEN", "t")
    settings = Settings()
    assert settings.admin_ids == [1, 2, 3]
    assert settings.allowed_domains == ["example.com", "localhost"]
    assert settings.allowed_ips == ["8.8.8.8", "1.1.1.1"]
    assert settings.allowed_github_orgs == ["myorg"]
    assert "ghcr.io" in settings.allowed_docker_registries


def test_empty_csv(monkeypatch):
    monkeypatch.setenv("ADMIN_IDS", "")
    monkeypatch.setenv("ALLOWED_DOMAINS", "")
    monkeypatch.setenv("BOT_TOKEN", "")
    settings = Settings()
    assert settings.admin_ids == []
    assert settings.allowed_domains == []
