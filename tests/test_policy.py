from app.services.policy import (
    allow_image,
    allow_repo,
    allow_url,
    assert_host_public,
    assert_url_safe_to_connect,
    extract_docker_registry,
    parse_github_repo,
)

DOMAINS = ["example.com", "myproject.dev", "localhost", "127.0.0.1"]
ORGS = ["myusername", "myorg"]
REGISTRIES = ["docker.io", "ghcr.io", "localhost"]


def test_empty_domain_whitelist_denies():
    ok, reason = allow_url("https://example.com", allowed_domains=[])
    assert ok is False
    assert "пуст" in reason


def test_url_allows_exact_and_subdomain():
    assert allow_url("https://example.com/app", DOMAINS)[0] is True
    assert allow_url("https://api.example.com", DOMAINS)[0] is True
    # hostname still matches allowlist; connect-time DNS check blocks loopback
    assert allow_url("http://localhost/health", DOMAINS)[0] is True


def test_url_rejects_private_and_loopback_ip_literals():
    assert allow_url("http://127.0.0.1:8080/", DOMAINS)[0] is False
    assert allow_url("http://10.0.0.5/", ["10.0.0.5"])[0] is False
    assert allow_url("http://192.168.1.1/", ["192.168.1.1"])[0] is False
    assert allow_url("http://172.16.0.1/", ["172.16.0.1"])[0] is False
    assert allow_url("http://169.254.1.1/", ["169.254.1.1"])[0] is False


def test_url_rejects_suffix_tricks_and_schemes():
    assert allow_url("https://example.com.evil.com", DOMAINS)[0] is False
    assert allow_url("https://notexample.com", DOMAINS)[0] is False
    assert allow_url("https://example.com.attacker.tld", DOMAINS)[0] is False
    assert allow_url("javascript:alert(1)", DOMAINS)[0] is False
    assert allow_url("file:///etc/passwd", DOMAINS)[0] is False
    assert allow_url("ftp://example.com", DOMAINS)[0] is False


def test_url_rejects_credentials_and_metadata():
    assert allow_url("https://user:pass@example.com", DOMAINS)[0] is False
    assert allow_url("http://169.254.169.254/latest/meta-data", DOMAINS)[0] is False
    assert allow_url("http://metadata.google.internal/", ["metadata.google.internal"])[0] is False


def test_empty_github_whitelist_denies():
    ok, _ = allow_repo("myorg/app", allowed_orgs=[])
    assert ok is False


def test_repo_allowlist():
    assert allow_repo("myorg/app", ORGS)[0] is True
    assert allow_repo("https://github.com/myusername/repo.git", ORGS)[0] is True
    assert allow_repo("myorg/agent-Mr", ORGS)[0] is True
    assert allow_repo("not-my-org/repo", ORGS)[0] is False
    assert allow_repo("git@github.com:myorg/app.git", ORGS)[0] is False
    assert allow_repo("https://gitlab.com/myorg/app", ORGS)[0] is False


def test_parse_github_repo_rejects_traversal():
    assert parse_github_repo("myorg/..") is None
    assert parse_github_repo("myorg/.") is None
    assert parse_github_repo("-evil/repo") is None


def test_empty_docker_whitelist_denies():
    assert allow_image("nginx:latest", allowed_registries=[])[0] is False


def test_docker_registry_extraction():
    assert extract_docker_registry("nginx:1.27") == "docker.io"
    assert extract_docker_registry("library/nginx") == "docker.io"
    assert extract_docker_registry("ghcr.io/myorg/app:latest") == "ghcr.io"
    assert extract_docker_registry("localhost:5000/foo:tag") == "localhost:5000"


def test_dns_rebinding_blocked(monkeypatch):
    import socket

    from app.services import policy as policy_mod

    def fake_addrinfo(host, port, *a, **k):
        if host in {"evil.example.com", "localhost"}:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(policy_mod.socket, "getaddrinfo", fake_addrinfo)
    ok, reason = assert_host_public("evil.example.com")
    assert ok is False
    assert "внутренн" in reason
    assert "127.0.0.1" not in reason
    assert assert_host_public("example.com")[0] is True
    assert assert_host_public("localhost")[0] is False


def test_assert_url_safe_requires_allowlist_and_public_ip(monkeypatch):
    from app.services import policy as policy_mod

    monkeypatch.setattr(
        policy_mod.socket,
        "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))],
    )
    ok, _ = assert_url_safe_to_connect("https://example.com/", )
    # uses settings allowlist from conftest which includes example.com
    assert ok is True


def test_docker_allowlist():
    assert allow_image("nginx:1.27", REGISTRIES)[0] is True
    assert allow_image("ghcr.io/myorg/app:latest", REGISTRIES)[0] is True
    assert allow_image("evil.registry.example/foo", REGISTRIES)[0] is False
    assert allow_image("nginx; rm -rf /", REGISTRIES)[0] is False
    assert allow_image("nginx$(reboot)", REGISTRIES)[0] is False
