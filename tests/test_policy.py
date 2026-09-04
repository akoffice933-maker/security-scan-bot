from app.services.policy import (
    allow_image,
    allow_repo,
    allow_url,
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
    assert allow_url("http://127.0.0.1:8080/", DOMAINS)[0] is True
    assert allow_url("http://localhost/health", DOMAINS)[0] is True


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


def test_docker_allowlist():
    assert allow_image("nginx:1.27", REGISTRIES)[0] is True
    assert allow_image("ghcr.io/myorg/app:latest", REGISTRIES)[0] is True
    assert allow_image("evil.registry.example/foo", REGISTRIES)[0] is False
    assert allow_image("nginx; rm -rf /", REGISTRIES)[0] is False
    assert allow_image("nginx$(reboot)", REGISTRIES)[0] is False
