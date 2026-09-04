from app.services.textutil import mask_secrets, split_message, truncate


def test_mask_aws_and_github():
    text = "key=AKIAIOSFODNN7EXAMPLE token=ghp_" + ("a" * 36)
    masked = mask_secrets(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in masked
    assert "ghp_aaa" not in masked
    assert "AKIA***" in masked


def test_mask_private_key_header():
    assert "***PRIVATE KEY***" in mask_secrets("-----BEGIN RSA PRIVATE KEY-----")


def test_split_and_truncate():
    assert truncate("abcdef", 4).endswith("…")
    parts = split_message("a" * 50, limit=20)
    assert len(parts) == 3
    assert "".join(parts) == "a" * 50
