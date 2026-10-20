import pytest

from opsguard.redaction import REDACTED, contains_secret, redact


@pytest.mark.parametrize("text,secret", [
    ("export AWS_SECRET_ACCESS_KEY=abc123", "abc123"),
    ('curl -H "Authorization: Bearer abcdefgh12345" x', "abcdefgh12345"),
    ("AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
    ("postgres://u:p4ss@db/x", "p4ss"),
    ("mysql --password hunter2 db", "hunter2"),
    ("mysql --password=hunter2 db", "hunter2"),
    ("token: abcd", "abcd"),
    ("ghp_" + "a" * 30, "a" * 30),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIx\n-----END RSA PRIVATE KEY-----", "MIIx"),
])
def test_secrets_are_removed(text, secret):
    out = redact(text)
    assert secret not in out
    assert REDACTED in out


@pytest.mark.parametrize("text", ["kubectl get pods", "git status", "kubectl get pods -n production --token"])
def test_clean_text_unchanged(text):
    assert redact(text) == text
    assert not contains_secret(text)


def test_length_is_bounded():
    assert len(redact("a" * 10_000)) == 4_000
    assert redact(None) is None
