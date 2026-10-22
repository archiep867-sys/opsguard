from __future__ import annotations

import pytest

from opsguard.redaction import REDACTED, contains_secret, redact

SECRETS = [
    "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE",
    'curl -H "Authorization: Bearer abcdefghijklmnop123456" https://api.example.com',
    "curl -H 'Authorization: Basic dXNlcjpwYXNzd29yZA==' https://x",
    "psql postgres://admin:hunter2@db.internal:5432/app",
    "mysql -u root --password=hunter2 app",
    "mysql --password hunter2 app",
    "git clone https://ghp_" + "a" * 36 + "@github.com/org/repo",
    "export API_KEY=abc123def456",
    "token: abcdef123456",
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
    "slack xoxb-123456789012-abcdefghijkl",
    "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N",
]
VALUES = ["wJalrXUtnFEMI", "AKIAIOSFODNN7EXAMPLE", "abcdefghijklmnop123456", "dXNlcjpwYXNzd29yZA==", "hunter2",
          "abc123def456", "abcdef123456", "MIIEowIBAAKCAQEA", "xoxb-123456789012", "dozjgNryP4J3jVmNHl0w5N"]


@pytest.mark.parametrize("text", SECRETS)
def test_common_secret_shapes_are_redacted(text: str) -> None:
    cleaned = redact(text)
    assert REDACTED in cleaned
    assert not any(value in cleaned for value in VALUES)
    assert not contains_secret(cleaned)  # idempotent: nothing left to redact


@pytest.mark.parametrize("text", ["kubectl get pods -n production", "git status", "ls -la /var/log", "terraform plan"])
def test_ordinary_commands_are_untouched(text: str) -> None:
    assert redact(text) == text
    assert not contains_secret(text)


def test_length_is_bounded() -> None:
    assert len(redact("a" * 10_000, limit=100)) == 100
