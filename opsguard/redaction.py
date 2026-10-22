"""One shared secret redactor for audit storage and anything sent to Amazon Bedrock.

This is defence in depth, not a guarantee: pattern-based redaction cannot catch every
secret. Do not paste credentials or private data into OpsGuard.
"""

from __future__ import annotations

import re

REDACTED = "[REDACTED_SECRET]"
DEFAULT_LIMIT = 4_000

_FLAGS = r"(?:password|passwd|pass|pwd|token|secret|api-key|apikey|access-key|secret-key|auth)"
_ASSIGN_KEY = r"[A-Za-z0-9_.\-]*(?:api[_-]?key|access[_-]?key|secret|token|passwd|password|pwd|credential|session[_-]?token|private[_-]?key)[A-Za-z0-9_.\-]*"

# Each entry is (compiled pattern, replacement). Order matters: block-level secrets first.
_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)", re.S), REDACTED),
    (re.compile(r"(?i)(\b[a-z][a-z0-9+.\-]*://)[^/\s:@]+:[^/\s@]+@"), r"\1" + REDACTED + "@"),
    (re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA|A3T[A-Z0-9])[A-Z0-9]{16}\b"), REDACTED),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b"), REDACTED),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"), REDACTED),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b"), REDACTED),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), REDACTED),
    (re.compile(r"(?i)(\bauthorization\s*[:=]\s*)(?:(?:basic|bearer|token)\s+)?[^\s,;]+"), r"\1" + REDACTED),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=\-]{8,}"), "Bearer " + REDACTED),
    (re.compile(r"(?i)((?<![\w-])--?" + _FLAGS + r"(?:=|\s+))(?!-)\S+"), r"\1" + REDACTED),
    (re.compile(r"(?i)(\b" + _ASSIGN_KEY + r"\s*(?:=|:)\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"), r"\1" + REDACTED),
)


def redact(value: str | None, *, limit: int | None = DEFAULT_LIMIT) -> str | None:
    """Replace common credential shapes and bound the length of untrusted text."""
    if value is None:
        return None
    text = str(value)
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text if limit is None else text[:limit]


def contains_secret(value: str | None) -> bool:
    """True when redaction would still change the text (i.e. it was not already clean)."""
    if not value:
        return False
    return redact(value, limit=None) != value
