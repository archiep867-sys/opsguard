from __future__ import annotations

import sqlite3
from pathlib import Path

from opsguard.audit import AuditLog
from opsguard.bedrock_client import (BEDROCK_DISABLED, BEDROCK_INVALID, BEDROCK_SUCCESS, BEDROCK_UNAVAILABLE,
                                     ExplanationResult)
from opsguard.decider_client import DeciderUnavailable
from opsguard.decision_pipeline import decide
from opsguard.safety_engine import evaluate_command


class Offline:
    def classify(self, command: str):
        raise DeciderUnavailable("off")


def explanation(status: str, source: str = "local_template", attempted: bool = False, category: str | None = None,
                latency: float | None = None) -> ExplanationResult:
    return ExplanationResult(status, source, "SECRET-FREE TEXT THAT MUST NOT BE STORED", "example.model", latency, category, attempted)


def test_states_are_distinguishable_and_metadata_only(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "a.sqlite3")
    cases = [explanation(BEDROCK_DISABLED), explanation(BEDROCK_SUCCESS, "bedrock", True, None, 120.5),
             explanation(BEDROCK_UNAVAILABLE, attempted=True, category="throttled", latency=40.0), explanation(BEDROCK_INVALID, attempted=True, category="invalid_response")]
    for case in cases:
        pipeline = decide("pwd", Offline())  # type: ignore[arg-type]
        event_id = log.record(pipeline.final, decider_available=False, pipeline=pipeline)
        log.attach_explanation(event_id, case)
    stored = {row.bedrock_status: row for row in log.events()}
    assert set(stored) == {BEDROCK_DISABLED, BEDROCK_SUCCESS, BEDROCK_UNAVAILABLE, BEDROCK_INVALID}
    assert stored[BEDROCK_SUCCESS].bedrock_invoked and stored[BEDROCK_SUCCESS].bedrock_attempted
    assert stored[BEDROCK_SUCCESS].bedrock_latency_ms == 120.5
    assert not stored[BEDROCK_DISABLED].bedrock_attempted and not stored[BEDROCK_DISABLED].bedrock_invoked
    assert stored[BEDROCK_UNAVAILABLE].bedrock_attempted and not stored[BEDROCK_UNAVAILABLE].bedrock_invoked
    assert stored[BEDROCK_UNAVAILABLE].bedrock_error_category == "throttled"


def test_no_prompt_or_response_text_is_stored(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "a.sqlite3")
    pipeline = decide("pwd", Offline())  # type: ignore[arg-type]
    event_id = log.record(pipeline.final, decider_available=False, pipeline=pipeline)
    log.attach_explanation(event_id, explanation(BEDROCK_SUCCESS, "bedrock", True))
    with sqlite3.connect(log.path) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(audit_events)")}
        dump = " ".join(str(value) for row in conn.execute("SELECT * FROM audit_events") for value in row)
    assert not {name for name in columns if "prompt" in name or "response" in name or name.endswith("_text")}
    assert "MUST NOT BE STORED" not in dump


def test_secrets_in_commands_are_redacted_before_storage(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "a.sqlite3")
    command = "curl -H 'Authorization: Bearer abcdefghijklmnop123456' AKIAIOSFODNN7EXAMPLE --password hunter2"
    log.record(evaluate_command(command), decider_available=False)
    with sqlite3.connect(log.path) as conn:
        dump = " ".join(str(value) for row in conn.execute("SELECT * FROM audit_events") for value in row)
    for leaked in ("abcdefghijklmnop123456", "AKIAIOSFODNN7EXAMPLE", "hunter2"):
        assert leaked not in dump


def test_metrics_and_filters_remain_compatible(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "a.sqlite3")
    for command in ("pwd", "kubectl apply -f x.yaml", "rm -rf /"):
        log.record(evaluate_command(command), decider_available=False)
    metrics = log.metrics()
    assert metrics == {"total": 3, "SAFE": 1, "REVIEW": 1, "BLOCK": 1}


def test_legacy_database_gains_new_columns(tmp_path: Path) -> None:
    database = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(database) as conn:
        conn.execute("""CREATE TABLE audit_events (
            id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, command TEXT NOT NULL,
            normalized_command TEXT, decision TEXT NOT NULL, category TEXT NOT NULL,
            reasons TEXT NOT NULL, decider_available INTEGER NOT NULL,
            approval_outcome TEXT, confirmation_outcome TEXT, simulation_result TEXT)""")
        conn.execute("INSERT INTO audit_events VALUES (1, '2026-01-01T00:00:00+00:00', 'pwd', 'pwd', 'SAFE', 'read-only', '[]', 0, NULL, NULL, NULL)")
    log = AuditLog(database)
    event_id = log.record(evaluate_command("ls"), decider_available=False)
    log.attach_explanation(event_id, explanation(BEDROCK_DISABLED))
    old, new = log.events()[-1], log.events()[0]
    assert {old.command, new.command} == {"pwd", "ls"}
    assert all(hasattr(row, "bedrock_attempted") for row in log.events())
