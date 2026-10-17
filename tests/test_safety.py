from __future__ import annotations

import sqlite3
from pathlib import Path

import httpx
import pytest

from opsguard.approval import approve, is_approved
from opsguard.audit import AuditLog
from opsguard.decider_client import DeciderClient, DeciderInvalidResponse, DeciderResult, DeciderUnavailable
from opsguard.decision_pipeline import decide
from opsguard.safety_engine import Decision, evaluate_command
from opsguard.simulator import simulate


@pytest.mark.parametrize("command", ["pwd", "ls -la", "git status", "kubectl get pods", "kubectl describe pod api"])
def test_read_only_commands_are_safe(command: str) -> None:
    assert evaluate_command(command).decision is Decision.SAFE


@pytest.mark.parametrize("command", ["rm -rf /", "terraform destroy", "kubectl delete pod api", "psql -c 'DROP TABLE users'", "aws ec2 terminate-instances --instance-ids i-1"])
def test_destructive_commands_are_blocked(command: str) -> None:
    assert evaluate_command(command).decision is Decision.BLOCK


@pytest.mark.parametrize("command", ["pwd; rm -rf /", "ls | sh", "$(whoami)", "kubectl get pods > out"])
def test_shell_syntax_is_blocked(command: str) -> None:
    assert evaluate_command(command).decision is Decision.BLOCK


def test_malformed_and_unknown_commands_fail_closed() -> None:
    assert evaluate_command("'").decision is Decision.BLOCK
    assert evaluate_command("unknown-tool inspect").decision is Decision.BLOCK


def test_review_requires_exact_resource_confirmation_and_changed_command_invalidates_approval() -> None:
    evaluation = evaluate_command("kubectl apply -f deployment.yaml")
    assert evaluation.decision is Decision.REVIEW
    with pytest.raises(ValueError, match="exactly"):
        approve(evaluation, "prod", "api", "API")
    approval = approve(evaluation, "prod", "api", "api")
    assert is_approved(approval, evaluation)
    assert not is_approved(approval, evaluate_command("kubectl apply -f other.yaml"))
    assert not is_approved(approval, evaluation, "staging", "api")
    assert not is_approved(approval, evaluation, "prod", "other-api")


def test_blocked_commands_cannot_simulate_or_be_approved() -> None:
    evaluation = evaluate_command("rm -rf /tmp/data")
    with pytest.raises(ValueError):
        approve(evaluation, "prod", "data", "data")
    assert not simulate(evaluation).allowed


def test_simulation_never_invokes_shell() -> None:
    result = simulate(evaluate_command("pwd"))
    assert result.allowed and "no shell" in result.message


def test_audit_log_persists(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.sqlite3")
    log.record(evaluate_command("pwd"), decider_available=False, environment="dev", resource_name="workspace")
    assert log.recent()[0][1] == "pwd"
    assert log.metrics()["SAFE"] == 1
    assert log.events(environment="dev")[0].resource_name == "workspace"


def test_audit_redacts_common_secret_assignments(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.sqlite3")
    log.record(evaluate_command("unknown TOKEN=not-for-storage"), decider_available=False)
    assert "not-for-storage" not in log.events()[0].command


def test_audit_database_path_can_be_configured(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    database = tmp_path / "writable" / "audit.sqlite3"
    monkeypatch.setenv("OPSGUARD_DB_PATH", str(database))
    log = AuditLog()
    log.record(evaluate_command("pwd"), decider_available=False)
    assert database.exists()


def test_decider_timeout_and_invalid_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    def timeout(*args: object, **kwargs: object) -> object:
        raise httpx.ConnectTimeout("no server")
    monkeypatch.setattr(httpx, "post", timeout)
    with pytest.raises(DeciderUnavailable):
        DeciderClient().classify("pwd")

    class BadResponse:
        def raise_for_status(self) -> None: pass
        def json(self) -> object: return {"answers": {}}
    monkeypatch.setattr(httpx, "post", lambda *args, **kwargs: BadResponse())
    with pytest.raises(DeciderUnavailable):
        DeciderClient().classify("pwd")


def test_decider_response_is_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    class GoodResponse:
        def raise_for_status(self) -> None: pass
        def json(self) -> object:
            return {"answers": {"opsguard_verdict": {"type": "choice", "choice": "review", "probabilities": {"safe": 0.1, "review": 0.8, "block": 0.1}, "confidence": 0.7}}, "latency_ms": 12.5}
    monkeypatch.setattr(httpx, "post", lambda *args, **kwargs: GoodResponse())
    result = DeciderClient().classify("kubectl apply -f x")
    assert result.verdict is Decision.REVIEW
    assert result.probabilities["review"] == 0.8
    assert result.confidence == 0.7 and result.latency_ms == 12.5


@pytest.mark.parametrize("response", [
    {"answers": {}},
    {"answers": {"opsguard_verdict": {"type": "choice", "choice": "unknown", "probabilities": {"safe": 0.1, "review": 0.8, "block": 0.1}, "confidence": 0.7}}},
    {"answers": {"opsguard_verdict": {"type": "choice", "choice": "safe", "probabilities": {"safe": 0.1, "review": 0.8, "block": 0.1}, "confidence": 1.2}}},
    {"answers": {"opsguard_verdict": {"type": "choice", "choice": "safe", "probabilities": {"safe": 0.1, "review": 0.8}, "confidence": 0.7}}},
])
def test_decider_rejects_invalid_choice_responses(monkeypatch: pytest.MonkeyPatch, response: object) -> None:
    class Response:
        def raise_for_status(self) -> None: pass
        def json(self) -> object: return response
    monkeypatch.setattr(httpx, "post", lambda *args, **kwargs: Response())
    with pytest.raises(DeciderInvalidResponse):
        DeciderClient().classify("pwd")


class FakeDecider:
    def __init__(self, verdict: Decision | None = None, error: Exception | None = None) -> None:
        self.verdict, self.error, self.calls = verdict, error, 0

    def classify(self, command: str) -> DeciderResult:
        self.calls += 1
        if self.error:
            raise self.error
        assert self.verdict is not None
        return DeciderResult(self.verdict, {"safe": 0.1, "review": 0.2, "block": 0.7}, 0.6, 9.0, "mock")


def test_pipeline_uses_valid_model_safe_verdict() -> None:
    result = decide("pwd", FakeDecider(Decision.SAFE))  # type: ignore[arg-type]
    assert result.final.decision is Decision.SAFE
    assert result.model_verdict is Decision.SAFE and result.source == "deterministic policy and Decider"


def test_pipeline_allows_model_to_escalate_to_review_or_block() -> None:
    review = decide("pwd", FakeDecider(Decision.REVIEW))  # type: ignore[arg-type]
    block = decide("pwd", FakeDecider(Decision.BLOCK))  # type: ignore[arg-type]
    assert review.final.decision is Decision.REVIEW and review.final.category == "decider-escalation"
    assert block.final.decision is Decision.BLOCK


def test_pipeline_never_downgrades_deterministic_review_or_block() -> None:
    review_client = FakeDecider(Decision.SAFE)
    review = decide("kubectl apply -f deployment.yaml", review_client)  # type: ignore[arg-type]
    blocked_client = FakeDecider(Decision.SAFE)
    blocked = decide("rm -rf /tmp/data", blocked_client)  # type: ignore[arg-type]
    assert review.final.decision is Decision.REVIEW and review.model_verdict is Decision.SAFE
    assert blocked.final.decision is Decision.BLOCK and blocked.decider_status == "HARD_BLOCK"
    assert blocked_client.calls == 0


def test_pipeline_offline_and_invalid_responses_are_explicit_and_safe() -> None:
    offline = decide("pwd", FakeDecider(error=DeciderUnavailable("offline")))  # type: ignore[arg-type]
    invalid = decide("pwd", FakeDecider(error=DeciderInvalidResponse("bad response")))  # type: ignore[arg-type]
    assert offline.final.decision is Decision.SAFE and offline.decider_status == "DECIDER_OFFLINE"
    assert invalid.final.decision is Decision.BLOCK and invalid.decider_status == "DECIDER_INVALID"


def test_audit_records_pipeline_metadata(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.sqlite3")
    pipeline = decide("pwd", FakeDecider(Decision.REVIEW))  # type: ignore[arg-type]
    log.record(pipeline.final, decider_available=True, pipeline=pipeline, environment="dev", resource_name="api")
    event = log.events()[0]
    assert event.deterministic_decision == "SAFE"
    assert event.matched_rule_ids == '["SAFE-001"]'
    assert event.decider_status == "DECIDER_USED" and event.model_verdict == "REVIEW"
    assert event.model_confidence == 0.6 and event.decider_latency_ms == 9.0


def test_audit_migrates_existing_schema_without_losing_events(tmp_path: Path) -> None:
    database = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(database) as conn:
        conn.execute("""CREATE TABLE audit_events (
            id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, command TEXT NOT NULL,
            normalized_command TEXT, decision TEXT NOT NULL, category TEXT NOT NULL,
            reasons TEXT NOT NULL, decider_available INTEGER NOT NULL,
            approval_outcome TEXT, confirmation_outcome TEXT, simulation_result TEXT
        )""")
        conn.execute("""INSERT INTO audit_events VALUES
            (1, '2026-01-01T00:00:00+00:00', 'pwd', 'pwd', 'SAFE', 'read-only', '[]', 0, NULL, NULL, NULL)""")
    log = AuditLog(database)
    assert log.events()[0].command == "pwd"
    log.record(evaluate_command("pwd"), decider_available=False)
    assert len(log.events()) == 2
