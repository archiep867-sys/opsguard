from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from opsguard.approval import approve, is_approved
from opsguard.audit import AuditLog
from opsguard.decider_client import DeciderClient, DeciderUnavailable
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
        def json(self) -> object: return {"answers": {"risky": {"noul": 0.8}}}
    monkeypatch.setattr(httpx, "post", lambda *args, **kwargs: GoodResponse())
    result = DeciderClient().classify("kubectl apply -f x")
    assert result.available and result.risk_probability == 0.8
