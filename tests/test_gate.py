from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest
from strands.interventions import Deny, Proceed

from opsguard.audit import AuditLog
from opsguard.decider_client import DeciderUnavailable
from opsguard.gate import ApprovalStore, OpsGuardGate


class Offline:
    def classify(self, command: str):
        raise DeciderUnavailable("offline")


def event(command: str, environment: str = "staging", resource: str = "web", tool: str = "run_command"):
    return SimpleNamespace(tool_use={"name": tool, "input": {"command": command, "environment": environment, "resource_name": resource}},
                           agent=SimpleNamespace(messages=[]))


def test_safe_proceeds_and_block_is_denied() -> None:
    gate = OpsGuardGate(Offline())  # type: ignore[arg-type]
    assert isinstance(gate.before_tool_call(event("kubectl get pods")), Proceed)
    denied = gate.before_tool_call(event("terraform destroy"))
    assert isinstance(denied, Deny) and "BLOCKED" in denied.reason
    assert gate.log[-1]["action"] == "deny"


def test_review_is_denied_until_a_human_approves_the_exact_resource() -> None:
    gate = OpsGuardGate(Offline())  # type: ignore[arg-type]
    first = gate.before_tool_call(event("kubectl scale deployment web --replicas=3"))
    assert isinstance(first, Deny) and "REVIEW required" in first.reason
    request = gate.store.pending()[0]
    with pytest.raises(ValueError):
        gate.store.grant(request.request_id, "wrong-name")
    gate.store.grant(request.request_id, "web")
    assert isinstance(gate.before_tool_call(event("kubectl scale deployment web --replicas=3")), Proceed)


def test_approval_is_bound_to_command_and_target_and_single_use() -> None:
    gate = OpsGuardGate(Offline())  # type: ignore[arg-type]
    gate.before_tool_call(event("kubectl scale deployment web --replicas=3"))
    gate.store.grant(gate.store.pending()[0].request_id, "web")
    assert isinstance(gate.before_tool_call(event("kubectl scale deployment web --replicas=9")), Deny)  # different command
    assert isinstance(gate.before_tool_call(event("kubectl scale deployment web --replicas=3", resource="db")), Deny)  # different target
    message = gate.simulate_tool("kubectl scale deployment web --replicas=3", "staging", "web")
    assert "simulat" in message.lower()
    assert isinstance(gate.before_tool_call(event("kubectl scale deployment web --replicas=3")), Deny)  # consumed


def test_model_cannot_self_approve_through_tool_arguments() -> None:
    gate = OpsGuardGate(Offline())  # type: ignore[arg-type]
    sneaky = event("kubectl scale deployment web --replicas=3")
    sneaky.tool_use["input"].update(approved=True, confirmation="web")
    assert isinstance(gate.before_tool_call(sneaky), Deny)
    assert "denied" in gate.simulate_tool("kubectl scale deployment web --replicas=3", "staging", "web").lower()  # no human approval exists


def test_unknown_tools_are_denied_and_failures_fail_closed() -> None:
    gate = OpsGuardGate(Offline())  # type: ignore[arg-type]
    assert isinstance(gate.before_tool_call(event("pwd", tool="shell")), Deny)
    assert gate.on_error == "deny"


def test_simulation_never_runs_blocked_commands() -> None:
    gate = OpsGuardGate(Offline())  # type: ignore[arg-type]
    assert "denied" in gate.simulate_tool("rm -rf /", "prod", "root").lower()
    assert "denied" in gate.simulate_tool("terraform destroy", "prod", "stack").lower()


def test_gate_decisions_are_audited(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path / "audit.sqlite3")
    gate = OpsGuardGate(Offline(), audit=audit)  # type: ignore[arg-type]
    gate.before_tool_call(event("kubectl get pods"))
    events = audit.events()
    assert len(events) == 1 and events[0].channel == "agent" and events[0].decision == "SAFE"


def test_store_rejects_unknown_requests() -> None:
    with pytest.raises(ValueError):
        ApprovalStore().grant(99, "x")


def test_package_contains_no_execution_paths() -> None:
    """No shell/process/eval APIs anywhere in the application package."""
    banned_calls = {"system", "popen", "run", "Popen", "call", "check_output", "exec", "eval", "execv", "spawn"}
    banned_imports = {"subprocess", "pty", "ctypes"}
    for path in (Path(__file__).parents[1] / "opsguard").glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not banned_imports & {alias.name.split(".")[0] for alias in node.names}, path.name
            if isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in banned_imports, path.name
            if isinstance(node, ast.Call):
                name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
                assert name not in banned_calls, f"{path.name}: {name}"
