from types import SimpleNamespace

import pytest
from strands.interventions import Deny, Proceed

from opsguard.decider_client import DeciderUnavailable
from opsguard.gate import OpsGuardGate


class Offline:
    def classify(self, command):
        raise DeciderUnavailable("offline")


def event(command, environment="staging", resource="web", tool="run_command"):
    return SimpleNamespace(
        tool_use={"name": tool, "input": {"command": command, "environment": environment, "resource_name": resource}},
        agent=SimpleNamespace(messages=[]),
    )


def test_safe_proceeds():
    assert isinstance(OpsGuardGate(Offline()).before_tool_call(event("kubectl get pods")), Proceed)


def test_block_denied():
    assert isinstance(OpsGuardGate(Offline()).before_tool_call(event("rm -rf /")), Deny)


def test_other_tools_denied():
    assert isinstance(OpsGuardGate(Offline()).before_tool_call(event("pwd", tool="shell")), Deny)


def test_review_requires_human_and_is_single_use():
    gate = OpsGuardGate(Offline())
    cmd = "kubectl apply -f x.yaml"
    assert isinstance(gate.before_tool_call(event(cmd)), Deny)
    pending = gate.store.pending()
    assert len(pending) == 1
    with pytest.raises(ValueError):
        gate.store.grant(pending[0].request_id, "wrong-name")
    gate.store.grant(pending[0].request_id, "web")
    assert isinstance(gate.before_tool_call(event(cmd)), Proceed)
    assert gate.simulate_tool(cmd, "staging", "web").startswith("SIMULATION ONLY")
    assert isinstance(gate.before_tool_call(event(cmd)), Deny)


def test_approval_does_not_transfer_to_other_resource():
    gate = OpsGuardGate(Offline())
    cmd = "kubectl apply -f x.yaml"
    gate.before_tool_call(event(cmd))
    gate.store.grant(gate.store.pending()[0].request_id, "web")
    assert isinstance(gate.before_tool_call(event(cmd, resource="db")), Deny)
