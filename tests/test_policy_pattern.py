from types import SimpleNamespace

from strands.interventions import Deny, Proceed

from decider_patterns.policy_gate.policy_gate import PolicyGate
from decider_patterns.policy_gate.policy_question import QUESTION_ID, build_payload


def ev(cmd, tool="run_command"):
    return SimpleNamespace(tool_use={"name": tool, "input": {"command": cmd}}, agent=SimpleNamespace(messages=[]))


def make(verdict, conf, approved=False):
    return PolicyGate(lambda a: (verdict, conf), "run_command", "command", 0.5, lambda a: approved)


def test_safe_confident_proceeds():
    assert isinstance(make("safe", 0.9).before_tool_call(ev("ls")), Proceed)


def test_safe_low_confidence_denied():
    assert isinstance(make("safe", 0.2).before_tool_call(ev("ls")), Deny)


def test_review_needs_human():
    assert isinstance(make("review", 0.9).before_tool_call(ev("x")), Deny)
    assert isinstance(make("review", 0.9, approved=True).before_tool_call(ev("x")), Proceed)


def test_block_never_proceeds_even_if_approved():
    assert isinstance(make("block", 0.99, approved=True).before_tool_call(ev("rm -rf /")), Deny)


def test_other_tools_denied():
    assert isinstance(make("safe", 0.9).before_tool_call(ev("ls", tool="shell")), Deny)


def test_payload_shape():
    payload = build_payload("ls")
    assert payload["questions"][QUESTION_ID]["type"] == "choice"
