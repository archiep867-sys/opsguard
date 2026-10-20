from types import SimpleNamespace

import pytest

from opsguard.decider_client import DeciderInvalidResponse, DeciderUnavailable
from opsguard.decision_pipeline import decide
from opsguard.safety_engine import Decision


class Fake:
    def __init__(self, verdict=None, confidence=0.9, error=None):
        self.verdict, self.confidence, self.error, self.calls = verdict, confidence, error, 0

    def classify(self, command):
        self.calls += 1
        if self.error:
            raise self.error
        return SimpleNamespace(verdict=self.verdict, confidence=self.confidence,
                               probabilities={"safe": 0.1, "review": 0.1, "block": 0.8}, latency_ms=5.0)


def test_hard_block_never_calls_model():
    client = Fake(Decision.SAFE)
    result = decide("rm -rf /", client, model_assist=True)
    assert result.final.decision is Decision.BLOCK
    assert client.calls == 0


def test_safe_command_model_can_escalate():
    result = decide("kubectl get pods", Fake(Decision.BLOCK, 0.9), model_assist=True)
    assert result.final.decision is Decision.BLOCK


def test_low_confidence_block_becomes_review():
    result = decide("kubectl get pods", Fake(Decision.BLOCK, 0.2), model_assist=True, min_confidence=0.5)
    assert result.final.decision is Decision.REVIEW


def test_safe_command_offline_stays_safe():
    result = decide("kubectl get pods", Fake(error=DeciderUnavailable("off")), model_assist=True)
    assert result.final.decision is Decision.SAFE


def test_invalid_response_blocks():
    result = decide("kubectl get pods", Fake(error=DeciderInvalidResponse("bad")), model_assist=True)
    assert result.final.decision is Decision.BLOCK


@pytest.mark.parametrize("verdict", [Decision.SAFE, Decision.REVIEW])
def test_unknown_command_never_becomes_safe(verdict):
    result = decide("docker ps", Fake(verdict, 0.9), model_assist=True)
    assert result.final.decision is Decision.REVIEW


def test_unknown_command_blocked_when_model_votes_block_or_offline_or_unsure():
    assert decide("docker ps", Fake(Decision.BLOCK, 0.9), model_assist=True).final.decision is Decision.BLOCK
    assert decide("docker ps", Fake(error=DeciderUnavailable("off")), model_assist=True).final.decision is Decision.BLOCK
    assert decide("docker ps", Fake(Decision.SAFE, 0.2), model_assist=True, min_confidence=0.5).final.decision is Decision.BLOCK


def test_unknown_command_blocked_when_assist_disabled():
    client = Fake(Decision.SAFE)
    assert decide("docker ps", client, model_assist=False).final.decision is Decision.BLOCK
    assert client.calls == 0
