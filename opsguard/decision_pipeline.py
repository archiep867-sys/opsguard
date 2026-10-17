"""Combine a deterministic safety floor with validated Strands Decider output."""

from __future__ import annotations

from dataclasses import dataclass, replace

from .decider_client import DeciderClient, DeciderInvalidResponse, DeciderUnavailable
from .safety_engine import Decision, Evaluation, evaluate_command

_SEVERITY = {Decision.SAFE: 0, Decision.REVIEW: 1, Decision.BLOCK: 2}


@dataclass(frozen=True)
class PipelineDecision:
    deterministic: Evaluation
    final: Evaluation
    decider_called: bool
    decider_status: str
    model_verdict: Decision | None
    model_probabilities: dict[str, float] | None
    model_confidence: float | None
    latency_ms: float | None
    failure_reason: str | None
    source: str


def decide(command: str, client: DeciderClient) -> PipelineDecision:
    """Apply hard policy first; the model may only make the outcome stricter."""
    deterministic = evaluate_command(command)
    if deterministic.decision is Decision.BLOCK:
        return PipelineDecision(deterministic, deterministic, False, "HARD_BLOCK", None, None, None, None, None, "deterministic policy")
    try:
        result = client.classify(command)
    except DeciderInvalidResponse as exc:
        final = replace(deterministic, decision=Decision.BLOCK, category="decider-invalid", reasons=(*deterministic.reasons, "Decider response was invalid; blocked conservatively."))
        return PipelineDecision(deterministic, final, True, "DECIDER_INVALID", None, None, None, None, str(exc), "combined verdict")
    except DeciderUnavailable as exc:
        return PipelineDecision(deterministic, deterministic, True, "DECIDER_OFFLINE", None, None, None, None, str(exc), "deterministic policy")

    final_decision = max((deterministic.decision, result.verdict), key=_SEVERITY.__getitem__)
    final = deterministic if final_decision is deterministic.decision else replace(
        deterministic,
        decision=final_decision,
        category="decider-escalation",
        reasons=(*deterministic.reasons, f"Strands Decider escalated this operation to {final_decision.value}."),
    )
    source = "combined verdict" if final_decision is not deterministic.decision else "deterministic policy and Decider"
    return PipelineDecision(deterministic, final, True, "DECIDER_USED", result.verdict, result.probabilities, result.confidence, result.latency_ms, None, source)
