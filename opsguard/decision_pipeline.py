"""Combine a deterministic safety floor with validated Strands Decider output.

The invariants (all covered by tests):
* Hard destructive/obfuscated/malformed commands are BLOCKED without calling the model.
* The model can only make a verdict stricter, with one exception: a command that is merely
  *unknown* (not recognised as destructive) may be routed to human REVIEW instead of BLOCK.
  The model can never produce SAFE for such a command, and a missing, invalid, or
  low-confidence model answer leaves it blocked.
* A low-confidence BLOCK vote escalates only to REVIEW (a human decides), not to BLOCK.
"""

from __future__ import annotations

import os
import shlex
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
    model_assisted: bool = False


def _env_flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    return default if raw is None else raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return default


def decide(
    command: str,
    client: DeciderClient,
    *,
    model_assist: bool | None = None,
    min_confidence: float | None = None,
) -> PipelineDecision:
    """Apply hard policy first, then let the Decider tighten (or triage) the result."""
    assist = _env_flag("OPSGUARD_MODEL_ASSISTED_UNKNOWN", True) if model_assist is None else model_assist
    floor = _env_float("OPSGUARD_MIN_MODEL_CONFIDENCE", 0.5) if min_confidence is None else min_confidence
    deterministic = evaluate_command(command)
    unknown = deterministic.decision is Decision.BLOCK and deterministic.category == "unknown"

    if deterministic.decision is Decision.BLOCK and not (unknown and assist):
        return PipelineDecision(deterministic, deterministic, False, "HARD_BLOCK", None, None, None, None, None, "deterministic policy")

    try:
        result = client.classify(command)
    except DeciderInvalidResponse as exc:
        reason = "Decider response was invalid; blocked conservatively."
        final = replace(deterministic, decision=Decision.BLOCK, category="decider-invalid", reasons=(*deterministic.reasons, reason))
        return PipelineDecision(deterministic, final, True, "DECIDER_INVALID", None, None, None, None, str(exc), "combined verdict")
    except DeciderUnavailable as exc:
        if unknown:
            final = replace(deterministic, reasons=(*deterministic.reasons, "Decider is offline, so this unknown command stays blocked."))
            return PipelineDecision(deterministic, final, True, "DECIDER_OFFLINE", None, None, None, None, str(exc), "deterministic policy")
        return PipelineDecision(deterministic, deterministic, True, "DECIDER_OFFLINE", None, None, None, None, str(exc), "deterministic policy")

    if unknown:
        if result.verdict is Decision.BLOCK or result.confidence < floor:
            why = (
                f"Strands Decider voted {result.verdict.value} (confidence {result.confidence:.2f}); "
                f"the unknown command stays blocked."
            )
            final = replace(deterministic, reasons=(*deterministic.reasons, why), confidence=result.confidence)
            return PipelineDecision(deterministic, final, True, "DECIDER_USED", result.verdict, result.probabilities, result.confidence, result.latency_ms, None, "combined verdict")
        try:
            normalized = " ".join(shlex.split(command))
        except ValueError:  # pragma: no cover - unknown implies it already parsed
            normalized = None
        final = replace(
            deterministic,
            normalized_command=normalized,
            decision=Decision.REVIEW,
            category="model-assisted",
            reasons=(
                "Command is outside the explicit allowlist. Strands Decider voted "
                f"{result.verdict.value} (confidence {result.confidence:.2f}), so it needs human review. "
                "A model vote alone never makes an unknown command SAFE.",
            ),
            confidence=result.confidence,
            rule_ids=(*deterministic.rule_ids, "MODEL-001"),
        )
        return PipelineDecision(deterministic, final, True, "DECIDER_USED", result.verdict, result.probabilities, result.confidence, result.latency_ms, None, "decider-assisted triage", True)

    effective = result.verdict
    if effective is Decision.BLOCK and result.confidence < floor:
        effective = Decision.REVIEW
    final_decision = max((deterministic.decision, effective), key=_SEVERITY.__getitem__)
    if final_decision is deterministic.decision:
        final = deterministic
    else:
        note = f"Strands Decider escalated this operation to {final_decision.value}."
        if effective is not result.verdict:
            note += f" (Its {result.verdict.value} vote had low confidence {result.confidence:.2f}, so a human decides.)"
        final = replace(deterministic, decision=final_decision, category="decider-escalation", reasons=(*deterministic.reasons, note))
    source = "combined verdict" if final_decision is not deterministic.decision else "deterministic policy and Decider"
    return PipelineDecision(deterministic, final, True, "DECIDER_USED", result.verdict, result.probabilities, result.confidence, result.latency_ms, None, source)
