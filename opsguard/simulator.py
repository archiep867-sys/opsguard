"""Simulation only: this module intentionally has no process-execution API."""

from __future__ import annotations

from dataclasses import dataclass

from .approval import Approval, is_approved
from .safety_engine import Decision, Evaluation


@dataclass(frozen=True)
class SimulationResult:
    allowed: bool
    message: str


def simulate(
    evaluation: Evaluation,
    approval: Approval | None = None,
    *,
    environment: str | None = None,
    resource_name: str | None = None,
) -> SimulationResult:
    if evaluation.decision is Decision.BLOCK:
        return SimulationResult(False, "Simulation denied: blocked commands are never executed or simulated as approved.")
    if evaluation.decision is Decision.REVIEW and not is_approved(
        approval, evaluation, environment, resource_name
    ):
        return SimulationResult(False, "Simulation denied: explicit approval and exact resource confirmation are required.")
    return SimulationResult(True, f"SIMULATION ONLY: would propose {evaluation.command!r}; no shell, host, cloud, cluster, file, or database action was performed.")
