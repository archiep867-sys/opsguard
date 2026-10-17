"""Immutable review records tied to exactly one command and resource."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .safety_engine import Decision, Evaluation


def command_fingerprint(command: str) -> str:
    return hashlib.sha256(command.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Approval:
    command_digest: str
    environment: str
    resource_name: str
    approved: bool
    confirmation_required: bool


def approve(evaluation: Evaluation, environment: str, resource_name: str, confirmation: str) -> Approval:
    if evaluation.decision is Decision.BLOCK:
        raise ValueError("BLOCK decisions cannot be approved.")
    if evaluation.decision is Decision.SAFE:
        return Approval(command_fingerprint(evaluation.command), environment, resource_name, True, False)
    if not environment.strip() or not resource_name.strip():
        raise ValueError("Environment and resource name are required for review.")
    if confirmation != resource_name:
        raise ValueError("Resource confirmation must exactly match the intended resource name.")
    return Approval(command_fingerprint(evaluation.command), environment, resource_name, True, True)


def is_approved(
    approval: Approval | None,
    evaluation: Evaluation,
    environment: str | None = None,
    resource_name: str | None = None,
) -> bool:
    """Validate that approval still belongs to this command and, when supplied, target."""
    return (
        approval is not None
        and approval.approved
        and approval.command_digest == command_fingerprint(evaluation.command)
        and (environment is None or approval.environment == environment)
        and (resource_name is None or approval.resource_name == resource_name)
    )
