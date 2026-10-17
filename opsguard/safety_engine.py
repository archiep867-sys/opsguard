"""Conservative command classification. This module never executes commands."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from enum import StrEnum


class Decision(StrEnum):
    SAFE = "SAFE"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class Evaluation:
    command: str
    normalized_command: str | None
    decision: Decision
    category: str
    reasons: tuple[str, ...]
    confidence: float | None

    @property
    def human_approval_required(self) -> bool:
        return self.decision is Decision.REVIEW


_SHELL_SYNTAX = re.compile(r"(?:[;|&<>`]|\$\(|\$\{|\n|\r)")
_SAFE_EXACT = {"pwd", "ls", "git status"}

# Display metadata for the dashboard. Each rule maps directly to logic in
# ``evaluate_command``; it does not claim coverage that the evaluator lacks.
POLICY_RULES = (
    ("SAFE-001", "Explicit read-only allowlist", "SAFE", "Allows pwd, ls, and git status."),
    ("SAFE-002", "Read-only Kubernetes queries", "SAFE", "Allows kubectl get and kubectl describe."),
    ("BLOCK-001", "Shell syntax and obfuscation", "BLOCK", "Rejects chaining, pipes, redirects, substitutions, and control characters."),
    ("BLOCK-002", "Destructive operations", "BLOCK", "Rejects recursive deletion, Terraform destroy, Kubernetes deletion, destructive SQL, and cloud deletion."),
    ("REVIEW-001", "State-changing operations", "REVIEW", "Requires review for Kubernetes changes, service control, permissions, cloud operations, and file writes."),
    ("BLOCK-003", "Unknown commands", "BLOCK", "Fails closed for commands outside the explicit policy."),
)


def _blocked(command: str, category: str, reason: str) -> Evaluation:
    return Evaluation(command, None, Decision.BLOCK, category, (reason,), 1.0)


def evaluate_command(command: str) -> Evaluation:
    """Classify a single command without invoking a shell; uncertainty blocks it."""
    if not isinstance(command, str) or not command.strip():
        return _blocked(str(command), "malformed", "Command is empty or malformed.")
    if "\x00" in command or _SHELL_SYNTAX.search(command):
        return _blocked(command, "shell-syntax", "Shell chaining, redirection, substitution, or obfuscation is prohibited.")
    try:
        parts = shlex.split(command, posix=True)
    except ValueError:
        return _blocked(command, "malformed", "Command could not be parsed safely.")
    if not parts:
        return _blocked(command, "malformed", "Command is empty or malformed.")
    normalized = " ".join(parts)
    program = parts[0].lower()
    lower = [part.lower() for part in parts]

    if program == "rm" and any(flag in {"-r", "-f", "-rf", "-fr", "--recursive", "--force"} for flag in lower):
        return _blocked(command, "destructive", "Recursive or forced file deletion is prohibited.")
    if program == "terraform" and len(lower) > 1 and lower[1] == "destroy":
        return _blocked(command, "destructive", "Terraform destroy is prohibited.")
    if program == "kubectl" and len(lower) > 1 and lower[1] == "delete":
        return _blocked(command, "destructive", "Kubernetes deletion is prohibited.")
    if program in {"sql", "psql", "mysql", "sqlite3"} and re.search(
        r"\b(?:drop|truncate|delete)\b", " ".join(lower)
    ):
        return _blocked(command, "destructive", "Destructive database statements are prohibited.")
    if program in {"aws", "gcloud", "az"} and any(
        word in {"delete", "terminate", "destroy"}
        or word.startswith(("delete-", "terminate-", "destroy-"))
        for word in lower
    ):
        return _blocked(command, "destructive", "Cloud resource deletion is prohibited.")

    if normalized in _SAFE_EXACT:
        return Evaluation(command, normalized, Decision.SAFE, "read-only", ("Explicit read-only allowlist match.",), 1.0)
    if program == "ls" and all(not arg.startswith("-") or arg in {"-a", "-l", "-la", "-al", "-h"} for arg in parts[1:]):
        return Evaluation(command, normalized, Decision.SAFE, "read-only", ("Read-only directory listing.",), 0.98)
    if parts[:2] == ["git", "status"] and len(parts) <= 3:
        return Evaluation(command, normalized, Decision.SAFE, "read-only", ("Read-only Git status.",), 0.98)
    if program == "kubectl" and len(parts) >= 2 and parts[1] in {"get", "describe"}:
        return Evaluation(command, normalized, Decision.SAFE, "read-only", ("Read-only Kubernetes query.",), 0.95)

    if program == "kubectl" and len(parts) >= 2 and parts[1] in {"apply", "patch", "scale", "rollout", "edit"}:
        reason = f"Kubernetes {parts[1]} changes cluster state."
    elif program in {"systemctl", "service", "launchctl"}:
        reason = "Service management can restart or alter a running service."
    elif program in {"chmod", "chown", "sudo", "terraform", "aws", "gcloud", "az"}:
        reason = "Infrastructure, permission, or cloud operation requires human review."
    elif program in {"cp", "mv", "touch", "mkdir", "tee", "sed", "python", "python3"}:
        reason = "Command can modify files or execute code and requires human review."
    else:
        return _blocked(command, "unknown", "Command is not in the explicit read-only allowlist.")
    return Evaluation(command, normalized, Decision.REVIEW, "mutation", (reason,), 0.75)
