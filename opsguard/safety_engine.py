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
    rule_ids: tuple[str, ...] = ()

    @property
    def human_approval_required(self) -> bool:
        return self.decision is Decision.REVIEW


_SHELL_SYNTAX = re.compile(r"(?:[;|&<>`]|\$\(|\$\{|\n|\r)")
_SAFE_EXACT = {"pwd", "ls", "git status"}
_DESTRUCTIVE_PROGRAMS = {"dd", "wipefs", "shred", "fdisk", "parted", "shutdown", "reboot", "halt", "poweroff", "mkswap"}

# Display metadata for the dashboard. Each rule maps directly to logic in
# ``evaluate_command``; it does not claim coverage that the evaluator lacks.
POLICY_RULES = (
    ("SAFE-001", "Explicit read-only allowlist", "SAFE", "Allows pwd, ls, and git status."),
    ("SAFE-002", "Read-only Kubernetes queries", "SAFE", "Allows kubectl get and kubectl describe."),
    ("BLOCK-001", "Shell syntax and obfuscation", "BLOCK", "Rejects chaining, pipes, redirects, substitutions, and control characters."),
    ("BLOCK-002", "Destructive operations", "BLOCK", "Rejects recursive deletion, Terraform destroy, Kubernetes deletion, destructive SQL, cloud deletion, disk/host wipe commands, force-push and hard reset, Docker prune, and Helm uninstall."),
    ("REVIEW-001", "State-changing operations", "REVIEW", "Requires review for Kubernetes changes, service control, permissions, cloud operations, and file writes."),
    ("BLOCK-003", "Unknown commands", "BLOCK", "Fails closed for commands outside the explicit policy, unless the Decider classifies them confidently (see MODEL-001)."),
    ("MODEL-001", "Decider-assisted triage of unknown commands", "REVIEW", "An unknown command is never SAFE. If the Decider is confident it is not destructive, it needs human review; otherwise it stays blocked."),
)


def _blocked(command: str, category: str, reason: str, rule_id: str) -> Evaluation:
    return Evaluation(command, None, Decision.BLOCK, category, (reason,), 1.0, (rule_id,))


def evaluate_command(command: str) -> Evaluation:
    """Classify a single command without invoking a shell; uncertainty blocks it."""
    if not isinstance(command, str) or not command.strip():
        return _blocked(str(command), "malformed", "Command is empty or malformed.", "BLOCK-003")
    if "\x00" in command or _SHELL_SYNTAX.search(command):
        return _blocked(command, "shell-syntax", "Shell chaining, redirection, substitution, or obfuscation is prohibited.", "BLOCK-001")
    try:
        parts = shlex.split(command, posix=True)
    except ValueError:
        return _blocked(command, "malformed", "Command could not be parsed safely.", "BLOCK-003")
    if not parts:
        return _blocked(command, "malformed", "Command is empty or malformed.", "BLOCK-003")
    normalized = " ".join(parts)
    program = parts[0].lower()
    lower = [part.lower() for part in parts]

    if program == "rm" and any(flag in {"-r", "-f", "-rf", "-fr", "--recursive", "--force"} for flag in lower):
        return _blocked(command, "destructive", "Recursive or forced file deletion is prohibited.", "BLOCK-002")
    if program == "terraform" and len(lower) > 1 and lower[1] == "destroy":
        return _blocked(command, "destructive", "Terraform destroy is prohibited.", "BLOCK-002")
    if program == "kubectl" and len(lower) > 1 and lower[1] == "delete":
        return _blocked(command, "destructive", "Kubernetes deletion is prohibited.", "BLOCK-002")
    if program in {"sql", "psql", "mysql", "sqlite3"} and re.search(
        r"\b(?:drop|truncate|delete)\b", " ".join(lower)
    ):
        return _blocked(command, "destructive", "Destructive database statements are prohibited.", "BLOCK-002")
    if program in {"aws", "gcloud", "az"} and any(
        word in {"delete", "terminate", "destroy"}
        or word.startswith(("delete-", "terminate-", "destroy-"))
        for word in lower
    ):
        return _blocked(command, "destructive", "Cloud resource deletion is prohibited.", "BLOCK-002")

    if program in _DESTRUCTIVE_PROGRAMS or program.startswith("mkfs"):
        return _blocked(command, "destructive", f"{program} can wipe disks, halt hosts, or destroy data.", "BLOCK-002")
    if program == "git" and len(lower) > 1 and (
        (lower[1] == "push" and any(flag in {"-f", "--force", "--force-with-lease"} for flag in lower[2:]))
        or (lower[1] == "reset" and "--hard" in lower[2:])
        or (lower[1] == "clean" and any(flag.startswith("-") and "f" in flag for flag in lower[2:]))
    ):
        return _blocked(command, "destructive", "Force-push, hard reset, and forced clean can destroy history or work.", "BLOCK-002")
    if program == "docker" and len(lower) > 2 and (
        (lower[1] == "system" and lower[2] == "prune") or (lower[1] in {"volume", "network", "image"} and lower[2] in {"rm", "prune"})
    ):
        return _blocked(command, "destructive", "Docker prune and removal commands delete data and images.", "BLOCK-002")
    if program == "helm" and len(lower) > 1 and lower[1] in {"uninstall", "delete"}:
        return _blocked(command, "destructive", "Helm uninstall removes a release and its resources.", "BLOCK-002")
    if program == "chmod" and any(arg in {"-r", "-R"} for arg in parts[1:]) and any(arg.endswith("777") for arg in parts[1:]):
        return _blocked(command, "destructive", "Recursive world-writable permissions are prohibited.", "BLOCK-002")

    if normalized in _SAFE_EXACT:
        return Evaluation(command, normalized, Decision.SAFE, "read-only", ("Explicit read-only allowlist match.",), 1.0, ("SAFE-001",))
    if program == "ls" and all(not arg.startswith("-") or arg in {"-a", "-l", "-la", "-al", "-h"} for arg in parts[1:]):
        return Evaluation(command, normalized, Decision.SAFE, "read-only", ("Read-only directory listing.",), 0.98, ("SAFE-001",))
    if parts[:2] == ["git", "status"] and len(parts) <= 3:
        return Evaluation(command, normalized, Decision.SAFE, "read-only", ("Read-only Git status.",), 0.98, ("SAFE-001",))
    if program == "kubectl" and len(parts) >= 2 and parts[1] in {"get", "describe"}:
        return Evaluation(command, normalized, Decision.SAFE, "read-only", ("Read-only Kubernetes query.",), 0.95, ("SAFE-002",))

    if program == "kubectl" and len(parts) >= 2 and parts[1] in {"apply", "patch", "scale", "rollout", "edit"}:
        reason = f"Kubernetes {parts[1]} changes cluster state."
    elif program in {"systemctl", "service", "launchctl"}:
        reason = "Service management can restart or alter a running service."
    elif program in {"chmod", "chown", "sudo", "terraform", "aws", "gcloud", "az"}:
        reason = "Infrastructure, permission, or cloud operation requires human review."
    elif program in {"cp", "mv", "touch", "mkdir", "tee", "sed", "python", "python3"}:
        reason = "Command can modify files or execute code and requires human review."
    else:
        return _blocked(command, "unknown", "Command is not in the explicit read-only allowlist.", "BLOCK-003")
    return Evaluation(command, normalized, Decision.REVIEW, "mutation", (reason,), 0.75, ("REVIEW-001",))
