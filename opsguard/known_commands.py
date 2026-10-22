"""Explicit read-only and state-changing command tables for the safety engine.

Anything not listed here (or in safety_engine) stays unknown, which fails closed.
The model can never promote an unknown command to SAFE.
"""

_FLAG_ONLY = {"-h", "-a", "-l", "-la", "-al", "-v", "-vv", "-r", "-i", "-s", "-t", "--no-stream", "--tail"}

_READ_ONLY_SUBCOMMANDS = {
    "kubectl": {"logs", "top", "version", "api-resources", "cluster-info"},
    "docker": {"ps", "images", "logs", "version", "info", "stats"},
    "helm": {"list", "ls", "status", "history", "version"},
}
_HOST_READ_ONLY = {"df", "free", "uptime", "whoami", "hostname", "date", "uname"}
_GIT_READ_ONLY = {"log", "diff", "show"}
_GIT_BRANCH_FLAGS = {"-a", "-r", "-v", "-vv", "--list", "--show-current"}

_MUTATING_SUBCOMMANDS = {
    "kubectl": {"set", "annotate", "label", "cordon", "uncordon", "drain", "taint", "exec", "cp", "create", "run", "expose", "autoscale", "replace", "port-forward"},
    "docker": {"restart", "stop", "start", "run", "build", "exec", "kill", "pull", "push", "compose", "tag"},
    "helm": {"upgrade", "install", "rollback", "repo", "pull", "push"},
    "git": {"add", "commit", "push", "pull", "fetch", "checkout", "switch", "merge", "rebase", "stash", "tag", "cherry-pick", "restore", "revert", "branch"},
}


def read_only_reason(parts: list[str], lower: list[str]) -> str | None:
    """Return a short reason if this is an explicitly allowlisted read-only command."""
    program = lower[0]
    sub = lower[1] if len(lower) > 1 else ""
    if program in _HOST_READ_ONLY:
        if program == "date" and any(a.startswith(("-s", "--set")) for a in lower[1:]):
            return None  # setting the clock is a state change
        if all(a.startswith("-") or a.startswith("/") for a in parts[1:]):
            return "Read-only host information."
        return None
    if program in _READ_ONLY_SUBCOMMANDS and sub in _READ_ONLY_SUBCOMMANDS[program]:
        return f"Read-only {program} query."
    if program == "kubectl" and sub == "config" and len(lower) > 2 and lower[2] in {"current-context", "get-contexts"}:
        return "Read-only kubectl context query."
    if program == "git" and sub in _GIT_READ_ONLY and not any(a.startswith(("--output", "--ext-diff")) for a in lower[2:]):
        return "Read-only Git history query."
    if program == "git" and sub == "branch" and all(a in _GIT_BRANCH_FLAGS for a in lower[2:]):
        return "Read-only Git branch listing."
    if program == "aws" and len(lower) >= 3:
        if lower[1] == "s3" and lower[2] == "ls":
            return "Read-only S3 listing."
        if lower[1] == "sts" and lower[2] == "get-caller-identity":
            return "Read-only AWS identity lookup."
        if lower[2].startswith(("describe-", "list-")):
            return "Read-only AWS describe/list call."
    return None


def mutating_reason(lower: list[str]) -> str | None:
    """Return a reason if this is a known state-changing command that needs human review."""
    program = lower[0]
    sub = lower[1] if len(lower) > 1 else ""
    if sub in _MUTATING_SUBCOMMANDS.get(program, ()):
        return f"{program} {sub} changes state and requires human review."
    return None
