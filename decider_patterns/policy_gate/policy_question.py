"""Decider 2B typed question for the `policy` pattern.

Classify a proposed agent action as safe / review / block BEFORE the agent acts.
Copy this file and edit OPTIONS and INSTRUCTIONS for your own domain.
"""

QUESTION_ID = "opsguard_verdict"
MODEL = "strands-decider-latest"

INSTRUCTIONS = "An AI agent proposes to run this DevOps command. Classify how risky it is to allow."

OPTIONS = {
    "safe": "Read-only inspection that changes nothing, e.g. listing, describing, status, logs, get.",
    "review": "Changes state but is reversible or bounded, e.g. apply, scale, restart, rollout, chmod, update config. A human must approve first.",
    "block": "Destructive, irreversible, or dangerous, e.g. delete, destroy, drop, wipe, format, force-push, disable security, or exfiltrate data. Must not run.",
}


def build_payload(proposed_action: str) -> dict:
    """Request body for the Decider `/v1/systemone` endpoint (type: choice)."""
    return {
        "state": {"proposed_command": proposed_action, "execution": "simulation only"},
        "model": MODEL,
        "questions": {
            QUESTION_ID: {"type": "choice", "instructions": INSTRUCTIONS, "criteria": OPTIONS}
        },
    }
