"""Strands InterventionHandler that gates tool calls with a Decider 2B decision.

classify(action) must return (verdict, confidence) where verdict is "safe", "review" or "block".
Rules: safe + confident -> Proceed. Everything else -> Deny. The model never approves anything;
a human step (is_approved) is the only way a "review" call can proceed.
"""

from __future__ import annotations

from typing import Callable

from strands.interventions import Deny, InterventionHandler, Proceed


class PolicyGate(InterventionHandler):
    name = "decider-policy-gate"
    on_error = "deny"  # fail closed

    def __init__(
        self,
        classify: Callable[[str], tuple[str, float]],
        tool_name: str,
        action_arg: str,
        min_confidence: float = 0.5,
        is_approved: Callable[[str], bool] | None = None,
    ) -> None:
        self._classify = classify
        self._tool_name = tool_name
        self._action_arg = action_arg
        self._min_confidence = min_confidence
        self._is_approved = is_approved or (lambda action: False)
        self.log: list[dict] = []

    def before_tool_call(self, event, **kwargs):
        tool_use = event.tool_use
        if tool_use.get("name") != self._tool_name:
            return Deny(reason=f"Only the {self._tool_name!r} tool is allowed.")
        action = str((tool_use.get("input") or {}).get(self._action_arg, ""))
        verdict, confidence = self._classify(action)
        self.log.append({"action": action, "verdict": verdict, "confidence": confidence})

        if verdict == "safe" and confidence >= self._min_confidence:
            return Proceed()
        if verdict == "review" and self._is_approved(action):
            return Proceed()
        if verdict == "review" or (verdict == "safe" and confidence < self._min_confidence):
            return Deny(reason=f"REVIEW required (verdict={verdict}, confidence={confidence:.2f}). A person must approve; do not retry until they confirm.")
        return Deny(reason=f"BLOCKED (verdict={verdict}, confidence={confidence:.2f}). Explain why and suggest a safer alternative.")
