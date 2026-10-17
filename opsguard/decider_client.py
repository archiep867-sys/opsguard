"""Local Strands Decider client using its typed System One choice protocol."""

from __future__ import annotations

import math
import os
from dataclasses import dataclass
from typing import Any

import httpx

from .safety_engine import Decision


class DeciderUnavailable(RuntimeError):
    """The local server could not be reached or returned an HTTP error."""


class DeciderInvalidResponse(DeciderUnavailable):
    """The server replied, but not with a valid OpsGuard classification."""


@dataclass(frozen=True)
class DeciderResult:
    verdict: Decision
    probabilities: dict[str, float]
    confidence: float
    latency_ms: float | None
    detail: str


class DeciderClient:
    def __init__(self, base_url: str | None = None, timeout: float = 3.0) -> None:
        self.base_url = (base_url or os.getenv("STRANDS_DECIDER_URL", "http://127.0.0.1:8099")).rstrip("/")
        self.timeout = timeout

    def classify(self, command: str) -> DeciderResult:
        """Request the documented ``choice`` answer and validate every returned value."""
        payload: dict[str, Any] = {
            "state": {"proposed_command": command, "execution": "simulation only"},
            "model": "strands-decider-latest",
            "questions": {
                "opsguard_verdict": {
                    "type": "choice",
                    "instructions": "Classify the proposed DevOps operation for a safety gate.",
                    "criteria": {
                        "safe": "Read-only, explicitly bounded operation that needs no human approval.",
                        "review": "State-changing or operationally sensitive operation requiring human approval.",
                        "block": "Destructive, unsafe, malformed, or prohibited operation that must not proceed.",
                    },
                }
            },
        }
        api_key = os.getenv("STRANDS_DECIDER_API_KEY")
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else None
        try:
            response = httpx.post(
                f"{self.base_url}/v1/systemone", json=payload, headers=headers, timeout=self.timeout
            )
            response.raise_for_status()
            body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise DeciderUnavailable("Local Decider is unavailable.") from exc

        if not isinstance(body, dict) or not isinstance(body.get("answers"), dict):
            raise DeciderInvalidResponse("Local Decider returned an invalid response schema.")
        answer = body["answers"].get("opsguard_verdict")
        if not isinstance(answer, dict) or answer.get("type") != "choice":
            raise DeciderInvalidResponse("Local Decider response is missing a choice answer.")
        selected = answer.get("choice")
        if not isinstance(selected, str) or selected not in {"safe", "review", "block"}:
            raise DeciderInvalidResponse("Local Decider returned an unknown classification.")
        probabilities = self._probabilities(answer.get("probabilities"))
        confidence = answer.get("confidence")
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
            raise DeciderInvalidResponse("Local Decider returned an invalid confidence value.")
        latency = body.get("latency_ms")
        if latency is not None and (not isinstance(latency, (int, float)) or isinstance(latency, bool) or not math.isfinite(latency) or latency < 0):
            raise DeciderInvalidResponse("Local Decider returned an invalid latency value.")
        return DeciderResult(Decision(selected.upper()), probabilities, float(confidence), float(latency) if latency is not None else None, "Validated Strands Decider choice classification.")

    @staticmethod
    def _probabilities(value: object) -> dict[str, float]:
        if not isinstance(value, dict) or set(value) != {"safe", "review", "block"}:
            raise DeciderInvalidResponse("Local Decider returned invalid class probabilities.")
        probabilities: dict[str, float] = {}
        for name, probability in value.items():
            if not isinstance(probability, (int, float)) or isinstance(probability, bool) or not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
                raise DeciderInvalidResponse("Local Decider returned invalid class probabilities.")
            probabilities[name] = float(probability)
        if not math.isclose(sum(probabilities.values()), 1.0, rel_tol=0.0, abs_tol=1e-6):
            raise DeciderInvalidResponse("Local Decider probabilities do not sum to one.")
        return probabilities

    def health(self) -> str:
        try:
            response = httpx.get(f"{self.base_url}/health", timeout=self.timeout)
            response.raise_for_status()
            return "available"
        except httpx.HTTPError:
            return "offline"
