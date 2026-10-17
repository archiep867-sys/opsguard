"""Optional local Strands Decider integration with validated, fail-safe responses."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx


class DeciderUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class DeciderResult:
    available: bool
    risk_probability: float | None
    detail: str


class DeciderClient:
    def __init__(self, base_url: str | None = None, timeout: float = 3.0) -> None:
        self.base_url = (base_url or os.getenv("STRANDS_DECIDER_URL", "http://127.0.0.1:8099")).rstrip("/")
        self.timeout = timeout

    def classify(self, command: str) -> DeciderResult:
        payload: dict[str, Any] = {
            "state": f"Proposed DevOps command:\n{command}",
            "model": "strands-decider-latest",
            "questions": {
                "risky": {
                    "type": "noul",
                    "instructions": "Would executing this command mutate, damage, or expose infrastructure?",
                },
                "risk_level": {
                    "type": "choice",
                    "instructions": "Classify operational risk.",
                    "criteria": {"low": "read-only", "high": "changes or deletes resources"},
                },
            },
        }
        try:
            response = httpx.post(f"{self.base_url}/v1/systemone", json=payload, timeout=self.timeout)
            response.raise_for_status()
            body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise DeciderUnavailable(f"Local Decider unavailable at {self.base_url}: {exc}") from exc
        if not isinstance(body, dict) or not isinstance(body.get("answers"), dict):
            raise DeciderUnavailable("Local Decider returned an invalid response schema.")
        risky = body["answers"].get("risky")
        if not isinstance(risky, dict) or not isinstance(risky.get("noul"), (float, int)):
            raise DeciderUnavailable("Local Decider response is missing answers.risky.noul.")
        probability = float(risky["noul"])
        if not 0.0 <= probability <= 1.0:
            raise DeciderUnavailable("Local Decider returned an out-of-range probability.")
        return DeciderResult(True, probability, "Local Decider classification received.")

    def health(self) -> str:
        try:
            response = httpx.get(f"{self.base_url}/health", timeout=self.timeout)
            response.raise_for_status()
            return "available"
        except httpx.HTTPError:
            return "offline"
