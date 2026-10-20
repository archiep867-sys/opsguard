"""Strands Agents integration: an InterventionHandler that gates every proposed tool call.

Pattern (see docs/DECISION_PATTERN.md):
    SAFE   -> Proceed
    REVIEW -> Deny until a *human* approves (the model cannot approve)
    BLOCK  -> Deny
The agent only ever proposes `run_command`; the tool itself performs a simulation, never
a real action.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

from strands.interventions import Deny, InterventionHandler, Proceed

from .approval import Approval, approve, command_fingerprint, is_approved
from .audit import AuditLog
from .decider_client import DeciderClient
from .decision_pipeline import PipelineDecision, decide
from .safety_engine import Decision
from .simulator import simulate

TOOL_NAME = "run_command"


@dataclass
class PendingRequest:
    request_id: int
    command: str
    environment: str
    resource_name: str
    pipeline: PipelineDecision
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


class ApprovalStore:
    """Holds human approvals out-of-band. Only human-facing code calls `grant`; the model cannot."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending: dict[int, PendingRequest] = {}
        self._granted: dict[tuple[str, str, str], Approval] = {}
        self._next_id = 1

    @staticmethod
    def _key(command: str, environment: str, resource_name: str) -> tuple[str, str, str]:
        return (command_fingerprint(command), environment.strip(), resource_name.strip())

    def request(self, pipeline: PipelineDecision, environment: str, resource_name: str) -> PendingRequest:
        with self._lock:
            for existing in self._pending.values():
                if self._key(existing.command, existing.environment, existing.resource_name) == self._key(
                        pipeline.final.command, environment, resource_name):
                    return existing
            request = PendingRequest(self._next_id, pipeline.final.command, environment, resource_name, pipeline)
            self._pending[request.request_id] = request
            self._next_id += 1
            return request

    def pending(self) -> list[PendingRequest]:
        with self._lock:
            return list(self._pending.values())

    def grant(self, request_id: int, confirmation: str) -> Approval:
        """Human step: exact resource-name confirmation, bound to one command and target."""
        with self._lock:
            request = self._pending.get(request_id)
            if request is None:
                raise ValueError("Unknown approval request.")
            approval = approve(request.pipeline.final, request.environment, request.resource_name, confirmation)
            self._granted[self._key(request.command, request.environment, request.resource_name)] = approval
            del self._pending[request_id]
            return approval

    def reject(self, request_id: int) -> None:
        with self._lock:
            self._pending.pop(request_id, None)

    def approval_for(self, command: str, environment: str, resource_name: str) -> Approval | None:
        with self._lock:
            return self._granted.get(self._key(command, environment, resource_name))

    def consume(self, command: str, environment: str, resource_name: str) -> None:
        """Approvals are single-use: a repeat of the same command needs a new approval."""
        with self._lock:
            self._granted.pop(self._key(command, environment, resource_name), None)


class OpsGuardGate(InterventionHandler):
    """Review each proposed tool call before Strands executes it."""

    name = "opsguard-gate"
    on_error = "deny"  # fail closed if this handler ever raises

    def __init__(self, decider: DeciderClient, store: ApprovalStore | None = None, audit: AuditLog | None = None) -> None:
        self._decider = decider
        self.store = store or ApprovalStore()
        self._audit = audit
        self.log: list[dict[str, object]] = []

    def before_tool_call(self, event, **kwargs):
        tool_use = event.tool_use
        if tool_use.get("name") != TOOL_NAME:
            return Deny(reason=f"OpsGuard only allows the {TOOL_NAME!r} tool.")
        arguments = tool_use.get("input") or {}
        command = str(arguments.get("command", ""))
        environment = str(arguments.get("environment", "") or "")
        resource_name = str(arguments.get("resource_name", "") or "")

        started = time.perf_counter()
        pipeline = decide(command, self._decider)
        gate_ms = round((time.perf_counter() - started) * 1000, 1)
        verdict = pipeline.final.decision
        entry: dict[str, object] = {
            "command": pipeline.final.command, "verdict": verdict.value,
            "decider_status": pipeline.decider_status, "confidence": pipeline.model_confidence,
            "model_verdict": pipeline.model_verdict.value if pipeline.model_verdict else None,
            "gate_ms": gate_ms, "action": "", "request_id": None,
        }

        if verdict is Decision.BLOCK:
            entry["action"] = "deny"
            reason = "BLOCKED by OpsGuard: " + " ".join(pipeline.final.reasons)
            result = Deny(reason=reason + " Explain this to the user in plain words and suggest a safe read-only alternative.")
        elif verdict is Decision.REVIEW:
            approval = self.store.approval_for(command, environment, resource_name)
            if is_approved(approval, pipeline.final, environment, resource_name):
                entry["action"] = "proceed (human approved)"
                result = Proceed()
            else:
                request = self.store.request(pipeline, environment, resource_name)
                entry["action"], entry["request_id"] = "deny (awaiting human approval)", request.request_id
                result = Deny(reason=(
                    f"REVIEW required: a person must approve request #{request.request_id} "
                    "by typing the exact resource name. Tell the user this, and do not retry until they confirm."))
        else:
            entry["action"] = "proceed"
            result = Proceed()

        self.log.append(entry)
        if self._audit is not None:
            self._audit.record(
                pipeline.final, decider_available=pipeline.decider_status in {"DECIDER_USED"},
                environment=environment or None, resource_name=resource_name or None, pipeline=pipeline,
                approval_outcome=str(entry["action"]), channel="agent")
        return result

    def simulate_tool(self, command: str, environment: str, resource_name: str) -> str:
        """Used by the tool body: re-validates with the same policy and only ever simulates."""
        pipeline = decide(command, self._decider)
        approval = self.store.approval_for(command, environment, resource_name)
        result = simulate(pipeline.final, approval, environment=environment or None, resource_name=resource_name or None)
        if result.allowed and pipeline.final.decision is Decision.REVIEW:
            self.store.consume(command, environment, resource_name)
        return result.message
