"""SQLite-backed local audit logging; values are stored with parameterized queries."""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .decision_pipeline import PipelineDecision
from .safety_engine import Evaluation
from .bedrock_client import ExplanationResult
from .redaction import redact


@dataclass(frozen=True)
class AuditEvent:
    id: int
    created_at: str
    command: str
    normalized_command: str | None
    decision: str
    category: str
    reasons: str
    decider_available: bool
    environment: str | None
    resource_name: str | None
    approval_outcome: str | None
    confirmation_outcome: str | None
    simulation_result: str | None
    deterministic_decision: str | None
    matched_rule_ids: str | None
    decider_called: bool
    decider_status: str | None
    model_verdict: str | None
    model_confidence: float | None
    model_probabilities: str | None
    decision_source: str | None
    decider_latency_ms: float | None
    decider_failure_reason: str | None
    bedrock_invoked: bool
    bedrock_model_id: str | None
    bedrock_status: str | None
    explanation_source: str | None
    bedrock_latency_ms: float | None
    bedrock_error_category: str | None
    bedrock_attempted: bool = False
    channel: str | None = None


def _redact(value: str) -> str:
    return redact(value, limit=None) or ""


class AuditLog:
    def __init__(self, path: str | Path | None = None) -> None:
        """Open a configured local audit database; Render can use a writable /tmp path."""
        self.path = Path(path or os.getenv("OPSGUARD_DB_PATH", "opsguard_audit.sqlite3"))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._create()

    def _create(self) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, command TEXT NOT NULL,
                normalized_command TEXT, decision TEXT NOT NULL, category TEXT NOT NULL,
                reasons TEXT NOT NULL, decider_available INTEGER NOT NULL,
                approval_outcome TEXT, confirmation_outcome TEXT, simulation_result TEXT
            )""")
            columns = {row[1] for row in conn.execute("PRAGMA table_info(audit_events)")}
            if "environment" not in columns:
                conn.execute("ALTER TABLE audit_events ADD COLUMN environment TEXT")
            if "resource_name" not in columns:
                conn.execute("ALTER TABLE audit_events ADD COLUMN resource_name TEXT")
            additions = {
                "deterministic_decision": "TEXT",
                "matched_rule_ids": "TEXT",
                "decider_called": "INTEGER NOT NULL DEFAULT 0",
                "decider_status": "TEXT",
                "model_verdict": "TEXT",
                "model_confidence": "REAL",
                "model_probabilities": "TEXT",
                "decision_source": "TEXT",
                "decider_latency_ms": "REAL",
                "decider_failure_reason": "TEXT",
                "bedrock_invoked": "INTEGER NOT NULL DEFAULT 0",
                "bedrock_model_id": "TEXT",
                "bedrock_status": "TEXT",
                "explanation_source": "TEXT",
                "bedrock_latency_ms": "REAL",
                "bedrock_error_category": "TEXT",
                "bedrock_attempted": "INTEGER NOT NULL DEFAULT 0",
                "channel": "TEXT",
            }
            for column, kind in additions.items():
                if column not in columns:
                    conn.execute(f"ALTER TABLE audit_events ADD COLUMN {column} {kind}")

    def record(self, evaluation: Evaluation, *, decider_available: bool, approval_outcome: str | None = None,
               confirmation_outcome: str | None = None, simulation_result: str | None = None,
               environment: str | None = None, resource_name: str | None = None,
               pipeline: PipelineDecision | None = None,
               explanation: ExplanationResult | None = None, channel: str = "dashboard") -> int:
        deterministic = pipeline.deterministic if pipeline else evaluation
        with sqlite3.connect(self.path) as conn:
            cursor = conn.execute("""INSERT INTO audit_events
                (created_at, command, normalized_command, decision, category, reasons, decider_available,
                 approval_outcome, confirmation_outcome, simulation_result, environment, resource_name,
                 deterministic_decision, matched_rule_ids, decider_called, decider_status, model_verdict,
                 model_confidence, model_probabilities, decision_source, decider_latency_ms, decider_failure_reason,
                 bedrock_invoked, bedrock_model_id, bedrock_status, explanation_source, bedrock_latency_ms,
                 bedrock_error_category, bedrock_attempted, channel)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (datetime.now(UTC).isoformat(), _redact(evaluation.command), _redact(evaluation.normalized_command or "") or None,
                 evaluation.decision.value, evaluation.category, json.dumps(evaluation.reasons), int(decider_available),
                 approval_outcome, confirmation_outcome, simulation_result, environment or None, resource_name or None,
                 deterministic.decision.value, json.dumps(deterministic.rule_ids), int(pipeline.decider_called) if pipeline else 0,
                 pipeline.decider_status if pipeline else None, pipeline.model_verdict.value if pipeline and pipeline.model_verdict else None,
                 pipeline.model_confidence if pipeline else None, json.dumps(pipeline.model_probabilities) if pipeline and pipeline.model_probabilities else None,
                 pipeline.source if pipeline else "deterministic policy", pipeline.latency_ms if pipeline else None,
                 _redact(pipeline.failure_reason) if pipeline and pipeline.failure_reason else None,
                 int(explanation is not None and explanation.source == "bedrock"), explanation.model_id if explanation else None,
                 explanation.status if explanation else None, explanation.source if explanation else None,
                 explanation.latency_ms if explanation else None, explanation.error_category if explanation else None,
                 int(bool(explanation and explanation.attempted)), channel))
            return int(cursor.lastrowid or 0)

    def attach_explanation(self, event_id: int, explanation: ExplanationResult) -> None:
        """Record which explanation path was used for an existing decision (metadata only)."""
        with sqlite3.connect(self.path) as conn:
            conn.execute("""UPDATE audit_events SET bedrock_invoked = ?, bedrock_model_id = ?, bedrock_status = ?,
                            explanation_source = ?, bedrock_latency_ms = ?, bedrock_error_category = ?,
                            bedrock_attempted = ? WHERE id = ?""",
                         (int(explanation.source == "bedrock"), explanation.model_id, explanation.status,
                          explanation.source, explanation.latency_ms, explanation.error_category,
                          int(explanation.attempted), event_id))

    def recent(self, limit: int = 100) -> list[tuple[object, ...]]:
        with sqlite3.connect(self.path) as conn:
            return conn.execute("SELECT created_at, command, decision, reasons, approval_outcome, simulation_result "
                                "FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def events(self, *, decision: str | None = None, environment: str | None = None,
               search: str | None = None, limit: int = 500) -> list[AuditEvent]:
        clauses: list[str] = []
        values: list[object] = []
        if decision and decision != "ALL":
            clauses.append("decision = ?")
            values.append(decision)
        if environment:
            clauses.append("environment = ?")
            values.append(environment)
        if search:
            clauses.append("(command LIKE ? OR reasons LIKE ? OR resource_name LIKE ?)")
            values.extend([f"%{search}%"] * 3)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        query = """SELECT id, created_at, command, normalized_command, decision, category, reasons,
                   decider_available, environment, resource_name, approval_outcome, confirmation_outcome,
                   simulation_result, deterministic_decision, matched_rule_ids, decider_called, decider_status,
                   model_verdict, model_confidence, model_probabilities, decision_source, decider_latency_ms,
                   decider_failure_reason, bedrock_invoked, bedrock_model_id, bedrock_status, explanation_source,
                   bedrock_latency_ms, bedrock_error_category, bedrock_attempted, channel FROM audit_events""" + where + " ORDER BY id DESC LIMIT ?"
        values.append(limit)
        with sqlite3.connect(self.path) as conn:
            return [AuditEvent(*row[:29], bool(row[29]), row[30]) for row in conn.execute(query, values).fetchall()]

    def metrics(self) -> dict[str, int]:
        with sqlite3.connect(self.path) as conn:
            rows = conn.execute("SELECT decision, COUNT(*) FROM audit_events GROUP BY decision").fetchall()
        counts = {str(decision): int(count) for decision, count in rows}
        return {"total": sum(counts.values()), "SAFE": counts.get("SAFE", 0),
                "REVIEW": counts.get("REVIEW", 0), "BLOCK": counts.get("BLOCK", 0)}
