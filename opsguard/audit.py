"""SQLite-backed local audit logging; values are stored with parameterized queries."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .safety_engine import Evaluation


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


_SECRET = re.compile(r"(?i)(?:api[_-]?key|token|password|secret)\s*(?:=|:)\s*[^\s]+")


def _redact(command: str) -> str:
    return _SECRET.sub("[REDACTED_SECRET]", command)


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

    def record(self, evaluation: Evaluation, *, decider_available: bool, approval_outcome: str | None = None,
               confirmation_outcome: str | None = None, simulation_result: str | None = None,
               environment: str | None = None, resource_name: str | None = None) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute("""INSERT INTO audit_events
                (created_at, command, normalized_command, decision, category, reasons, decider_available,
                 approval_outcome, confirmation_outcome, simulation_result, environment, resource_name)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (datetime.now(UTC).isoformat(), _redact(evaluation.command), _redact(evaluation.normalized_command or "") or None,
                 evaluation.decision.value, evaluation.category, json.dumps(evaluation.reasons), int(decider_available),
                 approval_outcome, confirmation_outcome, simulation_result, environment or None, resource_name or None))

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
                   simulation_result FROM audit_events""" + where + " ORDER BY id DESC LIMIT ?"
        values.append(limit)
        with sqlite3.connect(self.path) as conn:
            return [AuditEvent(*row) for row in conn.execute(query, values).fetchall()]

    def metrics(self) -> dict[str, int]:
        with sqlite3.connect(self.path) as conn:
            rows = conn.execute("SELECT decision, COUNT(*) FROM audit_events GROUP BY decision").fetchall()
        counts = {str(decision): int(count) for decision, count in rows}
        return {"total": sum(counts.values()), "SAFE": counts.get("SAFE", 0),
                "REVIEW": counts.get("REVIEW", 0), "BLOCK": counts.get("BLOCK", 0)}
