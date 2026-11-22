"""Core C8 - Provenance and Audit Logging.

Every intercepted action, decision, risk score, policy trace and execution
outcome is written to a hash-chained SQLite log so experiments are reproducible
and single-field tampering is detectable (FR-028, FR-031, NFR-014).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .config import Config
from .models import Decision, Task, decision_json, new_id, now_ts

GENESIS = "0" * 64


class AuditLogger:
    """Append-only, hash-chained audit log backed by SQLite."""

    def __init__(self, db_path: Optional[Path] = None, config: Optional[Config] = None) -> None:
        self.config = config or Config()
        self.db_path = Path(db_path or self.config.db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._create_schema()

    def _create_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    event_type TEXT NOT NULL,
                    task_id TEXT,
                    timestamp REAL NOT NULL,
                    payload TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    hash TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_task ON audit_events(task_id)"
            )

    def _last_hash(self) -> str:
        row = self._conn.execute(
            "SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return str(row["hash"]) if row else GENESIS

    def log(self, event_type: str, payload: Dict[str, Any], task_id: Optional[str] = None) -> str:
        """Append one event and return its hash."""
        event_id = new_id("EVT")
        record = {
            "event_id": event_id,
            "event_type": event_type,
            "task_id": task_id or payload.get("task_id"),
            "timestamp": now_ts(),
            "payload": payload,
        }
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
        with self._lock, self._conn:
            prev = self._last_hash()
            digest = hashlib.sha256((prev + canonical).encode("utf-8")).hexdigest()
            self._conn.execute(
                """
                INSERT INTO audit_events
                    (event_id, event_type, task_id, timestamp, payload, prev_hash, hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    event_type,
                    record["task_id"],
                    record["timestamp"],
                    canonical,
                    prev,
                    digest,
                ),
            )
        return digest

    def log_task(self, task: Task) -> str:
        return self.log("TASK_REGISTERED", task.to_dict(), task.id)

    def log_capability(self, task_id: str, capability: Dict[str, Any]) -> str:
        return self.log("CAPABILITY_ISSUED", capability, task_id)

    def log_decision(self, decision: Decision) -> str:
        return self.log("DECISION", json.loads(decision_json(decision)), decision.task_id)

    def log_execution(self, decision: Decision, result: Dict[str, Any]) -> str:
        return self.log(
            "EXECUTION",
            {"action_id": decision.action_id, "outcome": decision.outcome, "result": result},
            decision.task_id,
        )

    def events(self, task_id: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            if task_id:
                rows = self._conn.execute(
                    "SELECT * FROM audit_events WHERE task_id = ? ORDER BY seq DESC LIMIT ?",
                    (task_id, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM audit_events ORDER BY seq DESC LIMIT ?", (limit,)
                ).fetchall()
        return [dict(row) for row in rows]

    def verify_chain(self) -> Tuple[bool, List[str]]:
        """Verify every hash link; return ``(ok, broken_event_ids)``."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM audit_events ORDER BY seq ASC"
            ).fetchall()
        previous = GENESIS
        broken: List[str] = []
        for row in rows:
            canonical = row["payload"]
            expected = hashlib.sha256((previous + canonical).encode("utf-8")).hexdigest()
            parsed = json.loads(canonical)
            if (
                expected != row["hash"]
                or row["prev_hash"] != previous
                or parsed.get("event_id") != row["event_id"]
            ):
                broken.append(row["event_id"])
            previous = row["hash"]
        return (not broken), broken

    def count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM audit_events").fetchone()
        return int(row["n"])

    def clear(self) -> None:
        """Remove all events (used by tests and fresh evaluation runs)."""
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM audit_events")

    def close(self) -> None:
        with self._lock:
            self._conn.close()
