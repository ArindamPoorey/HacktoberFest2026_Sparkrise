"""SQLite audit persistence and query service for Permission Fence (FR-09, Section 14)."""

from __future__ import annotations

from contextlib import closing
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.schemas import AuditEventRecord


CREATE_AUDIT_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS audit_events (
    operation_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    command_summary TEXT NOT NULL,
    full_redacted_command TEXT NOT NULL,
    shell TEXT NOT NULL,
    working_directory TEXT NOT NULL,
    invocation_source TEXT NOT NULL,
    user_intent_summary TEXT,
    redacted_context_summary TEXT NOT NULL,
    context_hash TEXT NOT NULL,
    provider TEXT NOT NULL,
    model_id TEXT NOT NULL,
    model_version TEXT,
    endpoint_label TEXT NOT NULL,
    latency_ms REAL NOT NULL DEFAULT 0.0,
    usage_json TEXT,
    action_class TEXT NOT NULL,
    confidence REAL,
    scores_json TEXT NOT NULL,
    first_decision TEXT NOT NULL,
    recheck_decision TEXT,
    final_decision TEXT NOT NULL,
    recheck_count INTEGER NOT NULL DEFAULT 0,
    policy_reason_code TEXT NOT NULL,
    policy_explanation TEXT NOT NULL,
    authorization_digest TEXT,
    start_time TEXT,
    end_time TEXT,
    exit_code INTEGER,
    execution_status TEXT NOT NULL,
    redacted_stdout TEXT NOT NULL DEFAULT '',
    redacted_stderr TEXT NOT NULL DEFAULT '',
    notification_status TEXT NOT NULL DEFAULT 'NONE',
    notification_message TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_final_decision ON audit_events(final_decision);
"""


class AuditStorageError(RuntimeError):
    """Raised in strict audit mode when an audit event cannot be written or updated."""


class AuditStore:
    """SQLite persistence layer for Permission Fence evaluations and execution outcomes."""

    def __init__(self, db_path: str = "permission_fence_audit.db", strict_mode: bool = True) -> None:
        self.db_path = str(db_path)
        self.strict_mode = strict_mode
        self._use_nolock_uri = False
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        if self._use_nolock_uri:
            abs_path = str(Path(self.db_path).resolve())
            uri = f"file:{abs_path}?nolock=1"
            conn = sqlite3.connect(uri, uri=True, timeout=5.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=MEMORY;")
            conn.execute("PRAGMA synchronous=OFF;")
            return conn

        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        try:
            db_file = Path(self.db_path)
            if db_file.parent and str(db_file.parent) != ".":
                db_file.parent.mkdir(parents=True, exist_ok=True)
            try:
                with closing(self._connect()) as conn:
                    conn.executescript(CREATE_AUDIT_TABLE_SQL)
                    conn.commit()
            except sqlite3.OperationalError:
                self._use_nolock_uri = True
                with closing(self._connect()) as conn:
                    conn.executescript(CREATE_AUDIT_TABLE_SQL)
                    conn.commit()
        except Exception as exc:
            if self.strict_mode:
                raise AuditStorageError(f"Failed to initialize SQLite audit database at '{self.db_path}': {exc}") from exc

    def record_event(self, record: AuditEventRecord) -> bool:
        """Insert or replace an AuditEventRecord. Raises AuditStorageError if strict_mode is enabled."""
        sql = """
        INSERT OR REPLACE INTO audit_events (
            operation_id, timestamp, command_summary, full_redacted_command, shell,
            working_directory, invocation_source, user_intent_summary, redacted_context_summary,
            context_hash, provider, model_id, model_version, endpoint_label, latency_ms,
            usage_json, action_class, confidence, scores_json, first_decision,
            recheck_decision, final_decision, recheck_count, policy_reason_code,
            policy_explanation, authorization_digest, start_time, end_time, exit_code,
            execution_status, redacted_stdout, redacted_stderr, notification_status,
            notification_message
        ) VALUES (
            :operation_id, :timestamp, :command_summary, :full_redacted_command, :shell,
            :working_directory, :invocation_source, :user_intent_summary, :redacted_context_summary,
            :context_hash, :provider, :model_id, :model_version, :endpoint_label, :latency_ms,
            :usage_json, :action_class, :confidence, :scores_json, :first_decision,
            :recheck_decision, :final_decision, :recheck_count, :policy_reason_code,
            :policy_explanation, :authorization_digest, :start_time, :end_time, :exit_code,
            :execution_status, :redacted_stdout, :redacted_stderr, :notification_status,
            :notification_message
        );
        """
        try:
            payload = record.model_dump()
            with closing(self._connect()) as conn:
                conn.execute(sql, payload)
                conn.commit()
            return True
        except Exception as exc:
            if self.strict_mode:
                raise AuditStorageError(f"Strict audit mode failure: could not persist audit event: {exc}") from exc
            return False

    def list_recent(
        self,
        limit: int = 50,
        decision_filter: Optional[str] = None,
    ) -> List[AuditEventRecord]:
        """Return recent audit events ordered by timestamp descending."""
        try:
            with closing(self._connect()) as conn:
                if decision_filter and decision_filter.upper() in {"ALLOW", "BLOCK", "RECHECK"}:
                    cursor = conn.execute(
                        "SELECT * FROM audit_events WHERE final_decision = ? ORDER BY timestamp DESC LIMIT ?",
                        (decision_filter.upper(), limit),
                    )
                else:
                    cursor = conn.execute(
                        "SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT ?",
                        (limit,),
                    )
                rows = cursor.fetchall()
                return [AuditEventRecord(**dict(row)) for row in rows]
        except Exception:
            return []

    def get_event(self, operation_id: str) -> Optional[AuditEventRecord]:
        """Fetch a single audit event by operation_id."""
        try:
            with closing(self._connect()) as conn:
                cursor = conn.execute(
                    "SELECT * FROM audit_events WHERE operation_id = ?",
                    (operation_id,),
                )
                row = cursor.fetchone()
                return AuditEventRecord(**dict(row)) if row else None
        except Exception:
            return None

    def get_summary_metrics(self) -> Dict[str, Any]:
        """Compute dashboard overview metrics (counts, rechecks, average latency, provider health)."""
        metrics: Dict[str, Any] = {
            "total_evaluated": 0,
            "allowed_count": 0,
            "blocked_count": 0,
            "rechecked_count": 0,
            "executed_succeeded_count": 0,
            "avg_latency_ms": 0.0,
            "last_provider": None,
            "provider_health": "HEALTHY",
        }
        try:
            with closing(self._connect()) as conn:
                row = conn.execute(
                    """
                    SELECT
                        COUNT(*) AS total,
                        SUM(CASE WHEN final_decision = 'ALLOW' THEN 1 ELSE 0 END) AS allowed,
                        SUM(CASE WHEN final_decision = 'BLOCK' THEN 1 ELSE 0 END) AS blocked,
                        SUM(CASE WHEN recheck_count > 0 THEN 1 ELSE 0 END) AS rechecked,
                        SUM(CASE WHEN execution_status = 'SUCCEEDED' THEN 1 ELSE 0 END) AS succeeded,
                        AVG(latency_ms) AS avg_latency
                    FROM audit_events
                    """
                ).fetchone()
                if row and row["total"]:
                    metrics["total_evaluated"] = int(row["total"] or 0)
                    metrics["allowed_count"] = int(row["allowed"] or 0)
                    metrics["blocked_count"] = int(row["blocked"] or 0)
                    metrics["rechecked_count"] = int(row["rechecked"] or 0)
                    metrics["executed_succeeded_count"] = int(row["succeeded"] or 0)
                    metrics["avg_latency_ms"] = round(float(row["avg_latency"] or 0.0), 1)

                latest = conn.execute(
                    "SELECT provider, policy_reason_code FROM audit_events ORDER BY timestamp DESC LIMIT 1"
                ).fetchone()
                if latest:
                    metrics["last_provider"] = latest["provider"]
                    if "PROVIDER_OR_SCHEMA_ERROR" in (latest["policy_reason_code"] or ""):
                        metrics["provider_health"] = "DEGRADED"
        except Exception:
            metrics["provider_health"] = "UNKNOWN"
        return metrics

    def purge_older_than(self, retention_days: int = 7) -> int:
        """Delete audit records older than retention_days."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        try:
            with closing(self._connect()) as conn:
                cur = conn.execute("DELETE FROM audit_events WHERE timestamp < ?", (cutoff,))
                conn.commit()
                return cur.rowcount
        except Exception:
            return 0

    def clear_all(self) -> int:
        """Clear all local audit history."""
        try:
            with closing(self._connect()) as conn:
                cur = conn.execute("DELETE FROM audit_events")
                conn.commit()
                return cur.rowcount
        except Exception:
            return 0
