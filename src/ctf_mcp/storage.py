"""Layer 1 SQLite WAL persistence and atomic transaction foundation.

Provides schema initialization and ``BEGIN IMMEDIATE`` transaction control for
all Wave 1 subsystems (``gateway/``, ``runs/``, ``evidence/``, ``verification/``).
Supports composable nested transactions via ``SAVEPOINT`` on the active thread
and strictly monotonic fencing-token generation.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from ctf_mcp.contracts import ConfigurationError

SCHEMA_VERSION = 1

DDL_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS runs (
        run_id TEXT PRIMARY KEY,
        owner_principal_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        mode TEXT NOT NULL,
        scope_revision TEXT NOT NULL,
        manifest_json TEXT NOT NULL,
        budget_spec_json TEXT NOT NULL,
        remaining_ms INTEGER NOT NULL,
        remaining_bytes INTEGER NOT NULL,
        remaining_calls INTEGER NOT NULL,
        active_heavy_jobs INTEGER NOT NULL DEFAULT 0,
        active_sessions INTEGER NOT NULL DEFAULT 0,
        guest_health TEXT NOT NULL DEFAULT 'ready',
        revision INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        closed_at TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS scopes (
        run_id TEXT NOT NULL,
        scope_revision TEXT NOT NULL,
        scope_sha256 TEXT NOT NULL,
        mode TEXT NOT NULL,
        expires_at TEXT,
        policy_json TEXT NOT NULL,
        revoked_at TEXT,
        created_at TEXT NOT NULL,
        PRIMARY KEY (run_id, scope_revision),
        FOREIGN KEY (run_id) REFERENCES runs(run_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS capabilities (
        name TEXT PRIMARY KEY,
        adapter_id TEXT NOT NULL,
        adapter_commit TEXT NOT NULL,
        dependency_lock_sha256 TEXT NOT NULL,
        descriptor_sha256 TEXT NOT NULL,
        execution_classes_json TEXT NOT NULL,
        descriptor_json TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        registered_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS artifacts (
        artifact_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        byte_length INTEGER NOT NULL,
        media_type TEXT NOT NULL,
        source_origin TEXT NOT NULL,
        storage_relpath TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (run_id) REFERENCES runs(run_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS actions (
        action_id TEXT PRIMARY KEY,
        principal_id TEXT NOT NULL,
        run_id TEXT NOT NULL,
        request_id TEXT NOT NULL,
        expected_revision INTEGER NOT NULL,
        capability_name TEXT NOT NULL,
        operation TEXT NOT NULL,
        adapter_revision TEXT NOT NULL,
        canonical_args_sha256 TEXT NOT NULL,
        sanitized_args_json TEXT NOT NULL,
        scope_revision TEXT NOT NULL,
        repeat_of TEXT,
        state TEXT NOT NULL,
        reserved_ms INTEGER NOT NULL,
        reserved_bytes INTEGER NOT NULL,
        used_ms INTEGER NOT NULL DEFAULT 0,
        used_bytes INTEGER NOT NULL DEFAULT 0,
        fencing_token INTEGER,
        supervisor_instance_id TEXT,
        process_start_id TEXT,
        envelope_json TEXT,
        error_code TEXT,
        error_message TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE (principal_id, run_id, request_id),
        FOREIGN KEY (run_id) REFERENCES runs(run_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS fencing_counters (
        supervisor_key TEXT PRIMARY KEY,
        current_token INTEGER NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS hypotheses (
        hypothesis_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        claim TEXT NOT NULL,
        state TEXT NOT NULL,
        supporting_evidence_json TEXT NOT NULL,
        contradicting_evidence_json TEXT NOT NULL,
        next_observation TEXT NOT NULL,
        revision INTEGER NOT NULL DEFAULT 1,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (run_id) REFERENCES runs(run_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS evidence_objects (
        evidence_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        owner_principal_id TEXT NOT NULL,
        action_id TEXT NOT NULL,
        raw_sha256 TEXT NOT NULL,
        byte_length INTEGER NOT NULL,
        media_type TEXT NOT NULL,
        capture_complete INTEGER NOT NULL,
        omission_reason TEXT,
        role TEXT NOT NULL,
        parent_evidence_ids_json TEXT NOT NULL,
        manifest_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (run_id) REFERENCES runs(run_id),
        FOREIGN KEY (action_id) REFERENCES actions(action_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS evidence_views (
        evidence_id TEXT NOT NULL,
        view_revision TEXT NOT NULL,
        run_id TEXT NOT NULL,
        owner_principal_id TEXT NOT NULL,
        view_sha256 TEXT NOT NULL,
        view_bytes INTEGER NOT NULL,
        encoding TEXT NOT NULL,
        capture_complete INTEGER NOT NULL,
        omission_reason TEXT,
        storage_relpath TEXT NOT NULL,
        redaction_policy_rev TEXT,
        revoked_at TEXT,
        created_at TEXT NOT NULL,
        PRIMARY KEY (evidence_id, view_revision),
        FOREIGN KEY (evidence_id) REFERENCES evidence_objects(evidence_id),
        FOREIGN KEY (run_id) REFERENCES runs(run_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_events (
        event_id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        run_id TEXT NOT NULL,
        principal_id TEXT NOT NULL,
        action_id TEXT,
        capability TEXT,
        operation TEXT,
        outcome TEXT NOT NULL,
        usage_json TEXT,
        scope_revision TEXT,
        destination_summary TEXT,
        event_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS verifications (
        verification_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        verifier_id TEXT NOT NULL,
        verifier_revision TEXT NOT NULL,
        status TEXT NOT NULL,
        checks_json TEXT NOT NULL,
        limitations_json TEXT NOT NULL,
        evidence_ids_json TEXT NOT NULL,
        verified_at TEXT NOT NULL,
        FOREIGN KEY (run_id) REFERENCES runs(run_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_actions_run_state ON actions (run_id, state)",
    "CREATE INDEX IF NOT EXISTS idx_artifacts_run ON artifacts (run_id)",
    "CREATE INDEX IF NOT EXISTS idx_hypotheses_run ON hypotheses (run_id)",
    "CREATE INDEX IF NOT EXISTS idx_evidence_objects_run ON evidence_objects (run_id)",
    "CREATE INDEX IF NOT EXISTS idx_evidence_views_run ON evidence_views (run_id)",
    "CREATE INDEX IF NOT EXISTS idx_audit_events_run_ts ON audit_events (run_id, timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_verifications_run ON verifications (run_id)",
)

REQUIRED_TABLES: frozenset[str] = frozenset(
    {
        "schema_migrations",
        "runs",
        "scopes",
        "capabilities",
        "artifacts",
        "actions",
        "fencing_counters",
        "hypotheses",
        "evidence_objects",
        "evidence_views",
        "audit_events",
        "verifications",
    }
)


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(UTC).isoformat()


class Storage:
    """SQLite WAL storage engine with atomic ``BEGIN IMMEDIATE`` transactions."""

    def __init__(self, db_path: str | Path) -> None:
        raw_path = str(db_path).strip()
        if not raw_path or raw_path == ":memory:":
            raise ConfigurationError(
                "Storage requires an explicit filesystem SQLite path for WAL persistence."
            )
        self.db_path = Path(raw_path)
        self._local = threading.local()

    def connect(self) -> sqlite3.Connection:
        """Open a SQLite connection configured with WAL mode and strict FKs."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=5.0,
            isolation_level=None,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA busy_timeout = 5000")
        return conn

    def initialize(self) -> None:
        """Create required tables and indexes idempotently."""
        with self.transaction() as conn:
            for ddl in DDL_STATEMENTS:
                conn.execute(ddl)
            existing = conn.execute(
                "SELECT version FROM schema_migrations WHERE version = ?",
                (SCHEMA_VERSION,),
            ).fetchone()
            if existing is None:
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (SCHEMA_VERSION, utc_now_iso()),
                )

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Yield a SQLite connection inside an atomic ``BEGIN IMMEDIATE`` transaction.

        Nested calls on the same thread reuse the outer transaction via ``SAVEPOINT``.
        """
        depth: int = getattr(self._local, "depth", 0)
        if depth == 0:
            conn = self.connect()
            self._local.conn = conn
            self._local.depth = 1
            try:
                conn.execute("BEGIN IMMEDIATE")
                yield conn
                conn.execute("COMMIT")
            except BaseException:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            finally:
                self._local.depth = 0
                self._local.conn = None
                conn.close()
        else:
            conn = self._local.conn
            sp_name = f"sp_{depth}"
            self._local.depth = depth + 1
            conn.execute(f"SAVEPOINT {sp_name}")
            try:
                yield conn
                conn.execute(f"RELEASE SAVEPOINT {sp_name}")
            except BaseException:
                conn.execute(f"ROLLBACK TO SAVEPOINT {sp_name}")
                conn.execute(f"RELEASE SAVEPOINT {sp_name}")
                raise
            finally:
                self._local.depth = depth

    @contextmanager
    def read_connection(self) -> Iterator[sqlite3.Connection]:
        """Yield a connection for read-only queries (reusing active tx if any)."""
        if getattr(self._local, "depth", 0) > 0:
            yield self._local.conn
            return
        conn = self.connect()
        try:
            yield conn
        finally:
            conn.close()

    def next_fencing_token(
        self,
        conn: sqlite3.Connection,
        supervisor_key: str,
    ) -> int:
        """Atomically increment and return a strictly monotonic fencing token."""
        if not supervisor_key or not supervisor_key.strip():
            raise ValueError("supervisor_key must be non-empty.")
        row = conn.execute(
            """
            INSERT INTO fencing_counters (supervisor_key, current_token, updated_at)
            VALUES (?, 1, ?)
            ON CONFLICT(supervisor_key) DO UPDATE SET
                current_token = current_token + 1,
                updated_at = excluded.updated_at
            RETURNING current_token
            """,
            (supervisor_key, utc_now_iso()),
        ).fetchone()
        assert row is not None
        return int(row["current_token"])

    def journal_mode(self) -> str:
        """Return active SQLite journal_mode (expected ``'wal'``)."""
        with self.read_connection() as conn:
            row = conn.execute("PRAGMA journal_mode").fetchone()
            assert row is not None
            return str(row[0]).lower()

    def table_names(self) -> set[str]:
        """Return set of user tables currently present in the database."""
        with self.read_connection() as conn:
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
            return {str(r["name"]) for r in rows}


__all__ = [
    "DDL_STATEMENTS",
    "REQUIRED_TABLES",
    "SCHEMA_VERSION",
    "Storage",
    "utc_now_iso",
]
