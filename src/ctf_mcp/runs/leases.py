"""Interactive session lease tracking, idle expiry, reserved-action expiry, and restart loss marking.

Implements ``docs/08`` section 6 (15-minute / 900s idle expiry, lost sessions
after supervisor/VM restart) and ``docs/11`` section 2 (pre-launch ``reserved -> expired``).
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import uuid4

from pydantic import Field

from ctf_mcp.contracts import (
    ActionLifecycleState,
    BudgetExceededError,
    BudgetSpec,
    ContractViolationError,
    GuestBlockedError,
    GuestHealthState,
    InvalidStateTransitionError,
    ScopeDeniedError,
    StrictModel,
    UsageMetrics,
)
from ctf_mcp.runs.actions import ActionManager, ActionSubmission
from ctf_mcp.storage import Storage

SESSION_LEASES_DDL: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS session_leases (
        session_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        principal_id TEXT NOT NULL,
        capability_name TEXT NOT NULL,
        adapter_revision TEXT NOT NULL,
        artifact_id TEXT,
        endpoint TEXT,
        supervisor_instance_id TEXT,
        state TEXT NOT NULL,
        idle_seconds INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        last_activity_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        closed_at TEXT,
        termination_reason TEXT,
        FOREIGN KEY (run_id) REFERENCES runs(run_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_session_leases_run_state ON session_leases (run_id, state)",
)


def ensure_leases_schema_in_tx(conn: sqlite3.Connection) -> None:
    """Create the ``session_leases`` table idempotently inside an active connection."""
    for stmt in SESSION_LEASES_DDL:
        conn.execute(stmt)


def _normalize_utc(dt: datetime | None = None) -> datetime:
    current = datetime.now(UTC) if dt is None else dt
    if current.tzinfo is None:
        return current.replace(tzinfo=UTC)
    return current.astimezone(UTC)


def _parse_dt(raw: str) -> datetime:
    return _normalize_utc(datetime.fromisoformat(raw))


class SessionLeaseState(StrEnum):
    """Lifecycle states for persistent interactive session leases."""

    ACTIVE = "active"
    EXPIRED = "expired"
    CLOSED = "closed"
    LOST = "lost"


class SessionLease(StrictModel):
    """Persistent lease binding an interactive session to a run, target, and expiry."""

    session_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    principal_id: str = Field(min_length=1)
    capability_name: str = Field(min_length=1)
    adapter_revision: str = Field(min_length=1)
    artifact_id: str | None = None
    endpoint: str | None = None
    supervisor_instance_id: str | None = None
    state: SessionLeaseState
    idle_seconds: int = Field(gt=0)
    created_at: datetime
    last_activity_at: datetime
    expires_at: datetime
    closed_at: datetime | None = None
    termination_reason: str | None = None


def _row_to_lease(row: sqlite3.Row) -> SessionLease:
    return SessionLease(
        session_id=str(row["session_id"]),
        run_id=str(row["run_id"]),
        principal_id=str(row["principal_id"]),
        capability_name=str(row["capability_name"]),
        adapter_revision=str(row["adapter_revision"]),
        artifact_id=str(row["artifact_id"]) if row["artifact_id"] is not None else None,
        endpoint=str(row["endpoint"]) if row["endpoint"] is not None else None,
        supervisor_instance_id=(
            str(row["supervisor_instance_id"])
            if row["supervisor_instance_id"] is not None
            else None
        ),
        state=SessionLeaseState(str(row["state"])),
        idle_seconds=int(row["idle_seconds"]),
        created_at=_parse_dt(str(row["created_at"])),
        last_activity_at=_parse_dt(str(row["last_activity_at"])),
        expires_at=_parse_dt(str(row["expires_at"])),
        closed_at=_parse_dt(str(row["closed_at"])) if row["closed_at"] is not None else None,
        termination_reason=(
            str(row["termination_reason"]) if row["termination_reason"] is not None else None
        ),
    )


class LeaseManager:
    """Manages interactive session leases, idle expiry, and pre-launch action expiry."""

    def __init__(self, storage: Storage) -> None:
        self.storage = storage
        self._actions = ActionManager(storage)

    def ensure_schema(self) -> None:
        """Ensure ``session_leases`` table exists."""
        with self.storage.transaction() as conn:
            ensure_leases_schema_in_tx(conn)

    def acquire_lease_in_tx(
        self,
        conn: sqlite3.Connection,
        *,
        run_id: str,
        principal_id: str,
        capability_name: str,
        adapter_revision: str,
        artifact_id: str | None = None,
        endpoint: str | None = None,
        supervisor_instance_id: str | None = None,
        idle_seconds: int | None = None,
        now: datetime | None = None,
    ) -> SessionLease:
        """Acquire a new bounded interactive session lease within ``runs`` concurrency limits."""
        ensure_leases_schema_in_tx(conn)

        run_row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if run_row is None:
            raise ContractViolationError(f"Run {run_id!r} does not exist.")
        if str(run_row["owner_principal_id"]) != principal_id:
            raise ScopeDeniedError(
                f"Principal {principal_id!r} cannot open a session on run {run_id!r}."
            )
        if run_row["closed_at"] is not None:
            raise InvalidStateTransitionError(f"Run {run_id!r} is already closed.")

        guest_health = GuestHealthState(str(run_row["guest_health"]))
        if guest_health != GuestHealthState.READY:
            raise GuestBlockedError(
                f"Guest for run {run_id!r} is blocked ({guest_health.value}).",
                details={"run_id": run_id, "guest_health": guest_health.value},
            )

        budget_spec = BudgetSpec.model_validate_json(str(run_row["budget_spec_json"]))
        active_sessions = int(run_row["active_sessions"])
        if active_sessions >= budget_spec.interactive_session_limit:
            raise BudgetExceededError(
                f"Interactive session limit ({budget_spec.interactive_session_limit}) reached.",
                details={
                    "run_id": run_id,
                    "active_sessions": active_sessions,
                    "limit": budget_spec.interactive_session_limit,
                },
            )

        effective_idle = (
            budget_spec.session_idle_seconds if idle_seconds is None else idle_seconds
        )
        if effective_idle <= 0:
            raise ContractViolationError("idle_seconds must be positive.")

        ts = _normalize_utc(now)
        expires_at = ts + timedelta(seconds=effective_idle)
        session_id = f"sess-{uuid4().hex}"

        lease = SessionLease(
            session_id=session_id,
            run_id=run_id,
            principal_id=principal_id,
            capability_name=capability_name,
            adapter_revision=adapter_revision,
            artifact_id=artifact_id,
            endpoint=endpoint,
            supervisor_instance_id=supervisor_instance_id,
            state=SessionLeaseState.ACTIVE,
            idle_seconds=effective_idle,
            created_at=ts,
            last_activity_at=ts,
            expires_at=expires_at,
            closed_at=None,
            termination_reason=None,
        )

        conn.execute(
            """
            INSERT INTO session_leases (
                session_id, run_id, principal_id, capability_name, adapter_revision,
                artifact_id, endpoint, supervisor_instance_id, state, idle_seconds,
                created_at, last_activity_at, expires_at, closed_at, termination_reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
            """,
            (
                lease.session_id,
                lease.run_id,
                lease.principal_id,
                lease.capability_name,
                lease.adapter_revision,
                lease.artifact_id,
                lease.endpoint,
                lease.supervisor_instance_id,
                lease.state.value,
                lease.idle_seconds,
                ts.isoformat(),
                ts.isoformat(),
                expires_at.isoformat(),
            ),
        )
        conn.execute(
            "UPDATE runs SET active_sessions = active_sessions + 1, revision = revision + 1 WHERE run_id = ?",
            (run_id,),
        )
        return lease

    def acquire_lease(
        self,
        *,
        run_id: str,
        principal_id: str,
        capability_name: str,
        adapter_revision: str,
        artifact_id: str | None = None,
        endpoint: str | None = None,
        supervisor_instance_id: str | None = None,
        idle_seconds: int | None = None,
        now: datetime | None = None,
    ) -> SessionLease:
        """Acquire a persistent interactive session lease inside a transaction."""
        with self.storage.transaction() as conn:
            return self.acquire_lease_in_tx(
                conn,
                run_id=run_id,
                principal_id=principal_id,
                capability_name=capability_name,
                adapter_revision=adapter_revision,
                artifact_id=artifact_id,
                endpoint=endpoint,
                supervisor_instance_id=supervisor_instance_id,
                idle_seconds=idle_seconds,
                now=now,
            )

    def get_lease(self, session_id: str, *, run_id: str | None = None) -> SessionLease:
        """Read-only fetch of a SessionLease."""
        with self.storage.transaction() as conn:
            ensure_leases_schema_in_tx(conn)
            row = conn.execute(
                "SELECT * FROM session_leases WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            if row is None:
                raise ContractViolationError(f"Session lease {session_id!r} does not exist.")
            if run_id is not None and str(row["run_id"]) != run_id:
                raise ScopeDeniedError(
                    f"Session lease {session_id!r} does not belong to run {run_id!r}."
                )
            return _row_to_lease(row)

    def list_leases(
        self,
        run_id: str,
        *,
        states: tuple[SessionLeaseState, ...] | None = None,
    ) -> list[SessionLease]:
        """List session leases for a run, optionally filtered by state."""
        with self.storage.transaction() as conn:
            ensure_leases_schema_in_tx(conn)
            if states:
                placeholders = ", ".join("?" for _ in states)
                rows = conn.execute(
                    f"SELECT * FROM session_leases WHERE run_id = ? AND state IN ({placeholders}) "
                    "ORDER BY created_at ASC",
                    [run_id, *(s.value for s in states)],
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM session_leases WHERE run_id = ? ORDER BY created_at ASC",
                    (run_id,),
                ).fetchall()
            return [_row_to_lease(r) for r in rows]

    @staticmethod
    def is_idle_expired(lease: SessionLease, *, now: datetime | None = None) -> bool:
        """Return True if ``now`` is at or past ``lease.expires_at``."""
        return _normalize_utc(now) >= _normalize_utc(lease.expires_at)

    def touch_lease(
        self,
        session_id: str,
        *,
        run_id: str | None = None,
        principal_id: str | None = None,
        now: datetime | None = None,
    ) -> SessionLease:
        """Extend an active session lease; expires and rejects if already idle-expired."""
        ts = _normalize_utc(now)
        expired_now = False

        with self.storage.transaction() as conn:
            ensure_leases_schema_in_tx(conn)
            row = conn.execute(
                "SELECT * FROM session_leases WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            if row is None:
                raise ContractViolationError(f"Session lease {session_id!r} does not exist.")
            lease = _row_to_lease(row)
            if run_id is not None and lease.run_id != run_id:
                raise ScopeDeniedError(
                    f"Session lease {session_id!r} does not belong to run {run_id!r}."
                )
            if principal_id is not None and lease.principal_id != principal_id:
                raise ScopeDeniedError(
                    f"Principal {principal_id!r} does not own session {session_id!r}."
                )
            if lease.state != SessionLeaseState.ACTIVE:
                raise InvalidStateTransitionError(
                    f"Session lease {session_id!r} is not active (state={lease.state.value!r}).",
                    details={"session_id": session_id, "state": lease.state.value},
                )
            if self.is_idle_expired(lease, now=ts):
                self._terminate_lease_in_tx(
                    conn,
                    lease,
                    target_state=SessionLeaseState.EXPIRED,
                    reason="session_idle_timeout",
                    ts=ts,
                )
                expired_now = True
            else:
                new_expires = ts + timedelta(seconds=lease.idle_seconds)
                conn.execute(
                    """
                    UPDATE session_leases
                    SET last_activity_at = ?, expires_at = ?
                    WHERE session_id = ? AND state = 'active'
                    """,
                    (ts.isoformat(), new_expires.isoformat(), session_id),
                )
                updated_row = conn.execute(
                    "SELECT * FROM session_leases WHERE session_id = ?",
                    (session_id,),
                ).fetchone()
                assert updated_row is not None
                return _row_to_lease(updated_row)

        if expired_now:
            raise InvalidStateTransitionError(
                f"Session lease {session_id!r} has expired due to idle timeout.",
                details={"session_id": session_id, "state": SessionLeaseState.EXPIRED.value},
            )
        raise ContractViolationError("Unreachable lease state.")  # pragma: no cover

    def _terminate_lease_in_tx(
        self,
        conn: sqlite3.Connection,
        lease: SessionLease,
        *,
        target_state: SessionLeaseState,
        reason: str,
        ts: datetime,
    ) -> SessionLease:
        cur = conn.execute(
            """
            UPDATE session_leases
            SET state = ?, closed_at = ?, termination_reason = ?
            WHERE session_id = ? AND state = 'active'
            """,
            (target_state.value, ts.isoformat(), reason, lease.session_id),
        )
        if cur.rowcount == 1:
            conn.execute(
                """
                UPDATE runs
                SET active_sessions = CASE WHEN active_sessions > 0 THEN active_sessions - 1 ELSE 0 END
                WHERE run_id = ?
                """,
                (lease.run_id,),
            )
        row = conn.execute(
            "SELECT * FROM session_leases WHERE session_id = ?",
            (lease.session_id,),
        ).fetchone()
        assert row is not None
        return _row_to_lease(row)

    def expire_idle_leases_in_tx(
        self,
        conn: sqlite3.Connection,
        *,
        run_id: str | None = None,
        now: datetime | None = None,
    ) -> list[SessionLease]:
        """Transition all active leases past ``expires_at`` to ``expired``."""
        ensure_leases_schema_in_tx(conn)
        ts = _normalize_utc(now)
        if run_id is not None:
            rows = conn.execute(
                "SELECT * FROM session_leases WHERE run_id = ? AND state = 'active'",
                (run_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM session_leases WHERE state = 'active'"
            ).fetchall()

        expired: list[SessionLease] = []
        for row in rows:
            lease = _row_to_lease(row)
            if self.is_idle_expired(lease, now=ts):
                expired.append(
                    self._terminate_lease_in_tx(
                        conn,
                        lease,
                        target_state=SessionLeaseState.EXPIRED,
                        reason="session_idle_timeout",
                        ts=ts,
                    )
                )
        return expired

    def expire_idle_leases(
        self,
        *,
        run_id: str | None = None,
        now: datetime | None = None,
    ) -> list[SessionLease]:
        """Expire idle active session leases inside an atomic transaction."""
        with self.storage.transaction() as conn:
            return self.expire_idle_leases_in_tx(conn, run_id=run_id, now=now)

    def close_lease_in_tx(
        self,
        conn: sqlite3.Connection,
        session_id: str,
        *,
        run_id: str | None = None,
        reason: str = "closed_by_client",
        now: datetime | None = None,
    ) -> SessionLease:
        """Close an active session lease cleanly."""
        ensure_leases_schema_in_tx(conn)
        row = conn.execute(
            "SELECT * FROM session_leases WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        if row is None:
            raise ContractViolationError(f"Session lease {session_id!r} does not exist.")
        lease = _row_to_lease(row)
        if run_id is not None and lease.run_id != run_id:
            raise ScopeDeniedError(
                f"Session lease {session_id!r} does not belong to run {run_id!r}."
            )
        if lease.state != SessionLeaseState.ACTIVE:
            raise InvalidStateTransitionError(
                f"Cannot close session lease {session_id!r} in state {lease.state.value!r}."
            )
        return self._terminate_lease_in_tx(
            conn,
            lease,
            target_state=SessionLeaseState.CLOSED,
            reason=reason,
            ts=_normalize_utc(now),
        )

    def close_lease(
        self,
        session_id: str,
        *,
        run_id: str | None = None,
        reason: str = "closed_by_client",
        now: datetime | None = None,
    ) -> SessionLease:
        """Close an active session lease inside an atomic transaction."""
        with self.storage.transaction() as conn:
            return self.close_lease_in_tx(
                conn,
                session_id,
                run_id=run_id,
                reason=reason,
                now=now,
            )

    def mark_sessions_lost_in_tx(
        self,
        conn: sqlite3.Connection,
        *,
        run_id: str | None = None,
        supervisor_instance_id: str | None = None,
        reason: str = "supervisor_or_vm_restart",
        now: datetime | None = None,
    ) -> list[SessionLease]:
        """Mark active dynamic sessions as ``lost`` after supervisor/VM restart (CTF-08)."""
        ensure_leases_schema_in_tx(conn)
        ts = _normalize_utc(now)

        clauses = ["state = 'active'"]
        params: list[str] = []
        if run_id is not None:
            clauses.append("run_id = ?")
            params.append(run_id)
        if supervisor_instance_id is not None:
            clauses.append("supervisor_instance_id = ?")
            params.append(supervisor_instance_id)

        sql = f"SELECT * FROM session_leases WHERE {' AND '.join(clauses)} ORDER BY created_at ASC"
        rows = conn.execute(sql, params).fetchall()
        lost: list[SessionLease] = []
        for row in rows:
            lease = _row_to_lease(row)
            lost.append(
                self._terminate_lease_in_tx(
                    conn,
                    lease,
                    target_state=SessionLeaseState.LOST,
                    reason=reason,
                    ts=ts,
                )
            )
        return lost

    def mark_sessions_lost(
        self,
        *,
        run_id: str | None = None,
        supervisor_instance_id: str | None = None,
        reason: str = "supervisor_or_vm_restart",
        now: datetime | None = None,
    ) -> list[SessionLease]:
        """Mark active dynamic sessions as ``lost`` inside an atomic transaction."""
        with self.storage.transaction() as conn:
            return self.mark_sessions_lost_in_tx(
                conn,
                run_id=run_id,
                supervisor_instance_id=supervisor_instance_id,
                reason=reason,
                now=now,
            )

    def expire_reserved_actions_in_tx(
        self,
        conn: sqlite3.Connection,
        *,
        run_id: str | None = None,
        max_age_seconds: int = 60,
        expiry_reason: str = "reservation_expired_before_launch",
        manage_run_budget: bool = True,
        now: datetime | None = None,
    ) -> list[ActionSubmission]:
        """Transition stale pre-launch ``reserved`` actions to ``expired`` (``denied``)."""
        if max_age_seconds < 0:
            raise ValueError("max_age_seconds must be non-negative.")
        if not expiry_reason or not expiry_reason.strip():
            raise ContractViolationError("expiry_reason must be non-empty.")

        ts = _normalize_utc(now)
        if run_id is not None:
            rows = conn.execute(
                "SELECT action_id, created_at FROM actions WHERE run_id = ? AND state = 'reserved'",
                (run_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT action_id, created_at FROM actions WHERE state = 'reserved'"
            ).fetchall()

        expired: list[ActionSubmission] = []
        for row in rows:
            created = _parse_dt(str(row["created_at"]))
            age = (ts - created).total_seconds()
            if age >= max_age_seconds:
                sub = self._actions.settle_action_in_tx(
                    conn,
                    action_id=str(row["action_id"]),
                    target_state=ActionLifecycleState.EXPIRED,
                    usage=UsageMetrics(wall_ms=0, output_bytes=0),
                    expiry_reason=expiry_reason,
                    summary=expiry_reason,
                    manage_run_budget=manage_run_budget,
                    now=ts,
                )
                expired.append(sub)
        return expired

    def expire_reserved_actions(
        self,
        *,
        run_id: str | None = None,
        max_age_seconds: int = 60,
        expiry_reason: str = "reservation_expired_before_launch",
        now: datetime | None = None,
    ) -> list[ActionSubmission]:
        """Expire stale ``reserved`` actions inside an atomic transaction."""
        with self.storage.transaction() as conn:
            return self.expire_reserved_actions_in_tx(
                conn,
                run_id=run_id,
                max_age_seconds=max_age_seconds,
                expiry_reason=expiry_reason,
                manage_run_budget=True,
                now=now,
            )


__all__ = [
    "LeaseManager",
    "SESSION_LEASES_DDL",
    "SessionLease",
    "SessionLeaseState",
    "ensure_leases_schema_in_tx",
]
