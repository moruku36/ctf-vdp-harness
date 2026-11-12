"""Gateway run-level budget reservation, concurrency gating, and settlement.

Manages ``runs`` budget columns (``remaining_ms``, ``remaining_bytes``,
``remaining_calls``, ``active_heavy_jobs``, ``active_sessions``,
``guest_health``) atomically inside existing or standalone SQLite transactions
(``docs/11`` sections 2 and 4). ``actions`` lifecycle rows remain owned by
``runs/actions.py``.
"""

from __future__ import annotations

import sqlite3

from pydantic import Field

from ctf_mcp.contracts import (
    BudgetExceededError,
    BudgetSpec,
    CapabilityDescriptor,
    ContractViolationError,
    GuestBlockedError,
    GuestHealthState,
    StrictModel,
)
from ctf_mcp.storage import Storage


class BudgetReservation(StrictModel):
    """Atomic budget slice granted to an action before dispatch."""

    run_id: str = Field(min_length=1)
    reserved_ms: int = Field(ge=0)
    reserved_bytes: int = Field(ge=0)
    reserved_calls: int = Field(default=1, ge=0)
    heavy_job_slot: bool = False
    interactive_session_slot: bool = False
    shrunk: bool = False


class BudgetSnapshot(StrictModel):
    """Current remaining run budget and guest health state."""

    run_id: str = Field(min_length=1)
    remaining_ms: int = Field(ge=0)
    remaining_bytes: int = Field(ge=0)
    remaining_calls: int = Field(ge=0)
    active_heavy_jobs: int = Field(ge=0)
    active_sessions: int = Field(ge=0)
    guest_health: GuestHealthState
    closed: bool


def _row_to_snapshot(row: sqlite3.Row) -> BudgetSnapshot:
    return BudgetSnapshot(
        run_id=str(row["run_id"]),
        remaining_ms=int(row["remaining_ms"]),
        remaining_bytes=int(row["remaining_bytes"]),
        remaining_calls=int(row["remaining_calls"]),
        active_heavy_jobs=int(row["active_heavy_jobs"]),
        active_sessions=int(row["active_sessions"]),
        guest_health=GuestHealthState(str(row["guest_health"])),
        closed=row["closed_at"] is not None,
    )


def get_budget_snapshot_in_tx(conn: sqlite3.Connection, run_id: str) -> BudgetSnapshot:
    """Fetch current remaining budget and guest health inside ``conn``."""
    row = conn.execute(
        """
        SELECT run_id, remaining_ms, remaining_bytes, remaining_calls,
               active_heavy_jobs, active_sessions, guest_health, closed_at
        FROM runs WHERE run_id = ?
        """,
        (run_id,),
    ).fetchone()
    if row is None:
        raise ContractViolationError(f"Run {run_id!r} does not exist.")
    return _row_to_snapshot(row)


def set_guest_health_in_tx(
    conn: sqlite3.Connection,
    run_id: str,
    health: GuestHealthState,
) -> BudgetSnapshot:
    """Update ``runs.guest_health`` inside ``conn`` and return the updated snapshot."""
    cur = conn.execute(
        "UPDATE runs SET guest_health = ? WHERE run_id = ?",
        (health.value, run_id),
    )
    if cur.rowcount == 0:
        raise ContractViolationError(f"Run {run_id!r} does not exist.")
    return get_budget_snapshot_in_tx(conn, run_id)


def reserve_run_budget_in_tx(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    capability: CapabilityDescriptor,
    is_heavy_job: bool = False,
    is_interactive_session: bool = False,
    allow_shrink: bool = True,
    min_ms: int = 1,
    min_bytes: int = 1,
) -> BudgetReservation:
    """Atomically validate guest health, concurrency slots, and reserve run budget.

    When remaining run time or byte allowance is smaller than the capability
    request and ``allow_shrink=True``, the granted reservation is shrunk to fit
    the remaining run budget (provided it still meets ``min_ms``/``min_bytes``).
    """
    if min_ms < 1 or min_bytes < 1:
        raise ValueError("min_ms and min_bytes must be >= 1.")

    row = conn.execute(
        """
        SELECT run_id, budget_spec_json, remaining_ms, remaining_bytes,
               remaining_calls, active_heavy_jobs, active_sessions,
               guest_health, closed_at
        FROM runs WHERE run_id = ?
        """,
        (run_id,),
    ).fetchone()
    if row is None:
        raise ContractViolationError(f"Run {run_id!r} does not exist.")
    if row["closed_at"] is not None:
        raise BudgetExceededError(f"Run {run_id!r} is already closed.")

    guest_health = GuestHealthState(str(row["guest_health"]))
    if guest_health == GuestHealthState.CLEANUP_UNCONFIRMED:
        raise GuestBlockedError(
            f"Run {run_id!r} guest is blocked due to cleanup_unconfirmed.",
            details={"run_id": run_id, "guest_health": guest_health.value},
        )
    if guest_health != GuestHealthState.READY:
        raise GuestBlockedError(
            f"Run {run_id!r} guest is not ready (state={guest_health.value!r}).",
            details={"run_id": run_id, "guest_health": guest_health.value},
        )

    budget_spec = BudgetSpec.model_validate_json(row["budget_spec_json"])
    remaining_calls = int(row["remaining_calls"])
    if remaining_calls < 1:
        raise BudgetExceededError(
            f"Run {run_id!r} has exhausted max_tool_calls.",
            details={"run_id": run_id, "remaining_calls": remaining_calls},
        )

    active_heavy = int(row["active_heavy_jobs"])
    if is_heavy_job and active_heavy >= budget_spec.heavy_job_concurrency:
        raise BudgetExceededError(
            f"Heavy job concurrency limit ({budget_spec.heavy_job_concurrency}) reached.",
            details={"run_id": run_id, "active_heavy_jobs": active_heavy},
        )

    active_sessions = int(row["active_sessions"])
    if is_interactive_session and active_sessions >= budget_spec.interactive_session_limit:
        raise BudgetExceededError(
            f"Interactive session limit ({budget_spec.interactive_session_limit}) reached.",
            details={"run_id": run_id, "active_sessions": active_sessions},
        )

    requested_ms = min(
        capability.limits.timeout_seconds * 1000,
        budget_spec.action_timeout_seconds * 1000,
    )
    requested_bytes = min(
        capability.limits.max_output_bytes,
        budget_spec.max_evidence_bytes_per_run,
    )

    remaining_ms = int(row["remaining_ms"])
    remaining_bytes = int(row["remaining_bytes"])

    if remaining_ms < min_ms:
        raise BudgetExceededError(
            f"Run {run_id!r} remaining time budget ({remaining_ms} ms) is below minimum ({min_ms} ms).",
            details={"run_id": run_id, "remaining_ms": remaining_ms},
        )
    if remaining_bytes < min_bytes:
        raise BudgetExceededError(
            f"Run {run_id!r} remaining byte budget ({remaining_bytes} B) is below minimum ({min_bytes} B).",
            details={"run_id": run_id, "remaining_bytes": remaining_bytes},
        )

    shrunk = False
    if remaining_ms < requested_ms:
        if not allow_shrink:
            raise BudgetExceededError(
                f"Insufficient remaining time ({remaining_ms} ms < {requested_ms} ms).",
                details={"run_id": run_id, "remaining_ms": remaining_ms, "requested_ms": requested_ms},
            )
        grant_ms = remaining_ms
        shrunk = True
    else:
        grant_ms = requested_ms

    if remaining_bytes < requested_bytes:
        if not allow_shrink:
            raise BudgetExceededError(
                f"Insufficient remaining bytes ({remaining_bytes} B < {requested_bytes} B).",
                details={
                    "run_id": run_id,
                    "remaining_bytes": remaining_bytes,
                    "requested_bytes": requested_bytes,
                },
            )
        grant_bytes = remaining_bytes
        shrunk = True
    else:
        grant_bytes = requested_bytes

    heavy_inc = 1 if is_heavy_job else 0
    session_inc = 1 if is_interactive_session else 0

    cur = conn.execute(
        """
        UPDATE runs
        SET remaining_ms = remaining_ms - ?,
            remaining_bytes = remaining_bytes - ?,
            remaining_calls = remaining_calls - 1,
            active_heavy_jobs = active_heavy_jobs + ?,
            active_sessions = active_sessions + ?
        WHERE run_id = ?
          AND remaining_ms >= ?
          AND remaining_bytes >= ?
          AND remaining_calls >= 1
          AND guest_health = 'ready'
          AND closed_at IS NULL
        """,
        (
            grant_ms,
            grant_bytes,
            heavy_inc,
            session_inc,
            run_id,
            grant_ms,
            grant_bytes,
        ),
    )
    if cur.rowcount != 1:
        raise BudgetExceededError(
            f"Atomic budget reservation failed for run {run_id!r}.",
            details={"run_id": run_id},
        )

    return BudgetReservation(
        run_id=run_id,
        reserved_ms=grant_ms,
        reserved_bytes=grant_bytes,
        reserved_calls=1,
        heavy_job_slot=is_heavy_job,
        interactive_session_slot=is_interactive_session,
        shrunk=shrunk,
    )


def settle_run_budget_in_tx(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    reserved_ms: int,
    reserved_bytes: int,
    used_ms: int | None = None,
    used_bytes: int | None = None,
    heavy_job_slot: bool = False,
    interactive_session_slot: bool = False,
    cleanup_confirmed: bool = True,
    usage_unknown: bool = False,
) -> BudgetSnapshot:
    """Settle an action's reserved budget on completion, partial output, timeout, or failure.

    Rules (``docs/11`` sections 2 & 4):
    - Retries and partial outputs stay charged (``remaining_calls`` is never refunded).
    - Unknown usage retains the full reserved budget slice (0 refund).
    - Unconfirmed cleanup retains conservative reservations (no time/byte/slot release)
      and transitions ``guest_health`` to ``cleanup_unconfirmed``.
    """
    if reserved_ms < 0 or reserved_bytes < 0:
        raise ValueError("reserved_ms and reserved_bytes must be non-negative.")
    if used_ms is not None and used_ms < 0:
        raise ValueError("used_ms must be non-negative when provided.")
    if used_bytes is not None and used_bytes < 0:
        raise ValueError("used_bytes must be non-negative when provided.")

    row = conn.execute(
        """
        SELECT run_id, remaining_ms, remaining_bytes, remaining_calls,
               active_heavy_jobs, active_sessions, guest_health, closed_at
        FROM runs WHERE run_id = ?
        """,
        (run_id,),
    ).fetchone()
    if row is None:
        raise ContractViolationError(f"Run {run_id!r} does not exist.")

    current_ms = int(row["remaining_ms"])
    current_bytes = int(row["remaining_bytes"])
    current_health = str(row["guest_health"])

    if not cleanup_confirmed:
        # Retain conservative reservation and keep active slots locked while blocking guest.
        conn.execute(
            "UPDATE runs SET guest_health = ? WHERE run_id = ?",
            (GuestHealthState.CLEANUP_UNCONFIRMED.value, run_id),
        )
        return get_budget_snapshot_in_tx(conn, run_id)

    if usage_unknown or used_ms is None:
        new_remaining_ms = current_ms
    else:
        new_remaining_ms = max(0, current_ms + reserved_ms - used_ms)

    if usage_unknown or used_bytes is None:
        new_remaining_bytes = current_bytes
    else:
        new_remaining_bytes = max(0, current_bytes + reserved_bytes - used_bytes)

    release_heavy = 1 if heavy_job_slot else 0
    release_session = 1 if interactive_session_slot else 0

    conn.execute(
        """
        UPDATE runs
        SET remaining_ms = ?,
            remaining_bytes = ?,
            active_heavy_jobs = MAX(0, active_heavy_jobs - ?),
            active_sessions = MAX(0, active_sessions - ?),
            guest_health = ?
        WHERE run_id = ?
        """,
        (
            new_remaining_ms,
            new_remaining_bytes,
            release_heavy,
            release_session,
            current_health,
            run_id,
        ),
    )
    return get_budget_snapshot_in_tx(conn, run_id)


class RunBudgetManager:
    """High-level service wrapping ``Storage`` for standalone and in-tx budget operations."""

    def __init__(self, storage: Storage) -> None:
        self._storage = storage

    def get_budget_snapshot(self, run_id: str) -> BudgetSnapshot:
        """Read current run budget snapshot."""
        with self._storage.read_connection() as conn:
            return get_budget_snapshot_in_tx(conn, run_id)

    def set_guest_health(self, run_id: str, health: GuestHealthState) -> BudgetSnapshot:
        """Update guest health status atomically."""
        with self._storage.transaction() as conn:
            return set_guest_health_in_tx(conn, run_id, health)

    def reserve_run_budget(
        self,
        *,
        run_id: str,
        capability: CapabilityDescriptor,
        is_heavy_job: bool = False,
        is_interactive_session: bool = False,
        allow_shrink: bool = True,
        min_ms: int = 1,
        min_bytes: int = 1,
    ) -> BudgetReservation:
        """Atomically reserve run budget in a standalone transaction."""
        with self._storage.transaction() as conn:
            return reserve_run_budget_in_tx(
                conn,
                run_id=run_id,
                capability=capability,
                is_heavy_job=is_heavy_job,
                is_interactive_session=is_interactive_session,
                allow_shrink=allow_shrink,
                min_ms=min_ms,
                min_bytes=min_bytes,
            )

    def settle_run_budget(
        self,
        *,
        run_id: str,
        reserved_ms: int,
        reserved_bytes: int,
        used_ms: int | None = None,
        used_bytes: int | None = None,
        heavy_job_slot: bool = False,
        interactive_session_slot: bool = False,
        cleanup_confirmed: bool = True,
        usage_unknown: bool = False,
    ) -> BudgetSnapshot:
        """Settle reserved run budget in a standalone transaction."""
        with self._storage.transaction() as conn:
            return settle_run_budget_in_tx(
                conn,
                run_id=run_id,
                reserved_ms=reserved_ms,
                reserved_bytes=reserved_bytes,
                used_ms=used_ms,
                used_bytes=used_bytes,
                heavy_job_slot=heavy_job_slot,
                interactive_session_slot=interactive_session_slot,
                cleanup_confirmed=cleanup_confirmed,
                usage_unknown=usage_unknown,
            )


__all__ = [
    "BudgetReservation",
    "BudgetSnapshot",
    "RunBudgetManager",
    "get_budget_snapshot_in_tx",
    "reserve_run_budget_in_tx",
    "set_guest_health_in_tx",
    "settle_run_budget_in_tx",
]
