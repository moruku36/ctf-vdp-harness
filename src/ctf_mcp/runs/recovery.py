"""Crash reconciliation, fencing-token exclusion, and unconfirmed-cleanup blocking.

Implements ``docs/11`` section 4:
- ``CTF-06``: Restart reconciliation of in-flight ``reserved``/``running`` actions
  without duplicate launches or fabricated success outcomes.
- ``CTF-07``: Marking ``guest_health = 'cleanup_unconfirmed'`` retains conservative
  reservations and blocks subsequent launches in that guest via ``GuestBlockedError``.
- ``CTF-08``: Stale fencing tokens after supervisor restart are rejected with
  ``FencingError`` and active dynamic sessions are marked ``lost``.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime

from ctf_mcp.contracts import (
    ActionLifecycleState,
    ActionRecord,
    ContractViolationError,
    ErrorDetail,
    EvidenceRef,
    FencingError,
    GuestBlockedError,
    GuestHealthState,
    InvalidStateTransitionError,
    StrictModel,
    UsageMetrics,
)
from ctf_mcp.runs.actions import ActionManager, ActionSubmission
from ctf_mcp.runs.leases import LeaseManager
from ctf_mcp.storage import Storage


def _normalize_utc(dt: datetime | None = None) -> datetime:
    current = datetime.now(UTC) if dt is None else dt
    if current.tzinfo is None:
        return current.replace(tzinfo=UTC)
    return current.astimezone(UTC)


class ReconciliationReport(StrictModel):
    """Summary of non-terminal actions and dynamic sessions reconciled on restart."""

    reconciled_to_required: tuple[ActionRecord, ...] = ()
    expired_reserved: tuple[ActionRecord, ...] = ()
    still_running: tuple[ActionRecord, ...] = ()
    lost_session_ids: tuple[str, ...] = ()
    new_supervisor_token: int | None = None


class RecoveryManager:
    """Coordinates restart reconciliation, fencing verification, and guest blocking."""

    def __init__(self, storage: Storage) -> None:
        self.storage = storage
        self._actions = ActionManager(storage)
        self._leases = LeaseManager(storage)

    def mint_fencing_token_in_tx(
        self,
        conn: sqlite3.Connection,
        supervisor_key: str,
    ) -> int:
        """Allocate the next strictly monotonic fencing token for ``supervisor_key``."""
        return self.storage.next_fencing_token(conn, supervisor_key)

    def assert_guest_ready_in_tx(
        self,
        conn: sqlite3.Connection,
        run_id: str,
    ) -> None:
        """Ensure guest is in ``ready`` state; raise ``GuestBlockedError`` otherwise."""
        row = conn.execute(
            "SELECT guest_health FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            raise ContractViolationError(
                f"Run {run_id!r} does not exist.",
                details={"run_id": run_id},
            )
        health = GuestHealthState(str(row["guest_health"]))
        if health != GuestHealthState.READY:
            raise GuestBlockedError(
                f"Guest for run {run_id!r} is blocked (guest_health={health.value!r}).",
                details={"run_id": run_id, "guest_health": health.value},
            )

    def assert_guest_ready(self, run_id: str) -> None:
        """Read-only guest health verification."""
        with self.storage.read_connection() as conn:
            self.assert_guest_ready_in_tx(conn, run_id)

    def mark_cleanup_unconfirmed_in_tx(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        reason: str,
        *,
        action_id: str | None = None,
        now: datetime | None = None,
    ) -> GuestHealthState:
        """Mark ``runs.guest_health = 'cleanup_unconfirmed'`` and block reuse (CTF-07).

        Retains conservative budget reservations until manual or verified recovery.
        """
        if not reason or not reason.strip():
            raise ContractViolationError("cleanup_unconfirmed reason must be non-empty.")

        row = conn.execute(
            "SELECT run_id FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            raise ContractViolationError(
                f"Run {run_id!r} does not exist.",
                details={"run_id": run_id},
            )

        conn.execute(
            """
            UPDATE runs
            SET guest_health = ?, revision = revision + 1
            WHERE run_id = ?
            """,
            (GuestHealthState.CLEANUP_UNCONFIRMED.value, run_id),
        )
        if action_id is not None:
            conn.execute(
                """
                UPDATE actions
                SET error_code = COALESCE(error_code, 'cleanup_unconfirmed'),
                    error_message = ?,
                    updated_at = ?
                WHERE action_id = ? AND run_id = ?
                """,
                (reason, _normalize_utc(now).isoformat(), action_id, run_id),
            )
        return GuestHealthState.CLEANUP_UNCONFIRMED

    def mark_cleanup_unconfirmed(
        self,
        run_id: str,
        reason: str,
        *,
        action_id: str | None = None,
        now: datetime | None = None,
    ) -> GuestHealthState:
        """Mark a run's guest as ``cleanup_unconfirmed`` inside an atomic transaction."""
        with self.storage.transaction() as conn:
            return self.mark_cleanup_unconfirmed_in_tx(
                conn,
                run_id,
                reason,
                action_id=action_id,
                now=now,
            )

    def mark_guest_rolled_back_in_tx(
        self,
        conn: sqlite3.Connection,
        run_id: str,
    ) -> GuestHealthState:
        """Mark a run's guest as ``rolled_back`` after verified host evidence import."""
        row = conn.execute(
            "SELECT guest_health FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            raise ContractViolationError(f"Run {run_id!r} does not exist.")
        if str(row["guest_health"]) == GuestHealthState.CLEANUP_UNCONFIRMED.value:
            raise GuestBlockedError(
                f"Run {run_id!r} has cleanup_unconfirmed and requires reconciliation before rollback."
            )
        conn.execute(
            "UPDATE runs SET guest_health = ?, revision = revision + 1 WHERE run_id = ?",
            (GuestHealthState.ROLLED_BACK.value, run_id),
        )
        return GuestHealthState.ROLLED_BACK

    def recover_guest_ready_in_tx(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        *,
        cleanup_verified: bool,
        note: str,
        now: datetime | None = None,
    ) -> GuestHealthState:
        """Restore a ``cleanup_unconfirmed`` run to ``ready`` after verified recovery.

        Requires ``cleanup_verified=True``, a non-empty verification ``note``, and zero
        remaining ``reserved``/``running``/``reconciliation_required`` actions or active
        session leases. Preserves conservative time/byte deductions while clearing any
        stale concurrency locks held pending cleanup confirmation.
        """
        if not cleanup_verified:
            raise ContractViolationError(
                "cleanup_verified must be True to recover guest_health to 'ready'."
            )
        if not note or not note.strip():
            raise ContractViolationError("A non-empty recovery verification note is required.")

        row = conn.execute(
            "SELECT guest_health FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            raise ContractViolationError(
                f"Run {run_id!r} does not exist.",
                details={"run_id": run_id},
            )
        current_health = GuestHealthState(str(row["guest_health"]))
        if current_health == GuestHealthState.ROLLED_BACK:
            raise InvalidStateTransitionError(
                f"Run {run_id!r} is already 'rolled_back' and cannot recover to 'ready'."
            )

        non_terminal = conn.execute(
            """
            SELECT action_id FROM actions
            WHERE run_id = ? AND state IN ('reserved', 'running', 'reconciliation_required')
            ORDER BY created_at ASC
            """,
            (run_id,),
        ).fetchall()
        if non_terminal:
            raise ContractViolationError(
                f"Cannot recover run {run_id!r} to 'ready' while non-terminal actions remain.",
                details={"non_terminal_actions": [str(r["action_id"]) for r in non_terminal]},
            )

        leases_exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'session_leases'"
        ).fetchone()
        if leases_exists is not None:
            active_leases = conn.execute(
                "SELECT session_id FROM session_leases WHERE run_id = ? AND state = 'active'",
                (run_id,),
            ).fetchall()
            if active_leases:
                raise ContractViolationError(
                    f"Cannot recover run {run_id!r} to 'ready' while active session leases remain.",
                    details={"active_sessions": [str(r["session_id"]) for r in active_leases]},
                )

        _ = _normalize_utc(now)
        conn.execute(
            """
            UPDATE runs
            SET guest_health = ?, active_heavy_jobs = 0, active_sessions = 0, revision = revision + 1
            WHERE run_id = ?
            """,
            (GuestHealthState.READY.value, run_id),
        )
        return GuestHealthState.READY

    def recover_guest_ready(
        self,
        run_id: str,
        *,
        cleanup_verified: bool,
        note: str,
        now: datetime | None = None,
    ) -> GuestHealthState:
        """Restore a ``cleanup_unconfirmed`` run to ``ready`` inside a transaction."""
        with self.storage.transaction() as conn:
            return self.recover_guest_ready_in_tx(
                conn,
                run_id,
                cleanup_verified=cleanup_verified,
                note=note,
                now=now,
            )

    def reconcile_inflight_actions_in_tx(
        self,
        conn: sqlite3.Connection,
        *,
        run_id: str | None = None,
        is_process_alive: Callable[[ActionRecord], bool] | None = None,
        supervisor_key: str | None = None,
        mark_sessions_lost: bool = True,
        manage_run_budget: bool = True,
        now: datetime | None = None,
    ) -> ReconciliationReport:
        """Reconcile all non-terminal ``reserved``/``running`` actions on restart (CTF-06/08).

        - If ``supervisor_key`` is supplied, advances its monotonic fencing counter so
          pre-restart worker tokens are permanently fenced out.
        - ``running`` actions not confirmed alive transition to ``reconciliation_required``
          and retain conservative budget reservations.
        - ``reserved`` actions not confirmed alive transition to ``expired`` (mapping to
          ``denied``, never ``ok``) because ``RESERVED -> RECONCILIATION_REQUIRED`` is
          disallowed by ``ACTION_TRANSITIONS``.
        - Active dynamic session leases are marked ``lost`` when ``mark_sessions_lost=True``.
        """
        ts = _normalize_utc(now)
        new_token: int | None = None
        if supervisor_key is not None:
            new_token = self.storage.next_fencing_token(conn, supervisor_key)

        if run_id is not None:
            rows = conn.execute(
                """
                SELECT action_id FROM actions
                WHERE run_id = ? AND state IN ('reserved', 'running')
                ORDER BY created_at ASC
                """,
                (run_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT action_id FROM actions
                WHERE state IN ('reserved', 'running')
                ORDER BY created_at ASC
                """
            ).fetchall()

        reconciled_required: list[ActionRecord] = []
        expired_reserved: list[ActionRecord] = []
        still_running: list[ActionRecord] = []

        for row in rows:
            action_id = str(row["action_id"])
            action = self._actions.get_action_with_envelope_in_tx(conn, action_id).action
            alive = bool(is_process_alive(action)) if is_process_alive is not None else False

            if action.state == ActionLifecycleState.RUNNING:
                if alive:
                    still_running.append(action)
                else:
                    sub = self._actions.settle_action_in_tx(
                        conn,
                        action_id=action.action_id,
                        target_state=ActionLifecycleState.RECONCILIATION_REQUIRED,
                        usage=UsageMetrics(wall_ms=0, output_bytes=0),
                        fencing_token=action.fencing_token,
                        retain_reservation=True,
                        manage_run_budget=manage_run_budget,
                        error=ErrorDetail(
                            code="reconciliation_required",
                            message="Process not confirmed alive during restart reconciliation.",
                        ),
                        now=ts,
                    )
                    reconciled_required.append(sub.action)
            elif action.state == ActionLifecycleState.RESERVED:
                if alive:
                    still_running.append(action)
                else:
                    sub = self._actions.settle_action_in_tx(
                        conn,
                        action_id=action.action_id,
                        target_state=ActionLifecycleState.EXPIRED,
                        usage=UsageMetrics(wall_ms=0, output_bytes=0),
                        expiry_reason="reconciled_crash_before_launch",
                        summary="Action crashed or restarted while reserved before launch.",
                        usage_unknown=False,
                        cleanup_confirmed=True,
                        manage_run_budget=manage_run_budget,
                        now=ts,
                    )
                    expired_reserved.append(sub.action)

        lost_ids: tuple[str, ...] = ()
        if mark_sessions_lost:
            lost_leases = self._leases.mark_sessions_lost_in_tx(
                conn,
                run_id=run_id,
                reason="supervisor_or_vm_restart",
                now=ts,
            )
            lost_ids = tuple(lease.session_id for lease in lost_leases)

        return ReconciliationReport(
            reconciled_to_required=tuple(reconciled_required),
            expired_reserved=tuple(expired_reserved),
            still_running=tuple(still_running),
            lost_session_ids=lost_ids,
            new_supervisor_token=new_token,
        )

    def reconcile_inflight_actions(
        self,
        *,
        run_id: str | None = None,
        is_process_alive: Callable[[ActionRecord], bool] | None = None,
        supervisor_key: str | None = None,
        mark_sessions_lost: bool = True,
        now: datetime | None = None,
    ) -> ReconciliationReport:
        """Run restart reconciliation inside an atomic transaction."""
        with self.storage.transaction() as conn:
            return self.reconcile_inflight_actions_in_tx(
                conn,
                run_id=run_id,
                is_process_alive=is_process_alive,
                supervisor_key=supervisor_key,
                mark_sessions_lost=mark_sessions_lost,
                manage_run_budget=True,
                now=now,
            )

    def commit_worker_result_in_tx(
        self,
        conn: sqlite3.Connection,
        *,
        action_id: str,
        fencing_token: int,
        target_state: ActionLifecycleState,
        usage: UsageMetrics,
        has_tool_receipt: bool = True,
        summary: str | None = None,
        evidence: tuple[EvidenceRef, ...] = (),
        truncated: bool = False,
        next_cursor: str | None = None,
        error: ErrorDetail | None = None,
        supervisor_key: str | None = None,
        usage_unknown: bool = False,
        heavy_job_slot: bool | None = None,
        interactive_session_slot: bool | None = None,
        cleanup_confirmed: bool = True,
        manage_run_budget: bool = True,
        now: datetime | None = None,
    ) -> ActionSubmission:
        """Commit a worker execution result guarded by strict fencing token validation."""
        sub = self._actions.get_action_with_envelope_in_tx(conn, action_id)
        action = sub.action

        if action.fencing_token is None or fencing_token != action.fencing_token:
            raise FencingError(
                f"Stale or mismatched fencing token {fencing_token} for action {action_id!r} "
                f"(expected {action.fencing_token}).",
                details={
                    "action_id": action_id,
                    "provided_fencing_token": fencing_token,
                    "stored_fencing_token": action.fencing_token,
                },
            )
        if action.state != ActionLifecycleState.RUNNING:
            raise FencingError(
                f"Worker completion with fencing_token={fencing_token} rejected because "
                f"action {action_id!r} is in state {action.state.value!r}.",
                details={
                    "action_id": action_id,
                    "state": action.state.value,
                    "provided_fencing_token": fencing_token,
                },
            )
        if supervisor_key is not None:
            cnt_row = conn.execute(
                "SELECT current_token FROM fencing_counters WHERE supervisor_key = ?",
                (supervisor_key,),
            ).fetchone()
            if cnt_row is not None and int(cnt_row["current_token"]) > fencing_token:
                raise FencingError(
                    f"Fencing token {fencing_token} was superseded by supervisor epoch {cnt_row['current_token']}.",
                    details={
                        "action_id": action_id,
                        "provided_fencing_token": fencing_token,
                        "current_epoch_token": int(cnt_row["current_token"]),
                    },
                )

        return self._actions.settle_action_in_tx(
            conn,
            action_id=action_id,
            target_state=target_state,
            usage=usage,
            fencing_token=fencing_token,
            has_tool_receipt=has_tool_receipt,
            summary=summary,
            evidence=evidence,
            truncated=truncated,
            next_cursor=next_cursor,
            error=error,
            usage_unknown=usage_unknown,
            heavy_job_slot=heavy_job_slot,
            interactive_session_slot=interactive_session_slot,
            cleanup_confirmed=cleanup_confirmed,
            manage_run_budget=manage_run_budget,
            supervisor_key=supervisor_key,
            now=now,
        )

    def commit_worker_result(
        self,
        *,
        action_id: str,
        fencing_token: int,
        target_state: ActionLifecycleState,
        usage: UsageMetrics,
        has_tool_receipt: bool = True,
        summary: str | None = None,
        evidence: tuple[EvidenceRef, ...] = (),
        truncated: bool = False,
        next_cursor: str | None = None,
        error: ErrorDetail | None = None,
        supervisor_key: str | None = None,
        usage_unknown: bool = False,
        heavy_job_slot: bool | None = None,
        interactive_session_slot: bool | None = None,
        cleanup_confirmed: bool = True,
        now: datetime | None = None,
    ) -> ActionSubmission:
        """Commit a fenced worker result inside an atomic transaction."""
        with self.storage.transaction() as conn:
            return self.commit_worker_result_in_tx(
                conn,
                action_id=action_id,
                fencing_token=fencing_token,
                target_state=target_state,
                usage=usage,
                has_tool_receipt=has_tool_receipt,
                summary=summary,
                evidence=evidence,
                truncated=truncated,
                next_cursor=next_cursor,
                error=error,
                supervisor_key=supervisor_key,
                usage_unknown=usage_unknown,
                heavy_job_slot=heavy_job_slot,
                interactive_session_slot=interactive_session_slot,
                cleanup_confirmed=cleanup_confirmed,
                manage_run_budget=True,
                now=now,
            )

    def resolve_reconciled_action_in_tx(
        self,
        conn: sqlite3.Connection,
        *,
        action_id: str,
        target_state: ActionLifecycleState,
        usage: UsageMetrics | None = None,
        has_tool_receipt: bool = False,
        summary: str | None = None,
        evidence: tuple[EvidenceRef, ...] = (),
        error: ErrorDetail | None = None,
        supervisor_key: str | None = None,
        supervisor_instance_id: str | None = None,
        process_start_id: str | None = None,
        retain_reservation: bool = False,
        usage_unknown: bool | None = None,
        heavy_job_slot: bool | None = None,
        interactive_session_slot: bool | None = None,
        cleanup_confirmed: bool = True,
        manage_run_budget: bool = True,
        now: datetime | None = None,
    ) -> ActionSubmission:
        """Resolve an action in ``reconciliation_required`` to ``running`` or a terminal state."""
        current = self._actions.get_action_with_envelope_in_tx(conn, action_id).action
        if current.state != ActionLifecycleState.RECONCILIATION_REQUIRED:
            raise ContractViolationError(
                f"Action {action_id!r} is in state {current.state.value!r}, not 'reconciliation_required'."
            )

        if target_state == ActionLifecycleState.RUNNING:
            if not supervisor_key or not supervisor_instance_id or not process_start_id:
                raise ContractViolationError(
                    "Resuming a reconciled action to 'running' requires supervisor_key, "
                    "supervisor_instance_id, and process_start_id."
                )
            restarted = self._actions.start_action_in_tx(
                conn,
                action_id=action_id,
                supervisor_key=supervisor_key,
                supervisor_instance_id=supervisor_instance_id,
                process_start_id=process_start_id,
                now=now,
            )
            return ActionSubmission(action=restarted, envelope=None, replayed=False)

        eff_usage_unknown = (
            usage is None
            or (not has_tool_receipt and usage.wall_ms == 0 and usage.output_bytes == 0)
            if usage_unknown is None
            else bool(usage_unknown)
        )
        return self._actions.settle_action_in_tx(
            conn,
            action_id=action_id,
            target_state=target_state,
            usage=UsageMetrics(wall_ms=0, output_bytes=0) if usage is None else usage,
            has_tool_receipt=has_tool_receipt,
            summary=summary,
            evidence=evidence,
            error=error,
            retain_reservation=retain_reservation,
            usage_unknown=eff_usage_unknown,
            heavy_job_slot=heavy_job_slot,
            interactive_session_slot=interactive_session_slot,
            cleanup_confirmed=cleanup_confirmed,
            manage_run_budget=manage_run_budget,
            allow_reconciled_resolution=True,
            now=now,
        )

    def resolve_reconciled_action(
        self,
        *,
        action_id: str,
        target_state: ActionLifecycleState,
        usage: UsageMetrics | None = None,
        has_tool_receipt: bool = False,
        summary: str | None = None,
        evidence: tuple[EvidenceRef, ...] = (),
        error: ErrorDetail | None = None,
        supervisor_key: str | None = None,
        supervisor_instance_id: str | None = None,
        process_start_id: str | None = None,
        retain_reservation: bool = False,
        usage_unknown: bool | None = None,
        heavy_job_slot: bool | None = None,
        interactive_session_slot: bool | None = None,
        cleanup_confirmed: bool = True,
        now: datetime | None = None,
    ) -> ActionSubmission:
        """Resolve a ``reconciliation_required`` action inside an atomic transaction."""
        with self.storage.transaction() as conn:
            return self.resolve_reconciled_action_in_tx(
                conn,
                action_id=action_id,
                target_state=target_state,
                usage=usage,
                has_tool_receipt=has_tool_receipt,
                summary=summary,
                evidence=evidence,
                error=error,
                supervisor_key=supervisor_key,
                supervisor_instance_id=supervisor_instance_id,
                process_start_id=process_start_id,
                retain_reservation=retain_reservation,
                usage_unknown=usage_unknown,
                heavy_job_slot=heavy_job_slot,
                interactive_session_slot=interactive_session_slot,
                cleanup_confirmed=cleanup_confirmed,
                manage_run_budget=True,
                now=now,
            )


__all__ = [
    "ReconciliationReport",
    "RecoveryManager",
]
