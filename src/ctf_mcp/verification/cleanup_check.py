"""Run close-time integrity verification (CTF-07 and CTF-10).

Enforces ``docs/11`` section 4:
- Non-terminal actions block run close.
- ``guest_health == 'cleanup_unconfirmed'`` or unconfirmed child process exits
  block close and reuse.
- Incomplete or failed host evidence imports block close and never treat a
  successful VM rollback as a successful evidence export.
- Remaining valid evidence objects and stored artifacts are preserved and
  explicitly reported on failed close/import.
"""

from __future__ import annotations

import hmac
import sqlite3
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from pydantic import Field

from ctf_mcp.contracts import (
    TERMINAL_ACTION_STATES,
    ActionLifecycleState,
    ContractViolationError,
    GuestBlockedError,
    GuestHealthState,
    StrictModel,
    sha256_bytes,
)
from ctf_mcp.fs_guard import safe_read_bounded
from ctf_mcp.storage import Storage

DEFAULT_MAX_EVIDENCE_VERIFY_BYTES = 104_857_600


class CloseIntegrityReport(StrictModel):
    """Structured close-time integrity and export readiness report."""

    run_id: str = Field(min_length=1)
    close_allowed: bool
    cleanup_confirmed: bool
    import_verified: bool
    export_succeeded: bool
    vm_rollback_succeeded: bool
    guest_health: GuestHealthState | None = None
    non_terminal_action_ids: tuple[str, ...] = ()
    unconfirmed_process_ids: tuple[str, ...] = ()
    missing_evidence_ids: tuple[str, ...] = ()
    corrupted_evidence_ids: tuple[str, ...] = ()
    preserved_evidence_ids: tuple[str, ...] = ()
    blocking_reasons: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    checked_at: datetime


def evaluate_close_integrity_in_tx(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    vault_root: str | Path | None = None,
    child_processes_confirmed_stopped: bool = True,
    unconfirmed_process_ids: Sequence[str | int] = (),
    import_completed: bool = True,
    import_errors: Sequence[str] = (),
    expected_evidence_ids: Sequence[str] = (),
    vm_rollback_succeeded: bool = False,
    require_verification: bool = False,
    max_evidence_verify_bytes: int = DEFAULT_MAX_EVIDENCE_VERIFY_BYTES,
    clock: Callable[[], datetime] | None = None,
) -> CloseIntegrityReport:
    """Inspect DB state and host import/cleanup status inside an open transaction."""
    if not isinstance(run_id, str) or not run_id.strip():
        raise ContractViolationError("run_id must be a non-empty string.")
    if max_evidence_verify_bytes <= 0:
        raise ContractViolationError("max_evidence_verify_bytes must be positive.")

    now = (clock or (lambda: datetime.now(UTC)))()
    blocking: list[str] = []
    warnings: list[str] = []

    run_row = conn.execute(
        """
        SELECT run_id, guest_health, active_heavy_jobs, active_sessions, closed_at
        FROM runs
        WHERE run_id = ?
        """,
        (run_id,),
    ).fetchone()

    if run_row is None:
        return CloseIntegrityReport(
            run_id=run_id,
            close_allowed=False,
            cleanup_confirmed=False,
            import_verified=False,
            export_succeeded=False,
            vm_rollback_succeeded=vm_rollback_succeeded,
            guest_health=None,
            blocking_reasons=("run_not_found",),
            checked_at=now,
        )

    guest_health = GuestHealthState(str(run_row["guest_health"]))
    cleanup_confirmed = True

    if guest_health == GuestHealthState.CLEANUP_UNCONFIRMED:
        cleanup_confirmed = False
        blocking.append("guest_cleanup_unconfirmed")

    if int(run_row["active_heavy_jobs"]) > 0 or int(run_row["active_sessions"]) > 0:
        cleanup_confirmed = False
        blocking.append("active_jobs_or_sessions_remaining")

    normalized_unconfirmed_pids = tuple(str(p) for p in unconfirmed_process_ids)
    if not child_processes_confirmed_stopped or normalized_unconfirmed_pids:
        cleanup_confirmed = False
        blocking.append("child_processes_unconfirmed")

    action_rows = conn.execute(
        "SELECT action_id, state FROM actions WHERE run_id = ? ORDER BY created_at ASC",
        (run_id,),
    ).fetchall()
    non_terminal_ids = tuple(
        str(row["action_id"])
        for row in action_rows
        if ActionLifecycleState(str(row["state"])) not in TERMINAL_ACTION_STATES
    )
    if non_terminal_ids:
        blocking.append("non_terminal_actions_remaining")

    obj_rows = conn.execute(
        """
        SELECT evidence_id, raw_sha256
        FROM evidence_objects
        WHERE run_id = ?
        ORDER BY created_at ASC, evidence_id ASC
        """,
        (run_id,),
    ).fetchall()
    stored_ids = {str(r["evidence_id"]) for r in obj_rows}

    deduped_expected = tuple(dict.fromkeys(expected_evidence_ids))
    missing_evidence_ids = tuple(
        eid for eid in deduped_expected if eid not in stored_ids
    )
    if missing_evidence_ids:
        blocking.append("missing_expected_evidence")

    vault_path = Path(vault_root) if vault_root is not None else None
    corrupted_list: list[str] = []
    preserved_list: list[str] = []

    for obj_row in obj_rows:
        eid = str(obj_row["evidence_id"])
        if vault_path is None:
            preserved_list.append(eid)
            continue

        view_rows = conn.execute(
            """
            SELECT view_sha256, storage_relpath
            FROM evidence_views
            WHERE evidence_id = ? AND run_id = ? AND revoked_at IS NULL
            ORDER BY created_at DESC
            """,
            (eid, run_id),
        ).fetchall()
        if not view_rows:
            # Check if any view row (even revoked) exists on disk so preserved evidence is verified
            view_rows = conn.execute(
                """
                SELECT view_sha256, storage_relpath
                FROM evidence_views
                WHERE evidence_id = ? AND run_id = ?
                ORDER BY created_at DESC
                """,
                (eid, run_id),
            ).fetchall()

        if not view_rows:
            corrupted_list.append(eid)
            continue

        eid_ok = True
        for vrow in view_rows:
            try:
                res = safe_read_bounded(
                    vault_path,
                    str(vrow["storage_relpath"]),
                    max_bytes=max_evidence_verify_bytes,
                    allow_truncate=False,
                )
            except Exception:
                eid_ok = False
                break
            if not hmac.compare_digest(
                sha256_bytes(res.data), str(vrow["view_sha256"]).lower()
            ):
                eid_ok = False
                break

        if eid_ok:
            preserved_list.append(eid)
        else:
            corrupted_list.append(eid)

    corrupted_evidence_ids = tuple(corrupted_list)
    preserved_evidence_ids = tuple(preserved_list)

    if corrupted_evidence_ids:
        blocking.append("evidence_integrity_check_failed")

    if not import_completed or import_errors:
        blocking.append("host_import_incomplete")

    if require_verification:
        ver_count_row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM verifications WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if ver_count_row is None or int(ver_count_row["cnt"]) == 0:
            blocking.append("verification_record_missing")

    import_verified = (
        bool(import_completed)
        and len(import_errors) == 0
        and len(missing_evidence_ids) == 0
        and len(corrupted_evidence_ids) == 0
    )

    if vm_rollback_succeeded and not import_verified:
        warnings.append(
            "vm_rollback_succeeded_does_not_imply_export_success: host import failed or remained incomplete."
        )

    close_allowed = len(blocking) == 0
    export_succeeded = (
        close_allowed
        and import_verified
        and cleanup_confirmed
        and len(non_terminal_ids) == 0
    )

    return CloseIntegrityReport(
        run_id=run_id,
        close_allowed=close_allowed,
        cleanup_confirmed=cleanup_confirmed,
        import_verified=import_verified,
        export_succeeded=export_succeeded,
        vm_rollback_succeeded=vm_rollback_succeeded,
        guest_health=guest_health,
        non_terminal_action_ids=non_terminal_ids,
        unconfirmed_process_ids=normalized_unconfirmed_pids,
        missing_evidence_ids=missing_evidence_ids,
        corrupted_evidence_ids=corrupted_evidence_ids,
        preserved_evidence_ids=preserved_evidence_ids,
        blocking_reasons=tuple(blocking),
        warnings=tuple(warnings),
        checked_at=now,
    )


def evaluate_close_integrity(
    storage: Storage,
    *,
    run_id: str,
    vault_root: str | Path | None = None,
    child_processes_confirmed_stopped: bool = True,
    unconfirmed_process_ids: Sequence[str | int] = (),
    import_completed: bool = True,
    import_errors: Sequence[str] = (),
    expected_evidence_ids: Sequence[str] = (),
    vm_rollback_succeeded: bool = False,
    require_verification: bool = False,
    max_evidence_verify_bytes: int = DEFAULT_MAX_EVIDENCE_VERIFY_BYTES,
    clock: Callable[[], datetime] | None = None,
) -> CloseIntegrityReport:
    """Evaluate run close-time integrity and export readiness."""
    with storage.read_connection() as conn:
        return evaluate_close_integrity_in_tx(
            conn,
            run_id=run_id,
            vault_root=vault_root,
            child_processes_confirmed_stopped=child_processes_confirmed_stopped,
            unconfirmed_process_ids=unconfirmed_process_ids,
            import_completed=import_completed,
            import_errors=import_errors,
            expected_evidence_ids=expected_evidence_ids,
            vm_rollback_succeeded=vm_rollback_succeeded,
            require_verification=require_verification,
            max_evidence_verify_bytes=max_evidence_verify_bytes,
            clock=clock,
        )


def assert_close_ready(
    storage: Storage,
    *,
    run_id: str,
    vault_root: str | Path | None = None,
    child_processes_confirmed_stopped: bool = True,
    unconfirmed_process_ids: Sequence[str | int] = (),
    import_completed: bool = True,
    import_errors: Sequence[str] = (),
    expected_evidence_ids: Sequence[str] = (),
    vm_rollback_succeeded: bool = False,
    require_verification: bool = False,
    max_evidence_verify_bytes: int = DEFAULT_MAX_EVIDENCE_VERIFY_BYTES,
    clock: Callable[[], datetime] | None = None,
) -> CloseIntegrityReport:
    """Assert close-time integrity passes, or raise an explicit domain error."""
    report = evaluate_close_integrity(
        storage,
        run_id=run_id,
        vault_root=vault_root,
        child_processes_confirmed_stopped=child_processes_confirmed_stopped,
        unconfirmed_process_ids=unconfirmed_process_ids,
        import_completed=import_completed,
        import_errors=import_errors,
        expected_evidence_ids=expected_evidence_ids,
        vm_rollback_succeeded=vm_rollback_succeeded,
        require_verification=require_verification,
        max_evidence_verify_bytes=max_evidence_verify_bytes,
        clock=clock,
    )
    if not report.close_allowed:
        details = report.model_dump(mode="json")
        if not report.cleanup_confirmed:
            raise GuestBlockedError(
                f"Run {run_id!r} close blocked because cleanup could not be confirmed: {report.blocking_reasons}.",
                details=details,
            )
        raise ContractViolationError(
            f"Run {run_id!r} close blocked by integrity check: {report.blocking_reasons}.",
            details=details,
        )
    return report


class CloseIntegrityChecker:
    """Service wrapper for evaluating and enforcing close-time integrity."""

    def __init__(
        self,
        storage: Storage,
        *,
        vault_root: str | Path | None = None,
        max_evidence_verify_bytes: int = DEFAULT_MAX_EVIDENCE_VERIFY_BYTES,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._storage = storage
        self._vault_root = Path(vault_root) if vault_root is not None else None
        self._max_evidence_verify_bytes = max_evidence_verify_bytes
        self._clock = clock

    def evaluate(
        self,
        *,
        run_id: str,
        child_processes_confirmed_stopped: bool = True,
        unconfirmed_process_ids: Sequence[str | int] = (),
        import_completed: bool = True,
        import_errors: Sequence[str] = (),
        expected_evidence_ids: Sequence[str] = (),
        vm_rollback_succeeded: bool = False,
        require_verification: bool = False,
    ) -> CloseIntegrityReport:
        """Evaluate close integrity without raising on blocked states."""
        return evaluate_close_integrity(
            self._storage,
            run_id=run_id,
            vault_root=self._vault_root,
            child_processes_confirmed_stopped=child_processes_confirmed_stopped,
            unconfirmed_process_ids=unconfirmed_process_ids,
            import_completed=import_completed,
            import_errors=import_errors,
            expected_evidence_ids=expected_evidence_ids,
            vm_rollback_succeeded=vm_rollback_succeeded,
            require_verification=require_verification,
            max_evidence_verify_bytes=self._max_evidence_verify_bytes,
            clock=self._clock,
        )

    def assert_ready(
        self,
        *,
        run_id: str,
        child_processes_confirmed_stopped: bool = True,
        unconfirmed_process_ids: Sequence[str | int] = (),
        import_completed: bool = True,
        import_errors: Sequence[str] = (),
        expected_evidence_ids: Sequence[str] = (),
        vm_rollback_succeeded: bool = False,
        require_verification: bool = False,
    ) -> CloseIntegrityReport:
        """Evaluate close integrity and raise on any blocking violation."""
        return assert_close_ready(
            self._storage,
            run_id=run_id,
            vault_root=self._vault_root,
            child_processes_confirmed_stopped=child_processes_confirmed_stopped,
            unconfirmed_process_ids=unconfirmed_process_ids,
            import_completed=import_completed,
            import_errors=import_errors,
            expected_evidence_ids=expected_evidence_ids,
            vm_rollback_succeeded=vm_rollback_succeeded,
            require_verification=require_verification,
            max_evidence_verify_bytes=self._max_evidence_verify_bytes,
            clock=self._clock,
        )


__all__ = [
    "CloseIntegrityChecker",
    "CloseIntegrityReport",
    "DEFAULT_MAX_EVIDENCE_VERIFY_BYTES",
    "assert_close_ready",
    "evaluate_close_integrity",
    "evaluate_close_integrity_in_tx",
]
