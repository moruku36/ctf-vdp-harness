"""Action admission, idempotency, optimistic locking, and lifecycle settlement.

Implements ``docs/11`` section 2 (CTF-02, CTF-11) and conforms to
``BudgetManagerPort`` while exposing composable ``*_in_tx`` methods so Wave 2
can combine ``gateway/budget.py`` and ``runs/actions.py`` in a single SQLite
transaction.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from ctf_mcp.contracts import (
    TERMINAL_ACTION_STATES,
    ActionConflictError,
    ActionLifecycleState,
    ActionRecord,
    ActionRequest,
    BudgetExceededError,
    BudgetSpec,
    CapabilityDeniedError,
    CapabilityDescriptor,
    ContractViolationError,
    EnvelopeStatus,
    ErrorDetail,
    EvidenceRef,
    ExecutionClass,
    FencingError,
    GuestBlockedError,
    GuestHealthState,
    InvalidStateTransitionError,
    ProvenanceInfo,
    ResultEnvelope,
    StrictModel,
    UsageMetrics,
    canonical_digest,
    canonical_json,
    lifecycle_to_envelope_status,
    validate_action_transition,
)
from ctf_mcp.storage import Storage


def _normalize_utc(dt: datetime | None = None) -> datetime:
    current = datetime.now(UTC) if dt is None else dt
    if current.tzinfo is None:
        return current.replace(tzinfo=UTC)
    return current.astimezone(UTC)


def _parse_dt(raw: str) -> datetime:
    dt = datetime.fromisoformat(raw)
    return _normalize_utc(dt)


def _row_to_action_record(row: sqlite3.Row) -> ActionRecord:
    return ActionRecord(
        run_id=str(row["run_id"]),
        action_id=str(row["action_id"]),
        request_id=str(row["request_id"]),
        principal_id=str(row["principal_id"]),
        expected_revision=int(row["expected_revision"]),
        capability_name=str(row["capability_name"]),
        operation=str(row["operation"]),
        adapter_revision=str(row["adapter_revision"]),
        canonical_args_sha256=str(row["canonical_args_sha256"]),
        sanitized_args=json.loads(row["sanitized_args_json"]),
        scope_revision=str(row["scope_revision"]),
        repeat_of=str(row["repeat_of"]) if row["repeat_of"] is not None else None,
        state=ActionLifecycleState(str(row["state"])),
        reserved_ms=int(row["reserved_ms"]),
        reserved_bytes=int(row["reserved_bytes"]),
        used_ms=int(row["used_ms"]),
        used_bytes=int(row["used_bytes"]),
        fencing_token=int(row["fencing_token"]) if row["fencing_token"] is not None else None,
        supervisor_instance_id=(
            str(row["supervisor_instance_id"])
            if row["supervisor_instance_id"] is not None
            else None
        ),
        process_start_id=(
            str(row["process_start_id"]) if row["process_start_id"] is not None else None
        ),
        created_at=_parse_dt(str(row["created_at"])),
        updated_at=_parse_dt(str(row["updated_at"])),
    )


def _row_to_envelope(row: sqlite3.Row) -> ResultEnvelope | None:
    raw = row["envelope_json"]
    if raw is None:
        return None
    return ResultEnvelope.model_validate_json(str(raw))


class ActionSubmission(StrictModel):
    """Combined ActionRecord, optional ResultEnvelope, and replay indicator."""

    action: ActionRecord
    envelope: ResultEnvelope | None = None
    replayed: bool = False


def build_result_envelope(
    *,
    action: ActionRecord,
    target_state: ActionLifecycleState,
    usage: UsageMetrics,
    has_tool_receipt: bool = True,
    expiry_reason: str | None = None,
    summary: str | None = None,
    evidence: tuple[EvidenceRef, ...] = (),
    truncated: bool = False,
    next_cursor: str | None = None,
    error: ErrorDetail | None = None,
) -> ResultEnvelope:
    """Construct a contract-compliant ResultEnvelope from a terminal action state.

    Enforces ``CTF-11``: ``FAILED`` always maps to ``tool_error`` with explicit error
    metadata and is never disguised as an empty success finding.
    """
    env_status = lifecycle_to_envelope_status(
        target_state,
        has_tool_receipt=has_tool_receipt,
        expiry_reason=expiry_reason,
    )

    effective_error = error
    effective_summary = (summary or "").strip()

    if env_status == EnvelopeStatus.TOOL_ERROR:
        if effective_error is None:
            effective_error = ErrorDetail(
                code="tool_error",
                message=effective_summary or "Analyzer execution failed.",
            )
        if not effective_summary:
            effective_summary = "Tool execution failed; no finding verdict can be inferred."
    elif env_status == EnvelopeStatus.DENIED:
        if effective_error is None:
            code = "expired" if target_state == ActionLifecycleState.EXPIRED else "denied"
            msg = (
                expiry_reason
                if target_state == ActionLifecycleState.EXPIRED and expiry_reason
                else (effective_summary or "Action denied.")
            )
            effective_error = ErrorDetail(code=code, message=msg)
        if not effective_summary:
            effective_summary = effective_error.message
    elif env_status == EnvelopeStatus.OK:
        if effective_error is not None:
            raise ContractViolationError("Successful ResultEnvelope (ok) cannot carry an error.")
        if not effective_summary:
            effective_summary = "Action completed."
    else:
        if not effective_summary:
            effective_summary = f"Action ended with status={env_status.value}."

    return ResultEnvelope(
        run_id=action.run_id,
        action_id=action.action_id,
        status=env_status,
        summary=effective_summary,
        evidence=evidence,
        truncated=truncated,
        next_cursor=next_cursor,
        error=effective_error,
        usage=usage,
        provenance=ProvenanceInfo(
            adapter_revision=action.adapter_revision,
            scope_revision=action.scope_revision,
        ),
    )


class ActionManager:
    """Manages action admission, idempotency, budget reservations, and settlement."""

    def __init__(self, storage: Storage) -> None:
        self.storage = storage

    def get_action_with_envelope_in_tx(
        self,
        conn: sqlite3.Connection,
        action_id: str,
        *,
        run_id: str | None = None,
    ) -> ActionSubmission:
        """Retrieve an action record and its persisted ResultEnvelope if present."""
        row = conn.execute(
            "SELECT * FROM actions WHERE action_id = ?",
            (action_id,),
        ).fetchone()
        if row is None:
            raise ContractViolationError(
                f"Action {action_id!r} does not exist.",
                details={"action_id": action_id},
            )
        if run_id is not None and str(row["run_id"]) != run_id:
            raise ContractViolationError(
                f"Action {action_id!r} does not belong to run {run_id!r}.",
                details={"action_id": action_id, "run_id": run_id},
            )
        return ActionSubmission(
            action=_row_to_action_record(row),
            envelope=_row_to_envelope(row),
            replayed=False,
        )

    def get_action_with_envelope(
        self,
        action_id: str,
        *,
        run_id: str | None = None,
    ) -> ActionSubmission:
        """Read-only fetch of an action and its ResultEnvelope."""
        with self.storage.read_connection() as conn:
            return self.get_action_with_envelope_in_tx(conn, action_id, run_id=run_id)

    def get_action(self, action_id: str, *, run_id: str | None = None) -> ActionRecord:
        """Fetch an ActionRecord by ID."""
        return self.get_action_with_envelope(action_id, run_id=run_id).action

    def list_actions(
        self,
        run_id: str,
        *,
        states: tuple[ActionLifecycleState, ...] | None = None,
    ) -> list[ActionRecord]:
        """List actions for ``run_id``, optionally filtered by lifecycle states."""
        with self.storage.read_connection() as conn:
            if states:
                placeholders = ", ".join("?" for _ in states)
                params: list[Any] = [run_id, *(s.value for s in states)]
                rows = conn.execute(
                    f"SELECT * FROM actions WHERE run_id = ? AND state IN ({placeholders}) "
                    "ORDER BY created_at ASC",
                    params,
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM actions WHERE run_id = ? ORDER BY created_at ASC",
                    (run_id,),
                ).fetchall()
            return [_row_to_action_record(r) for r in rows]

    def lookup_by_request_in_tx(
        self,
        conn: sqlite3.Connection,
        *,
        principal_id: str,
        run_id: str,
        request_id: str,
    ) -> ActionSubmission | None:
        """Look up an existing action by idempotency key ``(principal_id, run_id, request_id)``."""
        row = conn.execute(
            """
            SELECT * FROM actions
            WHERE principal_id = ? AND run_id = ? AND request_id = ?
            """,
            (principal_id, run_id, request_id),
        ).fetchone()
        if row is None:
            return None
        return ActionSubmission(
            action=_row_to_action_record(row),
            envelope=_row_to_envelope(row),
            replayed=True,
        )

    def check_idempotent_replay_in_tx(
        self,
        conn: sqlite3.Connection,
        *,
        principal_id: str,
        request: ActionRequest,
    ) -> ActionSubmission | None:
        """Check whether ``(principal_id, run_id, request_id)`` already exists.

        Returns ``ActionSubmission(..., replayed=True)`` on exact canonical match,
        ``None`` if unseen, or raises ``ActionConflictError`` if arguments or
        operation parameters differ.
        """
        existing = self.lookup_by_request_in_tx(
            conn,
            principal_id=principal_id,
            run_id=request.run_id,
            request_id=request.request_id,
        )
        if existing is None:
            return None

        incoming_digest = canonical_digest(request.arguments)
        act = existing.action
        if (
            act.canonical_args_sha256 != incoming_digest
            or act.capability_name != request.capability_name
            or act.operation != request.operation
            or act.repeat_of != request.repeat_of
        ):
            raise ActionConflictError(
                f"Idempotency key ({principal_id!r}, {request.run_id!r}, {request.request_id!r}) "
                "was reused with modified arguments or operation.",
                details={
                    "principal_id": principal_id,
                    "run_id": request.run_id,
                    "request_id": request.request_id,
                    "existing_digest": act.canonical_args_sha256,
                    "incoming_digest": incoming_digest,
                },
            )
        return existing

    def reserve_action_in_tx(
        self,
        conn: sqlite3.Connection,
        *,
        run_id: str,
        principal_id: str,
        request: ActionRequest,
        capability: CapabilityDescriptor,
        scope_revision: str,
        sanitized_args: dict[str, Any] | None = None,
        reserved_ms: int | None = None,
        reserved_bytes: int | None = None,
        manage_run_budget: bool = True,
        now: datetime | None = None,
    ) -> ActionSubmission:
        """Admit and reserve an action inside an active ``BEGIN IMMEDIATE`` transaction.

        Checks idempotency BEFORE optimistic revision and budget reservation so
        retrying a committed request returns the prior action without double-charging
        or failing due to the bumped ``runs.revision``.
        """
        if request.run_id != run_id:
            raise ContractViolationError(
                f"ActionRequest.run_id {request.run_id!r} does not match run_id {run_id!r}.",
                details={"request_run_id": request.run_id, "run_id": run_id},
            )

        replay = self.check_idempotent_replay_in_tx(
            conn,
            principal_id=principal_id,
            request=request,
        )
        if replay is not None:
            return replay

        run_row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if run_row is None:
            raise ContractViolationError(
                f"Run {run_id!r} does not exist.",
                details={"run_id": run_id},
            )
        if run_row["closed_at"] is not None:
            raise InvalidStateTransitionError(
                f"Cannot admit new action on closed run {run_id!r}.",
                details={"run_id": run_id},
            )

        guest_health = GuestHealthState(str(run_row["guest_health"]))
        if guest_health != GuestHealthState.READY:
            raise GuestBlockedError(
                f"Guest for run {run_id!r} is blocked (guest_health={guest_health.value!r}).",
                details={"run_id": run_id, "guest_health": guest_health.value},
            )

        current_revision = int(run_row["revision"])
        if current_revision != request.expected_revision:
            raise ActionConflictError(
                f"Run revision mismatch: expected {request.expected_revision}, actual {current_revision}.",
                details={
                    "run_id": run_id,
                    "expected_revision": request.expected_revision,
                    "actual_revision": current_revision,
                },
            )

        if request.capability_name != capability.name:
            raise CapabilityDeniedError(
                f"Requested capability {request.capability_name!r} does not match descriptor {capability.name!r}."
            )
        if request.operation not in capability.operations:
            raise CapabilityDeniedError(
                f"Operation {request.operation!r} is not permitted for capability {capability.name!r}.",
                details={"capability": capability.name, "operation": request.operation},
            )

        if request.repeat_of is not None:
            if not request.repeat_of.strip():
                raise ContractViolationError("repeat_of cannot be blank whitespace.")
            orig = conn.execute(
                "SELECT action_id FROM actions WHERE action_id = ? AND run_id = ?",
                (request.repeat_of, run_id),
            ).fetchone()
            if orig is None:
                raise ContractViolationError(
                    f"repeat_of references unknown action_id {request.repeat_of!r} in run {run_id!r}.",
                    details={"run_id": run_id, "repeat_of": request.repeat_of},
                )

        budget_spec = BudgetSpec.model_validate_json(str(run_row["budget_spec_json"]))
        desired_ms = (
            min(capability.limits.timeout_seconds * 1000, budget_spec.action_timeout_seconds * 1000)
            if reserved_ms is None
            else reserved_ms
        )
        desired_bytes = (
            capability.limits.max_output_bytes if reserved_bytes is None else reserved_bytes
        )
        if desired_ms <= 0 or desired_bytes <= 0:
            raise BudgetExceededError("Action budget reservation must be strictly positive.")

        if manage_run_budget:
            remaining_ms = int(run_row["remaining_ms"])
            remaining_bytes = int(run_row["remaining_bytes"])
            remaining_calls = int(run_row["remaining_calls"])
            active_heavy = int(run_row["active_heavy_jobs"])
            active_sessions = int(run_row["active_sessions"])

            if remaining_calls < 1:
                raise BudgetExceededError(
                    "Run max_tool_calls budget exhausted.",
                    details={"run_id": run_id, "remaining_calls": remaining_calls},
                )
            if remaining_ms <= 0:
                raise BudgetExceededError(
                    "Run execution time budget exhausted.",
                    details={"run_id": run_id, "remaining_ms": remaining_ms},
                )
            if remaining_bytes <= 0:
                raise BudgetExceededError(
                    "Run evidence byte budget exhausted.",
                    details={"run_id": run_id, "remaining_bytes": remaining_bytes},
                )
            if active_heavy >= budget_spec.heavy_job_concurrency:
                raise BudgetExceededError(
                    "Heavy job concurrency limit reached.",
                    details={
                        "run_id": run_id,
                        "active_heavy_jobs": active_heavy,
                        "limit": budget_spec.heavy_job_concurrency,
                    },
                )
            if (
                ExecutionClass.DYNAMIC in capability.execution_classes
                and active_sessions >= budget_spec.interactive_session_limit
            ):
                raise BudgetExceededError(
                    "Interactive session concurrency limit reached.",
                    details={
                        "run_id": run_id,
                        "active_sessions": active_sessions,
                        "limit": budget_spec.interactive_session_limit,
                    },
                )

            # Short remaining run budget lowers executable allowance before dispatch.
            effective_ms = min(desired_ms, remaining_ms)
            effective_bytes = min(desired_bytes, remaining_bytes)

            cur = conn.execute(
                """
                UPDATE runs
                SET remaining_ms = remaining_ms - ?,
                    remaining_bytes = remaining_bytes - ?,
                    remaining_calls = remaining_calls - 1,
                    active_heavy_jobs = active_heavy_jobs + 1,
                    revision = revision + 1
                WHERE run_id = ? AND revision = ?
                """,
                (effective_ms, effective_bytes, run_id, current_revision),
            )
            if cur.rowcount != 1:
                raise ActionConflictError("Concurrent modification while reserving run budget.")
        else:
            effective_ms = desired_ms
            effective_bytes = desired_bytes
            cur = conn.execute(
                "UPDATE runs SET revision = revision + 1 WHERE run_id = ? AND revision = ?",
                (run_id, current_revision),
            )
            if cur.rowcount != 1:
                raise ActionConflictError("Concurrent modification while advancing run revision.")

        validate_action_transition(ActionLifecycleState.PROPOSED, ActionLifecycleState.RESERVED)
        ts = _normalize_utc(now)
        ts_iso = ts.isoformat()
        action_id = f"act-{uuid4().hex}"
        args_digest = canonical_digest(request.arguments)
        args_to_store = request.arguments if sanitized_args is None else sanitized_args

        record = ActionRecord(
            run_id=run_id,
            action_id=action_id,
            request_id=request.request_id,
            principal_id=principal_id,
            expected_revision=request.expected_revision,
            capability_name=request.capability_name,
            operation=request.operation,
            adapter_revision=capability.adapter_commit,
            canonical_args_sha256=args_digest,
            sanitized_args=args_to_store,
            scope_revision=scope_revision,
            repeat_of=request.repeat_of,
            state=ActionLifecycleState.RESERVED,
            reserved_ms=effective_ms,
            reserved_bytes=effective_bytes,
            used_ms=0,
            used_bytes=0,
            fencing_token=None,
            supervisor_instance_id=None,
            process_start_id=None,
            created_at=ts,
            updated_at=ts,
        )

        conn.execute(
            """
            INSERT INTO actions (
                action_id, principal_id, run_id, request_id, expected_revision,
                capability_name, operation, adapter_revision, canonical_args_sha256,
                sanitized_args_json, scope_revision, repeat_of, state,
                reserved_ms, reserved_bytes, used_ms, used_bytes,
                fencing_token, supervisor_instance_id, process_start_id,
                envelope_json, error_code, error_message, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, ?, ?)
            """,
            (
                record.action_id,
                record.principal_id,
                record.run_id,
                record.request_id,
                record.expected_revision,
                record.capability_name,
                record.operation,
                record.adapter_revision,
                record.canonical_args_sha256,
                canonical_json(record.sanitized_args),
                record.scope_revision,
                record.repeat_of,
                record.state.value,
                record.reserved_ms,
                record.reserved_bytes,
                ts_iso,
                ts_iso,
            ),
        )
        return ActionSubmission(action=record, envelope=None, replayed=False)

    def submit_action(
        self,
        *,
        run_id: str,
        principal_id: str,
        request: ActionRequest,
        capability: CapabilityDescriptor,
        scope_revision: str,
        sanitized_args: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> ActionSubmission:
        """Reserve a new action or replay an existing idempotent submission."""
        with self.storage.transaction() as conn:
            return self.reserve_action_in_tx(
                conn,
                run_id=run_id,
                principal_id=principal_id,
                request=request,
                capability=capability,
                scope_revision=scope_revision,
                sanitized_args=sanitized_args,
                manage_run_budget=True,
                now=now,
            )

    def reserve_action(
        self,
        *,
        run_id: str,
        principal_id: str,
        request: ActionRequest,
        capability: CapabilityDescriptor,
        scope_revision: str,
    ) -> ActionRecord:
        """``BudgetManagerPort.reserve_action`` implementation."""
        return self.submit_action(
            run_id=run_id,
            principal_id=principal_id,
            request=request,
            capability=capability,
            scope_revision=scope_revision,
        ).action

    def record_denied_action_in_tx(
        self,
        conn: sqlite3.Connection,
        *,
        run_id: str,
        principal_id: str,
        request: ActionRequest,
        adapter_revision: str,
        scope_revision: str,
        error: ErrorDetail,
        summary: str | None = None,
        sanitized_args: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> ActionSubmission:
        """Record a ``proposed -> denied`` outcome without consuming run budget."""
        replay = self.check_idempotent_replay_in_tx(
            conn,
            principal_id=principal_id,
            request=request,
        )
        if replay is not None:
            return replay

        validate_action_transition(ActionLifecycleState.PROPOSED, ActionLifecycleState.DENIED)
        ts = _normalize_utc(now)
        ts_iso = ts.isoformat()
        action_id = f"act-{uuid4().hex}"
        args_digest = canonical_digest(request.arguments)
        args_to_store = request.arguments if sanitized_args is None else sanitized_args

        record = ActionRecord(
            run_id=run_id,
            action_id=action_id,
            request_id=request.request_id,
            principal_id=principal_id,
            expected_revision=request.expected_revision,
            capability_name=request.capability_name,
            operation=request.operation,
            adapter_revision=adapter_revision,
            canonical_args_sha256=args_digest,
            sanitized_args=args_to_store,
            scope_revision=scope_revision,
            repeat_of=request.repeat_of,
            state=ActionLifecycleState.DENIED,
            reserved_ms=0,
            reserved_bytes=0,
            used_ms=0,
            used_bytes=0,
            fencing_token=None,
            supervisor_instance_id=None,
            process_start_id=None,
            created_at=ts,
            updated_at=ts,
        )
        envelope = build_result_envelope(
            action=record,
            target_state=ActionLifecycleState.DENIED,
            usage=UsageMetrics(wall_ms=0, output_bytes=0),
            summary=summary or error.message,
            error=error,
        )
        conn.execute(
            """
            INSERT INTO actions (
                action_id, principal_id, run_id, request_id, expected_revision,
                capability_name, operation, adapter_revision, canonical_args_sha256,
                sanitized_args_json, scope_revision, repeat_of, state,
                reserved_ms, reserved_bytes, used_ms, used_bytes,
                fencing_token, supervisor_instance_id, process_start_id,
                envelope_json, error_code, error_message, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, NULL, NULL, NULL, ?, ?, ?, ?, ?)
            """,
            (
                record.action_id,
                record.principal_id,
                record.run_id,
                record.request_id,
                record.expected_revision,
                record.capability_name,
                record.operation,
                record.adapter_revision,
                record.canonical_args_sha256,
                canonical_json(record.sanitized_args),
                record.scope_revision,
                record.repeat_of,
                record.state.value,
                canonical_json(envelope),
                error.code,
                error.message,
                ts_iso,
                ts_iso,
            ),
        )
        return ActionSubmission(action=record, envelope=envelope, replayed=False)

    def start_action_in_tx(
        self,
        conn: sqlite3.Connection,
        *,
        action_id: str,
        supervisor_key: str,
        supervisor_instance_id: str,
        process_start_id: str,
        now: datetime | None = None,
    ) -> ActionRecord:
        """Transition a ``reserved`` (or reconciled) action to ``running`` with fencing."""
        if not supervisor_instance_id.strip() or not process_start_id.strip():
            raise ContractViolationError(
                "supervisor_instance_id and process_start_id must be non-empty."
            )

        row = conn.execute(
            "SELECT * FROM actions WHERE action_id = ?",
            (action_id,),
        ).fetchone()
        if row is None:
            raise ContractViolationError(
                f"Action {action_id!r} does not exist.",
                details={"action_id": action_id},
            )

        run_row = conn.execute(
            "SELECT guest_health, closed_at FROM runs WHERE run_id = ?",
            (row["run_id"],),
        ).fetchone()
        if run_row is None:
            raise ContractViolationError(f"Run {row['run_id']!r} missing.")
        if run_row["closed_at"] is not None:
            raise InvalidStateTransitionError("Cannot launch action on a closed run.")
        guest_health = GuestHealthState(str(run_row["guest_health"]))
        if guest_health != GuestHealthState.READY:
            raise GuestBlockedError(
                f"Guest for run {row['run_id']!r} is blocked ({guest_health.value}).",
                details={"run_id": str(row["run_id"]), "guest_health": guest_health.value},
            )

        current_state = ActionLifecycleState(str(row["state"]))
        validate_action_transition(current_state, ActionLifecycleState.RUNNING)

        token = self.storage.next_fencing_token(conn, supervisor_key)
        ts_iso = _normalize_utc(now).isoformat()

        cur = conn.execute(
            """
            UPDATE actions
            SET state = ?, fencing_token = ?, supervisor_instance_id = ?,
                process_start_id = ?, updated_at = ?
            WHERE action_id = ? AND state = ?
            """,
            (
                ActionLifecycleState.RUNNING.value,
                token,
                supervisor_instance_id,
                process_start_id,
                ts_iso,
                action_id,
                current_state.value,
            ),
        )
        if cur.rowcount != 1:
            raise ActionConflictError(
                f"Concurrent state change prevented starting action {action_id!r}."
            )
        updated = conn.execute("SELECT * FROM actions WHERE action_id = ?", (action_id,)).fetchone()
        assert updated is not None
        return _row_to_action_record(updated)

    def start_action(
        self,
        *,
        action_id: str,
        supervisor_key: str,
        supervisor_instance_id: str,
        process_start_id: str,
        now: datetime | None = None,
    ) -> ActionRecord:
        """Transition an action to ``running`` inside an atomic transaction."""
        with self.storage.transaction() as conn:
            return self.start_action_in_tx(
                conn,
                action_id=action_id,
                supervisor_key=supervisor_key,
                supervisor_instance_id=supervisor_instance_id,
                process_start_id=process_start_id,
                now=now,
            )

    def settle_action_in_tx(
        self,
        conn: sqlite3.Connection,
        *,
        action_id: str,
        target_state: ActionLifecycleState,
        usage: UsageMetrics,
        fencing_token: int | None = None,
        has_tool_receipt: bool = True,
        expiry_reason: str | None = None,
        summary: str | None = None,
        evidence: tuple[EvidenceRef, ...] = (),
        truncated: bool = False,
        next_cursor: str | None = None,
        error: ErrorDetail | None = None,
        retain_reservation: bool = False,
        manage_run_budget: bool = True,
        allow_reconciled_resolution: bool = False,
        supervisor_key: str | None = None,
        now: datetime | None = None,
    ) -> ActionSubmission:
        """Transition an action to a terminal or ``reconciliation_required`` state.

        Enforces ``WHERE action_id = ? AND fencing_token = ?`` for fenced
        running actions, rejects stale worker writes after reconciliation, and
        produces/persists a contract-compliant ``ResultEnvelope`` for terminal states.
        """
        row = conn.execute(
            "SELECT * FROM actions WHERE action_id = ?",
            (action_id,),
        ).fetchone()
        if row is None:
            raise ContractViolationError(
                f"Action {action_id!r} does not exist.",
                details={"action_id": action_id},
            )

        current_action = _row_to_action_record(row)
        current_state = current_action.state
        stored_token = current_action.fencing_token

        # Reject stale worker completions when state was already reconciled/superseded
        if (
            current_state == ActionLifecycleState.RECONCILIATION_REQUIRED
            and not allow_reconciled_resolution
        ):
            raise FencingError(
                f"Action {action_id!r} is awaiting reconciliation; worker completion rejected.",
                details={
                    "action_id": action_id,
                    "stored_fencing_token": stored_token,
                    "provided_fencing_token": fencing_token,
                },
            )

        if current_state in TERMINAL_ACTION_STATES:
            if fencing_token is not None and stored_token != fencing_token:
                raise FencingError(
                    f"Stale fencing token {fencing_token} rejected for terminal action {action_id!r}.",
                    details={
                        "action_id": action_id,
                        "stored_fencing_token": stored_token,
                        "provided_fencing_token": fencing_token,
                    },
                )
            raise InvalidStateTransitionError(
                f"Action {action_id!r} is already in terminal state {current_state.value!r}."
            )

        # Verify fencing token match for fenced running actions
        if current_state == ActionLifecycleState.RUNNING and stored_token is not None:
            if fencing_token is None or fencing_token != stored_token:
                raise FencingError(
                    f"Fencing token mismatch on action {action_id!r}: "
                    f"expected {stored_token}, got {fencing_token}.",
                    details={
                        "action_id": action_id,
                        "stored_fencing_token": stored_token,
                        "provided_fencing_token": fencing_token,
                    },
                )
            if supervisor_key is not None:
                cnt_row = conn.execute(
                    "SELECT current_token FROM fencing_counters WHERE supervisor_key = ?",
                    (supervisor_key,),
                ).fetchone()
                if cnt_row is not None and int(cnt_row["current_token"]) > stored_token:
                    raise FencingError(
                        f"Fencing token {stored_token} superseded by supervisor epoch {cnt_row['current_token']}.",
                        details={
                            "action_id": action_id,
                            "stored_fencing_token": stored_token,
                            "current_epoch_token": int(cnt_row["current_token"]),
                        },
                    )
        elif current_state == ActionLifecycleState.RESERVED and fencing_token is not None:
            raise FencingError(
                f"Unexpected fencing token {fencing_token} for unstarted reserved action {action_id!r}."
            )

        validate_action_transition(current_state, target_state)

        ts = _normalize_utc(now)
        ts_iso = ts.isoformat()

        envelope: ResultEnvelope | None = None
        envelope_json: str | None = None
        err_code: str | None = error.code if error is not None else None
        err_message: str | None = error.message if error is not None else None

        if target_state == ActionLifecycleState.RECONCILIATION_REQUIRED:
            err_code = err_code or "reconciliation_required"
            err_message = err_message or "Action state requires supervisor reconciliation."
        else:
            envelope = build_result_envelope(
                action=current_action,
                target_state=target_state,
                usage=usage,
                has_tool_receipt=has_tool_receipt,
                expiry_reason=expiry_reason,
                summary=summary,
                evidence=evidence,
                truncated=truncated,
                next_cursor=next_cursor,
                error=error,
            )
            envelope_json = canonical_json(envelope)
            if envelope.error is not None:
                err_code = envelope.error.code
                err_message = envelope.error.message

        if current_state == ActionLifecycleState.RUNNING and stored_token is not None:
            cur = conn.execute(
                """
                UPDATE actions
                SET state = ?, used_ms = ?, used_bytes = ?,
                    envelope_json = ?, error_code = ?, error_message = ?,
                    updated_at = ?
                WHERE action_id = ? AND state = ? AND fencing_token = ?
                """,
                (
                    target_state.value,
                    usage.wall_ms,
                    usage.output_bytes,
                    envelope_json,
                    err_code,
                    err_message,
                    ts_iso,
                    action_id,
                    current_state.value,
                    stored_token,
                ),
            )
            if cur.rowcount != 1:
                raise FencingError(
                    f"Fenced update failed for action {action_id!r} (token={stored_token})."
                )
        else:
            cur = conn.execute(
                """
                UPDATE actions
                SET state = ?, used_ms = ?, used_bytes = ?,
                    envelope_json = ?, error_code = ?, error_message = ?,
                    updated_at = ?
                WHERE action_id = ? AND state = ?
                """,
                (
                    target_state.value,
                    usage.wall_ms,
                    usage.output_bytes,
                    envelope_json,
                    err_code,
                    err_message,
                    ts_iso,
                    action_id,
                    current_state.value,
                ),
            )
            if cur.rowcount != 1:
                raise ActionConflictError(
                    f"Concurrent state change prevented settling action {action_id!r}."
                )

        # Budget settlement: retain reservation on reconciliation_required or unconfirmed cleanup.
        should_release = (
            manage_run_budget
            and target_state in TERMINAL_ACTION_STATES
            and not retain_reservation
            and current_state
            in {
                ActionLifecycleState.RESERVED,
                ActionLifecycleState.RUNNING,
                ActionLifecycleState.RECONCILIATION_REQUIRED,
            }
        )
        if should_release:
            run_row = conn.execute(
                "SELECT remaining_ms, remaining_bytes, active_heavy_jobs FROM runs WHERE run_id = ?",
                (current_action.run_id,),
            ).fetchone()
            if run_row is not None:
                refund_ms = current_action.reserved_ms - usage.wall_ms
                refund_bytes = current_action.reserved_bytes - usage.output_bytes
                new_rem_ms = max(0, int(run_row["remaining_ms"]) + refund_ms)
                new_rem_bytes = max(0, int(run_row["remaining_bytes"]) + refund_bytes)
                new_active = max(0, int(run_row["active_heavy_jobs"]) - 1)
                conn.execute(
                    """
                    UPDATE runs
                    SET remaining_ms = ?, remaining_bytes = ?, active_heavy_jobs = ?
                    WHERE run_id = ?
                    """,
                    (new_rem_ms, new_rem_bytes, new_active, current_action.run_id),
                )

        updated_row = conn.execute(
            "SELECT * FROM actions WHERE action_id = ?",
            (action_id,),
        ).fetchone()
        assert updated_row is not None
        return ActionSubmission(
            action=_row_to_action_record(updated_row),
            envelope=envelope,
            replayed=False,
        )

    def settle_action_with_envelope(
        self,
        *,
        action_id: str,
        target_state: ActionLifecycleState,
        usage: UsageMetrics,
        fencing_token: int | None = None,
        has_tool_receipt: bool = True,
        expiry_reason: str | None = None,
        summary: str | None = None,
        evidence: tuple[EvidenceRef, ...] = (),
        truncated: bool = False,
        next_cursor: str | None = None,
        error: ErrorDetail | None = None,
        retain_reservation: bool = False,
        supervisor_key: str | None = None,
        now: datetime | None = None,
    ) -> ActionSubmission:
        """Settle an action and return both ActionRecord and ResultEnvelope."""
        with self.storage.transaction() as conn:
            return self.settle_action_in_tx(
                conn,
                action_id=action_id,
                target_state=target_state,
                usage=usage,
                fencing_token=fencing_token,
                has_tool_receipt=has_tool_receipt,
                expiry_reason=expiry_reason,
                summary=summary,
                evidence=evidence,
                truncated=truncated,
                next_cursor=next_cursor,
                error=error,
                retain_reservation=retain_reservation,
                manage_run_budget=True,
                supervisor_key=supervisor_key,
                now=now,
            )

    def settle_action(
        self,
        *,
        action_id: str,
        target_state: ActionLifecycleState,
        usage: UsageMetrics,
        fencing_token: int | None = None,
    ) -> ActionRecord:
        """``BudgetManagerPort.settle_action`` implementation."""
        return self.settle_action_with_envelope(
            action_id=action_id,
            target_state=target_state,
            usage=usage,
            fencing_token=fencing_token,
        ).action


__all__ = [
    "ActionManager",
    "ActionSubmission",
    "build_result_envelope",
]
