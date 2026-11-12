"""Gateway scope registration, revocation, and fail-closed validation.

Implements ``ScopeValidatorPort`` (``docs/11`` sections 1 and 5, ``docs/05``
section 10) backed by the SQLite ``scopes`` and ``runs`` tables.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

from ctf_mcp.contracts import (
    CapabilityDescriptor,
    ExecutionClass,
    PrincipalContext,
    RunMode,
    ScopeDeniedError,
    ScopePolicy,
    ScopeValidatorPort,
)
from ctf_mcp.storage import Storage, utc_now_iso

_SUPPORTED_REQUIRED_SCOPE_KEYS: frozenset[str] = frozenset(
    {"mode", "modes", "network_enabled", "external_submission", "task_id"}
)


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _validate_required_scope(policy: ScopePolicy, capability: CapabilityDescriptor) -> None:
    req = capability.required_scope
    unknown = set(req.keys()) - _SUPPORTED_REQUIRED_SCOPE_KEYS
    if unknown:
        raise ScopeDeniedError(
            f"Capability {capability.name!r} specifies unsupported required_scope constraints.",
            details={"unknown_keys": sorted(unknown)},
        )

    if "mode" in req and policy.mode.value != req["mode"]:
        raise ScopeDeniedError(
            f"Scope mode {policy.mode.value!r} does not satisfy capability requirement {req['mode']!r}."
        )
    if "modes" in req:
        allowed_modes = req["modes"]
        if not isinstance(allowed_modes, (list, tuple, set)) or policy.mode.value not in allowed_modes:
            raise ScopeDeniedError(
                f"Scope mode {policy.mode.value!r} is not in capability required modes."
            )
    if req.get("network_enabled") is True and (not policy.network_enabled or not policy.allowed_targets):
        raise ScopeDeniedError(
            f"Capability {capability.name!r} requires enabled network targets in scope."
        )
    if req.get("external_submission") is True and not policy.external_submission:
        raise ScopeDeniedError(
            f"Capability {capability.name!r} requires external_submission authorization in scope."
        )
    if "task_id" in req and policy.task_id != req["task_id"]:
        raise ScopeDeniedError(
            f"Scope task_id {policy.task_id!r} does not match required {req['task_id']!r}."
        )


class ScopeValidator(ScopeValidatorPort):
    """Persists and enforces per-run scope policies outside the AI prompt."""

    def __init__(self, storage: Storage, *, allow_dynamic: bool = False) -> None:
        self._storage = storage
        self._allow_dynamic = allow_dynamic

    def register_scope_in_tx(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        policy: ScopePolicy,
        *,
        activate: bool = True,
    ) -> ScopePolicy:
        """Register an immutable scope revision for an open run inside ``conn``."""
        run_row = conn.execute(
            "SELECT run_id, mode, scope_revision, closed_at FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if run_row is None:
            raise ScopeDeniedError(f"Cannot register scope for unknown run {run_id!r}.")
        if run_row["closed_at"] is not None:
            raise ScopeDeniedError(f"Cannot register scope for closed run {run_id!r}.")
        if run_row["mode"] != policy.mode.value:
            raise ScopeDeniedError(
                f"Scope mode {policy.mode.value!r} mismatches run mode {run_row['mode']!r}."
            )

        existing = conn.execute(
            "SELECT 1 FROM scopes WHERE run_id = ? AND scope_revision = ?",
            (run_id, policy.scope_revision),
        ).fetchone()
        if existing is not None:
            raise ScopeDeniedError(
                f"Scope revision {policy.scope_revision!r} already exists for run {run_id!r}."
            )

        expires_iso = _ensure_utc(policy.expires_at).isoformat() if policy.expires_at else None
        conn.execute(
            """
            INSERT INTO scopes (
                run_id, scope_revision, scope_sha256, mode, expires_at,
                policy_json, revoked_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?)
            """,
            (
                run_id,
                policy.scope_revision,
                policy.scope_sha256,
                policy.mode.value,
                expires_iso,
                policy.model_dump_json(),
                utc_now_iso(),
            ),
        )
        if activate and run_row["scope_revision"] != policy.scope_revision:
            conn.execute(
                "UPDATE runs SET scope_revision = ? WHERE run_id = ?",
                (policy.scope_revision, run_id),
            )
        return policy

    def register_scope(
        self,
        run_id: str,
        policy: ScopePolicy,
        *,
        activate: bool = True,
    ) -> ScopePolicy:
        """Register an immutable scope revision for ``run_id`` atomically."""
        with self._storage.transaction() as conn:
            return self.register_scope_in_tx(conn, run_id, policy, activate=activate)

    def revoke_scope_in_tx(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        scope_revision: str | None = None,
    ) -> int:
        """Revoke active scope revision(s) for ``run_id`` immediately."""
        revoked_ts = utc_now_iso()
        if scope_revision is None:
            cur = conn.execute(
                "UPDATE scopes SET revoked_at = ? WHERE run_id = ? AND revoked_at IS NULL",
                (revoked_ts, run_id),
            )
        else:
            cur = conn.execute(
                """
                UPDATE scopes
                SET revoked_at = ?
                WHERE run_id = ? AND scope_revision = ? AND revoked_at IS NULL
                """,
                (revoked_ts, run_id, scope_revision),
            )
        if cur.rowcount == 0:
            raise ScopeDeniedError(
                f"No active scope found to revoke for run {run_id!r} (revision={scope_revision!r})."
            )
        return int(cur.rowcount)

    def revoke_scope(self, run_id: str, scope_revision: str | None = None) -> int:
        """Revoke active scope revision(s) for ``run_id`` atomically."""
        with self._storage.transaction() as conn:
            return self.revoke_scope_in_tx(conn, run_id, scope_revision)

    def get_active_scope_in_tx(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        *,
        now: datetime | None = None,
    ) -> ScopePolicy:
        """Fetch and validate the active, non-revoked, non-expired ``ScopePolicy``."""
        run_row = conn.execute(
            "SELECT run_id, mode, scope_revision, closed_at FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if run_row is None:
            raise ScopeDeniedError(f"Scope missing: unknown run {run_id!r}.")
        if run_row["closed_at"] is not None:
            raise ScopeDeniedError(f"Run {run_id!r} is closed; scope is no longer active.")

        scope_row = conn.execute(
            """
            SELECT scope_revision, scope_sha256, mode, expires_at, policy_json, revoked_at
            FROM scopes
            WHERE run_id = ? AND scope_revision = ?
            """,
            (run_id, run_row["scope_revision"]),
        ).fetchone()
        if scope_row is None:
            raise ScopeDeniedError(
                f"No scope registered for run {run_id!r} at revision {run_row['scope_revision']!r}."
            )
        if scope_row["revoked_at"] is not None:
            raise ScopeDeniedError(
                f"Scope revision {scope_row['scope_revision']!r} for run {run_id!r} has been revoked."
            )

        try:
            policy = ScopePolicy.model_validate_json(scope_row["policy_json"])
        except Exception as exc:
            raise ScopeDeniedError(f"Corrupted scope policy record: {exc}") from exc

        if (
            policy.scope_revision != scope_row["scope_revision"]
            or policy.scope_sha256 != scope_row["scope_sha256"]
            or policy.mode.value != scope_row["mode"]
            or policy.mode.value != run_row["mode"]
        ):
            raise ScopeDeniedError("Scope metadata consistency verification failed.")

        current_time = _ensure_utc(now) if now is not None else datetime.now(UTC)
        if policy.expires_at is not None and current_time >= _ensure_utc(policy.expires_at):
            raise ScopeDeniedError(
                f"Scope revision {policy.scope_revision!r} expired at {policy.expires_at.isoformat()}."
            )
        return policy

    def get_active_scope(self, run_id: str, *, now: datetime | None = None) -> ScopePolicy:
        """Fetch and validate the active scope for ``run_id``."""
        with self._storage.read_connection() as conn:
            return self.get_active_scope_in_tx(conn, run_id, now=now)

    def validate_action_in_tx(
        self,
        conn: sqlite3.Connection,
        principal: PrincipalContext,
        run_id: str,
        capability: CapabilityDescriptor,
        operation: str,
        *,
        now: datetime | None = None,
    ) -> ScopePolicy:
        """Verify principal ownership, active scope, mode, execution classes, and operation."""
        run_row = conn.execute(
            "SELECT owner_principal_id FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if run_row is None:
            raise ScopeDeniedError(f"Run {run_id!r} does not exist.")
        if run_row["owner_principal_id"] != principal.principal_id:
            raise ScopeDeniedError(
                f"Principal {principal.principal_id!r} is not authorized for run {run_id!r}."
            )

        policy = self.get_active_scope_in_tx(conn, run_id, now=now)

        if policy.mode not in capability.profile_modes:
            raise ScopeDeniedError(
                f"Capability {capability.name!r} is not allowed in mode {policy.mode.value!r}."
            )

        exec_classes = set(capability.execution_classes)
        if policy.mode == RunMode.OFFLINE_CTF:
            if policy.network_enabled or policy.external_submission or policy.allowed_targets:
                raise ScopeDeniedError("offline_ctf scope cannot permit network or submission.")
            if {ExecutionClass.NETWORK, ExecutionClass.SUBMISSION} & exec_classes:
                raise ScopeDeniedError(
                    f"Capability {capability.name!r} uses network/submission forbidden in offline_ctf."
                )

        if ExecutionClass.DYNAMIC in exec_classes and not self._allow_dynamic:
            raise ScopeDeniedError(
                f"Capability {capability.name!r} requires dynamic execution, disabled in current baseline."
            )

        if not exec_classes.issubset(set(policy.allowed_execution_classes)):
            raise ScopeDeniedError(
                f"Execution classes {sorted(c.value for c in exec_classes)} exceed scope allowance."
            )

        if capability.name not in policy.allowed_capabilities:
            raise ScopeDeniedError(
                f"Capability {capability.name!r} is not listed in scope allowed_capabilities."
            )

        if operation not in capability.operations:
            raise ScopeDeniedError(
                f"Operation {operation!r} is not supported by capability {capability.name!r}."
            )

        _validate_required_scope(policy, capability)
        return policy

    def validate_action(
        self,
        principal: PrincipalContext,
        run_id: str,
        capability: CapabilityDescriptor,
        operation: str,
        *,
        now: datetime | None = None,
    ) -> ScopePolicy:
        """Implement ``ScopeValidatorPort.validate_action``."""
        with self._storage.read_connection() as conn:
            return self.validate_action_in_tx(
                conn,
                principal,
                run_id,
                capability,
                operation,
                now=now,
            )


__all__ = ["ScopeValidator"]
