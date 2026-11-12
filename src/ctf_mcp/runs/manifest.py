"""Run manifest persistence, secret/flag guard, and run lifecycle closing.

Implements ``docs/08`` section 4 (run manifests) and ``docs/11`` (no credentials
or raw flags inside run manifests, atomic budget column initialization on ``runs``).
"""

from __future__ import annotations

import re
import sqlite3
from datetime import UTC, datetime
from typing import Any

from ctf_mcp.contracts import (
    ActionConflictError,
    BudgetSpec,
    BudgetUsage,
    ContractViolationError,
    GuestHealthState,
    InvalidStateTransitionError,
    RunManifest,
    ScopeDeniedError,
    StrictModel,
    canonical_json,
)
from ctf_mcp.storage import Storage

# Patterns that must never appear in persisted RunManifest metadata (docs/08 & CTF-12).
_FORBIDDEN_MANIFEST_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("flag_pattern", re.compile(r"(?:flag|ctf)\{[^}\r\n]*\}", re.IGNORECASE)),
    ("synthetic_secret", re.compile(r"SYNTHETIC_SECRET_[A-Za-z0-9_\-]+", re.IGNORECASE)),
    ("sensitive_marker", re.compile(r"CTF_SENSITIVE_MARKER[A-Za-z0-9_\-]*", re.IGNORECASE)),
    ("private_key_pem", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._\-+/=]{8,}", re.IGNORECASE)),
    ("api_token_prefix", re.compile(r"\b(?:sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b")),
    (
        "credential_assignment",
        re.compile(
            r"\b(?:password|passwd|api_key|access_token|secret_key|private_key)\s*[:=]\s*\S+",
            re.IGNORECASE,
        ),
    ),
)


def _normalize_utc(dt: datetime | None = None) -> datetime:
    current = datetime.now(UTC) if dt is None else dt
    if current.tzinfo is None:
        return current.replace(tzinfo=UTC)
    return current.astimezone(UTC)


def _scan_value_for_secrets(value: Any, path: str) -> None:
    if isinstance(value, str):
        for label, pattern in _FORBIDDEN_MANIFEST_PATTERNS:
            if pattern.search(value):
                raise ContractViolationError(
                    f"RunManifest field {path!r} contains forbidden secret or flag pattern ({label}).",
                    details={"field": path, "pattern": label},
                )
        return
    if isinstance(value, dict):
        for k, v in value.items():
            _scan_value_for_secrets(str(k), f"{path}.<key>")
            _scan_value_for_secrets(v, f"{path}.{k}")
        return
    if isinstance(value, (list, tuple)):
        for idx, item in enumerate(value):
            _scan_value_for_secrets(item, f"{path}[{idx}]")


def assert_no_secrets_in_manifest(manifest: RunManifest) -> None:
    """Reject RunManifest instances containing credential values, flags, or markers."""
    _scan_value_for_secrets(manifest.model_dump(mode="json"), "manifest")


class RunSnapshot(StrictModel):
    """Consistent read view of a run's manifest, health state, revision, and budget."""

    manifest: RunManifest
    guest_health: GuestHealthState
    revision: int
    remaining_ms: int
    remaining_bytes: int
    remaining_calls: int
    usage: BudgetUsage


def _row_to_run_snapshot(row: sqlite3.Row) -> RunSnapshot:
    manifest = RunManifest.model_validate_json(row["manifest_json"])
    budget = manifest.budget_spec
    total_ms = budget.run_budget_seconds * 1000
    total_bytes = budget.max_evidence_bytes_per_run
    total_calls = budget.max_tool_calls

    remaining_ms = int(row["remaining_ms"])
    remaining_bytes = int(row["remaining_bytes"])
    remaining_calls = int(row["remaining_calls"])

    usage = BudgetUsage(
        used_ms=max(0, total_ms - remaining_ms),
        reserved_ms=0,
        used_evidence_bytes=max(0, total_bytes - remaining_bytes),
        reserved_bytes=0,
        tool_calls_used=max(0, total_calls - remaining_calls),
        active_heavy_jobs=int(row["active_heavy_jobs"]),
        active_sessions=int(row["active_sessions"]),
    )
    return RunSnapshot(
        manifest=manifest,
        guest_health=GuestHealthState(str(row["guest_health"])),
        revision=int(row["revision"]),
        remaining_ms=remaining_ms,
        remaining_bytes=remaining_bytes,
        remaining_calls=remaining_calls,
        usage=usage,
    )


class RunManifestManager:
    """Creates, inspects, updates, and closes run manifests in SQLite."""

    def __init__(self, storage: Storage) -> None:
        self.storage = storage

    def create_run_in_tx(
        self,
        conn: sqlite3.Connection,
        manifest: RunManifest,
        *,
        initial_guest_health: GuestHealthState = GuestHealthState.READY,
    ) -> RunManifest:
        """Atomically persist a validated RunManifest and initialize run budget columns."""
        assert_no_secrets_in_manifest(manifest)

        existing = conn.execute(
            "SELECT run_id FROM runs WHERE run_id = ?",
            (manifest.run_id,),
        ).fetchone()
        if existing is not None:
            raise ActionConflictError(
                f"Run {manifest.run_id!r} already exists.",
                details={"run_id": manifest.run_id},
            )

        budget: BudgetSpec = manifest.budget_spec
        remaining_ms = budget.run_budget_seconds * 1000
        remaining_bytes = budget.max_evidence_bytes_per_run
        remaining_calls = budget.max_tool_calls
        created_at_iso = _normalize_utc(manifest.created_at).isoformat()
        closed_at_iso = (
            _normalize_utc(manifest.closed_at).isoformat()
            if manifest.closed_at is not None
            else None
        )

        conn.execute(
            """
            INSERT INTO runs (
                run_id, owner_principal_id, task_id, mode, scope_revision,
                manifest_json, budget_spec_json,
                remaining_ms, remaining_bytes, remaining_calls,
                active_heavy_jobs, active_sessions, guest_health,
                revision, created_at, closed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, 1, ?, ?)
            """,
            (
                manifest.run_id,
                manifest.owner_principal_id,
                manifest.task_id,
                manifest.mode.value,
                manifest.scope_revision,
                canonical_json(manifest),
                canonical_json(budget),
                remaining_ms,
                remaining_bytes,
                remaining_calls,
                initial_guest_health.value,
                created_at_iso,
                closed_at_iso,
            ),
        )
        return manifest

    def create_run(
        self,
        manifest: RunManifest,
        *,
        initial_guest_health: GuestHealthState = GuestHealthState.READY,
    ) -> RunManifest:
        """Create and persist a new RunManifest inside an atomic transaction."""
        with self.storage.transaction() as conn:
            return self.create_run_in_tx(
                conn,
                manifest,
                initial_guest_health=initial_guest_health,
            )

    def get_run_snapshot_in_tx(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        *,
        principal_id: str | None = None,
    ) -> RunSnapshot:
        """Fetch RunSnapshot for ``run_id`` enforcing owner principal match if supplied."""
        row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:
            raise ContractViolationError(
                f"Run {run_id!r} does not exist.",
                details={"run_id": run_id},
            )
        if principal_id is not None and str(row["owner_principal_id"]) != principal_id:
            raise ScopeDeniedError(
                f"Principal {principal_id!r} is not authorized for run {run_id!r}.",
                details={"run_id": run_id, "principal_id": principal_id},
            )
        return _row_to_run_snapshot(row)

    def get_run_snapshot(
        self,
        run_id: str,
        *,
        principal_id: str | None = None,
    ) -> RunSnapshot:
        """Read-only fetch of RunSnapshot."""
        with self.storage.read_connection() as conn:
            return self.get_run_snapshot_in_tx(conn, run_id, principal_id=principal_id)

    def get_manifest_in_tx(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        *,
        principal_id: str | None = None,
    ) -> RunManifest:
        """Fetch RunManifest inside an existing transaction."""
        return self.get_run_snapshot_in_tx(conn, run_id, principal_id=principal_id).manifest

    def get_manifest(
        self,
        run_id: str,
        *,
        principal_id: str | None = None,
    ) -> RunManifest:
        """Fetch RunManifest for ``run_id``."""
        return self.get_run_snapshot(run_id, principal_id=principal_id).manifest

    def record_provenance_hashes_in_tx(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        *,
        artifact_hashes: dict[str, str] | None = None,
        adapter_revisions: dict[str, str] | None = None,
    ) -> RunManifest:
        """Merge additional intake artifact hashes or adapter revisions into the manifest."""
        snap = self.get_run_snapshot_in_tx(conn, run_id)
        if snap.manifest.closed_at is not None:
            raise InvalidStateTransitionError(
                f"Cannot update manifest on closed run {run_id!r}.",
                details={"run_id": run_id},
            )
        merged_artifacts = dict(snap.manifest.artifact_hashes)
        if artifact_hashes:
            merged_artifacts.update(artifact_hashes)
        merged_adapters = dict(snap.manifest.adapter_revisions)
        if adapter_revisions:
            merged_adapters.update(adapter_revisions)

        updated = snap.manifest.model_copy(
            update={
                "artifact_hashes": merged_artifacts,
                "adapter_revisions": merged_adapters,
            }
        )
        assert_no_secrets_in_manifest(updated)
        conn.execute(
            "UPDATE runs SET manifest_json = ?, revision = revision + 1 WHERE run_id = ?",
            (canonical_json(updated), run_id),
        )
        return updated

    def close_run_in_tx(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        *,
        closed_at: datetime | None = None,
        expected_revision: int | None = None,
    ) -> RunManifest:
        """Finalize ``closed_at`` on a run atomically, forbidding re-closing."""
        row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:
            raise ContractViolationError(
                f"Run {run_id!r} does not exist.",
                details={"run_id": run_id},
            )
        if row["closed_at"] is not None:
            raise InvalidStateTransitionError(
                f"Run {run_id!r} is already closed.",
                details={"run_id": run_id, "closed_at": str(row["closed_at"])},
            )
        current_rev = int(row["revision"])
        if expected_revision is not None and current_rev != expected_revision:
            raise ActionConflictError(
                f"Run revision mismatch for {run_id!r}: expected {expected_revision}, got {current_rev}.",
                details={
                    "run_id": run_id,
                    "expected_revision": expected_revision,
                    "actual_revision": current_rev,
                },
            )

        close_ts = _normalize_utc(closed_at)
        manifest = RunManifest.model_validate_json(row["manifest_json"])
        updated_manifest = manifest.model_copy(update={"closed_at": close_ts})
        assert_no_secrets_in_manifest(updated_manifest)

        cur = conn.execute(
            """
            UPDATE runs
            SET closed_at = ?, manifest_json = ?, revision = revision + 1
            WHERE run_id = ? AND revision = ? AND closed_at IS NULL
            """,
            (
                close_ts.isoformat(),
                canonical_json(updated_manifest),
                run_id,
                current_rev,
            ),
        )
        if cur.rowcount != 1:
            raise ActionConflictError(
                f"Concurrent modification detected while closing run {run_id!r}.",
                details={"run_id": run_id},
            )
        return updated_manifest

    def close_run(
        self,
        run_id: str,
        *,
        closed_at: datetime | None = None,
        expected_revision: int | None = None,
    ) -> RunManifest:
        """Finalize ``closed_at`` on a run inside an atomic transaction."""
        with self.storage.transaction() as conn:
            return self.close_run_in_tx(
                conn,
                run_id,
                closed_at=closed_at,
                expected_revision=expected_revision,
            )


__all__ = [
    "RunManifestManager",
    "RunSnapshot",
    "assert_no_secrets_in_manifest",
]
