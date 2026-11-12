"""Immutable content-addressed evidence vault and SQLite metadata repository.

Implements ``EvidenceVaultPort`` from ``ctf_mcp.contracts`` (CTF-03, CTF-04):
- Persists immutable blobs under ``vault_root/blobs/<sha256[:2]>/<sha256>`` via
  ``fs_guard.safe_write_atomic`` (no automatic Git export).
- Registers ``evidence_objects`` and initial ``evidence_views`` (``raw-v1``) in
  SQLite within ``Storage.transaction()`` or a caller-provided connection.
- Enforces ``run_id`` and ``owner_principal_id`` authorization on every read,
  view creation, and revocation, and validates opaque HMAC-SHA256 cursors
  against the latest active non-revoked view on every ``read_page`` call.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from pydantic import Field

from ctf_mcp.config import MIN_HMAC_KEY_BYTES
from ctf_mcp.contracts import (
    MAX_PAGE_CONTENT_CHARS,
    SHA256_PATTERN,
    BoundsExceededError,
    ConfigurationError,
    ContractViolationError,
    CursorError,
    EvidenceAccessDeniedError,
    EvidenceManifest,
    EvidenceNotFoundError,
    EvidencePage,
    EvidenceRole,
    PageEncoding,
    PathSecurityError,
    StrictModel,
    sha256_bytes,
)
from ctf_mcp.evidence.paging import CursorSigner, build_evidence_page
from ctf_mcp.fs_guard import safe_read_bounded, safe_write_atomic
from ctf_mcp.storage import Storage, utc_now_iso

_FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_TEXT_MEDIA_EXACT = frozenset(
    {
        "application/json",
        "application/xml",
        "application/javascript",
        "application/x-ndjson",
        "application/yaml",
        "application/x-yaml",
        "application/toml",
        "application/csv",
    }
)


def _is_text_media_type(media_type: str) -> bool:
    base = media_type.split(";", 1)[0].strip().lower()
    if base.startswith("text/"):
        return True
    if base in _TEXT_MEDIA_EXACT:
        return True
    return base.endswith("+json") or base.endswith("+xml")


def _select_view_encoding(data: bytes, media_type: str, requested: PageEncoding | None) -> PageEncoding:
    if requested == PageEncoding.UTF8:
        try:
            data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ContractViolationError(
                f"Cannot store non-UTF-8 bytes with utf-8 page encoding: {exc}"
            ) from exc
        return PageEncoding.UTF8
    if requested == PageEncoding.BASE64:
        return PageEncoding.BASE64

    if _is_text_media_type(media_type) and b"\x00" not in data:
        try:
            data.decode("utf-8", errors="strict")
            return PageEncoding.UTF8
        except UnicodeDecodeError:
            return PageEncoding.BASE64
    return PageEncoding.BASE64


class EvidenceViewRecord(StrictModel):
    """Persisted view metadata row from ``evidence_views``."""

    evidence_id: str = Field(min_length=1)
    view_revision: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    owner_principal_id: str = Field(min_length=1)
    view_sha256: str = Field(pattern=SHA256_PATTERN)
    view_bytes: int = Field(ge=0)
    encoding: PageEncoding
    capture_complete: bool
    omission_reason: str | None = None
    storage_relpath: str = Field(min_length=1)
    redaction_policy_rev: str | None = None
    revoked_at: datetime | None = None
    created_at: datetime


def _row_to_view_record(row: sqlite3.Row) -> EvidenceViewRecord:
    return EvidenceViewRecord(
        evidence_id=str(row["evidence_id"]),
        view_revision=str(row["view_revision"]),
        run_id=str(row["run_id"]),
        owner_principal_id=str(row["owner_principal_id"]),
        view_sha256=str(row["view_sha256"]),
        view_bytes=int(row["view_bytes"]),
        encoding=PageEncoding(str(row["encoding"])),
        capture_complete=bool(row["capture_complete"]),
        omission_reason=row["omission_reason"],
        storage_relpath=str(row["storage_relpath"]),
        redaction_policy_rev=row["redaction_policy_rev"],
        revoked_at=datetime.fromisoformat(row["revoked_at"]) if row["revoked_at"] else None,
        created_at=datetime.fromisoformat(str(row["created_at"])),
    )


class EvidenceVault:
    """Private local content-addressed evidence vault implementing ``EvidenceVaultPort``."""

    def __init__(
        self,
        *,
        storage: Storage,
        vault_root: str | Path,
        cursor_hmac_key: bytes,
        max_evidence_bytes: int = 104_857_600,
        max_page_chars: int = MAX_PAGE_CONTENT_CHARS,
        max_decode_bytes: int | None = None,
        automatic_git_export: bool = False,
    ) -> None:
        if automatic_git_export:
            raise ConfigurationError("automatic_git_export must remain False.")
        if not isinstance(cursor_hmac_key, (bytes, bytearray)) or len(cursor_hmac_key) < MIN_HMAC_KEY_BYTES:
            raise ConfigurationError(
                f"cursor_hmac_key must provide at least {MIN_HMAC_KEY_BYTES} bytes."
            )
        if max_evidence_bytes <= 0:
            raise ConfigurationError("max_evidence_bytes must be positive.")
        if max_page_chars <= 0 or max_page_chars > MAX_PAGE_CONTENT_CHARS:
            raise ConfigurationError(
                f"max_page_chars must be within 1..{MAX_PAGE_CONTENT_CHARS}."
            )
        if max_decode_bytes is not None and max_decode_bytes <= 0:
            raise ConfigurationError("max_decode_bytes must be positive when specified.")

        self.storage = storage
        self.vault_root = Path(vault_root)
        self.max_evidence_bytes = max_evidence_bytes
        self.max_page_chars = max_page_chars
        self.max_decode_bytes = max_decode_bytes
        self.automatic_git_export = False
        self._signer = CursorSigner(bytes(cursor_hmac_key))

        self._ensure_safe_vault_root()

    def _ensure_safe_vault_root(self) -> None:
        if os.path.lexists(self.vault_root):
            st = os.lstat(self.vault_root)
            attrs = getattr(st, "st_file_attributes", 0)
            if stat.S_ISLNK(st.st_mode) or bool(attrs & _FILE_ATTRIBUTE_REPARSE_POINT):
                raise PathSecurityError("Vault root cannot be a symlink or reparse point.")
            if not stat.S_ISDIR(st.st_mode):
                raise PathSecurityError("Vault root must be a directory.")
        else:
            self.vault_root.mkdir(parents=True, exist_ok=True)

    def _store_blob(self, data: bytes) -> tuple[str, str]:
        if len(data) > self.max_evidence_bytes:
            raise BoundsExceededError(
                f"Evidence blob ({len(data)} bytes) exceeds max_evidence_bytes ({self.max_evidence_bytes}).",
                details={"size_bytes": len(data), "max_evidence_bytes": self.max_evidence_bytes},
            )
        digest = sha256_bytes(data)
        relpath = f"blobs/{digest[:2]}/{digest}"
        target = self.vault_root / relpath

        if os.path.lexists(target):
            existing = safe_read_bounded(
                self.vault_root,
                relpath,
                max_bytes=self.max_evidence_bytes,
                allow_truncate=False,
            )
            if len(existing.data) != len(data) or sha256_bytes(existing.data) != digest:
                raise ContractViolationError(
                    f"Existing content-addressed blob at {relpath!r} failed SHA-256 verification."
                )
            return digest, relpath

        try:
            safe_write_atomic(
                self.vault_root,
                relpath,
                data,
                max_bytes=self.max_evidence_bytes,
                overwrite=False,
                create_parents=True,
            )
        except PathSecurityError:
            # Handle benign race where identical content-addressed blob appeared concurrently.
            if not os.path.lexists(target):
                raise
            existing = safe_read_bounded(
                self.vault_root,
                relpath,
                max_bytes=self.max_evidence_bytes,
                allow_truncate=False,
            )
            if len(existing.data) != len(data) or sha256_bytes(existing.data) != digest:
                raise
        return digest, relpath

    def _read_blob_verified(self, storage_relpath: str, *, expected_sha256: str, expected_bytes: int) -> bytes:
        result = safe_read_bounded(
            self.vault_root,
            storage_relpath,
            max_bytes=self.max_evidence_bytes,
            allow_truncate=False,
        )
        if len(result.data) != expected_bytes or sha256_bytes(result.data) != expected_sha256:
            raise ContractViolationError(
                f"Stored evidence blob {storage_relpath!r} failed integrity verification."
            )
        return result.data

    def _tx_context(self, conn: sqlite3.Connection | None):
        if conn is not None:
            return nullcontext(conn)
        return self.storage.transaction()

    def _read_context(self, conn: sqlite3.Connection | None):
        if conn is not None:
            return nullcontext(conn)
        return self.storage.read_connection()

    def _verify_run_and_action(
        self,
        conn: sqlite3.Connection,
        *,
        run_id: str,
        owner_principal_id: str,
        action_id: str,
    ) -> None:
        run_row = conn.execute(
            "SELECT owner_principal_id FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if run_row is None:
            raise EvidenceNotFoundError(f"Run {run_id!r} not found.")
        if str(run_row["owner_principal_id"]) != owner_principal_id:
            raise EvidenceAccessDeniedError(
                f"Principal {owner_principal_id!r} does not own run {run_id!r}."
            )

        action_row = conn.execute(
            "SELECT run_id, principal_id FROM actions WHERE action_id = ?",
            (action_id,),
        ).fetchone()
        if action_row is None:
            raise EvidenceNotFoundError(f"Action {action_id!r} not found.")
        if str(action_row["run_id"]) != run_id:
            raise ContractViolationError(
                f"Action {action_id!r} belongs to another run, not {run_id!r}."
            )
        if str(action_row["principal_id"]) != owner_principal_id:
            raise EvidenceAccessDeniedError(
                f"Action {action_id!r} belongs to a different principal."
            )

    def _store_object(
        self,
        *,
        run_id: str,
        owner_principal_id: str,
        action_id: str,
        data: bytes,
        media_type: str,
        capture_complete: bool,
        omission_reason: str | None,
        source_artifact_hashes: tuple[str, ...],
        adapter_revision: str,
        sanitized_args_sha256: str,
        role: EvidenceRole,
        parent_evidence_ids: tuple[str, ...],
        view_revision: str,
        redaction_policy_rev: str | None,
        evidence_id: str | None,
        encoding: PageEncoding | None,
        conn: sqlite3.Connection | None,
    ) -> EvidenceManifest:
        assigned_id = evidence_id or f"ev-{uuid4().hex}"
        now_dt = datetime.now(UTC)
        now_iso = now_dt.isoformat()
        view_encoding = _select_view_encoding(data, media_type, encoding)
        digest = sha256_bytes(data)
        relpath = f"blobs/{digest[:2]}/{digest}"

        # Validate manifest invariants before touching disk or SQLite.
        try:
            manifest = EvidenceManifest(
                evidence_id=assigned_id,
                run_id=run_id,
                owner_principal_id=owner_principal_id,
                action_id=action_id,
                source_artifact_hashes=source_artifact_hashes,
                adapter_revision=adapter_revision,
                sanitized_args_sha256=sanitized_args_sha256,
                captured_at=now_dt,
                byte_length=len(data),
                media_type=media_type,
                capture_complete=capture_complete,
                omission_reason=omission_reason,
                role=role,
                parent_evidence_ids=parent_evidence_ids,
                view_revision=view_revision,
                view_sha256=digest,
                storage_relpath=relpath,
                redaction_policy_rev=redaction_policy_rev,
                revoked_at=None,
            )
        except Exception as exc:
            raise ContractViolationError(f"Invalid evidence manifest metadata: {exc}") from exc

        with self._tx_context(conn) as tx:
            self._verify_run_and_action(
                tx,
                run_id=run_id,
                owner_principal_id=owner_principal_id,
                action_id=action_id,
            )
            for parent_id in parent_evidence_ids:
                parent_row = tx.execute(
                    "SELECT run_id, owner_principal_id FROM evidence_objects WHERE evidence_id = ?",
                    (parent_id,),
                ).fetchone()
                if parent_row is None:
                    raise EvidenceNotFoundError(f"Parent evidence {parent_id!r} not found.")
                if (
                    str(parent_row["run_id"]) != run_id
                    or str(parent_row["owner_principal_id"]) != owner_principal_id
                ):
                    raise EvidenceAccessDeniedError(
                        f"Parent evidence {parent_id!r} does not belong to run/principal."
                    )

            stored_digest, stored_relpath = self._store_blob(data)
            assert stored_digest == digest and stored_relpath == relpath

            try:
                tx.execute(
                    """
                    INSERT INTO evidence_objects (
                        evidence_id, run_id, owner_principal_id, action_id,
                        raw_sha256, byte_length, media_type, capture_complete,
                        omission_reason, role, parent_evidence_ids_json,
                        manifest_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        manifest.evidence_id,
                        manifest.run_id,
                        manifest.owner_principal_id,
                        manifest.action_id,
                        manifest.view_sha256,
                        manifest.byte_length,
                        manifest.media_type,
                        1 if manifest.capture_complete else 0,
                        manifest.omission_reason,
                        manifest.role.value,
                        json.dumps(list(manifest.parent_evidence_ids)),
                        manifest.model_dump_json(),
                        now_iso,
                    ),
                )
                tx.execute(
                    """
                    INSERT INTO evidence_views (
                        evidence_id, view_revision, run_id, owner_principal_id,
                        view_sha256, view_bytes, encoding, capture_complete,
                        omission_reason, storage_relpath, redaction_policy_rev,
                        revoked_at, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        manifest.evidence_id,
                        manifest.view_revision,
                        manifest.run_id,
                        manifest.owner_principal_id,
                        manifest.view_sha256,
                        manifest.byte_length,
                        view_encoding.value,
                        1 if manifest.capture_complete else 0,
                        manifest.omission_reason,
                        manifest.storage_relpath,
                        manifest.redaction_policy_rev,
                        None,
                        now_iso,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ContractViolationError(
                    f"Failed to register evidence {manifest.evidence_id!r}: {exc}"
                ) from exc

        return manifest

    def store_raw(
        self,
        *,
        run_id: str,
        owner_principal_id: str,
        action_id: str,
        data: bytes,
        media_type: str,
        capture_complete: bool,
        omission_reason: str | None,
        source_artifact_hashes: tuple[str, ...],
        adapter_revision: str,
        sanitized_args_sha256: str,
        evidence_id: str | None = None,
        encoding: PageEncoding | None = None,
        conn: sqlite3.Connection | None = None,
    ) -> EvidenceManifest:
        """Store immutable raw evidence bytes and register ``raw-v1`` in SQLite."""
        return self._store_object(
            run_id=run_id,
            owner_principal_id=owner_principal_id,
            action_id=action_id,
            data=data,
            media_type=media_type,
            capture_complete=capture_complete,
            omission_reason=omission_reason,
            source_artifact_hashes=source_artifact_hashes,
            adapter_revision=adapter_revision,
            sanitized_args_sha256=sanitized_args_sha256,
            role=EvidenceRole.RAW,
            parent_evidence_ids=(),
            view_revision="raw-v1",
            redaction_policy_rev=None,
            evidence_id=evidence_id,
            encoding=encoding,
            conn=conn,
        )

    def store_derived(
        self,
        *,
        run_id: str,
        owner_principal_id: str,
        action_id: str,
        parent_evidence_ids: tuple[str, ...],
        data: bytes,
        media_type: str,
        capture_complete: bool,
        omission_reason: str | None,
        source_artifact_hashes: tuple[str, ...],
        adapter_revision: str,
        sanitized_args_sha256: str,
        view_revision: str = "derived-v1",
        redaction_policy_rev: str | None = None,
        evidence_id: str | None = None,
        encoding: PageEncoding | None = None,
        conn: sqlite3.Connection | None = None,
    ) -> EvidenceManifest:
        """Store an immutable derived evidence object linked to parent evidence IDs."""
        if not parent_evidence_ids:
            raise ContractViolationError("Derived evidence must specify at least one parent_evidence_id.")
        return self._store_object(
            run_id=run_id,
            owner_principal_id=owner_principal_id,
            action_id=action_id,
            data=data,
            media_type=media_type,
            capture_complete=capture_complete,
            omission_reason=omission_reason,
            source_artifact_hashes=source_artifact_hashes,
            adapter_revision=adapter_revision,
            sanitized_args_sha256=sanitized_args_sha256,
            role=EvidenceRole.DERIVED,
            parent_evidence_ids=parent_evidence_ids,
            view_revision=view_revision,
            redaction_policy_rev=redaction_policy_rev,
            evidence_id=evidence_id,
            encoding=encoding,
            conn=conn,
        )

    def _fetch_authorized_object_row(
        self,
        conn: sqlite3.Connection,
        *,
        run_id: str,
        principal_id: str,
        evidence_id: str,
    ) -> sqlite3.Row:
        row = conn.execute(
            "SELECT * FROM evidence_objects WHERE evidence_id = ?",
            (evidence_id,),
        ).fetchone()
        if row is None:
            raise EvidenceNotFoundError(f"Evidence {evidence_id!r} not found.")
        if str(row["run_id"]) != run_id or str(row["owner_principal_id"]) != principal_id:
            raise EvidenceAccessDeniedError(
                f"Access denied to evidence {evidence_id!r} for run={run_id!r}, principal={principal_id!r}."
            )
        return row

    def get_manifest(
        self,
        *,
        run_id: str,
        principal_id: str,
        evidence_id: str,
        conn: sqlite3.Connection | None = None,
    ) -> EvidenceManifest:
        """Retrieve ``EvidenceManifest`` after enforcing ``run_id`` and ``principal_id``."""
        with self._read_context(conn) as rc:
            row = self._fetch_authorized_object_row(
                rc, run_id=run_id, principal_id=principal_id, evidence_id=evidence_id
            )
            return EvidenceManifest.model_validate_json(str(row["manifest_json"]))

    def list_views(
        self,
        *,
        run_id: str,
        principal_id: str,
        evidence_id: str,
        conn: sqlite3.Connection | None = None,
    ) -> list[EvidenceViewRecord]:
        """List all registered views for an authorized evidence object (oldest first)."""
        with self._read_context(conn) as rc:
            self._fetch_authorized_object_row(
                rc, run_id=run_id, principal_id=principal_id, evidence_id=evidence_id
            )
            rows = rc.execute(
                """
                SELECT * FROM evidence_views
                WHERE evidence_id = ?
                ORDER BY created_at ASC, rowid ASC
                """,
                (evidence_id,),
            ).fetchall()
            return [_row_to_view_record(r) for r in rows]

    def get_active_view(
        self,
        *,
        run_id: str,
        principal_id: str,
        evidence_id: str,
        conn: sqlite3.Connection | None = None,
    ) -> EvidenceViewRecord:
        """Return the latest non-revoked view for ``evidence_id`` or raise ``EvidenceAccessDeniedError``."""
        with self._read_context(conn) as rc:
            self._fetch_authorized_object_row(
                rc, run_id=run_id, principal_id=principal_id, evidence_id=evidence_id
            )
            row = rc.execute(
                """
                SELECT * FROM evidence_views
                WHERE evidence_id = ? AND revoked_at IS NULL
                ORDER BY created_at DESC, rowid DESC
                LIMIT 1
                """,
                (evidence_id,),
            ).fetchone()
            if row is None:
                raise EvidenceAccessDeniedError(
                    f"No active non-revoked view remains for evidence {evidence_id!r}."
                )
            view = _row_to_view_record(row)
            if view.run_id != run_id or view.owner_principal_id != principal_id:
                raise EvidenceAccessDeniedError(
                    f"Active view ownership mismatch for evidence {evidence_id!r}."
                )
            return view

    def add_view(
        self,
        *,
        run_id: str,
        principal_id: str,
        evidence_id: str,
        view_revision: str,
        data: bytes,
        encoding: PageEncoding | None = None,
        redaction_policy_rev: str | None = None,
        revoke_prior_views: bool = True,
        conn: sqlite3.Connection | None = None,
    ) -> EvidenceViewRecord:
        """Persist a new view revision (e.g. redacted) and optionally revoke prior views."""
        if not view_revision or not view_revision.strip():
            raise ContractViolationError("view_revision must be non-empty.")

        with self._tx_context(conn) as tx:
            obj_row = self._fetch_authorized_object_row(
                tx, run_id=run_id, principal_id=principal_id, evidence_id=evidence_id
            )
            media_type = str(obj_row["media_type"])
            capture_complete = bool(obj_row["capture_complete"])
            omission_reason = obj_row["omission_reason"]

            view_encoding = _select_view_encoding(data, media_type, encoding)
            digest, relpath = self._store_blob(data)
            now_iso = utc_now_iso()

            if revoke_prior_views:
                tx.execute(
                    """
                    UPDATE evidence_views
                    SET revoked_at = ?
                    WHERE evidence_id = ? AND revoked_at IS NULL
                    """,
                    (now_iso, evidence_id),
                )

            try:
                tx.execute(
                    """
                    INSERT INTO evidence_views (
                        evidence_id, view_revision, run_id, owner_principal_id,
                        view_sha256, view_bytes, encoding, capture_complete,
                        omission_reason, storage_relpath, redaction_policy_rev,
                        revoked_at, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        evidence_id,
                        view_revision,
                        run_id,
                        principal_id,
                        digest,
                        len(data),
                        view_encoding.value,
                        1 if capture_complete else 0,
                        omission_reason,
                        relpath,
                        redaction_policy_rev,
                        None,
                        now_iso,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ContractViolationError(
                    f"View revision {view_revision!r} already exists for evidence {evidence_id!r}: {exc}"
                ) from exc

            inserted = tx.execute(
                "SELECT * FROM evidence_views WHERE evidence_id = ? AND view_revision = ?",
                (evidence_id, view_revision),
            ).fetchone()
            assert inserted is not None
            return _row_to_view_record(inserted)

    def revoke_view(
        self,
        *,
        run_id: str,
        principal_id: str,
        evidence_id: str,
        view_revision: str | None = None,
        conn: sqlite3.Connection | None = None,
    ) -> int:
        """Revoke one specific view revision or all active views for ``evidence_id``."""
        with self._tx_context(conn) as tx:
            self._fetch_authorized_object_row(
                tx, run_id=run_id, principal_id=principal_id, evidence_id=evidence_id
            )
            now_iso = utc_now_iso()
            if view_revision is None:
                cur = tx.execute(
                    """
                    UPDATE evidence_views
                    SET revoked_at = ?
                    WHERE evidence_id = ? AND revoked_at IS NULL
                    """,
                    (now_iso, evidence_id),
                )
            else:
                exists = tx.execute(
                    "SELECT 1 FROM evidence_views WHERE evidence_id = ? AND view_revision = ?",
                    (evidence_id, view_revision),
                ).fetchone()
                if exists is None:
                    raise EvidenceNotFoundError(
                        f"View {view_revision!r} not found for evidence {evidence_id!r}."
                    )
                cur = tx.execute(
                    """
                    UPDATE evidence_views
                    SET revoked_at = ?
                    WHERE evidence_id = ? AND view_revision = ? AND revoked_at IS NULL
                    """,
                    (now_iso, evidence_id, view_revision),
                )
            return int(cur.rowcount)

    def read_view_bytes(
        self,
        *,
        run_id: str,
        principal_id: str,
        evidence_id: str,
        view_revision: str | None = None,
        conn: sqlite3.Connection | None = None,
    ) -> tuple[EvidenceViewRecord, bytes]:
        """Authorize and read the verified raw bytes for an active (or named non-revoked) view."""
        with self._read_context(conn) as rc:
            self._fetch_authorized_object_row(
                rc, run_id=run_id, principal_id=principal_id, evidence_id=evidence_id
            )
            if view_revision is None:
                view = self.get_active_view(
                    run_id=run_id,
                    principal_id=principal_id,
                    evidence_id=evidence_id,
                    conn=rc,
                )
            else:
                row = rc.execute(
                    "SELECT * FROM evidence_views WHERE evidence_id = ? AND view_revision = ?",
                    (evidence_id, view_revision),
                ).fetchone()
                if row is None:
                    raise EvidenceNotFoundError(
                        f"View {view_revision!r} not found for evidence {evidence_id!r}."
                    )
                view = _row_to_view_record(row)
                if view.run_id != run_id or view.owner_principal_id != principal_id:
                    raise EvidenceAccessDeniedError("View ownership mismatch.")
                if view.revoked_at is not None:
                    raise EvidenceAccessDeniedError(
                        f"View {view_revision!r} for evidence {evidence_id!r} has been revoked."
                    )

        raw = self._read_blob_verified(
            view.storage_relpath,
            expected_sha256=view.view_sha256,
            expected_bytes=view.view_bytes,
        )
        return view, raw

    def read_page(
        self,
        *,
        run_id: str,
        principal_id: str,
        evidence_id: str,
        cursor: str | None = None,
        max_chars: int | None = None,
        max_decode_bytes: int | None = None,
        conn: sqlite3.Connection | None = None,
    ) -> EvidencePage:
        """Read one authorized, schema-validated ``EvidencePage`` from the latest active view."""
        effective_max_chars = (
            self.max_page_chars if max_chars is None else min(max_chars, self.max_page_chars)
        )
        effective_max_decode = self.max_decode_bytes
        if max_decode_bytes is not None:
            effective_max_decode = (
                max_decode_bytes
                if effective_max_decode is None
                else min(effective_max_decode, max_decode_bytes)
            )

        cursor_payload = None
        if cursor is not None:
            cursor_payload = self._signer.verify(cursor)
            if cursor_payload.run_id != run_id or cursor_payload.principal_id != principal_id:
                raise EvidenceAccessDeniedError(
                    "Cursor run_id or principal_id does not match caller context."
                )
            if cursor_payload.evidence_id != evidence_id:
                raise CursorError("Cursor evidence_id does not match requested evidence_id.")

        with self._read_context(conn) as rc:
            self._fetch_authorized_object_row(
                rc, run_id=run_id, principal_id=principal_id, evidence_id=evidence_id
            )
            active_view = self.get_active_view(
                run_id=run_id,
                principal_id=principal_id,
                evidence_id=evidence_id,
                conn=rc,
            )

            if cursor_payload is not None:
                cursor_view_row = rc.execute(
                    "SELECT * FROM evidence_views WHERE evidence_id = ? AND view_revision = ?",
                    (evidence_id, cursor_payload.view_revision),
                ).fetchone()
                if cursor_view_row is None:
                    raise CursorError("Cursor references an unknown evidence view revision.")
                cursor_view = _row_to_view_record(cursor_view_row)
                if cursor_view.revoked_at is not None:
                    raise EvidenceAccessDeniedError(
                        "Cursor references a revoked evidence view."
                    )
                if (
                    cursor_payload.view_revision != active_view.view_revision
                    or cursor_payload.view_sha256 != active_view.view_sha256
                ):
                    raise EvidenceAccessDeniedError(
                        "Cursor view revision or hash is stale after redaction or view update."
                    )
                offset_bytes = cursor_payload.offset_bytes
                if active_view.view_bytes == 0 or offset_bytes >= active_view.view_bytes:
                    raise CursorError(
                        f"Cursor offset ({offset_bytes}) is out of range for view_bytes ({active_view.view_bytes})."
                    )
                cursor_issued_at = cursor_payload.issued_at
            else:
                offset_bytes = 0
                cursor_issued_at = active_view.created_at

        raw = self._read_blob_verified(
            active_view.storage_relpath,
            expected_sha256=active_view.view_sha256,
            expected_bytes=active_view.view_bytes,
        )

        return build_evidence_page(
            run_id=run_id,
            principal_id=principal_id,
            evidence_id=evidence_id,
            view_sha256=active_view.view_sha256,
            view_revision=active_view.view_revision,
            encoding=active_view.encoding,
            raw_bytes=raw,
            offset_bytes=offset_bytes,
            capture_complete=active_view.capture_complete,
            omission_reason=active_view.omission_reason,
            signer=self._signer,
            issued_at=cursor_issued_at,
            max_chars=effective_max_chars,
            max_decode_bytes=effective_max_decode,
            validate_schema=True,
        )


__all__ = [
    "EvidenceVault",
    "EvidenceViewRecord",
]
