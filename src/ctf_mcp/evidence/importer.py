"""Bounded guest-to-host evidence importer.

Implements ``docs/11-contracts-and-acceptance(.ja).md`` section 3 (CTF-05, CTF-10):
- Accepts only strict opaque object IDs (or validated registered relative
  paths inside the staging root), never arbitrary host paths.
- Enforces an unprivileged importer identity (rejecting ``root``/``admin``/``SYSTEM``).
- Reads bounded bytes via ``fs_guard.safe_read_bounded`` to resist symlink/junction
  replacement and path traversal.
- Verifies media type, byte length, archive bounds (when applicable), and
  expected SHA-256 before registering immutable evidence in ``EvidenceVault``.
- Never masks import failures as successes.
"""

from __future__ import annotations

import os
import re
import sqlite3
import stat
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from pydantic import Field

from ctf_mcp.contracts import (
    SHA256_PATTERN,
    BoundsExceededError,
    ConfigurationError,
    ContractViolationError,
    EvidenceManifest,
    EvidenceNotFoundError,
    PageEncoding,
    PathSecurityError,
    StrictModel,
    sha256_bytes,
)
from ctf_mcp.evidence.capture import ArchiveLimits, validate_archive_bytes
from ctf_mcp.evidence.vault import EvidenceVault
from ctf_mcp.fs_guard import safe_read_bounded

_OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MEDIA_TYPE_RE = re.compile(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")
_SHA256_RE = re.compile(SHA256_PATTERN)
_PRIVILEGED_IDENTITIES = frozenset(
    {"root", "admin", "administrator", "system", "nt authority\\system"}
)
_ARCHIVE_MEDIA_TYPES = frozenset(
    {
        "application/zip",
        "application/x-zip-compressed",
        "application/x-tar",
        "application/gzip",
        "application/x-gzip",
        "application/x-bzip2",
        "application/x-xz",
    }
)
_FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class ImportReceipt(StrictModel):
    """Verified receipt returned only after bounded import into ``EvidenceVault`` succeeds."""

    evidence_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    owner_principal_id: str = Field(min_length=1)
    action_id: str = Field(min_length=1)
    object_id: str = Field(min_length=1)
    verified_sha256: str = Field(pattern=SHA256_PATTERN)
    verified_bytes: int = Field(ge=0)
    media_type: str = Field(min_length=1)
    importer_identity: str = Field(min_length=1)
    imported_at: datetime
    manifest: EvidenceManifest


def _validate_opaque_object_id(object_id: str) -> str:
    if not isinstance(object_id, str) or not object_id:
        raise PathSecurityError("Opaque object_id must be a non-empty string.")
    if "\x00" in object_id or "/" in object_id or "\\" in object_id or ":" in object_id:
        raise PathSecurityError(f"Opaque object_id {object_id!r} contains forbidden path characters.")
    if ".." in object_id or object_id.endswith((".", " ")):
        raise PathSecurityError(f"Opaque object_id {object_id!r} is unsafe.")
    if not _OPAQUE_ID_RE.fullmatch(object_id):
        raise PathSecurityError(f"Opaque object_id {object_id!r} does not match allowed ID format.")
    return object_id


def _normalize_media_type(media_type: str) -> str:
    if not isinstance(media_type, str) or not media_type.strip():
        raise ContractViolationError("media_type must be a non-empty string.")
    base = media_type.split(";", 1)[0].strip().lower()
    if not _MEDIA_TYPE_RE.fullmatch(base):
        raise ContractViolationError(f"Invalid media_type {media_type!r}.")
    return base


class BoundedEvidenceImporter:
    """Validates and imports staged guest outputs into the private host ``EvidenceVault``."""

    def __init__(
        self,
        *,
        vault: EvidenceVault,
        staging_root: str | Path,
        importer_identity: str = "ctf-evidence-importer",
        max_import_bytes: int = 10_485_760,
        allowed_media_types: Iterable[str] | None = None,
        archive_limits: ArchiveLimits | None = None,
        inspect_archives: bool = True,
    ) -> None:
        if not importer_identity or not importer_identity.strip():
            raise ConfigurationError("importer_identity must be non-empty.")
        if importer_identity.strip().lower() in _PRIVILEGED_IDENTITIES:
            raise ConfigurationError(
                f"Importer requires an unprivileged host identity, got {importer_identity!r}."
            )
        if max_import_bytes <= 0:
            raise ConfigurationError("max_import_bytes must be positive.")

        self.vault = vault
        self.staging_root = Path(staging_root)
        self.importer_identity = importer_identity.strip()
        self.max_import_bytes = min(max_import_bytes, vault.max_evidence_bytes)
        self.allowed_media_types: frozenset[str] | None = (
            frozenset(_normalize_media_type(mt) for mt in allowed_media_types)
            if allowed_media_types is not None
            else None
        )
        self.archive_limits = archive_limits or ArchiveLimits()
        self.inspect_archives = inspect_archives
        self._staged_registry: dict[str, str] = {}

        if os.path.lexists(self.staging_root):
            st = os.lstat(self.staging_root)
            attrs = getattr(st, "st_file_attributes", 0)
            if stat.S_ISLNK(st.st_mode) or bool(attrs & _FILE_ATTRIBUTE_REPARSE_POINT):
                raise PathSecurityError("Staging root cannot be a symlink or reparse point.")
            if not stat.S_ISDIR(st.st_mode):
                raise PathSecurityError("Staging root must be a directory.")

    def register_staged_object(self, object_id: str, staging_relpath: str) -> None:
        """Bind an opaque ``object_id`` to a validated relative path inside ``staging_root``."""
        clean_id = _validate_opaque_object_id(object_id)
        if not staging_relpath or not staging_relpath.strip():
            raise PathSecurityError("staging_relpath must be non-empty.")
        self._staged_registry[clean_id] = staging_relpath

    def import_object(
        self,
        *,
        run_id: str,
        owner_principal_id: str,
        action_id: str,
        object_id: str,
        expected_sha256: str,
        media_type: str,
        capture_complete: bool,
        omission_reason: str | None,
        source_artifact_hashes: tuple[str, ...],
        adapter_revision: str,
        sanitized_args_sha256: str,
        expected_size_bytes: int | None = None,
        staging_relpath: str | None = None,
        max_bytes: int | None = None,
        evidence_id: str | None = None,
        encoding: PageEncoding | None = None,
        conn: sqlite3.Connection | None = None,
    ) -> ImportReceipt:
        """Read, verify, and atomically import one staged object into ``EvidenceVault``."""
        clean_id = _validate_opaque_object_id(object_id)

        if not _SHA256_RE.fullmatch(expected_sha256):
            raise ContractViolationError(
                f"expected_sha256 must be lowercase 64-hex SHA-256, got {expected_sha256!r}."
            )

        base_media = _normalize_media_type(media_type)
        if self.allowed_media_types is not None and base_media not in self.allowed_media_types:
            raise ContractViolationError(
                f"Media type {base_media!r} is not permitted by importer allowlist."
            )

        if expected_size_bytes is not None and expected_size_bytes < 0:
            raise ContractViolationError("expected_size_bytes must be non-negative.")

        effective_max_bytes = (
            self.max_import_bytes if max_bytes is None else min(max_bytes, self.max_import_bytes)
        )
        if effective_max_bytes <= 0:
            raise ConfigurationError("max_bytes must be positive.")

        if expected_size_bytes is not None and expected_size_bytes > effective_max_bytes:
            raise BoundsExceededError(
                f"Declared import size ({expected_size_bytes} bytes) exceeds limit ({effective_max_bytes} bytes).",
                details={"expected_size_bytes": expected_size_bytes, "max_bytes": effective_max_bytes},
            )

        resolved_relpath = (
            staging_relpath
            if staging_relpath is not None
            else self._staged_registry.get(clean_id, clean_id)
        )

        try:
            read_result = safe_read_bounded(
                self.staging_root,
                resolved_relpath,
                max_bytes=effective_max_bytes,
                allow_truncate=False,
            )
        except PathSecurityError as exc:
            if isinstance(exc.__cause__, FileNotFoundError):
                raise EvidenceNotFoundError(
                    f"Staged evidence object {clean_id!r} was not found in staging root.",
                    details={"object_id": clean_id},
                ) from exc
            raise

        data = read_result.data
        if expected_size_bytes is not None and len(data) != expected_size_bytes:
            raise ContractViolationError(
                f"Imported byte length ({len(data)}) does not match expected_size_bytes ({expected_size_bytes}).",
                details={"actual_bytes": len(data), "expected_bytes": expected_size_bytes},
            )

        actual_sha256 = sha256_bytes(data)
        if actual_sha256 != expected_sha256:
            raise ContractViolationError(
                "Imported evidence SHA-256 verification failed.",
                details={"expected_sha256": expected_sha256, "actual_sha256": actual_sha256},
            )

        if self.inspect_archives and (
            base_media in _ARCHIVE_MEDIA_TYPES
            or resolved_relpath.lower().endswith(
                (".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".tar.gz", ".tar.bz2", ".tar.xz")
            )
        ):
            validate_archive_bytes(data, limits=self.archive_limits, filename=resolved_relpath)

        manifest = self.vault.store_raw(
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
            evidence_id=evidence_id,
            encoding=encoding,
            conn=conn,
        )

        return ImportReceipt(
            evidence_id=manifest.evidence_id,
            run_id=manifest.run_id,
            owner_principal_id=manifest.owner_principal_id,
            action_id=manifest.action_id,
            object_id=clean_id,
            verified_sha256=actual_sha256,
            verified_bytes=len(data),
            media_type=media_type,
            importer_identity=self.importer_identity,
            imported_at=datetime.now(UTC),
            manifest=manifest,
        )


__all__ = [
    "BoundedEvidenceImporter",
    "ImportReceipt",
]
