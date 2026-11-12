"""Offline artifact intake service with race-safe bounds and archive-bomb defenses.

Enforces ``docs/08`` section 3 and ``docs/11`` sections 1, 3, and CTF-05:
- Confines source reads via ``fs_guard.safe_read_bounded`` (rejecting traversal,
  symlinks, and NTFS reparse points/junctions).
- Validates archive inputs (ZIP, TAR, GZIP, BZIP2, XZ, and nested archives)
  against depth, entry count, decompressed byte quota, expansion ratio, and
  unsafe member path/symlink checks before storing.
- Assigns opaque ``artifact_id`` values, computes SHA-256, writes atomically
  into private storage, and registers ``ArtifactRecord`` rows in SQLite.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import ntpath
import sqlite3
import stat
import tarfile
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from pydantic import Field

from ctf_mcp.contracts import (
    ArtifactRecord,
    BoundsExceededError,
    ContractViolationError,
    PathSecurityError,
    ScopeDeniedError,
    StrictModel,
    sha256_bytes,
)
from ctf_mcp.fs_guard import safe_open_read, safe_read_bounded, safe_write_atomic
from ctf_mcp.storage import Storage, utc_now_iso

_CHUNK_BYTES = 65536
_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x01\x02")
_GZIP_MAGIC = b"\x1f\x8b"
_BZIP2_MAGIC = b"BZh"
_XZ_MAGIC = b"\xfd7zXZ\x00"


class IntakeLimits(StrictModel):
    """Bounded intake and archive inspection limits (``CTF-05``)."""

    max_intake_bytes: int = Field(default=16 * 1024 * 1024, gt=0)
    max_archive_depth: int = Field(default=3, ge=0)
    max_archive_entries: int = Field(default=256, gt=0)
    max_decompressed_bytes: int = Field(default=32 * 1024 * 1024, gt=0)
    max_expansion_ratio: float = Field(default=20.0, gt=0.0)
    ratio_grace_bytes: int = Field(default=4096, ge=0)


@dataclass
class _ArchiveState:
    entries: int = 0
    decompressed_bytes: int = 0


def _validate_archive_member_name(name: str) -> None:
    if not name or "\x00" in name:
        raise PathSecurityError("Archive member has empty name or null byte.")
    if name.startswith(("/", "\\")):
        raise PathSecurityError(f"Archive member {name!r} uses an absolute path.")
    drive, _ = ntpath.splitdrive(name)
    if drive or ":" in name:
        raise PathSecurityError(f"Archive member {name!r} contains drive letter or stream syntax.")
    for segment in name.replace("\\", "/").split("/"):
        if segment in ("..",):
            raise PathSecurityError(f"Archive member {name!r} contains path traversal.")


def _looks_like_tar(data: bytes) -> bool:
    return len(data) >= 265 and data[257:262] == b"ustar"


def _detect_archive_kind(
    data: bytes,
    *,
    media_type: str | None = None,
    filename: str | None = None,
) -> str | None:
    if data.startswith(_ZIP_MAGICS):
        return "zip"
    if data.startswith(_GZIP_MAGIC):
        return "gzip"
    if data.startswith(_BZIP2_MAGIC):
        return "bz2"
    if data.startswith(_XZ_MAGIC):
        return "xz"
    if _looks_like_tar(data):
        return "tar"

    lower_name = (filename or "").lower()
    lower_mt = (media_type or "").lower()
    if lower_name.endswith(".zip") or lower_mt in {"application/zip", "application/x-zip-compressed"}:
        return "zip"
    if lower_name.endswith((".tar.gz", ".tgz")):
        return "gzip"
    if lower_name.endswith(".tar.bz2") or lower_name.endswith(".tbz2"):
        return "bz2"
    if lower_name.endswith(".tar.xz") or lower_name.endswith(".txz"):
        return "xz"
    if lower_name.endswith(".tar") or lower_mt == "application/x-tar":
        return "tar"
    if lower_name.endswith(".gz") or lower_mt == "application/gzip":
        return "gzip"
    return None


def _check_ratio(
    decompressed: int,
    compressed: int,
    limits: IntakeLimits,
    *,
    context: str,
) -> None:
    if decompressed <= limits.ratio_grace_bytes:
        return
    ratio = decompressed / max(compressed, 1)
    if ratio > limits.max_expansion_ratio:
        raise BoundsExceededError(
            f"Archive expansion ratio ({ratio:.1f}x) exceeds limit ({limits.max_expansion_ratio:.1f}x) in {context}.",
            details={
                "decompressed_bytes": decompressed,
                "compressed_bytes": compressed,
                "max_expansion_ratio": limits.max_expansion_ratio,
            },
        )


def _read_bounded_stream(
    stream: BinaryIO,
    *,
    state: _ArchiveState,
    limits: IntakeLimits,
    compressed_size: int,
    context: str,
    capture_bytes: bool,
) -> bytes:
    chunks: list[bytes] = []
    entry_total = 0
    while True:
        chunk = stream.read(_CHUNK_BYTES)
        if not chunk:
            break
        entry_total += len(chunk)
        state.decompressed_bytes += len(chunk)
        if state.decompressed_bytes > limits.max_decompressed_bytes:
            raise BoundsExceededError(
                f"Decompressed bytes exceeded max_decompressed_bytes ({limits.max_decompressed_bytes}) in {context}.",
                details={
                    "decompressed_bytes": state.decompressed_bytes,
                    "max_decompressed_bytes": limits.max_decompressed_bytes,
                },
            )
        _check_ratio(entry_total, compressed_size, limits, context=context)
        if capture_bytes:
            chunks.append(chunk)
    return b"".join(chunks) if capture_bytes else b""


def _inspect_zip(
    data: bytes,
    *,
    depth: int,
    state: _ArchiveState,
    limits: IntakeLimits,
) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data), "r")
    except zipfile.BadZipFile as exc:
        raise ContractViolationError(f"Malformed ZIP artifact: {exc}") from exc

    with zf:
        infos = zf.infolist()
        if state.entries + len(infos) > limits.max_archive_entries:
            raise BoundsExceededError(
                f"Archive entry count exceeds max_archive_entries ({limits.max_archive_entries}).",
                details={"max_archive_entries": limits.max_archive_entries},
            )

        total_declared = sum(info.file_size for info in infos)
        if state.decompressed_bytes + total_declared > limits.max_decompressed_bytes:
            raise BoundsExceededError(
                f"Declared ZIP payload ({total_declared} B) exceeds max_decompressed_bytes ({limits.max_decompressed_bytes} B)."
            )
        _check_ratio(total_declared, len(data), limits, context="zip_header")

        for info in infos:
            state.entries += 1
            if state.entries > limits.max_archive_entries:
                raise BoundsExceededError(
                    f"Archive entry count exceeds max_archive_entries ({limits.max_archive_entries})."
                )
            _validate_archive_member_name(info.filename)

            unix_mode = (info.external_attr >> 16) & 0o170000
            if unix_mode == stat.S_IFLNK:
                raise PathSecurityError(
                    f"Symlink entry {info.filename!r} is forbidden inside ingested archive."
                )
            if info.is_dir():
                continue

            _check_ratio(info.file_size, max(info.compress_size, 1), limits, context=info.filename)

            # Inspect stream with bounded read regardless of declared header size.
            with zf.open(info, "r") as member_stream:
                entry_bytes = _read_bounded_stream(
                    member_stream,
                    state=state,
                    limits=limits,
                    compressed_size=max(info.compress_size, 1),
                    context=info.filename,
                    capture_bytes=True,
                )

            _check_ratio(len(entry_bytes), max(len(data), 1), limits, context=info.filename)
            nested_kind = _detect_archive_kind(entry_bytes, filename=info.filename)
            if nested_kind is not None:
                _inspect_archive(
                    entry_bytes,
                    kind=nested_kind,
                    depth=depth + 1,
                    state=state,
                    limits=limits,
                )


def _inspect_tar(
    data: bytes,
    *,
    depth: int,
    state: _ArchiveState,
    limits: IntakeLimits,
) -> None:
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
    except tarfile.TarError as exc:
        raise ContractViolationError(f"Malformed TAR artifact: {exc}") from exc

    with tf:
        for member in tf:
            state.entries += 1
            if state.entries > limits.max_archive_entries:
                raise BoundsExceededError(
                    f"Archive entry count exceeds max_archive_entries ({limits.max_archive_entries})."
                )
            _validate_archive_member_name(member.name)
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise PathSecurityError(
                    f"Special/link tar member {member.name!r} is forbidden inside ingested archive."
                )
            if not member.isfile():
                continue

            if state.decompressed_bytes + member.size > limits.max_decompressed_bytes:
                raise BoundsExceededError(
                    f"TAR member {member.name!r} exceeds max_decompressed_bytes ({limits.max_decompressed_bytes})."
                )
            extracted = tf.extractfile(member)
            if extracted is None:
                continue
            with extracted:
                entry_bytes = _read_bounded_stream(
                    extracted,
                    state=state,
                    limits=limits,
                    compressed_size=max(len(data), 1),
                    context=member.name,
                    capture_bytes=True,
                )

            nested_kind = _detect_archive_kind(entry_bytes, filename=member.name)
            if nested_kind is not None:
                _inspect_archive(
                    entry_bytes,
                    kind=nested_kind,
                    depth=depth + 1,
                    state=state,
                    limits=limits,
                )


def _inspect_compressed_stream(
    data: bytes,
    *,
    codec: str,
    depth: int,
    state: _ArchiveState,
    limits: IntakeLimits,
) -> None:
    try:
        if codec == "gzip":
            stream: BinaryIO = gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb")  # type: ignore[assignment]
        elif codec == "bz2":
            stream = bz2.BZ2File(io.BytesIO(data), mode="rb")  # type: ignore[assignment]
        elif codec == "xz":
            stream = lzma.LZMAFile(io.BytesIO(data), mode="rb")  # type: ignore[assignment]
        else:
            raise ContractViolationError(f"Unsupported compression codec {codec!r}.")

        with stream:
            decompressed = _read_bounded_stream(
                stream,
                state=state,
                limits=limits,
                compressed_size=max(len(data), 1),
                context=codec,
                capture_bytes=True,
            )
    except (EOFError, OSError, lzma.LZMAError) as exc:
        raise ContractViolationError(f"Malformed {codec} artifact: {exc}") from exc

    if _looks_like_tar(decompressed):
        _inspect_tar(decompressed, depth=depth, state=state, limits=limits)
    else:
        nested_kind = _detect_archive_kind(decompressed)
        if nested_kind is not None:
            _inspect_archive(
                decompressed,
                kind=nested_kind,
                depth=depth + 1,
                state=state,
                limits=limits,
            )


def _inspect_archive(
    data: bytes,
    *,
    kind: str,
    depth: int,
    state: _ArchiveState,
    limits: IntakeLimits,
) -> None:
    if depth > limits.max_archive_depth:
        raise BoundsExceededError(
            f"Archive nesting depth ({depth}) exceeds max_archive_depth ({limits.max_archive_depth}).",
            details={"depth": depth, "max_archive_depth": limits.max_archive_depth},
        )
    if kind == "zip":
        _inspect_zip(data, depth=depth, state=state, limits=limits)
    elif kind == "tar":
        _inspect_tar(data, depth=depth, state=state, limits=limits)
    elif kind in {"gzip", "bz2", "xz"}:
        _inspect_compressed_stream(data, codec=kind, depth=depth, state=state, limits=limits)


def validate_archive_safety(
    data: bytes,
    *,
    media_type: str | None = None,
    filename: str | None = None,
    limits: IntakeLimits | None = None,
) -> None:
    """Validate that raw or archived artifact bytes obey bomb and path-safety limits."""
    eff_limits = limits or IntakeLimits()
    kind = _detect_archive_kind(data, media_type=media_type, filename=filename)
    if kind is None:
        return
    state = _ArchiveState()
    _inspect_archive(data, kind=kind, depth=0, state=state, limits=eff_limits)


class ArtifactIntakeService:
    """Bounded offline intake registering immutable artifacts under opaque IDs."""

    def __init__(
        self,
        storage: Storage,
        vault_root: str | Path,
        *,
        limits: IntakeLimits | None = None,
    ) -> None:
        self._storage = storage
        self._vault_root = Path(vault_root)
        self._vault_root.mkdir(parents=True, exist_ok=True)
        self._limits = limits or IntakeLimits()

    def _verify_run_ownership_in_tx(
        self,
        conn: sqlite3.Connection,
        *,
        run_id: str,
        principal_id: str,
        require_open: bool,
    ) -> None:
        row = conn.execute(
            "SELECT owner_principal_id, closed_at FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            raise ScopeDeniedError(f"Run {run_id!r} does not exist.")
        if row["owner_principal_id"] != principal_id:
            raise ScopeDeniedError(
                f"Principal {principal_id!r} is not authorized for run {run_id!r}."
            )
        if require_open and row["closed_at"] is not None:
            raise ScopeDeniedError(f"Run {run_id!r} is closed and cannot accept new artifacts.")

    def _store_artifact_bytes(
        self,
        *,
        run_id: str,
        principal_id: str,
        data: bytes,
        media_type: str,
        source_origin: str,
        filename_hint: str | None,
        limits: IntakeLimits,
    ) -> ArtifactRecord:
        if len(data) > limits.max_intake_bytes:
            raise BoundsExceededError(
                f"Artifact size ({len(data)} B) exceeds max_intake_bytes ({limits.max_intake_bytes} B)."
            )

        with self._storage.read_connection() as conn:
            self._verify_run_ownership_in_tx(
                conn,
                run_id=run_id,
                principal_id=principal_id,
                require_open=True,
            )

        validate_archive_safety(
            data,
            media_type=media_type,
            filename=filename_hint,
            limits=limits,
        )

        digest = sha256_bytes(data)
        artifact_id = f"art_{uuid.uuid4().hex[:16]}"
        storage_relpath = f"artifacts/{run_id}/{artifact_id}.blob"
        written_path = safe_write_atomic(
            self._vault_root,
            storage_relpath,
            data,
            max_bytes=limits.max_intake_bytes,
            overwrite=False,
            create_parents=True,
        )

        record = ArtifactRecord(
            artifact_id=artifact_id,
            run_id=run_id,
            sha256=digest,
            byte_length=len(data),
            media_type=media_type,
            source_origin=source_origin,
            storage_relpath=storage_relpath,
        )

        try:
            with self._storage.transaction() as conn:
                self._verify_run_ownership_in_tx(
                    conn,
                    run_id=run_id,
                    principal_id=principal_id,
                    require_open=True,
                )
                conn.execute(
                    """
                    INSERT INTO artifacts (
                        artifact_id, run_id, sha256, byte_length,
                        media_type, source_origin, storage_relpath, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.artifact_id,
                        record.run_id,
                        record.sha256,
                        record.byte_length,
                        record.media_type,
                        record.source_origin,
                        record.storage_relpath,
                        utc_now_iso(),
                    ),
                )
        except BaseException:
            try:
                written_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise

        return record

    def ingest_from_workspace(
        self,
        *,
        run_id: str,
        principal_id: str,
        source_root: str | Path,
        rel_path: str | Path,
        media_type: str = "application/octet-stream",
        source_origin: str = "offline_iso",
        limits: IntakeLimits | None = None,
    ) -> ArtifactRecord:
        """Safely ingest a file from an offline workspace/ISO directory into the private store."""
        eff_limits = limits or self._limits
        with self._storage.read_connection() as conn:
            self._verify_run_ownership_in_tx(
                conn,
                run_id=run_id,
                principal_id=principal_id,
                require_open=True,
            )

        read_result = safe_read_bounded(
            source_root,
            rel_path,
            max_bytes=eff_limits.max_intake_bytes,
            allow_truncate=False,
        )
        return self._store_artifact_bytes(
            run_id=run_id,
            principal_id=principal_id,
            data=read_result.data,
            media_type=media_type,
            source_origin=source_origin,
            filename_hint=str(rel_path),
            limits=eff_limits,
        )

    def ingest_bytes(
        self,
        *,
        run_id: str,
        principal_id: str,
        data: bytes,
        media_type: str = "application/octet-stream",
        source_origin: str = "local_fixture",
        filename_hint: str | None = None,
        limits: IntakeLimits | None = None,
    ) -> ArtifactRecord:
        """Ingest in-memory fixture bytes through archive validation into the private store."""
        eff_limits = limits or self._limits
        return self._store_artifact_bytes(
            run_id=run_id,
            principal_id=principal_id,
            data=data,
            media_type=media_type,
            source_origin=source_origin,
            filename_hint=filename_hint,
            limits=eff_limits,
        )

    def get_artifact(
        self,
        *,
        run_id: str,
        principal_id: str,
        artifact_id: str,
    ) -> ArtifactRecord:
        """Fetch an ``ArtifactRecord`` strictly scoped to ``(run_id, principal_id)``."""
        with self._storage.read_connection() as conn:
            self._verify_run_ownership_in_tx(
                conn,
                run_id=run_id,
                principal_id=principal_id,
                require_open=False,
            )
            row = conn.execute(
                """
                SELECT artifact_id, run_id, sha256, byte_length,
                       media_type, source_origin, storage_relpath
                FROM artifacts
                WHERE artifact_id = ? AND run_id = ?
                """,
                (artifact_id, run_id),
            ).fetchone()
            if row is None:
                raise ContractViolationError(
                    f"Artifact {artifact_id!r} not found in run {run_id!r}.",
                    code="artifact_not_found",
                )
            return ArtifactRecord(
                artifact_id=str(row["artifact_id"]),
                run_id=str(row["run_id"]),
                sha256=str(row["sha256"]),
                byte_length=int(row["byte_length"]),
                media_type=str(row["media_type"]),
                source_origin=str(row["source_origin"]),
                storage_relpath=str(row["storage_relpath"]),
            )

    def list_artifacts(self, *, run_id: str, principal_id: str) -> list[ArtifactRecord]:
        """List all artifacts registered for ``(run_id, principal_id)``."""
        with self._storage.read_connection() as conn:
            self._verify_run_ownership_in_tx(
                conn,
                run_id=run_id,
                principal_id=principal_id,
                require_open=False,
            )
            rows = conn.execute(
                """
                SELECT artifact_id, run_id, sha256, byte_length,
                       media_type, source_origin, storage_relpath
                FROM artifacts
                WHERE run_id = ?
                ORDER BY created_at ASC, artifact_id ASC
                """,
                (run_id,),
            ).fetchall()
            return [
                ArtifactRecord(
                    artifact_id=str(row["artifact_id"]),
                    run_id=str(row["run_id"]),
                    sha256=str(row["sha256"]),
                    byte_length=int(row["byte_length"]),
                    media_type=str(row["media_type"]),
                    source_origin=str(row["source_origin"]),
                    storage_relpath=str(row["storage_relpath"]),
                )
                for row in rows
            ]

    def open_artifact(
        self,
        *,
        run_id: str,
        principal_id: str,
        artifact_id: str,
    ) -> BinaryIO:
        """Open a private ingested artifact safely via ``fs_guard.safe_open_read``."""
        record = self.get_artifact(run_id=run_id, principal_id=principal_id, artifact_id=artifact_id)
        return safe_open_read(
            self._vault_root,
            record.storage_relpath,
            max_bytes=record.byte_length,
        )

    def resolve_artifact_path(
        self,
        *,
        run_id: str,
        principal_id: str,
        artifact_id: str,
    ) -> Path:
        """Resolve private stored path for an authorized ``artifact_id`` (for server/adapter use only)."""
        with self.open_artifact(
            run_id=run_id,
            principal_id=principal_id,
            artifact_id=artifact_id,
        ):
            record = self.get_artifact(run_id=run_id, principal_id=principal_id, artifact_id=artifact_id)
            return self._vault_root / record.storage_relpath


__all__ = [
    "ArtifactIntakeService",
    "IntakeLimits",
    "validate_archive_safety",
]
