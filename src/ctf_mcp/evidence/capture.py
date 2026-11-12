"""Bounded pre-buffering stream capture and archive bomb boundary validation.

Enforces ``docs/11-contracts-and-acceptance(.ja).md`` section 3 (CTF-05):
- Enforces per-stream, per-action, and per-run byte quotas before buffering.
- Stops capture immediately when a quota is reached, preserving the partial
  object with ``capture_complete=False`` and an explicit ``omission_reason``.
- Enforces pre-check and streaming archive bounds (depth, entry count,
  decompressed bytes, expansion ratio, and unsafe archive entry paths/links).
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import ntpath
import stat
import tarfile
import zipfile
import zlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import BinaryIO

from ctf_mcp.contracts import BoundsExceededError, PathSecurityError, sha256_bytes

DEFAULT_ARCHIVE_CHUNK_BYTES = 65_536
_ZIP_MAGIC = b"PK\x03\x04"
_ZIP_EMPTY_MAGIC = b"PK\x05\x06"
_GZIP_MAGIC = b"\x1f\x8b"
_BZ2_MAGIC = b"BZh"
_XZ_MAGIC = b"\xfd7zXZ\x00"


@dataclass(frozen=True)
class CaptureResult:
    """Result produced by ``BoundedCaptureBuffer.finalize()``."""

    data: bytes
    bytes_captured: int
    bytes_seen: int
    capture_complete: bool
    omission_reason: str | None
    sha256: str
    truncated: bool
    limit_scope: str | None = None
    stream_bytes: tuple[tuple[str, int], ...] = ()


class BoundedCaptureBuffer:
    """Pre-buffering bounded byte accumulator across streams, action, and run quotas.

    Callers feed raw chunks via :meth:`append`. As soon as a stream, action, or
    run quota would be exceeded, only the permitted prefix is retained, no
    further bytes are buffered, ``capture_complete`` becomes ``False``, and
    :meth:`append` returns ``False`` so the caller can immediately terminate the
    producer process.
    """

    def __init__(
        self,
        *,
        max_action_bytes: int,
        max_stream_bytes: int | None = None,
        max_run_remaining_bytes: int | None = None,
        stream_limits: Mapping[str, int] | None = None,
    ) -> None:
        if max_action_bytes <= 0:
            raise ValueError("max_action_bytes must be positive.")
        if max_stream_bytes is not None and max_stream_bytes <= 0:
            raise ValueError("max_stream_bytes must be positive when specified.")
        if max_run_remaining_bytes is not None and max_run_remaining_bytes < 0:
            raise ValueError("max_run_remaining_bytes must be non-negative.")

        self.max_action_bytes = max_action_bytes
        self.max_stream_bytes = max_stream_bytes
        self.max_run_remaining_bytes = max_run_remaining_bytes
        self.stream_limits: dict[str, int] = {}
        if stream_limits is not None:
            for name, limit in stream_limits.items():
                if not name or not name.strip():
                    raise ValueError("Stream name must be non-empty.")
                if limit <= 0:
                    raise ValueError(f"Stream limit for {name!r} must be positive.")
                self.stream_limits[name] = limit

        self._chunks: list[bytes] = []
        self._stream_chunks: dict[str, list[bytes]] = {}
        self._stream_bytes: dict[str, int] = {}
        self._total_bytes = 0
        self._bytes_seen = 0
        self._capture_complete = True
        self._omission_reason: str | None = None
        self._limit_scope: str | None = None

    @property
    def bytes_captured(self) -> int:
        return self._total_bytes

    @property
    def bytes_seen(self) -> int:
        return self._bytes_seen

    @property
    def capture_complete(self) -> bool:
        return self._capture_complete

    @property
    def omission_reason(self) -> str | None:
        return self._omission_reason

    @property
    def should_stop(self) -> bool:
        return not self._capture_complete

    def stream_bytes_captured(self, stream: str) -> int:
        return self._stream_bytes.get(stream, 0)

    def _effective_stream_limit(self, stream: str) -> int | None:
        if stream in self.stream_limits:
            if self.max_stream_bytes is not None:
                return min(self.stream_limits[stream], self.max_stream_bytes)
            return self.stream_limits[stream]
        return self.max_stream_bytes

    def mark_incomplete(self, reason: str, *, scope: str = "producer") -> None:
        """Mark capture incomplete due to timeout, cancellation, or external cutoff."""
        cleaned = reason.strip()
        if not cleaned:
            raise ValueError("omission_reason must be non-empty.")
        self._capture_complete = False
        if self._omission_reason is None:
            self._omission_reason = cleaned
            self._limit_scope = scope

    def append(self, chunk: bytes | bytearray | memoryview, *, stream: str = "stdout") -> bool:
        """Append ``chunk`` within stream/action/run bounds without unbounded buffering.

        Returns ``True`` if the entire chunk fit inside quotas and capture may
        continue, or ``False`` if a quota was exceeded and capture is now stopped.
        """
        if not stream or not stream.strip():
            raise ValueError("stream name must be non-empty.")
        raw = bytes(chunk)
        if not raw:
            return self._capture_complete

        self._bytes_seen += len(raw)
        if not self._capture_complete:
            return False

        current_stream_bytes = self._stream_bytes.get(stream, 0)
        stream_limit = self._effective_stream_limit(stream)

        candidates: list[tuple[int, str, str]] = []
        if stream_limit is not None:
            candidates.append(
                (
                    max(0, stream_limit - current_stream_bytes),
                    "stream",
                    f"Stream '{stream}' byte quota ({stream_limit} bytes) exceeded.",
                )
            )
        candidates.append(
            (
                max(0, self.max_action_bytes - self._total_bytes),
                "action",
                f"Action output byte quota ({self.max_action_bytes} bytes) exceeded.",
            )
        )
        if self.max_run_remaining_bytes is not None:
            candidates.append(
                (
                    max(0, self.max_run_remaining_bytes - self._total_bytes),
                    "run",
                    f"Run evidence byte quota ({self.max_run_remaining_bytes} bytes) exceeded.",
                )
            )

        min_remaining, tightest_scope, reason = min(candidates, key=lambda item: item[0])

        if len(raw) <= min_remaining:
            self._chunks.append(raw)
            self._stream_chunks.setdefault(stream, []).append(raw)
            self._stream_bytes[stream] = current_stream_bytes + len(raw)
            self._total_bytes += len(raw)
            return True

        if min_remaining > 0:
            accepted = raw[:min_remaining]
            self._chunks.append(accepted)
            self._stream_chunks.setdefault(stream, []).append(accepted)
            self._stream_bytes[stream] = current_stream_bytes + len(accepted)
            self._total_bytes += len(accepted)

        self._capture_complete = False
        self._omission_reason = reason
        self._limit_scope = tightest_scope
        return False

    def data(self, *, stream: str | None = None) -> bytes:
        """Return captured immutable bytes (combined or for one stream)."""
        if stream is None:
            return b"".join(self._chunks)
        return b"".join(self._stream_chunks.get(stream, ()))

    def finalize(self) -> CaptureResult:
        """Return immutable ``CaptureResult`` with exact SHA-256 over retained bytes."""
        payload = b"".join(self._chunks)
        return CaptureResult(
            data=payload,
            bytes_captured=len(payload),
            bytes_seen=self._bytes_seen,
            capture_complete=self._capture_complete,
            omission_reason=self._omission_reason,
            sha256=sha256_bytes(payload),
            truncated=not self._capture_complete,
            limit_scope=self._limit_scope,
            stream_bytes=tuple(sorted(self._stream_bytes.items())),
        )


def capture_bounded_stream(
    stream_source: BinaryIO | Iterable[bytes],
    *,
    max_action_bytes: int,
    max_stream_bytes: int | None = None,
    max_run_remaining_bytes: int | None = None,
    stream_name: str = "stdout",
    chunk_size: int = DEFAULT_ARCHIVE_CHUNK_BYTES,
) -> CaptureResult:
    """Read from a binary stream or byte-chunk iterable under bounded quotas."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive.")

    buf = BoundedCaptureBuffer(
        max_action_bytes=max_action_bytes,
        max_stream_bytes=max_stream_bytes,
        max_run_remaining_bytes=max_run_remaining_bytes,
    )
    if hasattr(stream_source, "read"):
        reader = stream_source  # type: ignore[assignment]
        while True:
            chunk = reader.read(chunk_size)
            if not chunk:
                break
            if not buf.append(chunk, stream=stream_name):
                break
    else:
        for chunk in stream_source:
            if not chunk:
                continue
            if not buf.append(chunk, stream=stream_name):
                break
    return buf.finalize()


# ---------------------------------------------------------------------------
# Archive Boundary Validation (CTF-05)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ArchiveLimits:
    """Archive safety limits aligned with ``CapabilityLimits``."""

    max_archive_depth: int = 3
    max_archive_entries: int = 256
    max_uncompressed_bytes: int = 10_485_760
    max_expansion_ratio: float = 20.0

    def __post_init__(self) -> None:
        if self.max_archive_depth < 0:
            raise ValueError("max_archive_depth must be non-negative.")
        if self.max_archive_entries <= 0:
            raise ValueError("max_archive_entries must be positive.")
        if self.max_uncompressed_bytes <= 0:
            raise ValueError("max_uncompressed_bytes must be positive.")
        if self.max_expansion_ratio <= 0.0:
            raise ValueError("max_expansion_ratio must be positive.")


@dataclass(frozen=True)
class ArchiveInspectionResult:
    """Summary of a validated archive passing all bounds checks."""

    archive_format: str
    entry_count: int
    total_uncompressed_bytes: int
    compressed_bytes: int
    max_depth_observed: int
    expansion_ratio: float


def _validate_archive_entry_name(name: str) -> None:
    """Reject traversal, absolute paths, drive prefixes, and null bytes inside archives."""
    if not name or "\x00" in name:
        raise PathSecurityError("Archive entry name is empty or contains a null byte.")
    if name.startswith(("/", "\\")):
        raise PathSecurityError(f"Archive entry {name!r} uses an absolute path.")
    drive, _ = ntpath.splitdrive(name)
    if drive or ":" in name:
        raise PathSecurityError(f"Archive entry {name!r} contains drive or stream prefix.")
    normalized = name.replace("\\", "/")
    for segment in normalized.split("/"):
        if segment in (".", ".."):
            raise PathSecurityError(f"Archive entry {name!r} contains unsafe segment {segment!r}.")


class ArchiveBoundsTracker:
    """Stateful pre-check and sequential decompressor tracker for archive safety."""

    def __init__(self, *, limits: ArchiveLimits, root_compressed_bytes: int) -> None:
        if root_compressed_bytes < 0:
            raise ValueError("root_compressed_bytes must be non-negative.")
        self.limits = limits
        self.root_compressed_bytes = root_compressed_bytes
        self.entry_count = 0
        self.total_uncompressed_bytes = 0
        self.max_depth_observed = 0

    def check_depth(self, depth: int) -> None:
        if depth > self.limits.max_archive_depth:
            raise BoundsExceededError(
                f"Archive nesting depth ({depth}) exceeds max_archive_depth "
                f"({self.limits.max_archive_depth}).",
                details={"depth": depth, "max_archive_depth": self.limits.max_archive_depth},
            )
        if depth > self.max_depth_observed:
            self.max_depth_observed = depth

    def check_expansion_ratio(
        self,
        *,
        uncompressed_bytes: int,
        compressed_bytes: int,
        context: str,
    ) -> None:
        if uncompressed_bytes == 0:
            return
        if compressed_bytes <= 0:
            raise BoundsExceededError(
                f"Archive {context} has zero compressed bytes with {uncompressed_bytes} uncompressed bytes.",
                details={"uncompressed_bytes": uncompressed_bytes, "compressed_bytes": compressed_bytes},
            )
        ratio = uncompressed_bytes / compressed_bytes
        if ratio > self.limits.max_expansion_ratio:
            raise BoundsExceededError(
                f"Archive {context} expansion ratio ({ratio:.2f}x) exceeds "
                f"max_expansion_ratio ({self.limits.max_expansion_ratio:.2f}x).",
                details={
                    "expansion_ratio": ratio,
                    "max_expansion_ratio": self.limits.max_expansion_ratio,
                    "uncompressed_bytes": uncompressed_bytes,
                    "compressed_bytes": compressed_bytes,
                },
            )

    def record_entry(
        self,
        name: str,
        *,
        declared_size: int | None = None,
        compressed_size: int | None = None,
        is_link: bool = False,
        is_special: bool = False,
    ) -> None:
        """Register one archive entry and pre-check count, name, link, and declared size."""
        if is_link:
            raise PathSecurityError(f"Archive entry {name!r} is a symlink or hardlink (forbidden).")
        if is_special:
            raise PathSecurityError(f"Archive entry {name!r} is a special device/FIFO file (forbidden).")
        _validate_archive_entry_name(name)

        self.entry_count += 1
        if self.entry_count > self.limits.max_archive_entries:
            raise BoundsExceededError(
                f"Archive entry count ({self.entry_count}) exceeds max_archive_entries "
                f"({self.limits.max_archive_entries}).",
                details={
                    "entry_count": self.entry_count,
                    "max_archive_entries": self.limits.max_archive_entries,
                },
            )

        if declared_size is not None:
            if declared_size < 0:
                raise BoundsExceededError(f"Archive entry {name!r} has negative declared size.")
            projected = self.total_uncompressed_bytes + declared_size
            if projected > self.limits.max_uncompressed_bytes:
                raise BoundsExceededError(
                    f"Declared archive uncompressed size ({projected} bytes) exceeds "
                    f"max_uncompressed_bytes ({self.limits.max_uncompressed_bytes}).",
                    details={
                        "projected_bytes": projected,
                        "max_uncompressed_bytes": self.limits.max_uncompressed_bytes,
                    },
                )
            if compressed_size is not None and declared_size > 0:
                self.check_expansion_ratio(
                    uncompressed_bytes=declared_size,
                    compressed_bytes=compressed_size,
                    context=f"entry {name!r} (declared)",
                )
            if self.root_compressed_bytes > 0:
                self.check_expansion_ratio(
                    uncompressed_bytes=projected,
                    compressed_bytes=self.root_compressed_bytes,
                    context="cumulative (declared)",
                )

    def record_decompressed_chunk(
        self,
        chunk_bytes: int,
        *,
        entry_uncompressed_so_far: int | None = None,
        entry_compressed_bytes: int | None = None,
        entry_name: str = "<entry>",
    ) -> None:
        """Record actual decompressed bytes sequentially during streaming extraction."""
        if chunk_bytes < 0:
            raise ValueError("chunk_bytes must be non-negative.")
        if chunk_bytes == 0:
            return
        self.total_uncompressed_bytes += chunk_bytes
        if self.total_uncompressed_bytes > self.limits.max_uncompressed_bytes:
            raise BoundsExceededError(
                f"Decompressed archive size ({self.total_uncompressed_bytes} bytes) exceeds "
                f"max_uncompressed_bytes ({self.limits.max_uncompressed_bytes}).",
                details={
                    "total_uncompressed_bytes": self.total_uncompressed_bytes,
                    "max_uncompressed_bytes": self.limits.max_uncompressed_bytes,
                },
            )
        if entry_uncompressed_so_far is not None and entry_compressed_bytes is not None:
            self.check_expansion_ratio(
                uncompressed_bytes=entry_uncompressed_so_far,
                compressed_bytes=entry_compressed_bytes,
                context=f"entry {entry_name!r}",
            )
        self.check_expansion_ratio(
            uncompressed_bytes=self.total_uncompressed_bytes,
            compressed_bytes=self.root_compressed_bytes,
            context="cumulative",
        )


def _detect_archive_format(data: bytes, filename: str = "") -> str | None:
    lower = filename.lower()
    if data.startswith((_ZIP_MAGIC, _ZIP_EMPTY_MAGIC)):
        return "zip"
    if data.startswith(_GZIP_MAGIC):
        if lower.endswith((".tar.gz", ".tgz")):
            return "tar.gz"
        return "gzip"
    if data.startswith(_BZ2_MAGIC):
        if lower.endswith((".tar.bz2", ".tbz2")):
            return "tar.bz2"
        return "bz2"
    if data.startswith(_XZ_MAGIC):
        if lower.endswith((".tar.xz", ".txz")):
            return "tar.xz"
        return "xz"
    if len(data) >= 265 and data[257:262] == b"ustar":
        return "tar"
    if lower.endswith(".zip"):
        return "zip"
    if lower.endswith(".tar"):
        return "tar"
    if lower.endswith((".tar.gz", ".tgz")):
        return "tar.gz"
    if lower.endswith((".tar.bz2", ".tbz2")):
        return "tar.bz2"
    if lower.endswith((".tar.xz", ".txz")):
        return "tar.xz"
    if lower.endswith(".gz"):
        return "gzip"
    if lower.endswith(".bz2"):
        return "bz2"
    if lower.endswith(".xz"):
        return "xz"
    return None


def _looks_like_nested_archive(prefix: bytes, name: str) -> bool:
    if _detect_archive_format(prefix, name) is not None:
        return True
    return False


def _read_stream_with_tracker(
    stream: BinaryIO,
    tracker: ArchiveBoundsTracker,
    *,
    entry_name: str,
    entry_compressed_bytes: int | None,
    capture_for_nested_check: bool,
) -> bytes | None:
    """Read an archive member stream incrementally while checking bounds on each chunk.

    Returns the full member bytes only when ``capture_for_nested_check`` is
    True (already bounded by ``limits.max_uncompressed_bytes``); otherwise
    discards bytes after updating ``tracker``.
    """
    entry_seen = 0
    captured: list[bytes] = []
    while True:
        chunk = stream.read(DEFAULT_ARCHIVE_CHUNK_BYTES)
        if not chunk:
            break
        entry_seen += len(chunk)
        tracker.record_decompressed_chunk(
            len(chunk),
            entry_uncompressed_so_far=entry_seen,
            entry_compressed_bytes=entry_compressed_bytes,
            entry_name=entry_name,
        )
        if capture_for_nested_check:
            captured.append(chunk)
    return b"".join(captured) if capture_for_nested_check else None


def _validate_archive_recursive(
    data: bytes,
    *,
    filename: str,
    depth: int,
    tracker: ArchiveBoundsTracker,
) -> str:
    fmt = _detect_archive_format(data, filename)
    if fmt is None:
        raise BoundsExceededError(f"Unrecognized or unsupported archive format for {filename!r}.")
    tracker.check_depth(depth)

    if fmt == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data), mode="r") as zf:
                infos = zf.infolist()
                if len(infos) + tracker.entry_count > tracker.limits.max_archive_entries:
                    raise BoundsExceededError(
                        f"Archive entry count ({len(infos) + tracker.entry_count}) exceeds "
                        f"max_archive_entries ({tracker.limits.max_archive_entries})."
                    )
                for info in infos:
                    mode = info.external_attr >> 16
                    is_link = stat.S_ISLNK(mode)
                    tracker.record_entry(
                        info.filename,
                        declared_size=info.file_size,
                        compressed_size=info.compress_size,
                        is_link=is_link,
                    )
                    if info.is_dir():
                        continue
                    with zf.open(info, mode="r") as member:
                        peek = member.read(min(512, DEFAULT_ARCHIVE_CHUNK_BYTES))
                        entry_seen = len(peek)
                        if entry_seen:
                            tracker.record_decompressed_chunk(
                                entry_seen,
                                entry_uncompressed_so_far=entry_seen,
                                entry_compressed_bytes=info.compress_size,
                                entry_name=info.filename,
                            )
                        is_nested = _looks_like_nested_archive(peek, info.filename)
                        if is_nested:
                            rest = _read_stream_with_tracker(
                                member,
                                tracker,
                                entry_name=info.filename,
                                entry_compressed_bytes=info.compress_size,
                                capture_for_nested_check=True,
                            )
                            nested_bytes = peek + (rest or b"")
                            _validate_archive_recursive(
                                nested_bytes,
                                filename=info.filename,
                                depth=depth + 1,
                                tracker=tracker,
                            )
                        else:
                            _read_stream_with_tracker(
                                member,
                                tracker,
                                entry_name=info.filename,
                                entry_compressed_bytes=info.compress_size,
                                capture_for_nested_check=False,
                            )
        except (zipfile.BadZipFile, zlib.error) as exc:
            raise BoundsExceededError(f"Corrupt or invalid ZIP archive: {exc}") from exc
        return fmt

    if fmt in {"tar", "tar.gz", "tar.bz2", "tar.xz"}:
        mode_map = {
            "tar": "r:",
            "tar.gz": "r:gz",
            "tar.bz2": "r:bz2",
            "tar.xz": "r:xz",
        }
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode=mode_map[fmt]) as tf:  # type: ignore[call-overload]
                for member in tf:
                    is_link = member.issym() or member.islnk()
                    is_special = not (member.isreg() or member.isdir() or is_link)
                    tracker.record_entry(
                        member.name,
                        declared_size=member.size if member.isreg() else 0,
                        compressed_size=None,
                        is_link=is_link,
                        is_special=is_special,
                    )
                    if not member.isreg():
                        continue
                    extracted = tf.extractfile(member)
                    if extracted is None:
                        continue
                    with extracted:
                        peek = extracted.read(min(512, DEFAULT_ARCHIVE_CHUNK_BYTES))
                        if peek:
                            tracker.record_decompressed_chunk(
                                len(peek),
                                entry_uncompressed_so_far=len(peek),
                                entry_compressed_bytes=None,
                                entry_name=member.name,
                            )
                        if _looks_like_nested_archive(peek, member.name):
                            rest = _read_stream_with_tracker(
                                extracted,
                                tracker,
                                entry_name=member.name,
                                entry_compressed_bytes=None,
                                capture_for_nested_check=True,
                            )
                            _validate_archive_recursive(
                                peek + (rest or b""),
                                filename=member.name,
                                depth=depth + 1,
                                tracker=tracker,
                            )
                        else:
                            _read_stream_with_tracker(
                                extracted,
                                tracker,
                                entry_name=member.name,
                                entry_compressed_bytes=None,
                                capture_for_nested_check=False,
                            )
        except (tarfile.TarError, EOFError, OSError, lzma.LZMAError) as exc:
            raise BoundsExceededError(f"Corrupt or invalid TAR archive: {exc}") from exc
        return fmt

    # Single-stream compression (gzip / bz2 / xz) possibly wrapping a tar or nested archive
    decompressor_map = {
        "gzip": lambda bio: gzip.GzipFile(fileobj=bio, mode="rb"),
        "bz2": lambda bio: bz2.BZ2File(bio, mode="rb"),
        "xz": lambda bio: lzma.LZMAFile(bio, mode="rb"),
    }
    try:
        with decompressor_map[fmt](io.BytesIO(data)) as stream:
            tracker.record_entry(filename or f"stream.{fmt}")
            peek = stream.read(min(512, DEFAULT_ARCHIVE_CHUNK_BYTES))
            if peek:
                tracker.record_decompressed_chunk(
                    len(peek),
                    entry_uncompressed_so_far=len(peek),
                    entry_compressed_bytes=len(data),
                    entry_name=filename,
                )
            inner_name = filename.rsplit(".", 1)[0] if "." in filename else "inner"
            if _looks_like_nested_archive(peek, inner_name):
                rest = _read_stream_with_tracker(
                    stream,
                    tracker,
                    entry_name=inner_name,
                    entry_compressed_bytes=len(data),
                    capture_for_nested_check=True,
                )
                _validate_archive_recursive(
                    peek + (rest or b""),
                    filename=inner_name,
                    depth=depth + 1,
                    tracker=tracker,
                )
            else:
                _read_stream_with_tracker(
                    stream,
                    tracker,
                    entry_name=inner_name,
                    entry_compressed_bytes=len(data),
                    capture_for_nested_check=False,
                )
    except (OSError, EOFError, lzma.LZMAError) as exc:
        raise BoundsExceededError(f"Corrupt or invalid compressed stream ({fmt}): {exc}") from exc
    return fmt


def validate_archive_bytes(
    data: bytes,
    *,
    limits: ArchiveLimits | None = None,
    filename: str = "archive.zip",
) -> ArchiveInspectionResult:
    """Validate an archive payload against depth, entry count, size, ratio, and path bounds.

    Performs both header pre-checks and streaming decompression checks so
    forged central directory sizes or nested archive bombs are stopped
    before exhausting memory.
    """
    active_limits = limits or ArchiveLimits()
    if len(data) == 0:
        raise BoundsExceededError("Archive payload cannot be empty.")

    tracker = ArchiveBoundsTracker(limits=active_limits, root_compressed_bytes=len(data))
    fmt = _validate_archive_recursive(
        data,
        filename=filename,
        depth=1,
        tracker=tracker,
    )
    ratio = tracker.total_uncompressed_bytes / len(data)
    return ArchiveInspectionResult(
        archive_format=fmt,
        entry_count=tracker.entry_count,
        total_uncompressed_bytes=tracker.total_uncompressed_bytes,
        compressed_bytes=len(data),
        max_depth_observed=tracker.max_depth_observed,
        expansion_ratio=ratio,
    )


__all__ = [
    "ArchiveBoundsTracker",
    "ArchiveInspectionResult",
    "ArchiveLimits",
    "BoundedCaptureBuffer",
    "CaptureResult",
    "DEFAULT_ARCHIVE_CHUNK_BYTES",
    "capture_bounded_stream",
    "validate_archive_bytes",
]
