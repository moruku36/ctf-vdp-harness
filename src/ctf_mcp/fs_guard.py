"""Layer 1 race-resistant filesystem boundary guard (Windows and POSIX).

Enforces ``docs/11-contracts-and-acceptance(.ja).md`` section 3:
- Never relies solely on string prefix matching or resolve-then-open.
- Rejects path traversal, absolute/UNC/drive paths, null bytes, symlinks,
  and Windows NTFS reparse points/junctions at the root, intermediate segments,
  and final target handle.
- Provides bounded reads and atomic writes inside a confined workspace root.
"""

from __future__ import annotations

import ctypes
import ntpath
import os
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from ctf_mcp.contracts import BoundsExceededError, PathSecurityError

FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

if sys.platform == "win32":
    import msvcrt
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
    _GENERIC_READ = 0x80000000
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    _FILE_SHARE_DELETE = 0x00000004
    _OPEN_EXISTING = 3
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _FILE_ATTRIBUTE_DIRECTORY = 0x00000010

    class _FILETIME(ctypes.Structure):
        _fields_ = [
            ("dwLowDateTime", wintypes.DWORD),
            ("dwHighDateTime", wintypes.DWORD),
        ]

    class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", _FILETIME),
            ("ftLastAccessTime", _FILETIME),
            ("ftLastWriteTime", _FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION),
    ]
    _kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL


@dataclass(frozen=True)
class BoundedReadResult:
    """Result returned by ``safe_read_bounded``."""

    data: bytes
    truncated: bool
    bytes_read: int


def _is_reparse_or_symlink(st: os.stat_result) -> bool:
    if stat.S_ISLNK(st.st_mode):
        return True
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)


_WINDOWS_RESERVED_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }
)


def _validate_rel_parts(rel_path: str | Path) -> tuple[str, ...]:
    raw = os.fspath(rel_path)
    if not isinstance(raw, str) or not raw:
        raise PathSecurityError("Relative path must be a non-empty string.")
    if "\x00" in raw:
        raise PathSecurityError("Path contains null byte.")
    if raw.startswith(("/", "\\")):
        raise PathSecurityError("Absolute or root-relative paths are forbidden.")
    drive, _ = ntpath.splitdrive(raw)
    if drive or ":" in raw:
        raise PathSecurityError("Drive letters, UNC paths, and NTFS streams are forbidden.")
    if Path(raw).is_absolute():
        raise PathSecurityError("Absolute paths are forbidden.")

    parts: list[str] = []
    for segment in raw.replace("\\", "/").split("/"):
        if segment in ("", ".", ".."):
            raise PathSecurityError(f"Unsafe path segment {segment!r} in {raw!r}.")
        if segment.endswith((" ", ".")):
            raise PathSecurityError(f"Path segment {segment!r} cannot end with space or dot.")
        stem = segment.split(".", 1)[0].upper()
        if stem in _WINDOWS_RESERVED_NAMES:
            raise PathSecurityError(f"Reserved device name segment {segment!r} is forbidden.")
        parts.append(segment)
    if not parts:
        raise PathSecurityError("Path has no target component.")
    return tuple(parts)


def _validate_workspace_root(workspace_root: str | Path) -> Path:
    root = Path(workspace_root)
    try:
        root_lstat = os.lstat(root)
    except OSError as exc:
        raise PathSecurityError(f"Workspace root is inaccessible: {exc}") from exc
    if _is_reparse_or_symlink(root_lstat):
        raise PathSecurityError("Workspace root cannot be a symlink or reparse point.")
    if not stat.S_ISDIR(root_lstat.st_mode):
        raise PathSecurityError("Workspace root must be a directory.")
    try:
        resolved = Path(os.path.realpath(root, strict=True))
        resolved_lstat = os.lstat(resolved)
    except OSError as exc:
        raise PathSecurityError(f"Workspace root canonicalization failed: {exc}") from exc
    if _is_reparse_or_symlink(resolved_lstat):
        raise PathSecurityError("Resolved workspace root cannot be a symlink or reparse point.")
    if (resolved_lstat.st_dev, resolved_lstat.st_ino) != (
        root_lstat.st_dev,
        root_lstat.st_ino,
    ):
        raise PathSecurityError("Workspace root path changed or contains a symlink ancestor.")
    return resolved


def _walk_existing_segments(root: Path, parts: tuple[str, ...], *, check_leaf: bool) -> Path:
    """Walk path components from ``root`` checking ``lstat`` at every segment."""
    current = root
    limit = len(parts) if check_leaf else len(parts) - 1
    for idx in range(len(parts)):
        current = current / parts[idx]
        if idx >= limit:
            break
        try:
            st = os.lstat(current)
        except OSError as exc:
            raise PathSecurityError(f"Target path component inaccessible: {exc}") from exc
        if _is_reparse_or_symlink(st):
            raise PathSecurityError(
                f"Symlink or reparse point forbidden at component {parts[idx]!r}."
            )
        if idx < len(parts) - 1 and not stat.S_ISDIR(st.st_mode):
            raise PathSecurityError(f"Intermediate component {parts[idx]!r} is not a directory.")
    return current


def _open_nofollow_posix(root: Path, parts: tuple[str, ...]) -> int:
    o_nofollow = getattr(os, "O_NOFOLLOW", 0)
    o_directory = getattr(os, "O_DIRECTORY", 0)
    dir_fd = os.open(str(root), os.O_RDONLY | o_directory | o_nofollow)
    try:
        for seg in parts[:-1]:
            next_fd = os.open(seg, os.O_RDONLY | o_directory | o_nofollow, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = next_fd
        file_fd = os.open(parts[-1], os.O_RDONLY | o_nofollow, dir_fd=dir_fd)
        return file_fd
    finally:
        try:
            os.close(dir_fd)
        except OSError:
            pass


def _open_nofollow_windows(target: Path) -> int:
    handle = _kernel32.CreateFileW(
        str(target),
        _GENERIC_READ,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        err = ctypes.get_last_error()
        raise PathSecurityError(f"Failed to open path safely (winerror={err}).")

    info = _BY_HANDLE_FILE_INFORMATION()
    if not _kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
        err = ctypes.get_last_error()
        _kernel32.CloseHandle(handle)
        raise PathSecurityError(f"Failed to inspect opened handle (winerror={err}).")

    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
        _kernel32.CloseHandle(handle)
        raise PathSecurityError("Opened target is a Windows reparse point/symlink.")
    if info.dwFileAttributes & _FILE_ATTRIBUTE_DIRECTORY:
        _kernel32.CloseHandle(handle)
        raise PathSecurityError("Target is a directory, not a regular file.")

    try:
        return msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except OSError as exc:
        _kernel32.CloseHandle(handle)
        raise PathSecurityError(f"Failed to bind OS file descriptor: {exc}") from exc


def safe_open_read(
    workspace_root: str | Path,
    rel_path: str | Path,
    *,
    max_bytes: int | None = None,
) -> BinaryIO:
    """Open ``rel_path`` inside ``workspace_root`` for reading without following symlinks.

    Raises ``PathSecurityError`` on traversal, symlinks/reparse points, or non-regular files.
    Raises ``BoundsExceededError`` if ``max_bytes`` is provided and file size exceeds it.
    """
    if max_bytes is not None and max_bytes < 0:
        raise ValueError("max_bytes must be non-negative.")

    root = _validate_workspace_root(workspace_root)
    parts = _validate_rel_parts(rel_path)
    target = _walk_existing_segments(root, parts, check_leaf=True)

    if sys.platform == "win32":
        fd = _open_nofollow_windows(target)
    elif os.open in getattr(os, "supports_dir_fd", set()) and hasattr(os, "O_NOFOLLOW"):
        try:
            fd = _open_nofollow_posix(root, parts)
        except OSError as exc:
            raise PathSecurityError(f"Race-safe open refused path: {exc}") from exc
    else:
        raise PathSecurityError("Platform lacks race-safe O_NOFOLLOW directory traversal.")

    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode):
            raise PathSecurityError("Target is not a regular file.")
        if _is_reparse_or_symlink(fst):
            raise PathSecurityError("Target file descriptor refers to a symlink/reparse point.")
        lst = os.lstat(target)
        if _is_reparse_or_symlink(lst) or (fst.st_dev, fst.st_ino) != (lst.st_dev, lst.st_ino):
            raise PathSecurityError("Target changed concurrently or is a symlink.")
        if max_bytes is not None and fst.st_size > max_bytes:
            raise BoundsExceededError(
                f"File size ({fst.st_size} bytes) exceeds max_bytes ({max_bytes}).",
                details={"size_bytes": fst.st_size, "max_bytes": max_bytes},
            )
        return os.fdopen(fd, "rb")
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def safe_read_bounded(
    workspace_root: str | Path,
    rel_path: str | Path,
    *,
    max_bytes: int,
    allow_truncate: bool = False,
) -> BoundedReadResult:
    """Safely read up to ``max_bytes`` bytes from ``rel_path`` within ``workspace_root``.

    Reads at most ``max_bytes + 1`` bytes from the validated descriptor so concurrent
    file growth cannot bypass the limit. When ``allow_truncate=False`` (default),
    exceeding ``max_bytes`` raises ``BoundsExceededError``.
    """
    if max_bytes < 0:
        raise ValueError("max_bytes must be non-negative.")

    precheck_limit = None if allow_truncate else max_bytes
    with safe_open_read(workspace_root, rel_path, max_bytes=precheck_limit) as stream:
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = stream.read(min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)

    if len(raw) > max_bytes:
        if not allow_truncate:
            raise BoundsExceededError(
                f"Stream read exceeded max_bytes ({max_bytes}).",
                details={"max_bytes": max_bytes},
            )
        bounded = raw[:max_bytes]
        return BoundedReadResult(data=bounded, truncated=True, bytes_read=len(bounded))

    return BoundedReadResult(data=raw, truncated=False, bytes_read=len(raw))


def safe_write_atomic(
    workspace_root: str | Path,
    rel_path: str | Path,
    data: bytes,
    *,
    max_bytes: int | None = None,
    overwrite: bool = False,
    create_parents: bool = True,
) -> Path:
    """Atomically write ``data`` to ``rel_path`` inside ``workspace_root``.

    Rejects symlinks/reparse points along any ancestor or existing target,
    writes via a sibling temporary file + ``os.fsync`` + ``os.replace``,
    and checks ``max_bytes`` before writing.
    """
    if max_bytes is not None and len(data) > max_bytes:
        raise BoundsExceededError(
            f"Write payload ({len(data)} bytes) exceeds max_bytes ({max_bytes}).",
            details={"size_bytes": len(data), "max_bytes": max_bytes},
        )

    root = _validate_workspace_root(workspace_root)
    parts = _validate_rel_parts(rel_path)

    parent = root
    for seg in parts[:-1]:
        parent = parent / seg
        try:
            st = os.lstat(parent)
        except FileNotFoundError:
            if not create_parents:
                raise PathSecurityError(f"Parent directory {seg!r} does not exist.")
            try:
                os.mkdir(parent, 0o750)
            except FileExistsError:
                pass
            st = os.lstat(parent)
        except OSError as exc:
            raise PathSecurityError(f"Parent directory check failed: {exc}") from exc

        if _is_reparse_or_symlink(st):
            raise PathSecurityError(f"Parent component {seg!r} is a symlink or reparse point.")
        if not stat.S_ISDIR(st.st_mode):
            raise PathSecurityError(f"Parent component {seg!r} is not a directory.")

    target = parent / parts[-1]
    try:
        existing = os.lstat(target)
    except FileNotFoundError:
        existing = None
    except OSError as exc:
        raise PathSecurityError(f"Target inspection failed: {exc}") from exc

    if existing is not None:
        if _is_reparse_or_symlink(existing):
            raise PathSecurityError("Existing target is a symlink or reparse point.")
        if stat.S_ISDIR(existing.st_mode):
            raise PathSecurityError("Target path is an existing directory.")
        if not overwrite:
            raise PathSecurityError("Target file already exists and overwrite=False.")

    fd, tmp_name = tempfile.mkstemp(prefix=".tmp_ctf_", dir=str(parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if not overwrite and target.exists():
            raise PathSecurityError("Target file appeared concurrently while overwrite=False.")
        os.replace(tmp_path, target)
    except BaseException:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    return target


__all__ = [
    "BoundedReadResult",
    "safe_open_read",
    "safe_read_bounded",
    "safe_write_atomic",
]
