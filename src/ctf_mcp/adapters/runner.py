"""Sole external subprocess execution boundary (docs/11 & CTF-05 / CTF-07).

All external subprocess execution MUST go through this module:
- Strictly enforces ``shell=False``, explicit ``argv`` sequence (never string),
  minimal sanitized environment variables, and ``stdin=DEVNULL``.
- Performs pre-buffering bounded pipe capture via non-blocking chunk reads so
  oversized output immediately stops the producer and records
  ``capture_complete=False`` with an explicit ``omission_reason`` (CTF-05).
- Terminates the entire descendant process tree (Win32 Job Object on Windows;
  new session + ``os.killpg`` on POSIX) and explicitly verifies termination;
  returns ``cleanup_confirmed=False`` whenever termination cannot be confirmed
  (CTF-07).
"""

from __future__ import annotations

import asyncio
import ctypes
import os
import signal
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from pydantic import Field, model_validator

from ctf_mcp.contracts import ContractViolationError, PathSecurityError, StrictModel

DEFAULT_TIMEOUT_SECONDS = 60.0
DEFAULT_MAX_OUTPUT_BYTES = 65_536
DEFAULT_CLEANUP_CONFIRM_TIMEOUT_SECONDS = 3.0
_PIPE_READ_CHUNK_BYTES = 4096

_FORBIDDEN_ENV_PREFIXES: tuple[str, ...] = (
    "CTF_MCP_",
    "AWS_",
    "OPENAI_",
    "ANTHROPIC_",
    "GOOGLE_",
    "AZURE_",
    "GITHUB_",
)
_FORBIDDEN_ENV_SUBSTRINGS: tuple[str, ...] = (
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "PRIVATE_KEY",
    "API_KEY",
    "HMAC",
)


class SubprocessOutcome(StrEnum):
    """Execution outcome category before mapping into ResultEnvelope."""

    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    OUTPUT_LIMIT_EXCEEDED = "output_limit_exceeded"


class SubprocessResult(StrictModel):
    """Structured result from bounded subprocess execution and cleanup verification."""

    outcome: SubprocessOutcome
    returncode: int | None = None
    stdout: bytes = b""
    stderr: bytes = b""
    wall_ms: int = Field(ge=0)
    output_bytes: int = Field(ge=0)
    bytes_observed: int = Field(ge=0)
    capture_complete: bool
    omission_reason: str | None = None
    cleanup_confirmed: bool
    unconfirmed_pids: tuple[int, ...] = ()
    cleanup_detail: str | None = None
    root_pid: int | None = None
    observed_pids: tuple[int, ...] = ()
    peak_rss_bytes: int | None = Field(default=None, ge=0)
    cpu_ms: int | None = Field(default=None, ge=0)
    os_pid: int | None = Field(default=None, ge=1)
    process_start_id: str | None = None

    @model_validator(mode="after")
    def _validate_capture_invariants(self) -> SubprocessResult:
        if not self.capture_complete and (
            not self.omission_reason or not self.omission_reason.strip()
        ):
            raise ValueError(
                "Incomplete capture (capture_complete=False) requires omission_reason."
            )
        if self.capture_complete and self.omission_reason is not None:
            raise ValueError("Complete capture must set omission_reason=None.")
        actual = len(self.stdout) + len(self.stderr)
        if actual != self.output_bytes:
            raise ValueError(
                f"output_bytes ({self.output_bytes}) must equal len(stdout)+len(stderr) ({actual})."
            )
        return self


def _is_forbidden_env_key(key: str) -> bool:
    upper = key.strip().upper()
    if any(upper.startswith(prefix) for prefix in _FORBIDDEN_ENV_PREFIXES):
        return True
    return any(sub in upper for sub in _FORBIDDEN_ENV_SUBSTRINGS)


def build_minimal_env(extra_env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Construct a minimal, secret-free environment dictionary for child processes."""
    env: dict[str, str] = {
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUTF8": "1",
        "PYTHONIOENCODING": "utf-8",
    }
    if sys.platform == "win32":
        env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", r"C:\Windows")
        env["WINDIR"] = os.environ.get("WINDIR", env["SYSTEMROOT"])
    else:
        env["PATH"] = "/usr/bin:/bin"
        env["LC_ALL"] = "C.UTF-8"
        env["LANG"] = "C.UTF-8"

    if extra_env is not None:
        for raw_key, raw_val in extra_env.items():
            if not isinstance(raw_key, str) or not isinstance(raw_val, str):
                raise ContractViolationError("Environment entries must be strings.")
            if "\x00" in raw_key or "\x00" in raw_val or "=" in raw_key or not raw_key.strip():
                raise ContractViolationError(f"Invalid environment variable key {raw_key!r}.")
            if _is_forbidden_env_key(raw_key):
                raise ContractViolationError(
                    f"Environment variable {raw_key!r} is forbidden in minimal subprocess env."
                )
            env[raw_key] = raw_val
    return env


def _validate_argv(argv: Sequence[str]) -> list[str]:
    if isinstance(argv, (str, bytes)):
        raise ContractViolationError(
            "Subprocess argv must be an explicit sequence of strings, never a command string."
        )
    items = list(argv)
    if not items:
        raise ContractViolationError("Subprocess argv must not be empty.")
    validated: list[str] = []
    for item in items:
        if not isinstance(item, str) or not item:
            raise ContractViolationError("Every argv element must be a non-empty string.")
        if "\x00" in item:
            raise ContractViolationError("Null byte is forbidden in subprocess argv.")
        validated.append(item)
    return validated


def _validate_cwd(cwd: str | Path | None) -> str | None:
    if cwd is None:
        return None
    path = Path(cwd)
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise PathSecurityError(f"Subprocess cwd is inaccessible: {exc}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise PathSecurityError("Subprocess cwd cannot be a symlink.")
    attrs = getattr(st, "st_file_attributes", 0)
    if attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
        raise PathSecurityError("Subprocess cwd cannot be a Windows reparse point.")
    if not stat.S_ISDIR(st.st_mode):
        raise PathSecurityError("Subprocess cwd must be a directory.")
    return str(path)


class ProcessTreeGuard(Protocol):
    """Platform-specific process tree attachment, termination, and confirmation."""

    def popen_kwargs(self) -> dict[str, Any]: ...

    def attach(self, proc: subprocess.Popen[bytes]) -> bool: ...

    def collect_pids(self, root_pid: int) -> tuple[int, ...]: ...

    def active_descendants_remain(self, root_pid: int) -> bool: ...

    def terminate_tree(self) -> bool: ...

    def confirm_terminated(
        self,
        proc: subprocess.Popen[bytes],
        observed_pids: tuple[int, ...],
        *,
        timeout_seconds: float,
    ) -> tuple[bool, tuple[int, ...], str | None]: ...

    def close(self) -> None: ...


# ---------------------------------------------------------------------------
# Win32 Job Object Implementation
# ---------------------------------------------------------------------------

if sys.platform == "win32":
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    _JOB_OBJECT_BASIC_ACCOUNTING_INFO = 1
    _JOB_OBJECT_BASIC_PROCESS_ID_LIST = 3
    _JOB_OBJECT_EXTENDED_LIMIT_INFO = 9
    _PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    _SYNCHRONIZE = 0x00100000
    _WAIT_TIMEOUT = 0x00000102
    _STILL_ACTIVE = 259
    _ERROR_ACCESS_DENIED = 5
    _ERROR_INVALID_PARAMETER = 87

    class _PROCESS_MEMORY_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_uint64),
            ("WriteOperationCount", ctypes.c_uint64),
            ("OtherOperationCount", ctypes.c_uint64),
            ("ReadTransferCount", ctypes.c_uint64),
            ("WriteTransferCount", ctypes.c_uint64),
            ("OtherTransferCount", ctypes.c_uint64),
        ]

    class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", _IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    class _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("TotalUserTime", ctypes.c_int64),
            ("TotalKernelTime", ctypes.c_int64),
            ("ThisPeriodTotalUserTime", ctypes.c_int64),
            ("ThisPeriodTotalKernelTime", ctypes.c_int64),
            ("TotalPageFaultCount", wintypes.DWORD),
            ("TotalProcesses", wintypes.DWORD),
            ("ActiveProcesses", wintypes.DWORD),
            ("TotalTerminatedProcesses", wintypes.DWORD),
        ]

    class _JOBOBJECT_BASIC_PROCESS_ID_LIST(ctypes.Structure):
        _fields_ = [
            ("NumberOfAssignedProcesses", wintypes.DWORD),
            ("NumberOfProcessIdsInList", wintypes.DWORD),
            ("ProcessIdList", ctypes.c_size_t * 256),
        ]

    _k32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    _k32.CreateJobObjectW.restype = wintypes.HANDLE
    _k32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _k32.SetInformationJobObject.restype = wintypes.BOOL
    _k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _k32.AssignProcessToJobObject.restype = wintypes.BOOL
    _k32.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _k32.QueryInformationJobObject.restype = wintypes.BOOL
    _k32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _k32.TerminateJobObject.restype = wintypes.BOOL
    _k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _k32.OpenProcess.restype = wintypes.HANDLE
    _k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    _k32.GetExitCodeProcess.restype = wintypes.BOOL
    _k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _k32.WaitForSingleObject.restype = wintypes.DWORD
    _k32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    _k32.GetProcessTimes.restype = wintypes.BOOL
    _HAS_K32_MEMINFO = hasattr(_k32, "K32GetProcessMemoryInfo")
    if _HAS_K32_MEMINFO:
        _k32.K32GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_PROCESS_MEMORY_COUNTERS),
            wintypes.DWORD,
        ]
        _k32.K32GetProcessMemoryInfo.restype = wintypes.BOOL
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.CloseHandle.restype = wintypes.BOOL

    def _filetime_to_int(ft: wintypes.FILETIME) -> int:
        return (int(ft.dwHighDateTime) << 32) | int(ft.dwLowDateTime)

    def _query_process_times_from_handle(handle: int) -> tuple[int, int] | None:
        creation = wintypes.FILETIME()
        exit_ft = wintypes.FILETIME()
        kernel = wintypes.FILETIME()
        user = wintypes.FILETIME()
        ok = _k32.GetProcessTimes(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_ft),
            ctypes.byref(kernel),
            ctypes.byref(user),
        )
        if not ok:
            return None
        creation_int = _filetime_to_int(creation)
        total_100ns = _filetime_to_int(kernel) + _filetime_to_int(user)
        cpu_ms = max(0, total_100ns // 10_000)
        return creation_int, cpu_ms

    def _query_win32_process_peak_rss(handle: int) -> int | None:
        if not _HAS_K32_MEMINFO:
            return None
        pmc = _PROCESS_MEMORY_COUNTERS()
        pmc.cb = ctypes.sizeof(pmc)
        if not _k32.K32GetProcessMemoryInfo(handle, ctypes.byref(pmc), pmc.cb):
            return None
        peak = int(pmc.PeakWorkingSetSize)
        return peak if peak > 0 else None


class _WindowsProcessTreeGuard:
    """Win32 Job Object process-tree controller with active termination verification."""

    def __init__(self) -> None:
        self._job_handle: int | None = None
        self._attached: bool = False
        self._attach_error: int | None = None
        handle = _k32.CreateJobObjectW(None, None)
        if not handle:
            self._attach_error = ctypes.get_last_error()
            return
        ext = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        ext.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not _k32.SetInformationJobObject(
            handle,
            _JOB_OBJECT_EXTENDED_LIMIT_INFO,
            ctypes.byref(ext),
            ctypes.sizeof(ext),
        ):
            self._attach_error = ctypes.get_last_error()
            _k32.CloseHandle(handle)
            return
        self._job_handle = int(handle)

    def popen_kwargs(self) -> dict[str, Any]:
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}

    def attach(self, proc: subprocess.Popen[bytes]) -> bool:
        if self._job_handle is None:
            return False
        proc_handle = int(getattr(proc, "_handle", 0) or 0)
        if not proc_handle:
            return False
        ok = bool(_k32.AssignProcessToJobObject(self._job_handle, proc_handle))
        if not ok:
            self._attach_error = ctypes.get_last_error()
            self._attached = False
            return False
        self._attached = True
        return True

    def _query_job_pids(self) -> tuple[int, ...] | None:
        if self._job_handle is None or not self._attached:
            return None
        pid_list = _JOBOBJECT_BASIC_PROCESS_ID_LIST()
        ok = _k32.QueryInformationJobObject(
            self._job_handle,
            _JOB_OBJECT_BASIC_PROCESS_ID_LIST,
            ctypes.byref(pid_list),
            ctypes.sizeof(pid_list),
            None,
        )
        if not ok:
            return None
        count = min(int(pid_list.NumberOfProcessIdsInList), 256)
        return tuple(int(pid_list.ProcessIdList[i]) for i in range(count))

    def _query_active_count(self) -> int | None:
        if self._job_handle is None or not self._attached:
            return None
        acct = _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION()
        ok = _k32.QueryInformationJobObject(
            self._job_handle,
            _JOB_OBJECT_BASIC_ACCOUNTING_INFO,
            ctypes.byref(acct),
            ctypes.sizeof(acct),
            None,
        )
        if not ok:
            return None
        return int(acct.ActiveProcesses)

    def _is_pid_alive(self, pid: int) -> bool | None:
        """Return True if alive, False if confirmed exited, None if unconfirmable."""
        handle = _k32.OpenProcess(
            _PROCESS_QUERY_LIMITED_INFORMATION | _SYNCHRONIZE, False, pid
        )
        if not handle:
            err = ctypes.get_last_error()
            if err == _ERROR_INVALID_PARAMETER:
                return False
            if err == _ERROR_ACCESS_DENIED:
                return None
            return None
        try:
            exit_code = wintypes.DWORD()
            if not _k32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return None
            if int(exit_code.value) == _STILL_ACTIVE:
                return True
            return False
        finally:
            _k32.CloseHandle(handle)

    def collect_pids(self, root_pid: int) -> tuple[int, ...]:
        pids = self._query_job_pids()
        if pids is None:
            return (root_pid,)
        merged = list(dict.fromkeys([root_pid, *pids]))
        return tuple(merged)

    def active_descendants_remain(self, root_pid: int) -> bool:
        if not self._attached:
            # Cannot verify absence of descendants without an attached Job Object.
            return True
        active = self._query_active_count()
        if active is None:
            return True
        if active > 0:
            return True
        pids = self._query_job_pids()
        if pids is None or len(pids) > 0:
            return True
        return False

    def terminate_tree(self) -> bool:
        if self._job_handle is None or not self._attached:
            return False
        return bool(_k32.TerminateJobObject(self._job_handle, 1))

    def confirm_terminated(
        self,
        proc: subprocess.Popen[bytes],
        observed_pids: tuple[int, ...],
        *,
        timeout_seconds: float,
    ) -> tuple[bool, tuple[int, ...], str | None]:
        if not self._attached or self._job_handle is None:
            pid_state = self._is_pid_alive(proc.pid)
            unconfirmed = tuple(
                p for p in dict.fromkeys([proc.pid, *observed_pids]) if self._is_pid_alive(p) is not False
            )
            return (
                False,
                unconfirmed or (proc.pid,),
                f"win32_job_not_attached (err={self._attach_error}, root_alive={pid_state})",
            )

        deadline = time.monotonic() + max(0.05, timeout_seconds)
        while True:
            remaining = max(0.01, min(0.2, deadline - time.monotonic()))
            if proc.poll() is None:
                try:
                    proc.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    pass

            active = self._query_active_count()
            job_pids = self._query_job_pids()
            candidate_pids = tuple(
                dict.fromkeys([proc.pid, *observed_pids, *(job_pids or ())])
            )
            unconfirmed_list: list[int] = []
            for pid in candidate_pids:
                alive = self._is_pid_alive(pid)
                if alive is not False:
                    unconfirmed_list.append(pid)

            root_exited = proc.poll() is not None
            job_empty = active == 0 and job_pids is not None and len(job_pids) == 0
            if root_exited and job_empty and not unconfirmed_list:
                return True, (), None

            if time.monotonic() >= deadline:
                if not unconfirmed_list and not job_empty:
                    unconfirmed_list = list(job_pids or (proc.pid,))
                detail = (
                    f"win32_cleanup_unconfirmed: root_exited={root_exited}, "
                    f"active_processes={active}, remaining_job_pids={job_pids}"
                )
                return False, tuple(unconfirmed_list), detail

            time.sleep(0.02)

    def query_resource_metrics(
        self, proc: subprocess.Popen[bytes] | None = None
    ) -> tuple[int | None, int | None]:
        """Return observed ``(peak_rss_bytes, cpu_ms)`` from the Win32 Job Object."""
        peak_rss_bytes: int | None = None
        cpu_ms: int | None = None

        if self._job_handle is not None and self._attached:
            ext = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            if _k32.QueryInformationJobObject(
                self._job_handle,
                _JOB_OBJECT_EXTENDED_LIMIT_INFO,
                ctypes.byref(ext),
                ctypes.sizeof(ext),
                None,
            ):
                job_peak = int(ext.PeakJobMemoryUsed) or int(ext.PeakProcessMemoryUsed)
                if job_peak > 0:
                    peak_rss_bytes = job_peak

            acct = _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION()
            if _k32.QueryInformationJobObject(
                self._job_handle,
                _JOB_OBJECT_BASIC_ACCOUNTING_INFO,
                ctypes.byref(acct),
                ctypes.sizeof(acct),
                None,
            ):
                total_100ns = int(acct.TotalUserTime) + int(acct.TotalKernelTime)
                if total_100ns >= 0:
                    cpu_ms = total_100ns // 10_000

        proc_handle = int(getattr(proc, "_handle", 0) or 0) if proc is not None else 0
        if proc_handle:
            if cpu_ms is None:
                times = _query_process_times_from_handle(proc_handle)
                if times is not None:
                    cpu_ms = times[1]
            if peak_rss_bytes is None:
                peak_rss_bytes = _query_win32_process_peak_rss(proc_handle)

        return peak_rss_bytes, cpu_ms

    def close(self) -> None:
        if self._job_handle is not None:
            _k32.CloseHandle(self._job_handle)
            self._job_handle = None
            self._attached = False


# ---------------------------------------------------------------------------
# POSIX Process Group Implementation
# ---------------------------------------------------------------------------


class _PosixProcessTreeGuard:
    """POSIX session/process-group tree terminator and verification guard."""

    def __init__(self) -> None:
        self._pgid: int | None = None
        self._peak_rss_bytes: int | None = None
        self._cpu_ms: int | None = None

    def popen_kwargs(self) -> dict[str, Any]:
        return {"start_new_session": True}

    def attach(self, proc: subprocess.Popen[bytes]) -> bool:
        self._pgid = proc.pid
        self._sample_proc_metrics(proc.pid)
        return True

    def _sample_proc_metrics(self, pid: int) -> None:
        if pid <= 0 or sys.platform == "win32":
            return
        status_path = Path(f"/proc/{pid}/status")
        if status_path.exists():
            try:
                for line in status_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if line.startswith("VmHWM:"):
                        parts = line.split()
                        if len(parts) >= 2 and parts[1].isdigit():
                            rss_bytes = int(parts[1]) * 1024
                            if self._peak_rss_bytes is None or rss_bytes > self._peak_rss_bytes:
                                self._peak_rss_bytes = rss_bytes
                        break
            except OSError:
                pass

        stat_info = _read_proc_stat_info(pid)
        if stat_info is not None:
            _, _, cpu_ticks = stat_info
            clk_tck = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
            if clk_tck > 0:
                ms = max(0, int((cpu_ticks * 1000) // clk_tck))
                if self._cpu_ms is None or ms > self._cpu_ms:
                    self._cpu_ms = ms

    def collect_pids(self, root_pid: int) -> tuple[int, ...]:
        self._sample_proc_metrics(root_pid)
        return (root_pid,)

    def _group_exists(self) -> bool | None:
        if self._pgid is None:
            return None
        try:
            os.killpg(self._pgid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return None

    def active_descendants_remain(self, root_pid: int) -> bool:
        exists = self._group_exists()
        return exists is not False

    def terminate_tree(self) -> bool:
        if self._pgid is None:
            return False
        try:
            os.killpg(self._pgid, signal.SIGTERM)
        except ProcessLookupError:
            return True
        except OSError:
            return False

        deadline = time.monotonic() + 0.25
        while time.monotonic() < deadline:
            if self._group_exists() is False:
                return True
            time.sleep(0.02)

        try:
            os.killpg(self._pgid, signal.SIGKILL)
            return True
        except ProcessLookupError:
            return True
        except OSError:
            return False

    def confirm_terminated(
        self,
        proc: subprocess.Popen[bytes],
        observed_pids: tuple[int, ...],
        *,
        timeout_seconds: float,
    ) -> tuple[bool, tuple[int, ...], str | None]:
        if self._pgid is None:
            return False, (proc.pid,), "posix_pgid_not_initialized"

        deadline = time.monotonic() + max(0.05, timeout_seconds)
        while True:
            remaining = max(0.01, min(0.2, deadline - time.monotonic()))
            if proc.poll() is None:
                try:
                    proc.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    pass

            group_alive = self._group_exists()
            unconfirmed: list[int] = []
            for pid in dict.fromkeys([proc.pid, *observed_pids]):
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    continue
                except OSError:
                    unconfirmed.append(pid)
                else:
                    unconfirmed.append(pid)

            if proc.poll() is not None and group_alive is False and not unconfirmed:
                return True, (), None

            if time.monotonic() >= deadline:
                if not unconfirmed and group_alive is not False:
                    unconfirmed = [proc.pid]
                detail = (
                    f"posix_cleanup_unconfirmed: root_exited={proc.poll() is not None}, "
                    f"group_alive={group_alive}"
                )
                return False, tuple(unconfirmed), detail

            time.sleep(0.02)

    def query_resource_metrics(
        self, proc: subprocess.Popen[bytes] | None = None
    ) -> tuple[int | None, int | None]:
        """Return observed ``(peak_rss_bytes, cpu_ms)`` from POSIX ``/proc`` samples."""
        if proc is not None:
            self._sample_proc_metrics(proc.pid)
        return self._peak_rss_bytes, self._cpu_ms

    def close(self) -> None:
        self._pgid = None


def _default_tree_guard_factory() -> ProcessTreeGuard:
    if sys.platform == "win32":
        return _WindowsProcessTreeGuard()
    return _PosixProcessTreeGuard()


def _read_proc_stat_info(pid: int) -> tuple[str, int, int] | None:
    """Parse ``(state, starttime_ticks, utime_plus_stime_ticks)`` from ``/proc/<pid>/stat``."""
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    rparen = raw.rfind(")")
    if rparen < 0:
        return None
    fields = raw[rparen + 2 :].split()
    if len(fields) <= 19:
        return None
    try:
        state = fields[0]
        utime = int(fields[11])
        stime = int(fields[12])
        starttime = int(fields[19])
    except (ValueError, IndexError):
        return None
    return state, starttime, max(0, utime + stime)


def _is_win32_handle_alive(handle: int) -> bool:
    if _k32.WaitForSingleObject(handle, 0) != _WAIT_TIMEOUT:
        return False
    exit_code = wintypes.DWORD()
    if not _k32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
        return False
    return int(exit_code.value) == _STILL_ACTIVE


def get_os_process_start_id(pid: int) -> str | None:
    """Return a deterministic ``pid:<pid>:<kind>:<start_token>`` for a live OS process."""
    if pid <= 0:
        return None
    if sys.platform == "win32":
        handle = _k32.OpenProcess(
            _PROCESS_QUERY_LIMITED_INFORMATION | _SYNCHRONIZE, False, pid
        )
        if not handle:
            return None
        try:
            if not _is_win32_handle_alive(handle):
                return None
            times = _query_process_times_from_handle(handle)
            if times is None:
                return None
            return f"pid:{pid}:win:{times[0]}"
        finally:
            _k32.CloseHandle(handle)

    stat_info = _read_proc_stat_info(pid)
    if stat_info is not None:
        state, starttime, _ = stat_info
        if state in {"Z", "X", "x"}:
            return None
        return f"pid:{pid}:proc:{starttime}"

    try:
        os.kill(pid, 0)
    except OSError:
        return None
    try:
        res = subprocess.run(
            ["ps", "-o", "stat=,lstart=", "-p", str(pid)],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            shell=False,
            timeout=2.0,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    line = res.stdout.strip()
    if not line:
        return None
    parts = line.split(None, 1)
    if len(parts) < 2 or parts[0].startswith("Z"):
        return None
    return f"pid:{pid}:lstart:{parts[1].strip()}"


def _process_start_id_for_popen(proc: subprocess.Popen[bytes]) -> str | None:
    if sys.platform == "win32":
        proc_handle = int(getattr(proc, "_handle", 0) or 0)
        if proc_handle:
            times = _query_process_times_from_handle(proc_handle)
            if times is not None:
                return f"pid:{proc.pid}:win:{times[0]}"
    return get_os_process_start_id(proc.pid)


def is_os_process_alive(process_start_id: str | None) -> bool:
    """Verify real OS process liveness and creation-timestamp match (anti-PID-reuse)."""
    if process_start_id is None or not isinstance(process_start_id, str):
        return False
    raw = process_start_id.strip()
    if not raw.startswith("pid:"):
        return False
    parts = raw.split(":", 3)
    if len(parts) != 4:
        return False
    _, pid_str, kind, start_token = parts
    if not pid_str.isdigit() or not start_token:
        return False
    pid = int(pid_str)
    if pid <= 0:
        return False

    if sys.platform == "win32":
        if kind != "win" or not start_token.isdigit():
            return False
        expected_creation = int(start_token)
        handle = _k32.OpenProcess(
            _PROCESS_QUERY_LIMITED_INFORMATION | _SYNCHRONIZE, False, pid
        )
        if not handle:
            return False
        try:
            if not _is_win32_handle_alive(handle):
                return False
            times = _query_process_times_from_handle(handle)
            if times is None:
                return False
            return times[0] == expected_creation
        finally:
            _k32.CloseHandle(handle)

    if kind == "proc":
        stat_info = _read_proc_stat_info(pid)
        if stat_info is None:
            return False
        state, starttime, _ = stat_info
        return state not in {"Z", "X", "x"} and str(starttime) == start_token

    if kind == "lstart":
        current = get_os_process_start_id(pid)
        return current == raw

    return False


# ---------------------------------------------------------------------------
# Pre-Buffering Bounded Pipe Collector
# ---------------------------------------------------------------------------


class _BoundedPipeCollector:
    """Streams stdout/stderr into bounded buffers without unbounded pre-buffering."""

    def __init__(
        self,
        *,
        max_output_bytes: int,
        on_output_chunk: Callable[[str, bytes], None] | None = None,
    ) -> None:
        self.max_output_bytes = max_output_bytes
        self._on_output_chunk = on_output_chunk
        self._lock = threading.Lock()
        self.stdout_chunks: list[bytes] = []
        self.stderr_chunks: list[bytes] = []
        self.captured_bytes = 0
        self.observed_bytes = 0
        self.limit_exceeded = False
        self.stop_event = threading.Event()

    def read_stream(self, stream_name: str, pipe: Any) -> None:
        target = self.stdout_chunks if stream_name == "stdout" else self.stderr_chunks
        try:
            fd = pipe.fileno()
        except Exception:
            return

        while not self.stop_event.is_set():
            try:
                chunk = os.read(fd, _PIPE_READ_CHUNK_BYTES)
            except OSError:
                break
            if not chunk:
                break

            if self._on_output_chunk is not None:
                try:
                    self._on_output_chunk(stream_name, chunk)
                except Exception:
                    pass

            exceeded_now = False
            with self._lock:
                self.observed_bytes += len(chunk)
                remaining = self.max_output_bytes - self.captured_bytes
                if len(chunk) > remaining:
                    if remaining > 0:
                        target.append(chunk[:remaining])
                        self.captured_bytes += remaining
                    self.limit_exceeded = True
                    exceeded_now = True
                else:
                    target.append(chunk)
                    self.captured_bytes += len(chunk)

            if exceeded_now:
                self.stop_event.set()
                break

    def snapshot(self) -> tuple[bytes, bytes, int, bool]:
        with self._lock:
            out = b"".join(self.stdout_chunks)
            err = b"".join(self.stderr_chunks)
            return out, err, self.observed_bytes, self.limit_exceeded


# ---------------------------------------------------------------------------
# Public Runner
# ---------------------------------------------------------------------------


class SubprocessRunner:
    """Bounded subprocess runner enforcing shell=False, quotas, and tree cleanup."""

    def __init__(
        self,
        *,
        default_timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        default_max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
        cleanup_confirm_timeout_seconds: float = DEFAULT_CLEANUP_CONFIRM_TIMEOUT_SECONDS,
        tree_guard_factory: Callable[[], ProcessTreeGuard] | None = None,
    ) -> None:
        if default_timeout_seconds <= 0:
            raise ContractViolationError("default_timeout_seconds must be positive.")
        if default_max_output_bytes <= 0:
            raise ContractViolationError("default_max_output_bytes must be positive.")
        if cleanup_confirm_timeout_seconds <= 0:
            raise ContractViolationError("cleanup_confirm_timeout_seconds must be positive.")

        self.default_timeout_seconds = float(default_timeout_seconds)
        self.default_max_output_bytes = int(default_max_output_bytes)
        self.cleanup_confirm_timeout_seconds = float(cleanup_confirm_timeout_seconds)
        self._tree_guard_factory = tree_guard_factory or _default_tree_guard_factory

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float | None = None,
        max_output_bytes: int | None = None,
        extra_env: Mapping[str, str] | None = None,
        cwd: str | Path | None = None,
        cancel_event: threading.Event | None = None,
        on_output_chunk: Callable[[str, bytes], None] | None = None,
    ) -> SubprocessResult:
        """Execute ``argv`` with shell=False, bounded pipes, and verified tree cleanup."""
        validated_argv = _validate_argv(argv)
        eff_timeout = (
            float(timeout_seconds)
            if timeout_seconds is not None
            else self.default_timeout_seconds
        )
        eff_max_bytes = (
            int(max_output_bytes)
            if max_output_bytes is not None
            else self.default_max_output_bytes
        )
        if eff_timeout <= 0:
            raise ContractViolationError("timeout_seconds must be positive.")
        if eff_max_bytes <= 0:
            raise ContractViolationError("max_output_bytes must be positive.")

        validated_cwd = _validate_cwd(cwd)
        minimal_env = build_minimal_env(extra_env)

        guard = self._tree_guard_factory()
        collector = _BoundedPipeCollector(
            max_output_bytes=eff_max_bytes,
            on_output_chunk=on_output_chunk,
        )

        started_mono = time.monotonic()
        deadline = started_mono + eff_timeout
        proc: subprocess.Popen[bytes] | None = None
        stdout_thread: threading.Thread | None = None
        stderr_thread: threading.Thread | None = None
        observed_pids: tuple[int, ...] = ()
        outcome: SubprocessOutcome | None = None

        try:
            try:
                proc = subprocess.Popen(
                    validated_argv,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False,
                    env=minimal_env,
                    cwd=validated_cwd,
                    **guard.popen_kwargs(),
                )
            except OSError as exc:
                wall_ms = max(0, int((time.monotonic() - started_mono) * 1000))
                return SubprocessResult(
                    outcome=SubprocessOutcome.FAILED,
                    returncode=None,
                    stdout=b"",
                    stderr=b"",
                    wall_ms=wall_ms,
                    output_bytes=0,
                    bytes_observed=0,
                    capture_complete=True,
                    omission_reason=None,
                    cleanup_confirmed=True,
                    unconfirmed_pids=(),
                    cleanup_detail=f"spawn_failed: {type(exc).__name__}: {exc}",
                    root_pid=None,
                    observed_pids=(),
                    peak_rss_bytes=None,
                    cpu_ms=None,
                    os_pid=None,
                    process_start_id=None,
                )
            os_pid = proc.pid
            process_start_id = _process_start_id_for_popen(proc)
            guard.attach(proc)
            observed_pids = guard.collect_pids(proc.pid)

            if proc.stdout is not None:
                stdout_thread = threading.Thread(
                    target=collector.read_stream,
                    args=("stdout", proc.stdout),
                    daemon=True,
                )
                stdout_thread.start()
            if proc.stderr is not None:
                stderr_thread = threading.Thread(
                    target=collector.read_stream,
                    args=("stderr", proc.stderr),
                    daemon=True,
                )
                stderr_thread.start()

            while True:
                observed_pids = tuple(
                    dict.fromkeys([*observed_pids, *guard.collect_pids(proc.pid)])
                )

                if collector.limit_exceeded:
                    outcome = SubprocessOutcome.OUTPUT_LIMIT_EXCEEDED
                    break

                if cancel_event is not None and cancel_event.is_set():
                    outcome = SubprocessOutcome.CANCELLED
                    break

                if proc.poll() is not None:
                    break

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    outcome = SubprocessOutcome.TIMEOUT
                    break

                collector.stop_event.wait(timeout=min(0.02, remaining))

            # Refresh observed PIDs right before any teardown/kill.
            observed_pids = tuple(
                dict.fromkeys([*observed_pids, *guard.collect_pids(proc.pid)])
            )

            need_kill = outcome in {
                SubprocessOutcome.TIMEOUT,
                SubprocessOutcome.CANCELLED,
                SubprocessOutcome.OUTPUT_LIMIT_EXCEEDED,
            }
            if need_kill or guard.active_descendants_remain(proc.pid):
                guard.terminate_tree()

            cleanup_confirmed, unconfirmed_pids, cleanup_detail = guard.confirm_terminated(
                proc,
                observed_pids,
                timeout_seconds=self.cleanup_confirm_timeout_seconds,
            )

            # Only join pipe threads with bounded wait; if cleanup failed and a child
            # still holds a pipe open, never deadlock waiting for EOF.
            join_timeout = 2.0 if cleanup_confirmed else 0.2
            if stdout_thread is not None:
                stdout_thread.join(timeout=join_timeout)
            if stderr_thread is not None:
                stderr_thread.join(timeout=join_timeout)

            # Avoid closing pipes if a reader thread is still blocked in os.read on Windows.
            if proc.stdout is not None and (stdout_thread is None or not stdout_thread.is_alive()):
                try:
                    proc.stdout.close()
                except OSError:
                    pass
            if proc.stderr is not None and (stderr_thread is None or not stderr_thread.is_alive()):
                try:
                    proc.stderr.close()
                except OSError:
                    pass

            stdout_bytes, stderr_bytes, total_observed, limit_exceeded = collector.snapshot()
            returncode = proc.poll()

            if outcome is None:
                if limit_exceeded:
                    outcome = SubprocessOutcome.OUTPUT_LIMIT_EXCEEDED
                elif returncode == 0:
                    outcome = SubprocessOutcome.COMPLETED
                else:
                    outcome = SubprocessOutcome.FAILED

            if outcome == SubprocessOutcome.OUTPUT_LIMIT_EXCEEDED:
                capture_complete = False
                omission_reason: str | None = (
                    f"output_bytes_limit_exceeded (limit={eff_max_bytes}, observed={total_observed})"
                )
            elif outcome == SubprocessOutcome.TIMEOUT:
                capture_complete = False
                omission_reason = f"action_timeout_exceeded (timeout_seconds={eff_timeout})"
            elif outcome == SubprocessOutcome.CANCELLED:
                capture_complete = False
                omission_reason = "action_cancelled"
            else:
                capture_complete = True
                omission_reason = None

            peak_rss_bytes: int | None = None
            cpu_ms: int | None = None
            query_metrics = getattr(guard, "query_resource_metrics", None)
            if callable(query_metrics):
                metrics = query_metrics(proc)
                if isinstance(metrics, tuple) and len(metrics) == 2:
                    peak_rss_bytes, cpu_ms = metrics

            wall_ms = max(0, int((time.monotonic() - started_mono) * 1000))
            return SubprocessResult(
                outcome=outcome,
                returncode=returncode,
                stdout=stdout_bytes,
                stderr=stderr_bytes,
                wall_ms=wall_ms,
                output_bytes=len(stdout_bytes) + len(stderr_bytes),
                bytes_observed=total_observed,
                capture_complete=capture_complete,
                omission_reason=omission_reason,
                cleanup_confirmed=cleanup_confirmed,
                unconfirmed_pids=unconfirmed_pids,
                cleanup_detail=cleanup_detail,
                root_pid=proc.pid,
                observed_pids=observed_pids,
                peak_rss_bytes=peak_rss_bytes,
                cpu_ms=cpu_ms,
                os_pid=os_pid,
                process_start_id=process_start_id,
            )
        finally:
            guard.close()

    async def run_async(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float | None = None,
        max_output_bytes: int | None = None,
        extra_env: Mapping[str, str] | None = None,
        cwd: str | Path | None = None,
        cancel_event: asyncio.Event | None = None,
        on_output_chunk: Callable[[str, bytes], None] | None = None,
    ) -> SubprocessResult:
        """Asyncio wrapper that translates task/event cancellation into tree termination."""
        thread_cancel = threading.Event()
        watcher_task: asyncio.Task[None] | None = None

        if cancel_event is not None:
            async def _watch_cancel() -> None:
                await cancel_event.wait()
                thread_cancel.set()

            watcher_task = asyncio.create_task(_watch_cancel())

        worker = asyncio.create_task(
            asyncio.to_thread(
                self.run,
                argv,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
                extra_env=extra_env,
                cwd=cwd,
                cancel_event=thread_cancel,
                on_output_chunk=on_output_chunk,
            )
        )
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            thread_cancel.set()
            await worker
            raise
        finally:
            if watcher_task is not None and not watcher_task.done():
                watcher_task.cancel()
                try:
                    await watcher_task
                except asyncio.CancelledError:
                    pass


__all__ = [
    "DEFAULT_CLEANUP_CONFIRM_TIMEOUT_SECONDS",
    "DEFAULT_MAX_OUTPUT_BYTES",
    "DEFAULT_TIMEOUT_SECONDS",
    "ProcessTreeGuard",
    "SubprocessOutcome",
    "SubprocessResult",
    "SubprocessRunner",
    "build_minimal_env",
    "get_os_process_start_id",
    "is_os_process_alive",
]
