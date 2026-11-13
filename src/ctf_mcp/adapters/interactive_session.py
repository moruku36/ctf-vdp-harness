"""Interactive debug/trace session adapter (`session.control`, P4).

Exposes ONLY typed session lifecycle operations (`open`, `inspect`, `step`,
`close`) under ``ExecutionClass.DYNAMIC``.  Never accepts raw debugger
commands, Python ``eval``/``exec`` expressions, shell strings, or arbitrary
host/guest paths.  Each invocation executes inside an isolated stdlib-only
child process via ``SubprocessRunner(shell=False)``.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import sys
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Any

MAX_ARTIFACT_INSPECT_READ_BYTES = 2 * 1024 * 1024
MAX_MEMORY_SLICE_BYTES = 4096
MAX_STEP_COUNT = 64
MAX_TRACE_ENTRIES = 64
SESSION_CONTROL_ADAPTER_ID = "ctf-interactive-session"
SESSION_CONTROL_TOOL_NAME = "session.control"
SESSION_CONTROL_COMMIT = "p4-interactive-session-1"
SESSION_CONTROL_OPERATIONS: tuple[str, ...] = ("open", "inspect", "step", "close")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SAFE_SECTION_RE = re.compile(r"^\.?[A-Za-z0-9_.-]{1,64}$")

SESSION_CONTROL_ARG_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "artifact_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
        },
        "session_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
        },
        "view": {
            "type": "string",
            "enum": ["summary", "registers", "sections", "memory", "trace"],
        },
        "section_name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "pattern": "^\\.?[A-Za-z0-9_.-]{1,64}$",
        },
        "offset": {"type": "integer", "minimum": 0, "maximum": 16_777_216},
        "length": {"type": "integer", "minimum": 1, "maximum": MAX_MEMORY_SLICE_BYTES},
        "step_count": {"type": "integer", "minimum": 1, "maximum": MAX_STEP_COUNT},
    },
    "additionalProperties": False,
}


def _configure_stdio_utf8() -> None:
    """Force UTF-8 encoding on worker stdio streams (critical on Windows)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def _ensure_safe_regular_file(path: Path, *, max_bytes: int) -> bytes:
    """Read a regular non-symlink file with bounded size verification."""
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise ValueError("path is not a regular non-symlink file")
    with open(path, "rb") as handle:
        fst = os.fstat(handle.fileno())
        if fst.st_ino != st.st_ino or fst.st_dev != st.st_dev:
            raise ValueError("file changed concurrently during open")
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"file size exceeds bound of {max_bytes} bytes")
    return data


def _read_slice_non_symlink(path: Path, *, offset: int, length: int) -> bytes:
    """Read a bounded slice from a non-symlink regular file."""
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise ValueError("artifact path is not a regular non-symlink file")
    with open(path, "rb") as handle:
        fst = os.fstat(handle.fileno())
        if fst.st_ino != st.st_ino or fst.st_dev != st.st_dev:
            raise ValueError("artifact changed concurrently during open")
        handle.seek(max(0, offset))
        return handle.read(max(1, min(length, MAX_MEMORY_SLICE_BYTES)))


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    """Write session state atomically while guarding against symlinked targets."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode):
            raise ValueError("refusing to overwrite symlinked session state file")
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    fd, tmp_name = tempfile.mkstemp(
        prefix=".sess-",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        try:
            os.write(fd, encoded)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _parse_binary_metadata(data: bytes) -> dict[str, Any]:
    """Deterministically parse ELF32/ELF64 or raw binary sections and entry point."""
    file_size = len(data)
    file_sha256 = hashlib.sha256(data).hexdigest()

    if len(data) >= 52 and data[:4] == b"\x7fELF":
        ei_class = data[4]
        ei_data = data[5]
        endian = "<" if ei_data == 1 else (">" if ei_data == 2 else None)
        if endian is not None and ei_class in (1, 2):
            try:
                sections: list[dict[str, Any]] = []
                if ei_class == 2 and len(data) >= 64:
                    e_machine = struct.unpack_from(f"{endian}H", data, 18)[0]
                    e_entry = struct.unpack_from(f"{endian}Q", data, 24)[0]
                    e_shoff = struct.unpack_from(f"{endian}Q", data, 40)[0]
                    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                        f"{endian}HHH", data, 58
                    )
                    arch = {62: "x86_64", 183: "aarch64", 3: "x86", 40: "arm"}.get(
                        e_machine, f"elf64_machine_{e_machine}"
                    )
                    sh_fmt = f"{endian}IIQQQQIIQQ"
                    raw_sections: list[tuple[int, int, int, int]] = []
                    if e_shoff and e_shentsize >= 64 and e_shnum > 0:
                        for i in range(min(e_shnum, 128)):
                            off = e_shoff + i * e_shentsize
                            if off + 64 > len(data):
                                break
                            sh_name, sh_type, _flags, sh_addr, sh_offset, sh_size, *_ = (
                                struct.unpack_from(sh_fmt, data, off)
                            )
                            raw_sections.append((sh_name, sh_addr, sh_offset, sh_size))
                    strtab = b""
                    if 0 <= e_shstrndx < len(raw_sections):
                        _, _, str_off, str_sz = raw_sections[e_shstrndx]
                        if str_off < len(data):
                            strtab = data[str_off : min(len(data), str_off + min(str_sz, 65536))]
                    for idx, (sh_name, sh_addr, sh_offset, sh_size) in enumerate(raw_sections):
                        name = f".section_{idx}"
                        if strtab and sh_name < len(strtab):
                            end = strtab.find(b"\x00", sh_name)
                            raw_name = (
                                strtab[sh_name:end] if end != -1 else strtab[sh_name:]
                            ).decode("ascii", errors="replace")
                            if raw_name:
                                name = raw_name
                        sections.append(
                            {
                                "name": name,
                                "vaddr": int(sh_addr),
                                "offset": int(sh_offset),
                                "size": int(sh_size),
                            }
                        )
                    return {
                        "format": "ELF64",
                        "arch": arch,
                        "bits": 64,
                        "entry_point": int(e_entry),
                        "file_size": file_size,
                        "file_sha256": file_sha256,
                        "sections": sections,
                    }
                if ei_class == 1 and len(data) >= 52:
                    e_machine = struct.unpack_from(f"{endian}H", data, 18)[0]
                    e_entry = struct.unpack_from(f"{endian}I", data, 24)[0]
                    e_shoff = struct.unpack_from(f"{endian}I", data, 32)[0]
                    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                        f"{endian}HHH", data, 46
                    )
                    arch = {3: "x86", 40: "arm"}.get(e_machine, f"elf32_machine_{e_machine}")
                    sh_fmt = f"{endian}IIIIIIIIII"
                    raw_sections32: list[tuple[int, int, int, int]] = []
                    if e_shoff and e_shentsize >= 40 and e_shnum > 0:
                        for i in range(min(e_shnum, 128)):
                            off = e_shoff + i * e_shentsize
                            if off + 40 > len(data):
                                break
                            sh_name, _sh_type, _flags, sh_addr, sh_offset, sh_size, *_ = (
                                struct.unpack_from(sh_fmt, data, off)
                            )
                            raw_sections32.append((sh_name, sh_addr, sh_offset, sh_size))
                    strtab32 = b""
                    if 0 <= e_shstrndx < len(raw_sections32):
                        _, _, str_off, str_sz = raw_sections32[e_shstrndx]
                        if str_off < len(data):
                            strtab32 = data[str_off : min(len(data), str_off + min(str_sz, 65536))]
                    for idx, (sh_name, sh_addr, sh_offset, sh_size) in enumerate(raw_sections32):
                        name = f".section_{idx}"
                        if strtab32 and sh_name < len(strtab32):
                            end = strtab32.find(b"\x00", sh_name)
                            raw_name = (
                                strtab32[sh_name:end] if end != -1 else strtab32[sh_name:]
                            ).decode("ascii", errors="replace")
                            if raw_name:
                                name = raw_name
                        sections.append(
                            {
                                "name": name,
                                "vaddr": int(sh_addr),
                                "offset": int(sh_offset),
                                "size": int(sh_size),
                            }
                        )
                    return {
                        "format": "ELF32",
                        "arch": arch,
                        "bits": 32,
                        "entry_point": int(e_entry),
                        "file_size": file_size,
                        "file_sha256": file_sha256,
                        "sections": sections,
                    }
            except struct.error:
                pass

    return {
        "format": "raw",
        "arch": "generic",
        "bits": 64,
        "entry_point": 0,
        "file_size": file_size,
        "file_sha256": file_sha256,
        "sections": [
            {
                "name": ".raw",
                "vaddr": 0,
                "offset": 0,
                "size": file_size,
            }
        ],
    }


def _find_entry_window(meta: dict[str, Any]) -> tuple[int, int, int]:
    """Determine `(pc, file_offset, span_end)` for stepping through artifact bytes."""
    entry = int(meta.get("entry_point", 0))
    file_size = int(meta.get("file_size", 0))
    sections = meta.get("sections", [])
    for sec in sections:
        vaddr = int(sec.get("vaddr", 0))
        off = int(sec.get("offset", 0))
        size = int(sec.get("size", 0))
        if size > 0 and vaddr <= entry < vaddr + size and off < file_size:
            rel = entry - vaddr
            return entry, off + rel, min(file_size, off + size)
    for sec in sections:
        if sec.get("name") == ".text" and int(sec.get("size", 0)) > 0:
            off = min(file_size, int(sec.get("offset", 0)))
            size = int(sec.get("size", 0))
            return int(sec.get("vaddr", off)), off, min(file_size, off + size)
    return entry, 0, file_size


def _classify_opcode(chunk: bytes) -> tuple[str, int]:
    """Produce deterministic pseudo-instruction mnemonic and stride from real bytes."""
    if not chunk:
        return "eof", 1
    b0 = chunk[0]
    if b0 == 0x90:
        return "nop", 1
    if b0 == 0xC3:
        return "ret", 1
    if b0 == 0xCC:
        return "int3", 1
    if 0x50 <= b0 <= 0x57:
        return f"push_r{b0 - 0x50}", 1
    if 0x58 <= b0 <= 0x5F:
        return f"pop_r{b0 - 0x58}", 1
    if b0 in (0xE8, 0xE9) and len(chunk) >= 5:
        return ("call_rel32" if b0 == 0xE8 else "jmp_rel32"), 5
    if b0 in (0x48, 0x4C, 0x89, 0x8B) and len(chunk) >= 3:
        return f"op_{b0:02x}", 3
    if len(chunk) >= 2:
        return f"insn_{b0:02x}", 2
    return f"byte_{b0:02x}", 1


def _handle_open(req: dict[str, Any], state_path: Path) -> dict[str, Any]:
    """Initialize a persistent session checkpoint after verifying artifact."""
    artifact_path = Path(str(req["artifact_path"]))
    data = _ensure_safe_regular_file(artifact_path, max_bytes=MAX_ARTIFACT_INSPECT_READ_BYTES)
    meta = _parse_binary_metadata(data)
    pc, file_offset, span_end = _find_entry_window(meta)
    bits = int(meta.get("bits", 64))
    sp = 0x7FFFFFFFE000 if bits == 64 else 0x7FFFE000
    entry_sample = data[file_offset : min(len(data), file_offset + 8)]
    mnemonic, stride = _classify_opcode(entry_sample)

    registers = {
        "pc": f"0x{pc:x}",
        "sp": f"0x{sp:x}",
        "bp": f"0x{sp + 0x40:x}",
        "rax": "0x0",
        "rbx": "0x0",
        "rcx": f"0x{max(0, span_end - file_offset):x}",
        "rdx": f"0x{len(meta.get('sections', [])):x}",
        "flags": "0x202",
    }
    initial_trace = {
        "step": 0,
        "pc": f"0x{pc:x}",
        "file_offset": file_offset,
        "mnemonic": mnemonic,
        "bytes_hex": binascii.hexlify(entry_sample[:stride]).decode("ascii"),
    }
    session_state = {
        "session_id": str(req["session_id"]),
        "run_id": str(req["run_id"]),
        "artifact_id": str(req["artifact_id"]),
        "state": "active",
        "format": meta["format"],
        "arch": meta["arch"],
        "bits": bits,
        "entry_point": int(meta["entry_point"]),
        "file_size": int(meta["file_size"]),
        "file_sha256": str(meta["file_sha256"]),
        "sections": meta["sections"],
        "pc": pc,
        "file_offset": file_offset,
        "span_end": span_end,
        "step_index": 0,
        "registers": registers,
        "trace": [initial_trace],
    }
    _atomic_write_json(state_path, session_state)
    return {
        "ok": True,
        "operation": "open",
        "session_id": session_state["session_id"],
        "artifact_id": session_state["artifact_id"],
        "state": "active",
        "format": session_state["format"],
        "arch": session_state["arch"],
        "entry_point": f"0x{session_state['entry_point']:x}",
        "file_size": session_state["file_size"],
        "file_sha256": session_state["file_sha256"],
        "section_count": len(session_state["sections"]),
        "registers": registers,
        "initial_trace": initial_trace,
    }


def _load_active_session(req: dict[str, Any], state_path: Path) -> dict[str, Any]:
    """Load and validate an existing active session checkpoint."""
    raw = _ensure_safe_regular_file(state_path, max_bytes=256 * 1024)
    state = json.loads(raw.decode("utf-8"))
    if not isinstance(state, dict):
        raise ValueError("corrupted session state")
    if state.get("state") != "active":
        raise ValueError(f"session is not active (state={state.get('state')!r})")
    if state.get("session_id") != req["session_id"] or state.get("run_id") != req["run_id"]:
        raise ValueError("session identity mismatch")
    return state


def _handle_inspect(req: dict[str, Any], state_path: Path) -> dict[str, Any]:
    """Read bounded registers, sections, memory, or trace for an active session."""
    state = _load_active_session(req, state_path)
    view = str(req.get("view", "summary"))
    sections = list(state.get("sections", []))
    section_name = req.get("section_name")

    result: dict[str, Any] = {
        "ok": True,
        "operation": "inspect",
        "session_id": state["session_id"],
        "artifact_id": state["artifact_id"],
        "state": state["state"],
        "view": view,
        "step_index": int(state["step_index"]),
    }
    if view == "summary":
        result["format"] = state["format"]
        result["arch"] = state["arch"]
        result["pc"] = f"0x{int(state['pc']):x}"
        result["registers"] = state["registers"]
        result["section_names"] = [s.get("name") for s in sections[:32]]
        result["recent_trace"] = state.get("trace", [])[-5:]
    elif view == "registers":
        result["pc"] = f"0x{int(state['pc']):x}"
        result["registers"] = state["registers"]
    elif view == "sections":
        if section_name is not None:
            matched = [s for s in sections if s.get("name") == section_name]
            if not matched:
                raise ValueError(f"section {section_name!r} not found")
            result["sections"] = matched
        else:
            result["sections"] = sections
    elif view == "trace":
        result["trace"] = state.get("trace", [])
    elif view == "memory":
        artifact_path = Path(str(req["artifact_path"]))
        base_offset = int(req.get("offset", 0))
        if section_name is not None:
            matched = [s for s in sections if s.get("name") == section_name]
            if not matched:
                raise ValueError(f"section {section_name!r} not found")
            base_offset += int(matched[0].get("offset", 0))
        length = min(int(req.get("length", 64)), MAX_MEMORY_SLICE_BYTES)
        mem_bytes = _read_slice_non_symlink(
            artifact_path,
            offset=base_offset,
            length=length,
        )
        result["offset"] = base_offset
        result["bytes_read"] = len(mem_bytes)
        result["bytes_hex"] = binascii.hexlify(mem_bytes).decode("ascii")
        result["bytes_base64"] = base64.b64encode(mem_bytes).decode("ascii")
    else:
        raise ValueError(f"unsupported inspect view: {view!r}")
    return result


def _handle_step(req: dict[str, Any], state_path: Path) -> dict[str, Any]:
    """Advance deterministic trace state over bounded artifact bytes."""
    state = _load_active_session(req, state_path)
    step_count = max(1, min(int(req.get("step_count", 1)), MAX_STEP_COUNT))
    artifact_path = Path(str(req["artifact_path"]))
    data = _ensure_safe_regular_file(artifact_path, max_bytes=MAX_ARTIFACT_INSPECT_READ_BYTES)

    file_size = len(data)
    prev_pc = int(state["pc"])
    pc = prev_pc
    file_offset = int(state["file_offset"])
    span_end = min(file_size, max(file_offset, int(state.get("span_end", file_size))))
    if span_end <= 0:
        span_end = file_size

    step_index = int(state["step_index"])
    registers = dict(state["registers"])
    rax_val = int(str(registers.get("rax", "0x0")), 16)
    trace = list(state.get("trace", []))
    new_steps: list[dict[str, Any]] = []

    for _ in range(step_count):
        if file_size == 0:
            chunk = b""
        else:
            if file_offset >= span_end:
                file_offset = 0
                pc = int(state.get("entry_point", 0))
            chunk = data[file_offset : min(span_end, file_offset + 8)]
        mnemonic, stride = _classify_opcode(chunk)
        step_bytes = chunk[:stride]
        step_index += 1
        for b in step_bytes:
            rax_val = ((rax_val * 131) ^ b) & 0xFFFFFFFFFFFFFFFF
        entry = {
            "step": step_index,
            "pc": f"0x{pc:x}",
            "file_offset": file_offset,
            "mnemonic": mnemonic,
            "bytes_hex": binascii.hexlify(step_bytes).decode("ascii"),
        }
        trace.append(entry)
        new_steps.append(entry)
        if file_size > 0:
            pc += stride
            file_offset += stride

    registers["pc"] = f"0x{pc:x}"
    registers["rax"] = f"0x{rax_val:x}"
    registers["rcx"] = f"0x{max(0, span_end - file_offset):x}"
    registers["flags"] = "0x246" if (rax_val & 1) == 0 else "0x202"

    state["pc"] = pc
    state["file_offset"] = file_offset
    state["step_index"] = step_index
    state["registers"] = registers
    state["trace"] = trace[-MAX_TRACE_ENTRIES:]
    _atomic_write_json(state_path, state)

    return {
        "ok": True,
        "operation": "step",
        "session_id": state["session_id"],
        "state": "active",
        "steps_executed": step_count,
        "previous_pc": f"0x{prev_pc:x}",
        "current_pc": f"0x{pc:x}",
        "step_index": step_index,
        "registers": registers,
        "steps": new_steps,
    }


def _handle_close(req: dict[str, Any], state_path: Path) -> dict[str, Any]:
    """Cleanly terminate an active session checkpoint and delete its state file."""
    final_step_index = 0
    final_pc = "0x0"
    if state_path.exists():
        st = os.lstat(state_path)
        if stat.S_ISLNK(st.st_mode):
            raise ValueError("refusing to close symlinked session state file")
        try:
            raw = _ensure_safe_regular_file(state_path, max_bytes=256 * 1024)
            state = json.loads(raw.decode("utf-8"))
            final_step_index = int(state.get("step_index", 0))
            final_pc = f"0x{int(state.get('pc', 0)):x}"
        except Exception:
            pass
        state_path.unlink(missing_ok=True)
        try:
            if state_path.parent.exists() and not any(state_path.parent.iterdir()):
                state_path.parent.rmdir()
        except OSError:
            pass

    return {
        "ok": True,
        "operation": "close",
        "session_id": str(req["session_id"]),
        "state": "closed",
        "final_step_index": final_step_index,
        "final_pc": final_pc,
    }


def _worker_main(argv: list[str] | None = None) -> int:
    """Entrypoint for the isolated ``session.control`` worker process."""
    _configure_stdio_utf8()
    parser = argparse.ArgumentParser(description="Bounded interactive session control worker")
    parser.add_argument("--request-file", required=True)
    args = parser.parse_args(argv)

    try:
        req_bytes = _ensure_safe_regular_file(Path(args.request_file), max_bytes=128 * 1024)
        req = json.loads(req_bytes.decode("utf-8"))
        if not isinstance(req, dict):
            raise ValueError("request payload must be a JSON object")

        op = str(req["operation"])
        state_path = Path(str(req["state_file"]))
        if op == "open":
            result = _handle_open(req, state_path)
        elif op == "inspect":
            result = _handle_inspect(req, state_path)
        elif op == "step":
            result = _handle_step(req, state_path)
        elif op == "close":
            result = _handle_close(req, state_path)
        else:
            raise ValueError(f"unsupported session operation: {op!r}")

        sys.stdout.write(json.dumps(result, ensure_ascii=False))
        sys.stdout.flush()
        return 0
    except Exception as exc:
        err = {"ok": False, "error_code": "session_error", "message": str(exc)}
        sys.stderr.write(json.dumps(err, ensure_ascii=False))
        sys.stderr.flush()
        return 1


if __name__ != "__main__":
    from ctf_mcp.adapters.base import (
        AdapterExecutionOutcome,
        BaseAdapter,
        build_signed_descriptor,
        validate_action_request_inputs,
    )
    from ctf_mcp.adapters.runner import SubprocessRunner
    from ctf_mcp.contracts import (
        ActionRecord,
        CapabilityDescriptor,
        CapabilityLimits,
        ContractViolationError,
        EvidenceVaultPort,
        ExecutionClass,
        RunMode,
    )

    _SCRIPT_PATH = Path(__file__).resolve()

    def get_dependency_lock_sha256() -> str:
        """Compute SHA-256 of repository pyproject.toml for descriptor pinning."""
        repo_root = Path(__file__).resolve().parents[3]
        lock_file = repo_root / "pyproject.toml"
        if lock_file.is_file():
            return hashlib.sha256(lock_file.read_bytes()).hexdigest()
        return hashlib.sha256(b"ctf-vdp-harness-stdlib-only").hexdigest()

    def create_interactive_session_descriptor(
        *,
        name: str = SESSION_CONTROL_TOOL_NAME,
        enabled: bool = True,
        adapter_commit: str = SESSION_CONTROL_COMMIT,
        profile_modes: tuple[RunMode, ...] = (
            RunMode.OFFLINE_CTF,
            RunMode.SCOPED_CTF,
        ),
        limits: CapabilityLimits | None = None,
    ) -> CapabilityDescriptor:
        """Build the signed capability descriptor for ``session.control``."""
        return build_signed_descriptor(
            name=name,
            adapter_id=SESSION_CONTROL_ADAPTER_ID,
            adapter_commit=adapter_commit,
            dependency_lock_sha256=get_dependency_lock_sha256(),
            operations=SESSION_CONTROL_OPERATIONS,
            arg_schema=SESSION_CONTROL_ARG_SCHEMA,
            execution_classes=(ExecutionClass.DYNAMIC,),
            required_scope={"modes": [mode.value for mode in profile_modes]},
            limits=limits
            or CapabilityLimits(
                timeout_seconds=60,
                max_output_bytes=65_536,
                max_decode_bytes=16_384,
            ),
            enabled=enabled,
            profile_modes=profile_modes,
        )

    class InteractiveDebugSessionAdapter(BaseAdapter):
        """Typed dynamic session adapter (`session.control`, P4)."""

        def __init__(
            self,
            descriptor: CapabilityDescriptor | None = None,
            *,
            runner: SubprocessRunner | None = None,
            evidence_vault: EvidenceVaultPort | None = None,
            session_root: str | Path | None = None,
            worker_script: Path | None = None,
        ) -> None:
            resolved = descriptor or create_interactive_session_descriptor()
            super().__init__(resolved, runner=runner, evidence_vault=evidence_vault)
            self._worker_script = (worker_script or _SCRIPT_PATH).resolve()
            self._owns_temp_session_root = session_root is None
            if session_root is None:
                self._session_root = Path(tempfile.mkdtemp(prefix="ctf-sessions-")).resolve()
            else:
                self._session_root = Path(session_root).resolve()
                self._session_root.mkdir(parents=True, exist_ok=True)
            self._lock = threading.Lock()
            self._bound_sessions: dict[str, str] = {}
            self._pending_request_files: dict[str, Path] = {}

        @property
        def session_root(self) -> Path:
            """Return the root directory storing ephemeral session checkpoints."""
            return self._session_root

        def bind_action_session(self, action_id: str, session_id: str) -> None:
            """Bind a controller-allocated session ID for an in-flight action."""
            with self._lock:
                self._bound_sessions[action_id] = session_id

        def clear_action_session(self, action_id: str) -> None:
            """Remove any temporary session binding for ``action_id``."""
            with self._lock:
                self._bound_sessions.pop(action_id, None)

        def cleanup_session_files(
            self,
            session_ids: list[str] | tuple[str, ...],
            *,
            run_id: str | None = None,
        ) -> None:
            """Remove persisted session state files for expired, closed, or lost leases."""
            if not session_ids:
                return
            for sid in session_ids:
                if not _SAFE_ID_RE.match(sid):
                    continue
                if run_id is not None and _SAFE_ID_RE.match(run_id):
                    candidate = self._session_root / run_id / f"{sid}.json"
                    if candidate.exists() and not candidate.is_symlink():
                        candidate.unlink(missing_ok=True)
                else:
                    for run_dir in self._session_root.iterdir():
                        if run_dir.is_dir() and not run_dir.is_symlink():
                            candidate = run_dir / f"{sid}.json"
                            if candidate.exists() and not candidate.is_symlink():
                                candidate.unlink(missing_ok=True)

        def _state_file_path(self, run_id: str, session_id: str) -> Path:
            if not _SAFE_ID_RE.match(run_id):
                raise ContractViolationError(
                    f"Unsafe run_id {run_id!r}",
                    code="invalid_run_id",
                )
            if not _SAFE_ID_RE.match(session_id):
                raise ContractViolationError(
                    f"Unsafe session_id {session_id!r}",
                    code="invalid_session_id",
                )
            run_dir = (self._session_root / run_id).resolve()
            if self._session_root not in run_dir.parents:
                raise ContractViolationError("Session directory escapes root", code="path_security")
            run_dir.mkdir(parents=True, exist_ok=True)
            return run_dir / f"{session_id}.json"

        def _prepare_request_payload(
            self,
            action: ActionRecord,
            *,
            artifact_paths: dict[str, Path],
        ) -> dict[str, Any]:
            validate_action_request_inputs(self._descriptor, action)
            op = action.operation
            args = dict(action.sanitized_args)

            if op == "open":
                if "session_id" in args:
                    raise ContractViolationError(
                        "session.control 'open' allocates a new session and must not receive session_id",
                        code="invalid_session_arguments",
                    )
                for forbidden in ("view", "section_name", "offset", "length", "step_count"):
                    if forbidden in args:
                        raise ContractViolationError(
                            f"Argument {forbidden!r} is not valid for operation 'open'",
                            code="invalid_session_arguments",
                        )
                artifact_id = args.get("artifact_id")
                if not isinstance(artifact_id, str) or not artifact_id:
                    raise ContractViolationError(
                        "session.control 'open' requires 'artifact_id'",
                        code="missing_artifact_id",
                    )
                artifact_path = artifact_paths.get(artifact_id)
                if artifact_path is None:
                    raise ContractViolationError(
                        f"Unknown artifact_id {artifact_id!r}",
                        code="artifact_not_found",
                    )
                with self._lock:
                    session_id = self._bound_sessions.get(action.action_id)
                if not session_id:
                    session_id = f"sess-{uuid.uuid4().hex[:16]}"
                state_file = self._state_file_path(action.run_id, session_id)
                return {
                    "operation": "open",
                    "run_id": action.run_id,
                    "session_id": session_id,
                    "artifact_id": artifact_id,
                    "artifact_path": str(artifact_path),
                    "state_file": str(state_file),
                }

            session_id_arg = args.get("session_id")
            if not isinstance(session_id_arg, str) or not _SAFE_ID_RE.match(session_id_arg):
                raise ContractViolationError(
                    f"session.control {op!r} requires a valid 'session_id'",
                    code="missing_session_id",
                )
            state_file = self._state_file_path(action.run_id, session_id_arg)

            if op == "inspect":
                if "step_count" in args:
                    raise ContractViolationError(
                        "Argument 'step_count' is not valid for operation 'inspect'",
                        code="invalid_session_arguments",
                    )
                view = str(args.get("view", "summary"))
                payload: dict[str, Any] = {
                    "operation": "inspect",
                    "run_id": action.run_id,
                    "session_id": session_id_arg,
                    "state_file": str(state_file),
                    "view": view,
                }
                if "section_name" in args:
                    sec = str(args["section_name"])
                    if not _SAFE_SECTION_RE.match(sec):
                        raise ContractViolationError(
                            f"Invalid section_name {sec!r}",
                            code="invalid_session_arguments",
                        )
                    payload["section_name"] = sec
                if "offset" in args:
                    payload["offset"] = int(args["offset"])
                if "length" in args:
                    payload["length"] = int(args["length"])
                if view == "memory":
                    resolved_path = self._resolve_session_artifact_path(
                        args,
                        artifact_paths=artifact_paths,
                    )
                    if resolved_path is None:
                        raise ContractViolationError(
                            "inspect(view='memory') requires an active artifact path",
                            code="artifact_not_found",
                        )
                    payload["artifact_path"] = str(resolved_path)
                return payload

            if op == "step":
                for forbidden in ("view", "section_name", "offset", "length"):
                    if forbidden in args:
                        raise ContractViolationError(
                            f"Argument {forbidden!r} is not valid for operation 'step'",
                            code="invalid_session_arguments",
                        )
                resolved_path = self._resolve_session_artifact_path(
                    args,
                    artifact_paths=artifact_paths,
                )
                if resolved_path is None:
                    raise ContractViolationError(
                        "session.control 'step' requires an active artifact path",
                        code="artifact_not_found",
                    )
                return {
                    "operation": "step",
                    "run_id": action.run_id,
                    "session_id": session_id_arg,
                    "artifact_path": str(resolved_path),
                    "state_file": str(state_file),
                    "step_count": int(args.get("step_count", 1)),
                }

            if op == "close":
                for forbidden in ("view", "section_name", "offset", "length", "step_count"):
                    if forbidden in args:
                        raise ContractViolationError(
                            f"Argument {forbidden!r} is not valid for operation 'close'",
                            code="invalid_session_arguments",
                        )
                return {
                    "operation": "close",
                    "run_id": action.run_id,
                    "session_id": session_id_arg,
                    "state_file": str(state_file),
                }

            raise ContractViolationError(
                f"Unsupported session.control operation {op!r}",
                code="invalid_operation",
            )

        @staticmethod
        def _resolve_session_artifact_path(
            args: dict[str, Any],
            *,
            artifact_paths: dict[str, Path],
        ) -> Path | None:
            artifact_id = args.get("artifact_id")
            if isinstance(artifact_id, str) and artifact_id:
                return artifact_paths.get(artifact_id)
            if len(artifact_paths) == 1:
                return next(iter(artifact_paths.values()))
            return None

        def execute_with_capture(
            self,
            action: ActionRecord,
            *,
            artifact_paths: dict[str, Path] | None = None,
            cancel_event: threading.Event | None = None,
        ) -> AdapterExecutionOutcome:
            resolved_artifacts = artifact_paths or {}
            payload = self._prepare_request_payload(action, artifact_paths=resolved_artifacts)
            with tempfile.TemporaryDirectory(prefix="ctf-sess-req-") as tmp_dir:
                req_file = Path(tmp_dir) / "session_request.json"
                req_file.write_text(
                    json.dumps(payload, ensure_ascii=False),
                    encoding="utf-8",
                )
                with self._lock:
                    self._pending_request_files[action.action_id] = req_file
                try:
                    return super().execute_with_capture(
                        action,
                        artifact_paths=resolved_artifacts,
                        cancel_event=cancel_event,
                    )
                finally:
                    with self._lock:
                        self._pending_request_files.pop(action.action_id, None)
                        self._bound_sessions.pop(action.action_id, None)

        def _build_invocation(
            self,
            action: ActionRecord,
            *,
            artifact_paths: dict[str, Path],
        ) -> tuple[list[str], dict[str, str] | None, Path | None]:
            with self._lock:
                req_file = self._pending_request_files.get(action.action_id)
            if req_file is None:
                raise ContractViolationError(
                    "session.control must be invoked via execute_with_capture",
                    code="invalid_invocation_state",
                )
            argv = [
                sys.executable,
                str(self._worker_script),
                "--request-file",
                str(req_file),
            ]
            return argv, None, None

        def _summarize_result(self, action: ActionRecord, sub_res: Any) -> str:
            if sub_res.returncode != 0:
                err_text = sub_res.stderr.decode("utf-8", errors="replace").strip()
                try:
                    err_obj = json.loads(err_text)
                    return (
                        f"session.control {action.operation} failed: "
                        f"{err_obj.get('message', err_text)[:180]}"
                    )
                except Exception:
                    return (
                        f"session.control {action.operation} failed "
                        f"(outcome={getattr(sub_res.outcome, 'value', sub_res.outcome)}, "
                        f"returncode={sub_res.returncode}): {err_text[:180]}"
                    )
            try:
                parsed = json.loads(sub_res.stdout.decode("utf-8", errors="strict"))
                sid = parsed.get("session_id", "")
                state = parsed.get("state", "")
                if action.operation == "open":
                    return (
                        f"session.control open succeeded: session_id={sid}, "
                        f"format={parsed.get('format')}, entry={parsed.get('entry_point')}, "
                        f"state={state}."
                    )
                if action.operation == "step":
                    return (
                        f"session.control step succeeded: session_id={sid}, "
                        f"step_index={parsed.get('step_index')}, "
                        f"pc={parsed.get('previous_pc')}->{parsed.get('current_pc')}."
                    )
                if action.operation == "close":
                    return (
                        f"session.control close succeeded: session_id={sid}, "
                        f"final_step={parsed.get('final_step_index')}, state={state}."
                    )
                return (
                    f"session.control inspect({parsed.get('view')}) succeeded: "
                    f"session_id={sid}, step_index={parsed.get('step_index')}."
                )
            except Exception:
                return f"session.control {action.operation} completed ({len(sub_res.stdout)}B captured)."

        def close(self) -> None:
            """Clean up auto-created temporary session root if owned by this adapter."""
            if self._owns_temp_session_root and self._session_root.exists():
                shutil.rmtree(self._session_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(_worker_main())
