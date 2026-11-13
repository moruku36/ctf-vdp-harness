"""Deterministic data transform adapter (`helper.transform`, P4).

Runs all payload decoding, encoding, XOR, Caesar rotation, URL decoding, and
bounded zlib decompression inside an isolated stdlib-only child process via
``SubprocessRunner(shell=False)`` with strict input/output bounds and
protection against zlib bombs.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import stat
import sys
import tempfile
import threading
import urllib.parse
import zlib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

MAX_TRANSFORM_INPUT_BYTES = 64 * 1024
MAX_TRANSFORM_DECODE_BYTES = 64 * 1024
MAX_TRANSFORM_ENCODED_TEXT_CHARS = 256 * 1024
MAX_TRANSFORM_STDOUT_BYTES = 256 * 1024
MAX_XOR_KEY_BYTES = 256

TRANSFORM_HELPER_ADAPTER_ID = "ctf-helper-transform"
TRANSFORM_HELPER_TOOL_NAME = "helper.transform"
TRANSFORM_HELPER_COMMIT = "p4-transform-helper-1"
TRANSFORM_HELPER_OPERATIONS: tuple[str, ...] = (
    "base64_encode",
    "base64_decode",
    "hex_encode",
    "hex_decode",
    "xor_bytes",
    "rot_caesar",
    "url_decode",
    "zlib_decompress",
)
ALLOWED_ZLIB_WBITS: frozenset[int] = frozenset({15, -15, 31, 47})

TRANSFORM_HELPER_ARG_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "data_text": {"type": "string", "maxLength": MAX_TRANSFORM_ENCODED_TEXT_CHARS},
        "data_base64": {"type": "string", "maxLength": MAX_TRANSFORM_ENCODED_TEXT_CHARS},
        "data_hex": {"type": "string", "maxLength": MAX_TRANSFORM_ENCODED_TEXT_CHARS},
        "artifact_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
        },
        "offset": {"type": "integer", "minimum": 0, "maximum": 67_108_864},
        "length": {"type": "integer", "minimum": 1, "maximum": MAX_TRANSFORM_INPUT_BYTES},
        "key_hex": {"type": "string", "minLength": 2, "maxLength": MAX_XOR_KEY_BYTES * 2},
        "key_text": {"type": "string", "minLength": 1, "maxLength": MAX_XOR_KEY_BYTES},
        "key_byte": {"type": "integer", "minimum": 0, "maximum": 255},
        "shift": {"type": "integer", "minimum": -25, "maximum": 25},
        "urlsafe": {"type": "boolean"},
        "plus_as_space": {"type": "boolean"},
        "wbits": {"type": "integer", "enum": sorted(ALLOWED_ZLIB_WBITS)},
        "max_output_bytes": {
            "type": "integer",
            "minimum": 1,
            "maximum": MAX_TRANSFORM_DECODE_BYTES,
        },
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


def _read_bounded_non_symlink(
    file_path: Path,
    *,
    offset: int = 0,
    max_bytes: int = MAX_TRANSFORM_INPUT_BYTES,
    reject_if_larger: bool = True,
) -> bytes:
    """Safely open a regular non-symlink file and read up to ``max_bytes`` from ``offset``."""
    if offset < 0 or max_bytes < 0:
        raise ValueError("offset and max_bytes must be non-negative")
    st = os.lstat(file_path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise ValueError("input path is not a regular non-symlink file")
    with open(file_path, "rb") as handle:
        fst = os.fstat(handle.fileno())
        if fst.st_ino != st.st_ino or fst.st_dev != st.st_dev:
            raise ValueError("input path changed during open")
        if offset > 0:
            handle.seek(offset)
        read_size = max_bytes + 1 if reject_if_larger else max_bytes
        data = handle.read(read_size)
    if reject_if_larger and len(data) > max_bytes:
        raise ValueError(f"input exceeds maximum allowed size of {max_bytes} bytes")
    return data


def _decode_input_bytes(req: dict[str, Any]) -> bytes:
    """Load and validate raw input bytes for the transform worker."""
    source_kind = req["source_kind"]
    if source_kind == "data_text":
        raw = str(req["value"]).encode("utf-8")
    elif source_kind == "data_base64":
        cleaned = "".join(str(req["value"]).split())
        try:
            raw = base64.b64decode(cleaned, validate=True)
        except binascii.Error as exc:
            raise ValueError(f"invalid data_base64 input: {exc}") from exc
    elif source_kind == "data_hex":
        cleaned = "".join(str(req["value"]).split())
        if len(cleaned) % 2 != 0:
            raise ValueError("data_hex must contain an even number of hex characters")
        try:
            raw = binascii.unhexlify(cleaned)
        except binascii.Error as exc:
            raise ValueError(f"invalid data_hex input: {exc}") from exc
    elif source_kind == "artifact_id":
        offset = int(req.get("offset", 0))
        explicit_length = req.get("length")
        if explicit_length is not None:
            slice_length = int(explicit_length)
            if slice_length < 1 or slice_length > MAX_TRANSFORM_INPUT_BYTES:
                raise ValueError(
                    f"slice length {slice_length} must be between 1 and {MAX_TRANSFORM_INPUT_BYTES}"
                )
            raw = _read_bounded_non_symlink(
                Path(str(req["artifact_path"])),
                offset=offset,
                max_bytes=slice_length,
                reject_if_larger=False,
            )
        else:
            raw = _read_bounded_non_symlink(
                Path(str(req["artifact_path"])),
                offset=offset,
                max_bytes=MAX_TRANSFORM_INPUT_BYTES,
                reject_if_larger=True,
            )
    else:
        raise ValueError(f"unsupported input source kind: {source_kind!r}")

    if len(raw) > MAX_TRANSFORM_INPUT_BYTES:
        raise ValueError(
            f"input payload size {len(raw)} exceeds maximum {MAX_TRANSFORM_INPUT_BYTES} bytes"
        )
    return raw


def _resolve_xor_key(req: dict[str, Any]) -> bytes:
    """Extract and validate a short XOR key or single byte key."""
    if "key_byte" in req and req["key_byte"] is not None:
        val = int(req["key_byte"])
        if val < 0 or val > 255:
            raise ValueError("key_byte must be in range 0..255")
        return bytes([val])
    if "key_hex" in req and req["key_hex"] is not None:
        cleaned = "".join(str(req["key_hex"]).split())
        if not cleaned or len(cleaned) % 2 != 0:
            raise ValueError("key_hex must contain an even non-empty number of hex characters")
        try:
            key = binascii.unhexlify(cleaned)
        except binascii.Error as exc:
            raise ValueError(f"invalid key_hex: {exc}") from exc
    elif "key_text" in req and req["key_text"] is not None:
        key = str(req["key_text"]).encode("utf-8")
    else:
        raise ValueError("xor_bytes requires one of key_byte, key_hex, or key_text")

    if not (1 <= len(key) <= MAX_XOR_KEY_BYTES):
        raise ValueError(f"XOR key length must be between 1 and {MAX_XOR_KEY_BYTES} bytes")
    return key


def _apply_caesar(raw: bytes, shift: int) -> bytes:
    """Apply deterministic ASCII alphabetic Caesar shift preserving all other bytes."""
    norm_shift = shift % 26
    out = bytearray(len(raw))
    for idx, b in enumerate(raw):
        if 65 <= b <= 90:
            out[idx] = 65 + ((b - 65 + norm_shift) % 26)
        elif 97 <= b <= 122:
            out[idx] = 97 + ((b - 97 + norm_shift) % 26)
        else:
            out[idx] = b
    return bytes(out)


def _decompress_zlib_bounded(raw: bytes, *, wbits: int, max_output_bytes: int) -> bytes:
    """Decompress a zlib/gzip/raw-deflate stream with strict output cap against bombs."""
    if wbits not in ALLOWED_ZLIB_WBITS:
        raise ValueError(f"unsupported zlib wbits={wbits}")
    decompressor = zlib.decompressobj(wbits)
    chunks: list[bytes] = []
    total = 0

    first = decompressor.decompress(raw, max_output_bytes + 1)
    total += len(first)
    if total > max_output_bytes or decompressor.unconsumed_tail:
        raise OverflowError(
            f"zlib_bomb_detected: decompressed stream exceeded {max_output_bytes} bytes"
        )
    if first:
        chunks.append(first)

    if not decompressor.eof:
        raise ValueError("zlib_corrupt_stream: incomplete compressed stream")

    tail = decompressor.flush()
    if tail:
        total += len(tail)
        if total > max_output_bytes:
            raise OverflowError(
                f"zlib_bomb_detected: decompressed stream exceeded {max_output_bytes} bytes"
            )
        chunks.append(tail)

    return b"".join(chunks)


def _execute_transform_request(req: dict[str, Any]) -> dict[str, Any]:
    """Perform one deterministic bounded transform operation and return JSON dict."""
    op = str(req["operation"])
    if op not in TRANSFORM_HELPER_OPERATIONS:
        raise ValueError(f"unsupported transform operation: {op!r}")

    max_output_bytes = min(
        int(req.get("max_output_bytes", MAX_TRANSFORM_DECODE_BYTES)),
        MAX_TRANSFORM_DECODE_BYTES,
    )
    if max_output_bytes < 1:
        raise ValueError("max_output_bytes must be >= 1")

    raw_input = _decode_input_bytes(req)

    if op == "base64_encode":
        urlsafe = bool(req.get("urlsafe", False))
        out_bytes = (
            base64.urlsafe_b64encode(raw_input) if urlsafe else base64.b64encode(raw_input)
        )
    elif op == "base64_decode":
        cleaned = b"".join(raw_input.split())
        urlsafe = bool(req.get("urlsafe", False))
        try:
            if urlsafe:
                padded = cleaned + b"=" * ((4 - len(cleaned) % 4) % 4)
                out_bytes = base64.urlsafe_b64decode(padded)
            else:
                out_bytes = base64.b64decode(cleaned, validate=True)
        except binascii.Error as exc:
            raise ValueError(f"invalid base64 input: {exc}") from exc
    elif op == "hex_encode":
        out_bytes = binascii.hexlify(raw_input)
    elif op == "hex_decode":
        cleaned = b"".join(raw_input.split())
        if len(cleaned) % 2 != 0:
            raise ValueError("hex_decode input must have an even number of hex digits")
        try:
            out_bytes = binascii.unhexlify(cleaned)
        except binascii.Error as exc:
            raise ValueError(f"invalid hex input: {exc}") from exc
    elif op == "xor_bytes":
        key = _resolve_xor_key(req)
        klen = len(key)
        out_bytes = bytes(b ^ key[i % klen] for i, b in enumerate(raw_input))
    elif op == "rot_caesar":
        shift = int(req.get("shift", 13))
        out_bytes = _apply_caesar(raw_input, shift)
    elif op == "url_decode":
        text = raw_input.decode("utf-8", errors="strict")
        plus_as_space = bool(req.get("plus_as_space", True))
        decoded_text = (
            urllib.parse.unquote_plus(text) if plus_as_space else urllib.parse.unquote(text)
        )
        out_bytes = decoded_text.encode("utf-8")
    elif op == "zlib_decompress":
        wbits = int(req.get("wbits", 15))
        out_bytes = _decompress_zlib_bounded(
            raw_input,
            wbits=wbits,
            max_output_bytes=max_output_bytes,
        )
    else:  # pragma: no cover - unreachable due to explicit check above
        raise ValueError(f"unsupported transform operation: {op!r}")

    if op != "base64_encode" and op != "hex_encode" and len(out_bytes) > max_output_bytes:
        raise OverflowError(
            f"output_limit_exceeded: output length {len(out_bytes)} exceeds limit {max_output_bytes}"
        )

    try:
        output_utf8: str | None = out_bytes.decode("utf-8")
    except UnicodeDecodeError:
        output_utf8 = None

    return {
        "ok": True,
        "operation": op,
        "input_bytes": len(raw_input),
        "input_sha256": hashlib.sha256(raw_input).hexdigest(),
        "output_bytes": len(out_bytes),
        "output_sha256": hashlib.sha256(out_bytes).hexdigest(),
        "output_hex": binascii.hexlify(out_bytes).decode("ascii"),
        "output_base64": base64.b64encode(out_bytes).decode("ascii"),
        "output_utf8": output_utf8,
    }


def _worker_main(argv: list[str] | None = None) -> int:
    """Entrypoint for the isolated transform subprocess worker."""
    _configure_stdio_utf8()
    parser = argparse.ArgumentParser(description="Bounded deterministic transform helper worker")
    parser.add_argument("--request-file", required=True)
    args = parser.parse_args(argv)

    try:
        req_bytes = _read_bounded_non_symlink(
            Path(args.request_file),
            offset=0,
            max_bytes=MAX_TRANSFORM_STDOUT_BYTES,
        )
        req = json.loads(req_bytes.decode("utf-8"))
        if not isinstance(req, dict):
            raise ValueError("request payload must be a JSON object")
        result = _execute_transform_request(req)
        sys.stdout.write(json.dumps(result, ensure_ascii=False))
        sys.stdout.flush()
        return 0
    except OverflowError as exc:
        err = {"ok": False, "error_code": "bounds_exceeded", "message": str(exc)}
        sys.stderr.write(json.dumps(err, ensure_ascii=False))
        sys.stderr.flush()
        return 2
    except Exception as exc:
        err = {"ok": False, "error_code": "transform_error", "message": str(exc)}
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
        BoundsExceededError,
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

    def create_transform_helper_descriptor(
        *,
        name: str = TRANSFORM_HELPER_TOOL_NAME,
        enabled: bool = True,
        adapter_commit: str = TRANSFORM_HELPER_COMMIT,
        profile_modes: tuple[RunMode, ...] = (
            RunMode.OFFLINE_CTF,
            RunMode.SCOPED_CTF,
            RunMode.VDP,
        ),
        limits: CapabilityLimits | None = None,
    ) -> CapabilityDescriptor:
        """Build the signed capability descriptor for ``helper.transform``."""
        return build_signed_descriptor(
            name=name,
            adapter_id=TRANSFORM_HELPER_ADAPTER_ID,
            adapter_commit=adapter_commit,
            dependency_lock_sha256=get_dependency_lock_sha256(),
            operations=TRANSFORM_HELPER_OPERATIONS,
            arg_schema=TRANSFORM_HELPER_ARG_SCHEMA,
            execution_classes=(ExecutionClass.STATIC,),
            required_scope={"modes": [mode.value for mode in profile_modes]},
            limits=limits
            or CapabilityLimits(
                timeout_seconds=30,
                max_output_bytes=MAX_TRANSFORM_STDOUT_BYTES,
                max_decode_bytes=MAX_TRANSFORM_DECODE_BYTES,
            ),
            enabled=enabled,
            profile_modes=profile_modes,
        )

    class DeterministicTransformAdapter(BaseAdapter):
        """Stdlib-only bounded transform adapter (`helper.transform`, P4)."""

        def __init__(
            self,
            descriptor: CapabilityDescriptor | None = None,
            *,
            runner: SubprocessRunner | None = None,
            evidence_vault: EvidenceVaultPort | None = None,
            worker_script: Path | None = None,
        ) -> None:
            resolved = descriptor or create_transform_helper_descriptor()
            super().__init__(resolved, runner=runner, evidence_vault=evidence_vault)
            self._worker_script = (worker_script or _SCRIPT_PATH).resolve()
            self._pending_lock = threading.Lock()
            self._pending_request_files: dict[str, Path] = {}

        def _prepare_request_payload(
            self,
            action: ActionRecord,
            *,
            artifact_paths: dict[str, Path],
            raw_arguments: Mapping[str, Any] | None = None,
        ) -> dict[str, Any]:
            validate_action_request_inputs(self._descriptor, action)
            args = dict(raw_arguments if raw_arguments is not None else action.sanitized_args)
            sources = [
                key
                for key in ("data_text", "data_base64", "data_hex", "artifact_id")
                if key in args and args[key] is not None
            ]
            if len(sources) != 1:
                raise ContractViolationError(
                    "helper.transform requires exactly one of data_text, data_base64, "
                    "data_hex, or artifact_id",
                    code="invalid_transform_input",
                )
            source_kind = sources[0]
            payload: dict[str, Any] = {
                "operation": action.operation,
                "source_kind": source_kind,
            }
            if source_kind == "artifact_id":
                artifact_id = str(args["artifact_id"])
                artifact_path = artifact_paths.get(artifact_id)
                if artifact_path is None:
                    raise ContractViolationError(
                        f"Unknown or missing artifact_id {artifact_id!r}",
                        code="artifact_not_found",
                    )
                payload["artifact_path"] = str(artifact_path)
                if "offset" in args:
                    payload["offset"] = int(args["offset"])
                if "length" in args:
                    payload["length"] = int(args["length"])
            else:
                raw_val = str(args[source_kind])
                if source_kind == "data_text":
                    raw_len = len(raw_val.encode("utf-8"))
                    max_allowed = MAX_TRANSFORM_INPUT_BYTES
                else:
                    raw_len = len(raw_val.encode("ascii", errors="strict"))
                    max_allowed = MAX_TRANSFORM_ENCODED_TEXT_CHARS
                if raw_len > max_allowed:
                    raise BoundsExceededError(
                        f"Transform input exceeds maximum of {max_allowed} bytes",
                        code="bounds_exceeded",
                    )
                payload["value"] = raw_val

            if action.operation == "xor_bytes":
                key_fields = [
                    k for k in ("key_hex", "key_text", "key_byte") if args.get(k) is not None
                ]
                if len(key_fields) != 1:
                    raise ContractViolationError(
                        "xor_bytes requires exactly one of key_hex, key_text, or key_byte",
                        code="invalid_xor_key",
                    )
                key_name = key_fields[0]
                payload[key_name] = args[key_name]
            elif any(k in args for k in ("key_hex", "key_text", "key_byte")):
                raise ContractViolationError(
                    f"XOR key arguments are only valid for operation 'xor_bytes', not {action.operation!r}",
                    code="invalid_transform_arguments",
                )

            if "shift" in args:
                if action.operation != "rot_caesar":
                    raise ContractViolationError(
                        "Argument 'shift' is only valid for operation 'rot_caesar'",
                        code="invalid_transform_arguments",
                    )
                payload["shift"] = int(args["shift"])
            if "urlsafe" in args:
                if action.operation not in {"base64_encode", "base64_decode"}:
                    raise ContractViolationError(
                        "Argument 'urlsafe' is only valid for base64 operations",
                        code="invalid_transform_arguments",
                    )
                payload["urlsafe"] = bool(args["urlsafe"])
            if "plus_as_space" in args:
                if action.operation != "url_decode":
                    raise ContractViolationError(
                        "Argument 'plus_as_space' is only valid for 'url_decode'",
                        code="invalid_transform_arguments",
                    )
                payload["plus_as_space"] = bool(args["plus_as_space"])
            if "wbits" in args:
                if action.operation != "zlib_decompress":
                    raise ContractViolationError(
                        "Argument 'wbits' is only valid for 'zlib_decompress'",
                        code="invalid_transform_arguments",
                    )
                payload["wbits"] = int(args["wbits"])
            if "max_output_bytes" in args:
                payload["max_output_bytes"] = int(args["max_output_bytes"])

            return payload

        def execute_with_capture(
            self,
            action: ActionRecord,
            *,
            artifact_paths: dict[str, Path] | None = None,
            cancel_event: threading.Event | None = None,
            raw_arguments: Mapping[str, Any] | None = None,
        ) -> AdapterExecutionOutcome:
            resolved_artifacts = artifact_paths or {}
            payload = self._prepare_request_payload(
                action,
                artifact_paths=resolved_artifacts,
                raw_arguments=raw_arguments,
            )
            with tempfile.TemporaryDirectory(prefix="ctf-transform-") as tmp_dir:
                req_file = Path(tmp_dir) / "transform_request.json"
                req_file.write_text(
                    json.dumps(payload, ensure_ascii=False),
                    encoding="utf-8",
                )
                with self._pending_lock:
                    self._pending_request_files[action.action_id] = req_file
                try:
                    return super().execute_with_capture(
                        action,
                        artifact_paths=resolved_artifacts,
                        cancel_event=cancel_event,
                    )
                finally:
                    with self._pending_lock:
                        self._pending_request_files.pop(action.action_id, None)

        def _build_invocation(
            self,
            action: ActionRecord,
            *,
            artifact_paths: dict[str, Path],
        ) -> tuple[list[str], dict[str, str] | None, Path | None]:
            with self._pending_lock:
                req_file = self._pending_request_files.get(action.action_id)
            if req_file is None:
                raise ContractViolationError(
                    "helper.transform must be invoked via execute_with_capture",
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
                    code = err_obj.get("error_code", "transform_error")
                    msg = err_obj.get("message", err_text)
                    return f"helper.transform {action.operation} failed ({code}): {msg[:180]}"
                except Exception:
                    return (
                        f"helper.transform {action.operation} failed "
                        f"(outcome={getattr(sub_res.outcome, 'value', sub_res.outcome)}, "
                        f"returncode={sub_res.returncode}): {err_text[:180]}"
                    )
            try:
                parsed = json.loads(sub_res.stdout.decode("utf-8", errors="strict"))
                in_bytes = int(parsed.get("input_bytes", 0))
                out_bytes = int(parsed.get("output_bytes", 0))
                out_sha = str(parsed.get("output_sha256", ""))[:12]
                return (
                    f"helper.transform {action.operation} succeeded: "
                    f"input_bytes={in_bytes}, output_bytes={out_bytes}, sha256_prefix={out_sha}."
                )
            except Exception:
                return f"helper.transform {action.operation} completed ({len(sub_res.stdout)}B captured)."


if __name__ == "__main__":
    raise SystemExit(_worker_main())
