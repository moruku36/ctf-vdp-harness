"""AdapterPort base class and strict descriptor/action contract enforcement (docs/11)."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
import threading
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import jsonschema

from ctf_mcp.adapters.runner import SubprocessOutcome, SubprocessResult, SubprocessRunner
from ctf_mcp.contracts import (
    SHA256_PATTERN,
    TERMINAL_ACTION_STATES,
    ActionLifecycleState,
    ActionRecord,
    CapabilityDeniedError,
    CapabilityDescriptor,
    CapabilityLimits,
    ContractViolationError,
    EnvelopeStatus,
    ErrorDetail,
    EvidenceRef,
    EvidenceVaultPort,
    ExecutionClass,
    InvalidStateTransitionError,
    PathSecurityError,
    ProvenanceInfo,
    ResultEnvelope,
    RunMode,
    SHA256_PATTERN,
    StrictModel,
    UsageMetrics,
    canonical_digest,
)

FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_SHA256_RE = re.compile(SHA256_PATTERN)

FORBIDDEN_ARG_KEYS: frozenset[str] = frozenset(
    {
        "command",
        "cmd",
        "raw_command",
        "shell",
        "shell_command",
        "script",
        "code",
        "eval",
        "exec",
        "debugger_command",
        "r2_command",
        "python_code",
        "expression",
        "path",
        "file_path",
        "filepath",
        "host_path",
        "guest_path",
        "local_path",
        "output_path",
        "target_path",
        "input_path",
        "cwd",
        "working_dir",
        "workdir",
        "executable",
        "binary_path",
        "argv",
        "args_raw",
    }
)

_PLACEHOLDER_COMMIT_PREFIXES: tuple[str, ...] = (
    "CHANGE_ME",
    "EXAMPLE",
    "PLACEHOLDER",
    "RECORD_",
    "REQUIRED_",
    "PIN_",
    "SET_FROM_",
    "COMMIT_PLACEHOLDER",
    "HASH_PLACEHOLDER",
    "UNKNOWN",
    "UNSET",
)


def _is_placeholder_commit(commit: str) -> bool:
    stripped = commit.strip()
    if not stripped:
        return True
    upper = stripped.upper()
    return any(upper.startswith(prefix) for prefix in _PLACEHOLDER_COMMIT_PREFIXES)


def compute_descriptor_sha256(
    descriptor: CapabilityDescriptor | Mapping[str, Any],
) -> str:
    """Compute canonical SHA-256 over all ``CapabilityDescriptor`` fields except ``descriptor_sha256``."""
    data = (
        descriptor.model_dump(mode="json")
        if isinstance(descriptor, CapabilityDescriptor)
        else dict(descriptor)
    )
    payload = {k: v for k, v in data.items() if k != "descriptor_sha256"}
    return canonical_digest(payload)


def build_signed_descriptor(
    *,
    name: str,
    adapter_id: str,
    adapter_commit: str,
    dependency_lock_sha256: str,
    operations: tuple[str, ...],
    arg_schema: dict[str, Any],
    execution_classes: tuple[ExecutionClass, ...],
    required_scope: dict[str, Any],
    limits: CapabilityLimits,
    enabled: bool = True,
    profile_modes: tuple[RunMode, ...] = (RunMode.OFFLINE_CTF,),
) -> CapabilityDescriptor:
    """Construct a ``CapabilityDescriptor`` with self-consistent ``descriptor_sha256``."""
    draft_payload: dict[str, Any] = {
        "name": name,
        "adapter_id": adapter_id,
        "adapter_commit": adapter_commit,
        "dependency_lock_sha256": dependency_lock_sha256,
        "operations": list(operations),
        "arg_schema": arg_schema,
        "execution_classes": [c.value for c in execution_classes],
        "required_scope": required_scope,
        "limits": limits.model_dump(mode="json"),
        "enabled": enabled,
        "profile_modes": [m.value for m in profile_modes],
    }
    digest = compute_descriptor_sha256(draft_payload)
    return CapabilityDescriptor(
        name=name,
        adapter_id=adapter_id,
        adapter_commit=adapter_commit,
        dependency_lock_sha256=dependency_lock_sha256,
        descriptor_sha256=digest,
        operations=operations,
        arg_schema=arg_schema,
        execution_classes=execution_classes,
        required_scope=required_scope,
        limits=limits,
        enabled=enabled,
        profile_modes=profile_modes,
    )


def _scan_schema_properties(schema_node: Any) -> None:
    if isinstance(schema_node, Mapping):
        props = schema_node.get("properties")
        if isinstance(props, Mapping):
            for prop_name, sub_schema in props.items():
                if str(prop_name).strip().lower() in FORBIDDEN_ARG_KEYS:
                    raise ContractViolationError(
                        f"Capability arg_schema forbids raw command or client path property {prop_name!r}.",
                        details={"property": str(prop_name)},
                    )
                _scan_schema_properties(sub_schema)
        for val in schema_node.values():
            if isinstance(val, (Mapping, list, tuple)):
                _scan_schema_properties(val)
    elif isinstance(schema_node, (list, tuple)):
        for item in schema_node:
            _scan_schema_properties(item)


def validate_descriptor_integrity(
    descriptor: CapabilityDescriptor,
    *,
    require_enabled: bool = True,
) -> None:
    """Self-verify ``CapabilityDescriptor`` pins, hashes, operations, and schema."""
    if _is_placeholder_commit(descriptor.adapter_commit):
        raise ContractViolationError(
            "CapabilityDescriptor adapter_commit is missing or still a placeholder.",
            details={"adapter_commit": descriptor.adapter_commit},
        )

    expected_sha = compute_descriptor_sha256(descriptor)
    if not hmac.compare_digest(descriptor.descriptor_sha256, expected_sha):
        raise ContractViolationError(
            f"CapabilityDescriptor descriptor_sha256 mismatch for {descriptor.name!r}.",
            details={
                "capability": descriptor.name,
                "expected": expected_sha,
                "actual": descriptor.descriptor_sha256,
            },
        )

    seen_ops: set[str] = set()
    for op in descriptor.operations:
        if not op.strip() or op != op.strip():
            raise ContractViolationError(
                f"Invalid operation name {op!r} in capability {descriptor.name!r}."
            )
        if op in seen_ops:
            raise ContractViolationError(
                f"Duplicate operation {op!r} in capability {descriptor.name!r}."
            )
        seen_ops.add(op)

    try:
        jsonschema.Draft202012Validator.check_schema(descriptor.arg_schema)
    except jsonschema.SchemaError as exc:
        raise ContractViolationError(
            f"Capability {descriptor.name!r} has an invalid JSON Schema: {exc}"
        ) from exc

    _scan_schema_properties(descriptor.arg_schema)

    if require_enabled and not descriptor.enabled:
        raise CapabilityDeniedError(
            f"Capability {descriptor.name!r} is disabled and cannot execute.",
            details={"capability": descriptor.name},
        )


def _scan_runtime_args(value: Any, *, key_path: str = "") -> None:
    if isinstance(value, Mapping):
        for raw_key, item in value.items():
            key_str = str(raw_key)
            lower_key = key_str.strip().lower()
            if lower_key in FORBIDDEN_ARG_KEYS:
                raise ContractViolationError(
                    f"Forbidden raw command or client path argument {key_str!r}.",
                    details={"argument": key_str},
                )
            if lower_key.endswith("_id") and isinstance(item, str):
                if (
                    not item.strip()
                    or "\x00" in item
                    or "/" in item
                    or "\\" in item
                    or ".." in item
                    or ":" in item
                ):
                    raise PathSecurityError(
                        f"Opaque ID argument {key_str!r} contains unsafe path characters.",
                        details={"argument": key_str},
                    )
            _scan_runtime_args(item, key_path=f"{key_path}.{key_str}" if key_path else key_str)
    elif isinstance(value, (list, tuple)):
        for idx, item in enumerate(value):
            _scan_runtime_args(item, key_path=f"{key_path}[{idx}]")


def validate_action_request_inputs(
    descriptor: CapabilityDescriptor,
    action: ActionRecord,
    *,
    require_running: bool = False,
) -> None:
    """Validate an ``ActionRecord`` against the adapter's pinned descriptor and contracts."""
    if action.capability_name != descriptor.name:
        raise CapabilityDeniedError(
            f"Action capability {action.capability_name!r} does not match adapter {descriptor.name!r}.",
            details={
                "expected_capability": descriptor.name,
                "actual_capability": action.capability_name,
            },
        )

    if action.adapter_revision != descriptor.adapter_commit:
        raise ContractViolationError(
            f"Action adapter_revision {action.adapter_revision!r} does not match pinned commit {descriptor.adapter_commit!r}.",
            details={
                "expected_revision": descriptor.adapter_commit,
                "actual_revision": action.adapter_revision,
            },
        )

    if action.state in TERMINAL_ACTION_STATES or action.state in {
        ActionLifecycleState.PROPOSED,
        ActionLifecycleState.RECONCILIATION_REQUIRED,
    }:
        raise InvalidStateTransitionError(
            f"Action in state {action.state.value!r} cannot be executed by adapter.",
            details={"state": action.state.value, "action_id": action.action_id},
        )
    if require_running and action.state != ActionLifecycleState.RUNNING:
        raise InvalidStateTransitionError(
            f"Adapter requires action state 'running', got {action.state.value!r}.",
            details={"state": action.state.value, "action_id": action.action_id},
        )

    if action.operation not in descriptor.operations:
        raise CapabilityDeniedError(
            f"Operation {action.operation!r} is not permitted for capability {descriptor.name!r}.",
            details={
                "operation": action.operation,
                "allowed_operations": list(descriptor.operations),
            },
        )

    _scan_runtime_args(action.sanitized_args)

    validator = jsonschema.Draft202012Validator(
        descriptor.arg_schema,
        format_checker=jsonschema.FormatChecker(),
    )
    errors = sorted(validator.iter_errors(action.sanitized_args), key=lambda e: str(e.path))
    if errors:
        first = errors[0]
        raise ContractViolationError(
            f"Action arguments failed schema validation for {descriptor.name!r}/{action.operation!r}: {first.message}",
            details={"capability": descriptor.name, "operation": action.operation},
        )


def _validate_resolved_artifact_paths(
    artifact_paths: Mapping[str, Any] | None,
) -> dict[str, Path]:
    if artifact_paths is None:
        return {}
    resolved: dict[str, Path] = {}
    for artifact_id, raw_path in artifact_paths.items():
        if not isinstance(artifact_id, str) or not artifact_id.strip():
            raise ContractViolationError("artifact_paths keys must be non-empty artifact IDs.")
        path_str = os.fspath(raw_path)
        if not isinstance(path_str, str) or "\x00" in path_str or not path_str.strip():
            raise PathSecurityError(f"Invalid resolved artifact path for {artifact_id!r}.")
        candidate = Path(path_str)
        try:
            st = os.lstat(candidate)
        except OSError as exc:
            raise PathSecurityError(
                f"Resolved artifact path for {artifact_id!r} is inaccessible: {exc}"
            ) from exc
        if stat.S_ISLNK(st.st_mode) or (
            getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise PathSecurityError(
                f"Resolved artifact path for {artifact_id!r} cannot be a symlink or reparse point."
            )
        if not stat.S_ISREG(st.st_mode):
            raise PathSecurityError(
                f"Resolved artifact path for {artifact_id!r} is not a regular file."
            )
        try:
            real_candidate = Path(os.path.realpath(candidate, strict=True))
            real_st = os.lstat(real_candidate)
        except OSError as exc:
            raise PathSecurityError(
                f"Resolved artifact canonicalization failed for {artifact_id!r}: {exc}"
            ) from exc
        if stat.S_ISLNK(real_st.st_mode) or (
            getattr(real_st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT
        ) or (real_st.st_dev, real_st.st_ino) != (st.st_dev, st.st_ino):
            raise PathSecurityError(
                f"Resolved artifact path for {artifact_id!r} traversed a symlink/reparse ancestor."
            )
        resolved[artifact_id] = real_candidate
    return resolved


class AdapterExecutionOutcome(StrictModel):
    """Combined adapter result carrying both ``ResultEnvelope`` and raw capture state."""

    envelope: ResultEnvelope
    subprocess_result: SubprocessResult
    captured_bytes: bytes
    capture_complete: bool
    omission_reason: str | None = None
    cleanup_confirmed: bool


class BaseAdapter(ABC):
    """Base implementation of ``AdapterPort`` enforcing pinned descriptors and bounded execution."""

    def __init__(
        self,
        descriptor: CapabilityDescriptor,
        *,
        runner: SubprocessRunner | None = None,
        evidence_vault: EvidenceVaultPort | None = None,
        require_running_state: bool = False,
    ) -> None:
        validate_descriptor_integrity(descriptor, require_enabled=False)
        self._descriptor = descriptor
        self._runner = runner or SubprocessRunner(
            default_timeout_seconds=float(descriptor.limits.timeout_seconds),
            default_max_output_bytes=descriptor.limits.max_output_bytes,
        )
        self._evidence_vault = evidence_vault
        self._require_running_state = require_running_state

    def descriptor(self) -> CapabilityDescriptor:
        """Return self-verified ``CapabilityDescriptor``."""
        validate_descriptor_integrity(self._descriptor, require_enabled=False)
        return self._descriptor

    def compute_effective_limits(self, action: ActionRecord) -> tuple[float, int]:
        """Clamp capability limits down to the action's remaining budget reservation."""
        desc = self._descriptor
        timeout_s = float(desc.limits.timeout_seconds)
        if action.reserved_ms > 0:
            timeout_s = min(timeout_s, max(0.05, action.reserved_ms / 1000.0))

        max_bytes = int(desc.limits.max_output_bytes)
        if action.reserved_bytes > 0:
            max_bytes = min(max_bytes, int(action.reserved_bytes))
        return timeout_s, max_bytes

    @abstractmethod
    def _build_invocation(
        self,
        action: ActionRecord,
        *,
        artifact_paths: dict[str, Path],
    ) -> tuple[list[str], dict[str, str] | None, Path | None]:
        """Build ``(argv, extra_env, cwd)`` for ``SubprocessRunner.run``."""

    def _summarize_result(
        self,
        action: ActionRecord,
        sub_res: SubprocessResult,
    ) -> str:
        """Return a sanitized summary string (must never echo secrets/flags)."""
        return (
            f"{action.capability_name}:{action.operation} finished with "
            f"outcome={sub_res.outcome.value}, cleanup_confirmed={sub_res.cleanup_confirmed}."
        )

    def _combine_captured_bytes(self, sub_res: SubprocessResult) -> bytes:
        # Preserve exact total byte budget (stdout + stderr <= max_output_bytes) without adding separators.
        return sub_res.stdout + sub_res.stderr

    def _build_envelope(
        self,
        action: ActionRecord,
        sub_res: SubprocessResult,
        *,
        evidence_refs: tuple[EvidenceRef, ...] = (),
    ) -> ResultEnvelope:
        provenance = ProvenanceInfo(
            adapter_revision=self._descriptor.adapter_commit,
            scope_revision=action.scope_revision,
        )
        usage = UsageMetrics(
            wall_ms=sub_res.wall_ms,
            output_bytes=sub_res.output_bytes,
        )
        summary = self._summarize_result(action, sub_res)

        if sub_res.outcome == SubprocessOutcome.TIMEOUT:
            status = EnvelopeStatus.TIMEOUT
            error = ErrorDetail(
                code="cleanup_unconfirmed" if not sub_res.cleanup_confirmed else "action_timeout",
                message=sub_res.cleanup_detail
                or sub_res.omission_reason
                or "Subprocess timed out.",
                retryable=False,
            )
            truncated = True
        elif sub_res.outcome == SubprocessOutcome.CANCELLED:
            status = EnvelopeStatus.CANCELLED
            error = ErrorDetail(
                code="cleanup_unconfirmed" if not sub_res.cleanup_confirmed else "action_cancelled",
                message=sub_res.cleanup_detail
                or sub_res.omission_reason
                or "Subprocess cancelled.",
                retryable=False,
            )
            truncated = True
        elif sub_res.outcome == SubprocessOutcome.OUTPUT_LIMIT_EXCEEDED:
            status = EnvelopeStatus.PARTIAL
            error = ErrorDetail(
                code="cleanup_unconfirmed"
                if not sub_res.cleanup_confirmed
                else "output_limit_exceeded",
                message=sub_res.cleanup_detail
                or sub_res.omission_reason
                or "Subprocess output limit exceeded.",
                retryable=False,
            )
            truncated = True
        elif not sub_res.cleanup_confirmed:
            # Unconfirmed process-tree cleanup must never report ok.
            status = EnvelopeStatus.TOOL_ERROR
            error = ErrorDetail(
                code="cleanup_unconfirmed",
                message=sub_res.cleanup_detail
                or "Process tree termination could not be confirmed.",
                retryable=False,
            )
            truncated = not sub_res.capture_complete
        elif sub_res.outcome == SubprocessOutcome.FAILED:
            status = EnvelopeStatus.TOOL_ERROR
            msg = (
                sub_res.cleanup_detail
                if sub_res.returncode is None and sub_res.cleanup_detail
                else (
                    f"Analyzer subprocess exited with returncode={sub_res.returncode} "
                    f"(output_bytes={sub_res.output_bytes})."
                )
            )
            error = ErrorDetail(
                code="tool_execution_failed",
                message=msg,
                retryable=False,
            )
            truncated = not sub_res.capture_complete
        else:
            status = EnvelopeStatus.OK
            error = None
            truncated = not sub_res.capture_complete

        return ResultEnvelope(
            run_id=action.run_id,
            action_id=action.action_id,
            status=status,
            summary=summary,
            evidence=evidence_refs,
            truncated=truncated,
            next_cursor=None,
            error=error,
            usage=usage,
            provenance=provenance,
        )

    @staticmethod
    def _hash_validated_file(artifact_id: str, path: Path) -> str:
        """Compute lowercase SHA-256 of a validated regular file without following swaps."""
        try:
            expected_st = os.lstat(path)
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
            fd = os.open(path, flags)
        except OSError as exc:
            raise PathSecurityError(
                f"Failed to open resolved artifact {artifact_id!r} for hashing: {exc}"
            ) from exc

        try:
            opened_st = os.fstat(fd)
            if not stat.S_ISREG(opened_st.st_mode) or (
                opened_st.st_dev,
                opened_st.st_ino,
            ) != (expected_st.st_dev, expected_st.st_ino):
                raise PathSecurityError(
                    f"Resolved artifact {artifact_id!r} changed or is not a regular file during hashing."
                )
            digest = hashlib.sha256()
            with os.fdopen(fd, "rb", closefd=True) as stream:
                fd = -1
                while chunk := stream.read(65_536):
                    digest.update(chunk)
            return digest.hexdigest()
        except OSError as exc:
            raise PathSecurityError(
                f"Failed reading resolved artifact {artifact_id!r} for hashing: {exc}"
            ) from exc
        finally:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def _resolve_source_artifact_hashes(
        self,
        action: ActionRecord,
        *,
        artifact_paths: Mapping[str, Path],
        explicit_hashes: Sequence[str] | None = None,
    ) -> tuple[str, ...]:
        """Resolve lowercase SHA-256 digests for the input artifacts of this action."""
        del action
        if explicit_hashes is not None:
            normalized: list[str] = []
            for raw in explicit_hashes:
                if not isinstance(raw, str):
                    raise ContractViolationError(
                        "source_artifact_hashes entries must be SHA-256 hex strings."
                    )
                candidate = raw.strip().lower()
                if not _SHA256_RE.fullmatch(candidate):
                    raise ContractViolationError(
                        f"Invalid source_artifact_hashes digest: {raw!r}."
                    )
                normalized.append(candidate)
            if normalized or not artifact_paths:
                return tuple(dict.fromkeys(normalized))

        if not artifact_paths:
            return ()

        computed = [
            self._hash_validated_file(artifact_id, path)
            for artifact_id, path in artifact_paths.items()
        ]
        return tuple(dict.fromkeys(computed))

    def execute_with_capture(
        self,
        action: ActionRecord,
        *,
        artifact_paths: dict[str, Any] | None = None,
        source_artifact_hashes: Sequence[str] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> AdapterExecutionOutcome:
        """Validate contract inputs, execute bounded subprocess, and return full capture."""
        validate_descriptor_integrity(self._descriptor, require_enabled=True)
        validate_action_request_inputs(
            self._descriptor,
            action,
            require_running=self._require_running_state,
        )
        validated_paths = _validate_resolved_artifact_paths(artifact_paths)
        resolved_source_hashes = self._resolve_source_artifact_hashes(
            action,
            artifact_paths=validated_paths,
            explicit_hashes=source_artifact_hashes,
        )
        timeout_s, max_bytes = self.compute_effective_limits(action)

        argv, extra_env, cwd = self._build_invocation(
            action, artifact_paths=validated_paths
        )
        sub_res = self._runner.run(
            argv,
            timeout_seconds=timeout_s,
            max_output_bytes=max_bytes,
            extra_env=extra_env,
            cwd=cwd,
            cancel_event=cancel_event,
        )
        captured = self._combine_captured_bytes(sub_res)

        evidence_refs: tuple[EvidenceRef, ...] = ()
        if self._evidence_vault is not None and (captured or not sub_res.capture_complete):
            try:
                captured.decode("utf-8")
                media_type = "text/plain; charset=utf-8"
            except UnicodeDecodeError:
                media_type = "application/octet-stream"
            manifest = self._evidence_vault.store_raw(
                run_id=action.run_id,
                owner_principal_id=action.principal_id,
                action_id=action.action_id,
                data=captured,
                media_type=media_type,
                capture_complete=sub_res.capture_complete,
                omission_reason=sub_res.omission_reason,
                source_artifact_hashes=resolved_source_hashes,
                adapter_revision=self._descriptor.adapter_commit,
                sanitized_args_sha256=action.canonical_args_sha256,
            )
            evidence_refs = (
                EvidenceRef(
                    id=manifest.evidence_id,
                    sha256=manifest.view_sha256,
                    kind="tool_output",
                ),
            )

        envelope = self._build_envelope(action, sub_res, evidence_refs=evidence_refs)
        return AdapterExecutionOutcome(
            envelope=envelope,
            subprocess_result=sub_res,
            captured_bytes=captured,
            capture_complete=sub_res.capture_complete,
            omission_reason=sub_res.omission_reason,
            cleanup_confirmed=sub_res.cleanup_confirmed,
        )

    def execute(
        self,
        action: ActionRecord,
        *,
        artifact_paths: dict[str, Any] | None = None,
    ) -> ResultEnvelope:
        """``AdapterPort.execute`` entrypoint returning a bounded ``ResultEnvelope``."""
        return self.execute_with_capture(action, artifact_paths=artifact_paths).envelope


__all__ = [
    "AdapterExecutionOutcome",
    "BaseAdapter",
    "FORBIDDEN_ARG_KEYS",
    "build_signed_descriptor",
    "compute_descriptor_sha256",
    "validate_action_request_inputs",
    "validate_descriptor_integrity",
]
