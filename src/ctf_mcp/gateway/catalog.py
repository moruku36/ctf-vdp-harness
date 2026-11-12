"""Gateway capability catalog, descriptor integrity verification, and allowlist filter.

Implements ``CatalogPort`` (``docs/05`` section 4, ``docs/08`` section 5,
``docs/11`` section 1) backed by the SQLite ``capabilities`` table.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from typing import Any

import jsonschema

from ctf_mcp.contracts import (
    CapabilityDeniedError,
    CapabilityDescriptor,
    CapabilityLimits,
    CatalogPort,
    ContractViolationError,
    ExecutionClass,
    RunMode,
    ScopePolicy,
    canonical_digest,
    canonical_json,
)
from ctf_mcp.storage import Storage, utc_now_iso


def compute_descriptor_sha256(descriptor: CapabilityDescriptor | Mapping[str, Any]) -> str:
    """Compute canonical SHA-256 over all ``CapabilityDescriptor`` fields except ``descriptor_sha256``."""
    if isinstance(descriptor, CapabilityDescriptor):
        payload = descriptor.model_dump(mode="json")
    else:
        payload = dict(descriptor)
    payload.pop("descriptor_sha256", None)
    return canonical_digest(payload)


def verify_descriptor_hash(descriptor: CapabilityDescriptor) -> None:
    """Verify ``descriptor.descriptor_sha256`` matches its canonical definition."""
    expected = compute_descriptor_sha256(descriptor)
    if descriptor.descriptor_sha256 != expected:
        raise CapabilityDeniedError(
            f"Descriptor SHA-256 mismatch for capability {descriptor.name!r}.",
            details={
                "capability": descriptor.name,
                "declared": descriptor.descriptor_sha256,
                "computed": expected,
            },
        )


def build_capability_descriptor(
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
    """Construct a ``CapabilityDescriptor`` with an authentic computed ``descriptor_sha256``."""
    raw_payload: dict[str, Any] = {
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
    digest = compute_descriptor_sha256(raw_payload)
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


class CapabilityCatalog(CatalogPort):
    """Fail-closed capability registry controlling ``tools/list`` visibility and invocation."""

    def __init__(self, storage: Storage, *, allow_dynamic: bool = False) -> None:
        self._storage = storage
        self._allow_dynamic = allow_dynamic

    def register_capability_in_tx(
        self,
        conn: sqlite3.Connection,
        descriptor: CapabilityDescriptor,
        *,
        verify_hash: bool = True,
        replace: bool = False,
    ) -> CapabilityDescriptor:
        """Validate and register an accepted capability descriptor inside ``conn``."""
        try:
            jsonschema.Draft202012Validator.check_schema(descriptor.arg_schema)
        except jsonschema.SchemaError as exc:
            raise ContractViolationError(
                f"Invalid arg_schema for capability {descriptor.name!r}: {exc.message}"
            ) from exc

        if verify_hash:
            verify_descriptor_hash(descriptor)

        existing = conn.execute(
            "SELECT descriptor_sha256 FROM capabilities WHERE name = ?",
            (descriptor.name,),
        ).fetchone()
        if existing is not None:
            if existing["descriptor_sha256"] == descriptor.descriptor_sha256 and not replace:
                return descriptor
            if not replace:
                raise CapabilityDeniedError(
                    f"Capability {descriptor.name!r} is already registered with a different descriptor."
                )

        exec_classes_json = canonical_json([c.value for c in descriptor.execution_classes])
        conn.execute(
            """
            INSERT INTO capabilities (
                name, adapter_id, adapter_commit, dependency_lock_sha256,
                descriptor_sha256, execution_classes_json, descriptor_json,
                enabled, registered_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                adapter_id = excluded.adapter_id,
                adapter_commit = excluded.adapter_commit,
                dependency_lock_sha256 = excluded.dependency_lock_sha256,
                descriptor_sha256 = excluded.descriptor_sha256,
                execution_classes_json = excluded.execution_classes_json,
                descriptor_json = excluded.descriptor_json,
                enabled = excluded.enabled,
                registered_at = excluded.registered_at
            """,
            (
                descriptor.name,
                descriptor.adapter_id,
                descriptor.adapter_commit,
                descriptor.dependency_lock_sha256,
                descriptor.descriptor_sha256,
                exec_classes_json,
                descriptor.model_dump_json(),
                1 if descriptor.enabled else 0,
                utc_now_iso(),
            ),
        )
        return descriptor

    def register_capability(
        self,
        descriptor: CapabilityDescriptor,
        *,
        verify_hash: bool = True,
        replace: bool = False,
    ) -> CapabilityDescriptor:
        """Validate and register a capability atomically."""
        with self._storage.transaction() as conn:
            return self.register_capability_in_tx(
                conn,
                descriptor,
                verify_hash=verify_hash,
                replace=replace,
            )

    def set_enabled(self, name: str, enabled: bool) -> None:
        """Toggle gateway operational enablement flag without mutating signed descriptor JSON."""
        with self._storage.transaction() as conn:
            cur = conn.execute(
                "UPDATE capabilities SET enabled = ? WHERE name = ?",
                (1 if enabled else 0, name),
            )
            if cur.rowcount == 0:
                raise CapabilityDeniedError(f"Capability {name!r} is not registered.")

    def _load_and_verify_row(self, row: sqlite3.Row) -> tuple[CapabilityDescriptor, bool]:
        try:
            descriptor = CapabilityDescriptor.model_validate_json(row["descriptor_json"])
        except Exception as exc:
            raise CapabilityDeniedError(
                f"Capability {row['name']!r} has corrupted descriptor_json: {exc}"
            ) from exc

        verify_descriptor_hash(descriptor)

        exec_classes_json = canonical_json([c.value for c in descriptor.execution_classes])
        if (
            row["name"] != descriptor.name
            or row["adapter_id"] != descriptor.adapter_id
            or row["adapter_commit"] != descriptor.adapter_commit
            or row["dependency_lock_sha256"] != descriptor.dependency_lock_sha256
            or row["descriptor_sha256"] != descriptor.descriptor_sha256
            or row["execution_classes_json"] != exec_classes_json
        ):
            raise CapabilityDeniedError(
                f"Capability {row['name']!r} failed column-to-descriptor integrity verification."
            )

        effective_enabled = bool(row["enabled"]) and descriptor.enabled
        return descriptor, effective_enabled

    def _is_visible(
        self,
        descriptor: CapabilityDescriptor,
        effective_enabled: bool,
        mode: RunMode,
        scope: ScopePolicy | None,
    ) -> bool:
        if not effective_enabled:
            return False
        if mode not in descriptor.profile_modes:
            return False

        exec_classes = set(descriptor.execution_classes)
        if mode == RunMode.OFFLINE_CTF:
            if {ExecutionClass.NETWORK, ExecutionClass.SUBMISSION} & exec_classes:
                return False
        if ExecutionClass.DYNAMIC in exec_classes and not self._allow_dynamic:
            return False

        if scope is not None:
            if scope.mode != mode:
                return False
            if descriptor.name not in scope.allowed_capabilities:
                return False
            if not exec_classes.issubset(set(scope.allowed_execution_classes)):
                return False
            req_mode = descriptor.required_scope.get("mode")
            if req_mode is not None and scope.mode.value != req_mode:
                return False
            req_modes = descriptor.required_scope.get("modes")
            if req_modes is not None and scope.mode.value not in req_modes:
                return False

        return True

    def verify_all_descriptors(self) -> list[CapabilityDescriptor]:
        """Verify integrity of every registered capability row (startup self-check)."""
        with self._storage.read_connection() as conn:
            rows = conn.execute("SELECT * FROM capabilities ORDER BY name ASC").fetchall()
            return [self._load_and_verify_row(row)[0] for row in rows]

    def list_visible_tools(
        self,
        mode: RunMode,
        *,
        scope: ScopePolicy | None = None,
    ) -> list[CapabilityDescriptor]:
        """Return only verified, enabled capabilities allowed for ``mode`` and optional ``scope``."""
        with self._storage.read_connection() as conn:
            rows = conn.execute("SELECT * FROM capabilities ORDER BY name ASC").fetchall()
            visible: list[CapabilityDescriptor] = []
            for row in rows:
                descriptor, effective_enabled = self._load_and_verify_row(row)
                if self._is_visible(descriptor, effective_enabled, mode, scope):
                    visible.append(descriptor)
            return visible

    def get_capability(
        self,
        name: str,
        mode: RunMode,
        *,
        scope: ScopePolicy | None = None,
    ) -> CapabilityDescriptor:
        """Retrieve a capability only if registered, untampered, enabled, and permitted."""
        with self._storage.read_connection() as conn:
            row = conn.execute("SELECT * FROM capabilities WHERE name = ?", (name,)).fetchone()
            if row is None:
                raise CapabilityDeniedError(f"Capability {name!r} is not registered.")
            descriptor, effective_enabled = self._load_and_verify_row(row)
            if not self._is_visible(descriptor, effective_enabled, mode, scope):
                raise CapabilityDeniedError(
                    f"Capability {name!r} is disabled or not permitted in profile {mode.value!r}."
                )
            return descriptor

    def validate_arguments(
        self,
        descriptor: CapabilityDescriptor,
        operation: str,
        arguments: Mapping[str, Any],
    ) -> None:
        """Validate ``operation`` enum membership and ``arguments`` against ``arg_schema``."""
        if operation not in descriptor.operations:
            raise CapabilityDeniedError(
                f"Operation {operation!r} is not allowed for capability {descriptor.name!r}.",
                details={"capability": descriptor.name, "operation": operation},
            )
        validator = jsonschema.Draft202012Validator(
            descriptor.arg_schema,
            format_checker=jsonschema.FormatChecker(),
        )
        errors = sorted(validator.iter_errors(dict(arguments)), key=lambda err: list(err.path))
        if errors:
            first = errors[0]
            raise ContractViolationError(
                f"Invalid arguments for capability {descriptor.name!r}: {first.message}",
                details={
                    "capability": descriptor.name,
                    "operation": operation,
                    "schema_path": [str(part) for part in first.path],
                },
            )

    def validate_invocation(
        self,
        name: str,
        mode: RunMode,
        operation: str,
        arguments: Mapping[str, Any],
        *,
        scope: ScopePolicy | None = None,
    ) -> CapabilityDescriptor:
        """Perform full catalog lookup, integrity verification, and argument validation."""
        descriptor = self.get_capability(name, mode, scope=scope)
        self.validate_arguments(descriptor, operation, arguments)
        return descriptor


__all__ = [
    "CapabilityCatalog",
    "build_capability_descriptor",
    "compute_descriptor_sha256",
    "verify_descriptor_hash",
]
