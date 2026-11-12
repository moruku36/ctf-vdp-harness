"""Layer 2 adapters subsystem: capability self-verification, bounded runner, and test synthetic adapter."""

from __future__ import annotations

from ctf_mcp.adapters.base import (
    FORBIDDEN_ARG_KEYS,
    AdapterExecutionOutcome,
    BaseAdapter,
    build_signed_descriptor,
    compute_descriptor_sha256,
    validate_action_request_inputs,
    validate_descriptor_integrity,
)
from ctf_mcp.adapters.runner import (
    DEFAULT_CLEANUP_CONFIRM_TIMEOUT_SECONDS,
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_TIMEOUT_SECONDS,
    ProcessTreeGuard,
    SubprocessOutcome,
    SubprocessResult,
    SubprocessRunner,
    build_minimal_env,
)
from ctf_mcp.adapters.static_inspector import (
    FORBIDDEN_OR_UNACCEPTED_OPERATIONS,
    STATIC_INSPECTOR_ADAPTER_COMMIT,
    STATIC_INSPECTOR_ADAPTER_ID,
    STATIC_INSPECTOR_ARG_SCHEMA,
    STATIC_INSPECTOR_CAPABILITY_NAME,
    STATIC_INSPECTOR_DEPENDENCY_LOCK_SHA256,
    STATIC_INSPECTOR_OPERATIONS,
    StaticArtifactInspectorAdapter,
    create_static_inspector_descriptor,
    get_dependency_lock_sha256,
)
from ctf_mcp.adapters.synthetic import (
    PRODUCTION_DEFAULT_ENABLED,
    SYNTHETIC_FLAG_MARKER,
    SYNTHETIC_SECRET_MARKER,
    SYNTHETIC_SENSITIVE_MARKER,
    SyntheticAdapter,
    create_synthetic_descriptor,
)

__all__ = [
    "AdapterExecutionOutcome",
    "BaseAdapter",
    "DEFAULT_CLEANUP_CONFIRM_TIMEOUT_SECONDS",
    "DEFAULT_MAX_OUTPUT_BYTES",
    "DEFAULT_TIMEOUT_SECONDS",
    "FORBIDDEN_ARG_KEYS",
    "FORBIDDEN_OR_UNACCEPTED_OPERATIONS",
    "PRODUCTION_DEFAULT_ENABLED",
    "ProcessTreeGuard",
    "STATIC_INSPECTOR_ADAPTER_COMMIT",
    "STATIC_INSPECTOR_ADAPTER_ID",
    "STATIC_INSPECTOR_ARG_SCHEMA",
    "STATIC_INSPECTOR_CAPABILITY_NAME",
    "STATIC_INSPECTOR_DEPENDENCY_LOCK_SHA256",
    "STATIC_INSPECTOR_OPERATIONS",
    "SYNTHETIC_FLAG_MARKER",
    "SYNTHETIC_SECRET_MARKER",
    "SYNTHETIC_SENSITIVE_MARKER",
    "StaticArtifactInspectorAdapter",
    "SubprocessOutcome",
    "SubprocessResult",
    "SubprocessRunner",
    "SyntheticAdapter",
    "build_minimal_env",
    "build_signed_descriptor",
    "compute_descriptor_sha256",
    "create_static_inspector_descriptor",
    "create_synthetic_descriptor",
    "get_dependency_lock_sha256",
    "validate_action_request_inputs",
    "validate_descriptor_integrity",
]
