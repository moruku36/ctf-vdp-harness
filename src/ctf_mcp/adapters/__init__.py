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
    "PRODUCTION_DEFAULT_ENABLED",
    "ProcessTreeGuard",
    "SYNTHETIC_FLAG_MARKER",
    "SYNTHETIC_SECRET_MARKER",
    "SYNTHETIC_SENSITIVE_MARKER",
    "SubprocessOutcome",
    "SubprocessResult",
    "SubprocessRunner",
    "SyntheticAdapter",
    "build_minimal_env",
    "build_signed_descriptor",
    "compute_descriptor_sha256",
    "create_synthetic_descriptor",
    "validate_action_request_inputs",
    "validate_descriptor_integrity",
]
