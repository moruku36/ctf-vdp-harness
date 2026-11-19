"""Bounded VDP real-code product test execution adapter (`vdp.test`).

Executes only server-allowlisted product smoke checks and targeted pytest
selectors inside a pinned, network-isolated Docker image (`--network none`)
with fixed CPU/memory/time caps, optional integrity-verified read-only
synthetic test overlays, and guaranteed container cleanup verification.

Execution host premise:
    Designed to run on the operator's WSL2 Ubuntu (or Linux) host where the
    harness server has local access to the Docker CLI/daemon and pinned product
    scanner images. Never assumes an isolated disposable VM can reach the
    owner's WSL images without explicit provisioning.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

if sys.platform == "win32":
    import msvcrt
else:
    msvcrt = None  # type: ignore[assignment]

try:
    import fcntl
except ImportError:
    fcntl = None  # type: ignore[assignment]

from pydantic import Field

from ctf_mcp.adapters.base import (
    AdapterExecutionOutcome,
    BaseAdapter,
    build_signed_descriptor,
    validate_action_request_inputs,
)
from ctf_mcp.adapters.runner import SubprocessOutcome, SubprocessResult, SubprocessRunner
from ctf_mcp.contracts import (
    ActionRecord,
    CapabilityDescriptor,
    CapabilityLimits,
    ContractViolationError,
    EnvelopeStatus,
    ErrorDetail,
    EvidenceRef,
    EvidenceVaultPort,
    ExecutionClass,
    PathSecurityError,
    ProvenanceInfo,
    ResultEnvelope,
    RunMode,
    ScopeDeniedError,
    ScopePolicy,
    StrictModel,
    UsageMetrics,
)
from ctf_mcp.fs_guard import _is_reparse_or_symlink, safe_read_bounded, safe_write_atomic
from ctf_mcp.vdp_fixtures.local_git_http import redact_sensitive_text, redact_structure

VDP_PRODUCT_TEST_CAPABILITY_NAME = "vdp.test"
VDP_PRODUCT_TEST_ADAPTER_ID = "ctf-vdp-product-test"
VDP_PRODUCT_TEST_ADAPTER_COMMIT = "p9vdp02c3d4e5f6"
VALID_SELECTOR_ROLES: tuple[str, ...] = (
    "positive_control",
    "defense_check",
    "anomaly_repro",
    "env_check",
)
VALID_VDP_NETWORK_MODES: tuple[str, ...] = (
    "none",
    "isolated_internal_services",
)
VALID_VDP_SERVICE_KINDS: tuple[str, ...] = (
    "postgres",
    "valkey",
    "redis",
    "generic_internal",
)
VALID_VDP_RUNNER_MODES: tuple[str, ...] = (
    "oss_scanner",
    "direct_pytest",
)
MAX_VDP_SERVICES_PER_PROFILE = 4
MAX_VDP_TOTAL_CPUS = 4
MAX_VDP_TOTAL_MEMORY_MB = 8192
DEFAULT_DIRECT_PYTEST_EXECUTABLE = "/opt/oss-scanner/venv/bin/pytest"
VDP_PRODUCT_TEST_OPERATIONS: tuple[str, ...] = (
    "describe_profile",
    "check_environment",
    "run_smoke",
    "run_pytest",
)
VDP_PROFILES_RELPATH = "_vdp/profiles.json"
VDP_PROFILES_LOCK_RELPATH = "_vdp/profiles.json.lock"
_PROFILES_THREAD_LOCKS_GUARD = threading.Lock()
_PROFILES_THREAD_LOCKS: dict[Path, threading.Lock] = {}
_UNSET = object()

WEBLATE_2026_11_2_PROFILE_NAME = "weblate-2026.11.2"
WEBLATE_2026_11_2_PROFILE_REVISION = "weblate-2026.11.2-r2"
WEBLATE_2026_11_2_SOURCE_COMMIT = "3562388dd005298e3d2c06562987dd3e07be1c89"
WEBLATE_2026_11_2_IMAGE_REF = "weblate-oss-scanner:2026.11.2"
WEBLATE_2026_11_2_IMAGE_DIGEST = (
    "sha256:f3556156645159fee3e3c08eda2f742661dfed1ee92b90bfa0b7dc713862948d"
)
WEBLATE_W01_OVERLAY_BUNDLE = "w01-2026-11-13"
WEBLATE_W01_TEST_FILE_SHA256 = (
    "fa288bdf5c5354661fd47ab9695314b0fa490fdc42c0b7ed76a5990ac234768f"
)
WEBLATE_W02_OVERLAY_BUNDLE = "w02-2026-11-14"
WEBLATE_W02_TEST_FILE_SHA256 = (
    "4d6d15f52d17318110bf908d5e6665bd35af9fe6dc0c1b1d06edb4f8a05b3f04"
)

DEFAULT_VDP_TEST_TIMEOUT_SECONDS = 300
DEFAULT_VDP_TEST_MAX_OUTPUT_BYTES = 262_144
DEFAULT_VDP_TEST_MAX_CPUS = 2
DEFAULT_VDP_TEST_MAX_MEMORY_MB = 6144
_OVERLAY_CONTAINER_PREFIX = "/src/vdp-test-overlay/"
_MAX_OVERLAY_FILE_BYTES = 256 * 1024

VDP_PRODUCT_TEST_ARG_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": ["target_profile"],
    "properties": {
        "target_profile": {
            "type": "string",
            "pattern": "^[a-z0-9][a-z0-9._-]{1,63}$",
        },
        "source_commit": {
            "type": "string",
            "pattern": "^[0-9a-f]{40}$",
        },
        "image_digest": {
            "type": "string",
            "pattern": "^sha256:[0-9a-f]{64}$",
        },
        "test_selectors": {
            "type": "array",
            "minItems": 1,
            "maxItems": 10,
            "items": {
                "type": "string",
                "pattern": "^[A-Za-z0-9_./:-]{3,240}$",
            },
        },
        "overlay_bundle": {
            "type": "string",
            "pattern": "^[a-z0-9][a-z0-9._-]{1,63}$",
        },
        "positive_selectors": {
            "type": "array",
            "maxItems": 10,
            "items": {
                "type": "string",
                "pattern": "^[A-Za-z0-9_./:-]{3,240}$",
            },
        },
        "negative_selectors": {
            "type": "array",
            "maxItems": 10,
            "items": {
                "type": "string",
                "pattern": "^[A-Za-z0-9_./:-]{3,240}$",
            },
        },
        "anomaly_repro_selectors": {
            "type": "array",
            "maxItems": 10,
            "items": {
                "type": "string",
                "pattern": "^[A-Za-z0-9_./:-]{3,240}$",
            },
        },
        "env_check_selectors": {
            "type": "array",
            "maxItems": 10,
            "items": {
                "type": "string",
                "pattern": "^[A-Za-z0-9_./:-]{3,240}$",
            },
        },
        "selector_roles": {
            "type": "object",
            "maxProperties": 20,
            "additionalProperties": {
                "type": "string",
                "enum": list(VALID_SELECTOR_ROLES),
            },
        },
        "test_context": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "sender_auth_state": {"type": "string", "maxLength": 160},
                "config_creation_path": {"type": "string", "maxLength": 160},
                "target_component": {"type": "string", "maxLength": 160},
                "confirmed_conditions": {
                    "type": "array",
                    "maxItems": 20,
                    "items": {"type": "string", "maxLength": 240},
                },
                "unverified_conditions": {
                    "type": "array",
                    "maxItems": 20,
                    "items": {"type": "string", "maxLength": 240},
                },
            },
        },
        "baseline_evidence_ref": {
            "type": "string",
            "pattern": "^[A-Za-z0-9_-]{3,80}$",
        },
        "timeout_seconds": {
            "type": "integer",
            "minimum": 5,
            "maximum": DEFAULT_VDP_TEST_TIMEOUT_SECONDS,
        },
        "cpus": {
            "type": "integer",
            "minimum": 1,
            "maximum": DEFAULT_VDP_TEST_MAX_CPUS,
        },
        "memory_mb": {
            "type": "integer",
            "minimum": 512,
            "maximum": DEFAULT_VDP_TEST_MAX_MEMORY_MB,
        },
        "network_mode": {
            "type": "string",
            "pattern": "^[a-z0-9_-]{1,32}$",
        },
    },
}

_WEBLATE_BASELINE_POSITIVE = (
    "weblate/trans/tests/test_search.py::BulkEditTest::"
    "test_replacement_processes_each_selected_translation_once"
)
_WEBLATE_BASELINE_NEGATIVE_BULK = (
    "weblate/trans/tests/test_search.py::BulkEditTest::"
    "test_bulk_edit_requires_bulk_permission_per_unit"
)
_WEBLATE_BASELINE_NEGATIVE_EDIT = (
    "weblate/trans/tests/test_edit.py::EditPropagateTest::"
    "test_edit_skips_restricted_propagated_component"
)
_WEBLATE_W01_CORE_POS = (
    "/src/vdp-test-overlay/test_w01.py::TestBulkPropagationPermission::"
    "test_positive_control_with_peer_permission"
)
_WEBLATE_W01_CORE_NEG = (
    "/src/vdp-test-overlay/test_w01.py::TestBulkPropagationPermission::"
    "test_restricted_peer_is_not_changed"
)
_WEBLATE_W01_HTTP_POS = (
    "/src/vdp-test-overlay/test_w01.py::TestBulkPropagationPermission::"
    "test_http_positive_control_with_peer_permission"
)
_WEBLATE_W01_HTTP_NEG = (
    "/src/vdp-test-overlay/test_w01.py::TestBulkPropagationPermission::"
    "test_http_restricted_peer_is_not_changed"
)
_WEBLATE_W02_UPSTREAM_NEG = (
    "weblate/api/tests.py::MemoryAPITest::"
    "test_delete_workspace_scope_requires_source_project_permission"
)
_WEBLATE_W02_UPSTREAM_COMPACTED = (
    "weblate/api/tests.py::MemoryAPITest::"
    "test_delete_removes_only_authorized_scope_from_compacted_entry"
)
_WEBLATE_W02_OVERLAY_SCOPE = (
    "/src/vdp-test-overlay/test_w02.py::TestMemoryCrossProjectScope::"
    "test_delete_preserves_foreign_project_scope"
)

_SELECTOR_RE = re.compile(r"^[A-Za-z0-9_./:-]{3,240}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PROFILE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_SERVICE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_ENV_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_SAFE_EXEC_PATH_RE = re.compile(r"^[A-Za-z0-9_./-]{1,160}$")
_SENSITIVE_MARKER_RE = re.compile(
    r"(?:SYNTHETIC_SECRET_[A-Za-z0-9_=-]*|CTF_SENSITIVE_MARKER[A-Za-z0-9_=-]*|(?:flag|ctf)\{[^}\r\n]*\}|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)",
    re.IGNORECASE,
)


def validate_vdp_selector_format(selector: str) -> str:
    """Validate that a pytest selector names an explicit test item with zero wildcards or flags."""
    cleaned = str(selector).strip()
    if (
        not cleaned
        or cleaned.startswith("-")
        or ".." in cleaned
        or "\\" in cleaned
        or any(ch in cleaned for ch in "*?[] \t\r\n")
        or not _SELECTOR_RE.fullmatch(cleaned)
        or ".py::" not in cleaned
    ):
        raise ContractViolationError(
            f"Invalid VDP pytest selector {selector!r}: must reference a specific <module>.py::<node> with no wildcards or flags."
        )
    return cleaned


class VdpOverlaySpec(StrictModel):
    """Server-side definition of an approved, synthetic-only read-only test overlay."""

    bundle_name: str = Field(min_length=1)
    host_dir: Path
    container_target: str = "/src/vdp-test-overlay"
    allowed_files: dict[str, str] = Field(default_factory=dict)


class VdpServiceSpec(StrictModel):
    """Server-side pinned internal dependency service for isolated offline VDP tests."""

    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,31}$")
    service_kind: Literal["postgres", "valkey", "redis", "generic_internal"] = "postgres"
    image_ref: str = Field(min_length=1)
    expected_image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    internal_port: int = Field(ge=1, le=65535)
    env: dict[str, str] = Field(default_factory=dict)
    client_env: dict[str, str] = Field(default_factory=dict)
    entrypoint: str | None = None
    command: tuple[str, ...] = ()
    readiness_command: tuple[str, ...] = ()
    readiness_timeout_seconds: int = Field(default=30, ge=2, le=60)
    cpus: int = Field(default=1, ge=1, le=2)
    memory_mb: int = Field(default=512, ge=128, le=2048)
    publish_ports: Literal[False] = False

    def to_public_summary(self) -> dict[str, Any]:
        """Return sanitized service specification omitting raw env values."""
        return {
            "name": self.name,
            "service_kind": self.service_kind,
            "image_ref": self.image_ref,
            "expected_image_digest": self.expected_image_digest,
            "internal_port": self.internal_port,
            "env_keys": sorted(self.env.keys()),
            "client_env_keys": sorted(self.client_env.keys()),
            "has_readiness_command": bool(self.readiness_command),
            "readiness_timeout_seconds": self.readiness_timeout_seconds,
            "cpus": self.cpus,
            "memory_mb": self.memory_mb,
            "publish_ports": False,
        }


class VdpTargetProfile(StrictModel):
    """Pinned product source/image/selector policy enforced server-side."""

    profile_name: str = Field(min_length=1)
    profile_revision: str = Field(default=WEBLATE_2026_11_2_PROFILE_REVISION, min_length=1)
    image_ref: str = Field(min_length=1)
    expected_image_digest: str = Field(pattern="^sha256:[0-9a-f]{64}$")
    expected_source_commit: str = Field(pattern="^[0-9a-f]{40}$")
    checkout_dir: Path | None = None
    network_mode: Literal["none", "isolated_internal_services"] = "none"
    services: tuple[VdpServiceSpec, ...] = ()
    runner_mode: Literal["oss_scanner", "direct_pytest"] = "oss_scanner"
    pytest_executable: str | None = None
    smoke_selectors: tuple[str, ...] = ()
    allowed_test_selectors: tuple[str, ...]
    positive_selectors: tuple[str, ...] = ()
    negative_selectors: tuple[str, ...] = ()
    anomaly_repro_selectors: tuple[str, ...] = ()
    env_check_selectors: tuple[str, ...] = ()
    selector_roles: dict[str, str] = Field(default_factory=dict)
    allowed_overlays: dict[str, VdpOverlaySpec] = Field(default_factory=dict)
    max_cpus: int = Field(default=DEFAULT_VDP_TEST_MAX_CPUS, ge=1)
    max_memory_mb: int = Field(default=DEFAULT_VDP_TEST_MAX_MEMORY_MB, ge=512)
    max_timeout_seconds: int = Field(default=DEFAULT_VDP_TEST_TIMEOUT_SECONDS, ge=5)
    max_output_bytes: int = Field(default=DEFAULT_VDP_TEST_MAX_OUTPUT_BYTES, ge=1024)
    expires_at: datetime | None = None

    def resolve_selector_role(self, selector: str) -> str | None:
        """Return canonical test role for ``selector`` if configured."""
        explicit = self.selector_roles.get(selector)
        if explicit in VALID_SELECTOR_ROLES:
            return explicit
        if selector in self.anomaly_repro_selectors:
            return "anomaly_repro"
        if selector in self.env_check_selectors:
            return "env_check"
        if selector in self.negative_selectors:
            return "defense_check"
        if selector in self.positive_selectors:
            return "positive_control"
        return None

    def resolve_selector_roles(self) -> dict[str, str]:
        """Return selector -> role mapping for all allowlisted selectors."""
        resolved: dict[str, str] = {}
        for sel in self.allowed_test_selectors:
            role = self.resolve_selector_role(sel)
            if role is not None:
                resolved[sel] = role
        return resolved

    def to_public_summary(self) -> dict[str, Any]:
        """Return sanitized profile metadata omitting internal host directory paths."""
        resolved_roles = self.resolve_selector_roles()
        return {
            "profile_name": self.profile_name,
            "profile_revision": self.profile_revision,
            "image_ref": self.image_ref,
            "expected_image_digest": self.expected_image_digest,
            "expected_source_commit": self.expected_source_commit,
            "network_mode": self.network_mode,
            "runner_mode": self.runner_mode,
            "pytest_executable": self.pytest_executable,
            "smoke_selectors": list(self.smoke_selectors),
            "services": [svc.to_public_summary() for svc in self.services],
            "allowed_test_selectors": list(self.allowed_test_selectors),
            "positive_selectors": list(self.positive_selectors),
            "negative_selectors": list(self.negative_selectors),
            "anomaly_repro_selectors": list(self.anomaly_repro_selectors),
            "env_check_selectors": list(self.env_check_selectors),
            "selector_roles": resolved_roles,
            "active_tests": [
                {"selector": sel, "role": resolved_roles.get(sel, "unassigned")}
                for sel in self.allowed_test_selectors
            ],
            "allowed_overlays": {
                name: {
                    "bundle_name": spec.bundle_name,
                    "container_target": spec.container_target,
                    "allowed_files": dict(spec.allowed_files),
                }
                for name, spec in sorted(self.allowed_overlays.items())
            },
            "max_cpus": self.max_cpus,
            "max_memory_mb": self.max_memory_mb,
            "max_timeout_seconds": self.max_timeout_seconds,
            "max_output_bytes": self.max_output_bytes,
            "expires_at": self.expires_at.isoformat() if self.expires_at is not None else None,
        }


def validate_vdp_profile_registration(profile: VdpTargetProfile) -> VdpTargetProfile:
    """Validate strict selector, role, digest, commit, overlay SHA-256, and bound constraints before saving."""
    if not _PROFILE_NAME_RE.fullmatch(profile.profile_name):
        raise ContractViolationError(
            f"Invalid profile_name {profile.profile_name!r}."
        )
    if not profile.allowed_test_selectors:
        raise ContractViolationError("VdpTargetProfile requires at least one allowlisted test selector.")

    cleaned_allowed = tuple(
        dict.fromkeys(validate_vdp_selector_format(s) for s in profile.allowed_test_selectors)
    )
    allowed_set = set(cleaned_allowed)
    cleaned_pos = tuple(dict.fromkeys(validate_vdp_selector_format(s) for s in profile.positive_selectors))
    cleaned_neg = tuple(dict.fromkeys(validate_vdp_selector_format(s) for s in profile.negative_selectors))
    cleaned_anom = tuple(dict.fromkeys(validate_vdp_selector_format(s) for s in profile.anomaly_repro_selectors))
    cleaned_env = tuple(dict.fromkeys(validate_vdp_selector_format(s) for s in profile.env_check_selectors))

    for label, group in (
        ("positive_selector", cleaned_pos),
        ("negative_selector", cleaned_neg),
        ("anomaly_repro_selector", cleaned_anom),
        ("env_check_selector", cleaned_env),
    ):
        for sel in group:
            if sel not in allowed_set:
                raise ContractViolationError(
                    f"{label} {sel!r} must be present in allowed_test_selectors."
                )

    cleaned_roles: dict[str, str] = {}
    for raw_sel, raw_role in profile.selector_roles.items():
        sel = validate_vdp_selector_format(raw_sel)
        if sel not in allowed_set:
            raise ContractViolationError(
                f"selector_roles key {sel!r} must be present in allowed_test_selectors."
            )
        role = str(raw_role).strip()
        if role not in VALID_SELECTOR_ROLES:
            raise ContractViolationError(
                f"Invalid selector role {raw_role!r} for {sel!r}; expected one of {VALID_SELECTOR_ROLES}."
            )
        cleaned_roles[sel] = role

    # Ensure anomaly_repro / env_check do not overlap with defense_check or positive_control,
    # while keeping W-02 self-contained positive+negative dual membership valid.
    pos_set = set(cleaned_pos)
    neg_set = set(cleaned_neg)
    anom_set = set(cleaned_anom)
    env_set = set(cleaned_env)
    for sel, role in cleaned_roles.items():
        if role == "anomaly_repro":
            anom_set.add(sel)
        elif role == "env_check":
            env_set.add(sel)
        elif role == "positive_control":
            pos_set.add(sel)
        elif role == "defense_check":
            neg_set.add(sel)

    if anom_set & env_set:
        raise ContractViolationError(
            "A selector cannot be assigned to both anomaly_repro and env_check."
        )
    if (anom_set | env_set) & (pos_set | neg_set):
        conflict = sorted((anom_set | env_set) & (pos_set | neg_set))
        raise ContractViolationError(
            f"Selectors {conflict!r} have conflicting role assignments."
        )
    for sel in cleaned_allowed:
        if sel in cleaned_roles:
            continue
        if sel in anom_set:
            cleaned_roles[sel] = "anomaly_repro"
        elif sel in env_set:
            cleaned_roles[sel] = "env_check"
        elif sel in neg_set:
            cleaned_roles[sel] = "defense_check"
        elif sel in pos_set:
            cleaned_roles[sel] = "positive_control"

    cleaned_pos = tuple(dict.fromkeys([*cleaned_pos, *(s for s, r in cleaned_roles.items() if r == "positive_control")]))
    cleaned_neg = tuple(dict.fromkeys([*cleaned_neg, *(s for s, r in cleaned_roles.items() if r == "defense_check")]))
    cleaned_anom = tuple(dict.fromkeys([*cleaned_anom, *(s for s, r in cleaned_roles.items() if r == "anomaly_repro")]))
    cleaned_env = tuple(dict.fromkeys([*cleaned_env, *(s for s, r in cleaned_roles.items() if r == "env_check")]))

    normalized_overlays: dict[str, VdpOverlaySpec] = {}
    for key, spec in profile.allowed_overlays.items():
        if not _PROFILE_NAME_RE.fullmatch(key) or key != spec.bundle_name:
            raise ContractViolationError(
                f"Overlay bundle key {key!r} must match sanitized bundle_name {spec.bundle_name!r}."
            )
        if spec.container_target != "/src/vdp-test-overlay":
            raise ContractViolationError(
                f"Overlay container_target must be '/src/vdp-test-overlay', got {spec.container_target!r}."
            )
        if not spec.allowed_files:
            raise ContractViolationError(
                f"Overlay bundle {spec.bundle_name!r} must pin at least one file SHA-256."
            )
        norm_files: dict[str, str] = {}
        for fname, digest in spec.allowed_files.items():
            if not fname or "/" in fname or "\\" in fname or ".." in fname:
                raise ContractViolationError(f"Invalid overlay filename {fname!r}.")
            low_digest = str(digest).strip().lower()
            if not _SHA256_RE.fullmatch(low_digest):
                raise ContractViolationError(
                    f"Overlay file {fname!r} must pin lowercase 64-hex SHA-256, got {digest!r}."
                )
            norm_files[fname] = low_digest
        normalized_overlays[key] = VdpOverlaySpec(
            bundle_name=spec.bundle_name,
            host_dir=spec.host_dir,
            container_target=spec.container_target,
            allowed_files=norm_files,
        )

    if profile.network_mode not in VALID_VDP_NETWORK_MODES:
        raise ContractViolationError(
            f"Unsupported VDP network_mode {profile.network_mode!r}; expected one of {VALID_VDP_NETWORK_MODES}."
        )
    if profile.runner_mode not in VALID_VDP_RUNNER_MODES:
        raise ContractViolationError(
            f"Unsupported VDP runner_mode {profile.runner_mode!r}; expected one of {VALID_VDP_RUNNER_MODES}."
        )

    cleaned_pytest_exec: str | None = None
    if profile.pytest_executable is not None and profile.pytest_executable.strip():
        cand_exec = profile.pytest_executable.strip()
        if ".." in cand_exec or not _SAFE_EXEC_PATH_RE.fullmatch(cand_exec):
            raise ContractViolationError(f"Unsafe pytest_executable {cand_exec!r}.")
        cleaned_pytest_exec = cand_exec
    elif profile.runner_mode == "direct_pytest":
        cleaned_pytest_exec = DEFAULT_DIRECT_PYTEST_EXECUTABLE

    cleaned_smoke_selectors = tuple(
        dict.fromkeys(validate_vdp_selector_format(s) for s in profile.smoke_selectors)
    )

    if profile.network_mode == "none" and profile.services:
        raise ContractViolationError(
            "VdpTargetProfile with network_mode='none' cannot declare dependency services."
        )

    normalized_services: list[VdpServiceSpec] = []
    if profile.network_mode == "isolated_internal_services":
        if not profile.services:
            raise ContractViolationError(
                "VdpTargetProfile with network_mode='isolated_internal_services' requires at least one pinned service."
            )
        if len(profile.services) > MAX_VDP_SERVICES_PER_PROFILE:
            raise ContractViolationError(
                f"At most {MAX_VDP_SERVICES_PER_PROFILE} internal services may be declared per profile."
            )
        seen_names: set[str] = set()
        for svc in profile.services:
            if not _SERVICE_NAME_RE.fullmatch(svc.name):
                raise ContractViolationError(f"Invalid VDP service name {svc.name!r}.")
            if svc.name in seen_names:
                raise ContractViolationError(f"Duplicate VDP service name {svc.name!r}.")
            seen_names.add(svc.name)
            if svc.publish_ports is not False:
                raise ContractViolationError(
                    f"VDP service {svc.name!r} cannot publish host ports (publish_ports must be False)."
                )
            for map_label, env_map in (("env", svc.env), ("client_env", svc.client_env)):
                if len(env_map) > 16:
                    raise ContractViolationError(
                        f"Service {svc.name!r} {map_label} cannot exceed 16 entries."
                    )
                for ek, ev in env_map.items():
                    ek_clean = str(ek).strip()
                    ev_str = str(ev)
                    if not _ENV_KEY_RE.fullmatch(ek_clean):
                        raise ContractViolationError(
                            f"Invalid {map_label} key {ek!r} for service {svc.name!r}."
                        )
                    if "\x00" in ev_str or len(ev_str) > 256 or _SENSITIVE_MARKER_RE.search(ev_str):
                        raise ContractViolationError(
                            f"Unsafe or oversized {map_label} value for key {ek_clean!r} on service {svc.name!r}."
                        )
            clean_ep: str | None = None
            if svc.entrypoint is not None and svc.entrypoint.strip():
                ep = svc.entrypoint.strip()
                if any(ch.isspace() or ch == "\x00" for ch in ep) or not _SAFE_EXEC_PATH_RE.fullmatch(ep):
                    raise ContractViolationError(
                        f"Unsafe entrypoint {ep!r} for service {svc.name!r}."
                    )
                clean_ep = ep
            if len(svc.command) > 32:
                raise ContractViolationError(
                    f"Service {svc.name!r} command exceeds 32 arguments."
                )
            for arg in svc.command:
                if "\x00" in str(arg) or len(str(arg)) > 512:
                    raise ContractViolationError(
                        f"Unsafe argument in command for service {svc.name!r}."
                    )
            if len(svc.readiness_command) > 16:
                raise ContractViolationError(
                    f"Service {svc.name!r} readiness_command exceeds 16 arguments."
                )
            for arg in svc.readiness_command:
                if "\x00" in str(arg) or len(str(arg)) > 256:
                    raise ContractViolationError(
                        f"Unsafe argument in readiness_command for service {svc.name!r}."
                    )
            normalized_services.append(
                VdpServiceSpec(
                    name=svc.name,
                    service_kind=svc.service_kind,
                    image_ref=svc.image_ref.strip(),
                    expected_image_digest=svc.expected_image_digest.strip().lower(),
                    internal_port=svc.internal_port,
                    env={str(k).strip(): str(v) for k, v in svc.env.items()},
                    client_env={str(k).strip(): str(v) for k, v in svc.client_env.items()},
                    entrypoint=clean_ep,
                    command=tuple(str(x) for x in svc.command),
                    readiness_command=tuple(str(x) for x in svc.readiness_command),
                    readiness_timeout_seconds=svc.readiness_timeout_seconds,
                    cpus=svc.cpus,
                    memory_mb=svc.memory_mb,
                    publish_ports=False,
                )
            )
        total_cpus = profile.max_cpus + sum(s.cpus for s in normalized_services)
        total_mem = profile.max_memory_mb + sum(s.memory_mb for s in normalized_services)
        if total_cpus > MAX_VDP_TOTAL_CPUS:
            raise ContractViolationError(
                f"Combined CPU cap ({total_cpus}) exceeds MAX_VDP_TOTAL_CPUS ({MAX_VDP_TOTAL_CPUS})."
            )
        if total_mem > MAX_VDP_TOTAL_MEMORY_MB:
            raise ContractViolationError(
                f"Combined memory cap ({total_mem} MiB) exceeds MAX_VDP_TOTAL_MEMORY_MB ({MAX_VDP_TOTAL_MEMORY_MB} MiB)."
            )

    return profile.model_copy(
        update={
            "pytest_executable": cleaned_pytest_exec,
            "smoke_selectors": cleaned_smoke_selectors,
            "services": tuple(normalized_services),
            "allowed_test_selectors": cleaned_allowed,
            "positive_selectors": cleaned_pos,
            "negative_selectors": cleaned_neg,
            "anomaly_repro_selectors": cleaned_anom,
            "env_check_selectors": cleaned_env,
            "selector_roles": cleaned_roles,
            "allowed_overlays": normalized_overlays,
        }
    )


def compute_vdp_profile_digest(profile: VdpTargetProfile) -> str:
    """Compute canonical SHA-256 digest of a ``VdpTargetProfile`` for CAS checks."""
    canonical = json.dumps(
        profile.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _get_profiles_thread_lock(lock_path: Path) -> threading.Lock:
    with _PROFILES_THREAD_LOCKS_GUARD:
        lock = _PROFILES_THREAD_LOCKS.get(lock_path)
        if lock is None:
            lock = threading.Lock()
            _PROFILES_THREAD_LOCKS[lock_path] = lock
        return lock


def _acquire_file_lock(fd: int, *, timeout_seconds: float = 30.0) -> None:
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_EX)
        return
    if sys.platform == "win32" and msvcrt is not None:
        if os.fstat(fd).st_size == 0:
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, b"\0")
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                return
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EDEADLK, errno.EAGAIN):
                    raise
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        "Timed out acquiring lock for VDP profiles store."
                    ) from exc
                time.sleep(0.01)


def _release_file_lock(fd: int) -> None:
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return
    if sys.platform == "win32" and msvcrt is not None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)


@contextmanager
def _vdp_profiles_lock(vault_path: Path) -> Iterator[None]:
    """Acquire an intra-process and cross-process exclusive lock on ``_vdp/profiles.json.lock``."""
    try:
        root_st = os.lstat(vault_path)
    except OSError as exc:
        raise PathSecurityError(f"Vault root is inaccessible: {exc}") from exc
    if _is_reparse_or_symlink(root_st) or not stat.S_ISDIR(root_st.st_mode):
        raise PathSecurityError("Vault root must be a non-symlink directory.")
    real_vault = Path(os.path.realpath(vault_path, strict=True))

    vdp_dir = real_vault / "_vdp"
    try:
        vdp_st = os.lstat(vdp_dir)
    except FileNotFoundError:
        try:
            os.mkdir(vdp_dir, 0o750)
        except FileExistsError:
            pass
        vdp_st = os.lstat(vdp_dir)
    except OSError as exc:
        raise PathSecurityError(f"Unable to inspect _vdp directory: {exc}") from exc
    if _is_reparse_or_symlink(vdp_st) or not stat.S_ISDIR(vdp_st.st_mode):
        raise PathSecurityError("Vault _vdp directory must be a non-symlink directory.")

    lock_path = Path(os.path.realpath(vdp_dir, strict=True)) / "profiles.json.lock"
    thread_lock = _get_profiles_thread_lock(lock_path)
    with thread_lock:
        try:
            existing_lock_st = os.lstat(lock_path)
        except FileNotFoundError:
            existing_lock_st = None
        except OSError as exc:
            raise PathSecurityError(f"Unable to inspect profiles lockfile: {exc}") from exc
        if existing_lock_st is not None and (
            _is_reparse_or_symlink(existing_lock_st) or not stat.S_ISREG(existing_lock_st.st_mode)
        ):
            raise PathSecurityError("VDP profiles lockfile cannot be a symlink or special file.")

        open_flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(lock_path, open_flags, 0o600)
        try:
            fd_st = os.fstat(fd)
            path_st = os.lstat(lock_path)
            if _is_reparse_or_symlink(path_st) or not stat.S_ISREG(fd_st.st_mode):
                raise PathSecurityError("VDP profiles lockfile is not a regular file.")
            if (fd_st.st_dev, fd_st.st_ino) != (path_st.st_dev, path_st.st_ino):
                raise PathSecurityError("VDP profiles lockfile changed during open.")
            _acquire_file_lock(fd)
            try:
                yield
            finally:
                _release_file_lock(fd)
        finally:
            os.close(fd)


def _load_registered_vdp_profiles_unlocked(vault_path: Path) -> dict[str, VdpTargetProfile]:
    target = vault_path / VDP_PROFILES_RELPATH
    if not target.exists():
        return {}
    raw = safe_read_bounded(
        vault_path,
        VDP_PROFILES_RELPATH,
        max_bytes=1_048_576,
        allow_truncate=False,
    )
    payload = json.loads(raw.data.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ContractViolationError("Registered VDP profiles file must be a JSON object.")
    profiles_raw = payload.get("profiles") or {}
    if not isinstance(profiles_raw, Mapping):
        raise ContractViolationError("Registered VDP profiles 'profiles' field must be an object.")
    loaded: dict[str, VdpTargetProfile] = {}
    for name, item in profiles_raw.items():
        prof = validate_vdp_profile_registration(VdpTargetProfile.model_validate(item))
        loaded[str(name)] = prof
    return loaded


def load_registered_vdp_profiles(vault_root: str | Path) -> dict[str, VdpTargetProfile]:
    """Load operator-registered VDP target profiles from ``<vault_root>/_vdp/profiles.json``."""
    vault_path = Path(vault_root)
    target = vault_path / VDP_PROFILES_RELPATH
    if not target.exists():
        return {}
    try:
        with _vdp_profiles_lock(vault_path):
            return _load_registered_vdp_profiles_unlocked(vault_path)
    except OSError as exc:
        if exc.errno in (errno.EROFS, errno.EACCES, errno.EPERM):
            return _load_registered_vdp_profiles_unlocked(vault_path)
        raise


def save_registered_vdp_profile(
    vault_root: str | Path,
    profile: VdpTargetProfile,
    *,
    expected_profile_revision: str | None | object = _UNSET,
    expected_profile_digest: str | None | object = _UNSET,
    disallow_existing_bundles: Sequence[str] = (),
) -> Path:
    """Validate and atomically persist an operator-registered ``VdpTargetProfile`` under ``vault_root``.

    Serializes read-check-write across threads and processes via an exclusive lockfile
    (``_vdp/profiles.json.lock``) and optionally enforces Compare-And-Swap preconditions
    (``expected_profile_revision``, ``expected_profile_digest``, ``disallow_existing_bundles``).
    """
    validated = validate_vdp_profile_registration(profile)
    vault_path = Path(vault_root)
    vault_path.mkdir(parents=True, exist_ok=True)
    with _vdp_profiles_lock(vault_path):
        existing = _load_registered_vdp_profiles_unlocked(vault_path)
        current = existing.get(validated.profile_name)

        if expected_profile_revision is not _UNSET:
            actual_rev = current.profile_revision if current is not None else None
            if actual_rev != expected_profile_revision:
                raise ContractViolationError(
                    f"Concurrent modification detected for VDP profile {validated.profile_name!r}: "
                    f"expected revision {expected_profile_revision!r}, found {actual_rev!r}. "
                    "Re-run preview/apply against the latest profile revision.",
                    code="profile_cas_conflict",
                    details={
                        "profile_name": validated.profile_name,
                        "expected_revision": expected_profile_revision,
                        "actual_revision": actual_rev,
                    },
                )

        if expected_profile_digest is not _UNSET:
            actual_digest = compute_vdp_profile_digest(current) if current is not None else None
            if actual_digest != expected_profile_digest:
                raise ContractViolationError(
                    f"Concurrent modification detected for VDP profile {validated.profile_name!r}: "
                    "stored profile state changed before save. Re-run preview/apply.",
                    code="profile_cas_conflict",
                    details={
                        "profile_name": validated.profile_name,
                        "expected_digest": expected_profile_digest,
                        "actual_digest": actual_digest,
                    },
                )

        if disallow_existing_bundles and current is not None:
            for bundle_name in disallow_existing_bundles:
                if bundle_name in current.allowed_overlays:
                    raise ContractViolationError(
                        f"Overlay bundle {bundle_name!r} already exists in {validated.profile_name!r}; "
                        "refusing overwrite.",
                        code="registration_overwrite_refused",
                        details={
                            "profile_name": validated.profile_name,
                            "overlay_bundle": bundle_name,
                        },
                    )

        existing[validated.profile_name] = validated
        data = {
            "schema_version": "vdp-profiles/1",
            "profiles": {
                name: prof.model_dump(mode="json")
                for name, prof in sorted(existing.items())
            },
        }
        return safe_write_atomic(
            vault_path,
            VDP_PROFILES_RELPATH,
            (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            overwrite=True,
            create_parents=True,
        )


def build_default_weblate_profile(
    *,
    overlay_host_dir: Path | None = None,
    w02_overlay_host_dir: Path | None = None,
    checkout_dir: Path | None = None,
) -> VdpTargetProfile:
    """Build the default pinned Weblate 2026.11.2 VDP scanner profile (W-01 + W-02)."""
    home = Path.home()
    resolved_w01_overlay = (
        overlay_host_dir
        if overlay_host_dir is not None
        else (home / "vdp-test-overlay" / WEBLATE_W01_OVERLAY_BUNDLE)
    )
    resolved_w02_overlay = (
        w02_overlay_host_dir
        if w02_overlay_host_dir is not None
        else (home / "vdp-test-overlay" / WEBLATE_W02_OVERLAY_BUNDLE)
    )
    resolved_checkout = (
        checkout_dir
        if checkout_dir is not None
        else (home / "vdp-weblate-2026.11.2")
    )
    return VdpTargetProfile(
        profile_name=WEBLATE_2026_11_2_PROFILE_NAME,
        profile_revision=WEBLATE_2026_11_2_PROFILE_REVISION,
        image_ref=WEBLATE_2026_11_2_IMAGE_REF,
        expected_image_digest=WEBLATE_2026_11_2_IMAGE_DIGEST,
        expected_source_commit=WEBLATE_2026_11_2_SOURCE_COMMIT,
        checkout_dir=resolved_checkout,
        allowed_test_selectors=(
            _WEBLATE_BASELINE_POSITIVE,
            _WEBLATE_BASELINE_NEGATIVE_BULK,
            _WEBLATE_BASELINE_NEGATIVE_EDIT,
            _WEBLATE_W01_CORE_POS,
            _WEBLATE_W01_CORE_NEG,
            _WEBLATE_W01_HTTP_POS,
            _WEBLATE_W01_HTTP_NEG,
            _WEBLATE_W02_UPSTREAM_NEG,
            _WEBLATE_W02_UPSTREAM_COMPACTED,
            _WEBLATE_W02_OVERLAY_SCOPE,
        ),
        positive_selectors=(
            _WEBLATE_BASELINE_POSITIVE,
            _WEBLATE_W01_CORE_POS,
            _WEBLATE_W01_HTTP_POS,
            _WEBLATE_W02_UPSTREAM_COMPACTED,
            _WEBLATE_W02_OVERLAY_SCOPE,
        ),
        negative_selectors=(
            _WEBLATE_BASELINE_NEGATIVE_BULK,
            _WEBLATE_BASELINE_NEGATIVE_EDIT,
            _WEBLATE_W01_CORE_NEG,
            _WEBLATE_W01_HTTP_NEG,
            _WEBLATE_W02_UPSTREAM_NEG,
            _WEBLATE_W02_UPSTREAM_COMPACTED,
            _WEBLATE_W02_OVERLAY_SCOPE,
        ),
        allowed_overlays={
            WEBLATE_W01_OVERLAY_BUNDLE: VdpOverlaySpec(
                bundle_name=WEBLATE_W01_OVERLAY_BUNDLE,
                host_dir=resolved_w01_overlay,
                container_target="/src/vdp-test-overlay",
                allowed_files={"test_w01.py": WEBLATE_W01_TEST_FILE_SHA256},
            ),
            WEBLATE_W02_OVERLAY_BUNDLE: VdpOverlaySpec(
                bundle_name=WEBLATE_W02_OVERLAY_BUNDLE,
                host_dir=resolved_w02_overlay,
                container_target="/src/vdp-test-overlay",
                allowed_files={"test_w02.py": WEBLATE_W02_TEST_FILE_SHA256},
            ),
        },
        max_cpus=DEFAULT_VDP_TEST_MAX_CPUS,
        max_memory_mb=DEFAULT_VDP_TEST_MAX_MEMORY_MB,
        max_timeout_seconds=DEFAULT_VDP_TEST_TIMEOUT_SECONDS,
        max_output_bytes=DEFAULT_VDP_TEST_MAX_OUTPUT_BYTES,
    )


def create_vdp_product_test_descriptor(
    *,
    enabled: bool = True,
    limits: CapabilityLimits | None = None,
    adapter_commit: str = VDP_PRODUCT_TEST_ADAPTER_COMMIT,
) -> CapabilityDescriptor:
    """Create the signed ``vdp.test`` capability descriptor for ``RunMode.VDP``."""
    return build_signed_descriptor(
        name=VDP_PRODUCT_TEST_CAPABILITY_NAME,
        adapter_id=VDP_PRODUCT_TEST_ADAPTER_ID,
        adapter_commit=adapter_commit,
        dependency_lock_sha256="c" * 64,
        operations=VDP_PRODUCT_TEST_OPERATIONS,
        arg_schema=VDP_PRODUCT_TEST_ARG_SCHEMA,
        execution_classes=(ExecutionClass.DYNAMIC,),
        required_scope={"mode": "vdp"},
        limits=limits
        or CapabilityLimits(
            timeout_seconds=DEFAULT_VDP_TEST_TIMEOUT_SECONDS,
            max_output_bytes=DEFAULT_VDP_TEST_MAX_OUTPUT_BYTES,
            max_decode_bytes=65_536,
        ),
        enabled=enabled,
        profile_modes=(RunMode.VDP,),
    )


class _ValidatedPlan(StrictModel):
    """Server-validated execution plan bound between preflight and execution."""

    profile_name: str
    profile_revision: str
    operation: str
    image_ref: str
    image_digest: str
    source_commit: str
    test_selectors: tuple[str, ...]
    positive_selectors: tuple[str, ...]
    negative_selectors: tuple[str, ...]
    anomaly_repro_selectors: tuple[str, ...] = ()
    env_check_selectors: tuple[str, ...] = ()
    selector_roles: dict[str, str] = Field(default_factory=dict)
    test_context: dict[str, Any] = Field(default_factory=dict)
    overlay_bundle: str | None = None
    overlay_host_dir: str | None = None
    overlay_container_target: str | None = None
    overlay_file_hashes: dict[str, str] = Field(default_factory=dict)
    cpus: int
    memory_mb: int
    timeout_seconds: int
    network_mode: str = "none"
    services: tuple[VdpServiceSpec, ...] = ()
    runner_mode: Literal["oss_scanner", "direct_pytest"] = "oss_scanner"
    pytest_executable: str | None = None
    smoke_selectors: tuple[str, ...] = ()
    baseline_evidence_ref: str | None = None


def _hash_regular_file(path: Path) -> str:
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise ScopeDeniedError(
            f"Overlay entry {path.name!r} is not a regular non-symlink file.",
            code="overlay_integrity_failed",
        )
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        fst = os.fstat(handle.fileno())
        if fst.st_ino != st.st_ino or fst.st_dev != st.st_dev:
            raise ScopeDeniedError(
                f"Overlay file {path.name!r} changed during verification.",
                code="overlay_integrity_failed",
            )
        total = 0
        while chunk := handle.read(65_536):
            total += len(chunk)
            if total > _MAX_OVERLAY_FILE_BYTES:
                raise ScopeDeniedError(
                    f"Overlay file {path.name!r} exceeds bounded overlay size.",
                    code="overlay_integrity_failed",
                )
            digest.update(chunk)
    return digest.hexdigest()


def _inspect_overlay_directory(
    spec: VdpOverlaySpec,
    *,
    require_exists: bool,
) -> tuple[Path | None, dict[str, str]]:
    """Verify overlay directory contains only allowlisted, hash-pinned synthetic files."""
    host_dir = spec.host_dir
    try:
        st = os.lstat(host_dir)
    except FileNotFoundError:
        if require_exists:
            return None, {}
        return None, {}
    except OSError as exc:
        raise ScopeDeniedError(
            f"Overlay directory for {spec.bundle_name!r} cannot be inspected: {exc}",
            code="overlay_integrity_failed",
        ) from exc

    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise ScopeDeniedError(
            f"Overlay directory for {spec.bundle_name!r} cannot be a symlink or non-directory.",
            code="overlay_integrity_failed",
        )

    real_dir = Path(os.path.realpath(host_dir, strict=True))
    observed_files: dict[str, str] = {}
    for entry in os.scandir(real_dir):
        if entry.name not in spec.allowed_files:
            raise ScopeDeniedError(
                f"Overlay directory {spec.bundle_name!r} contains unallowlisted entry {entry.name!r}.",
                code="overlay_integrity_failed",
            )
        entry_path = real_dir / entry.name
        est = os.lstat(entry_path)
        if stat.S_ISLNK(est.st_mode) or not stat.S_ISREG(est.st_mode):
            raise ScopeDeniedError(
                f"Overlay entry {entry.name!r} must be a regular non-symlink file.",
                code="overlay_integrity_failed",
            )
        actual_sha = _hash_regular_file(entry_path)
        expected_sha = spec.allowed_files[entry.name].lower()
        if actual_sha != expected_sha:
            raise ScopeDeniedError(
                f"Overlay file {entry.name!r} SHA-256 mismatch.",
                code="overlay_integrity_failed",
                details={"file": entry.name, "expected": expected_sha, "actual": actual_sha},
            )
        content_text = entry_path.read_text(encoding="utf-8", errors="replace")
        if re.search(
            r"(?:SYNTHETIC_SECRET_[A-Za-z0-9_=-]*|CTF_SENSITIVE_MARKER[A-Za-z0-9_=-]*|(?:flag|ctf)\{[^}\r\n]*\}|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)",
            content_text,
            re.IGNORECASE,
        ):
            raise ScopeDeniedError(
                f"Overlay file {entry.name!r} contains forbidden sensitive markers.",
                code="overlay_integrity_failed",
            )
        observed_files[entry.name] = actual_sha

    for expected_name in spec.allowed_files:
        if expected_name not in observed_files:
            if require_exists:
                return None, {}
            raise ScopeDeniedError(
                f"Overlay bundle {spec.bundle_name!r} is missing expected file {expected_name!r}.",
                code="overlay_integrity_failed",
            )

    return real_dir, observed_files


_COLLECTED_RE = re.compile(r"collected\s+(\d+)\s+items?")
_SUMMARY_COUNTS_RE = re.compile(
    r"=+\s*(?:.*?\b(\d+)\s+passed\b.*?)?(?:.*?\b(\d+)\s+failed\b.*?)?"
    r"(?:.*?\b(\d+)\s+skipped\b.*?)?(?:.*?\b(\d+)\s+errors?\b.*?)?in\s+[0-9.]+\s*s",
    re.IGNORECASE,
)
_COUNT_TOKEN_RE = re.compile(r"\b(\d+)\s+(passed|failed|skipped|errors?|xfailed|xpassed)\b", re.IGNORECASE)
_ITEM_RESULT_RE = re.compile(
    r"^([^\s]+\.py::[^\s]+)\s+(PASSED|FAILED|SKIPPED|ERROR|XFAIL|XPASS)\b",
    re.MULTILINE,
)
_SHORT_SUMMARY_RE = re.compile(
    r"^(PASSED|FAILED|ERROR|SKIPPED)\s+([^\s]+\.py::[^\s]+)\b",
    re.MULTILINE,
)
_EVIDENCE_MARKER_RE = re.compile(r"^VDP_EVIDENCE_MARKER:\s*(\{.*\})\s*$", re.MULTILINE)


class _VerdictResult(StrictModel):
    """Structured outcome classification produced from pytest results and selector roles."""

    verdict: str
    verdict_reason: str
    positive_passed: int = 0
    positive_failed: int = 0
    negative_passed: int = 0
    negative_failed: int = 0
    anomaly_repro_passed: int = 0
    anomaly_repro_failed: int = 0
    env_check_passed: int = 0
    env_check_failed: int = 0


def _extract_evidence_markers(text: str) -> dict[str, Any]:
    """Parse and merge redacted ``VDP_EVIDENCE_MARKER:{json}`` lines from stdout."""
    merged: dict[str, Any] = {}
    scenarios: list[Any] = []
    confirmed: list[str] = []
    unverified: list[str] = []
    for raw_json in _EVIDENCE_MARKER_RE.findall(text):
        try:
            obj = json.loads(raw_json)
        except Exception:
            continue
        if not isinstance(obj, dict):
            continue
        clean_obj = redact_structure(obj)
        for key in ("sender_auth_state", "config_creation_path", "target_component", "stage_verification", "state_diff"):
            if key in clean_obj and clean_obj[key] is not None:
                merged[key] = clean_obj[key]
        if isinstance(clean_obj.get("scenario_comparisons"), list):
            scenarios.extend(clean_obj["scenario_comparisons"])
        if isinstance(clean_obj.get("confirmed_conditions"), list):
            confirmed.extend(str(x) for x in clean_obj["confirmed_conditions"] if x)
        if isinstance(clean_obj.get("unverified_conditions"), list):
            unverified.extend(str(x) for x in clean_obj["unverified_conditions"] if x)
    if scenarios:
        merged["scenario_comparisons"] = scenarios
    if confirmed:
        merged["confirmed_conditions"] = list(dict.fromkeys(confirmed))
    if unverified:
        merged["unverified_conditions"] = list(dict.fromkeys(unverified))
    return merged


def _build_execution_context_and_conclusion(
    *,
    plan: _ValidatedPlan,
    verdict_res: _VerdictResult,
    parsed: Mapping[str, Any],
    marker_data: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build structured execution context and confirmed/unverified condition summaries."""
    ctx_arg = redact_structure(dict(plan.test_context))
    sender_auth_state = str(
        marker_data.get("sender_auth_state")
        or ctx_arg.get("sender_auth_state")
        or "unspecified"
    )
    config_creation_path = str(
        marker_data.get("config_creation_path")
        or ctx_arg.get("config_creation_path")
        or "unspecified"
    )
    target_component = str(
        marker_data.get("target_component")
        or ctx_arg.get("target_component")
        or "unspecified"
    )

    raw_stage = marker_data.get("stage_verification")
    stage_verification: dict[str, bool | None] = {
        "update_scheduled": (
            raw_stage.get("update_scheduled") if isinstance(raw_stage, Mapping) else None
        ),
        "sync_completed": (
            raw_stage.get("sync_completed") if isinstance(raw_stage, Mapping) else None
        ),
        "data_changed": (
            raw_stage.get("data_changed") if isinstance(raw_stage, Mapping) else None
        ),
    }

    execution_context: dict[str, Any] = {
        "sender_auth_state": sender_auth_state,
        "config_creation_path": config_creation_path,
        "target_component": target_component,
        "stage_verification": stage_verification,
        "scenario_comparisons": list(marker_data.get("scenario_comparisons") or []),
        "state_diff": dict(marker_data.get("state_diff") or {}),
    }

    confirmed: list[str] = []
    unverified: list[str] = []
    verdict = verdict_res.verdict

    if plan.network_mode == "isolated_internal_services" and verdict not in {"not_executed", "environment_failure", "timeout"}:
        confirmed.append("isolated_internal_service_network_no_external_egress")
        unverified.append("isolated_internal_service_ephemeral_topology")
    if verdict_res.positive_passed >= 1:
        confirmed.append("baseline_positive_control_passed")
    if verdict == "smoke_passed":
        confirmed.append("product_smoke_passed")
    elif verdict == "hypothesis_falsified":
        confirmed.append("defense_check_passed:boundary_defended_under_test_conditions")
        unverified.append("celery_eager_test_settings_async_unverified")
    elif verdict == "anomaly_observed":
        confirmed.append("anomaly_repro_passed:specified_behavior_observed")
        low_path = config_creation_path.lower()
        if config_creation_path == "unspecified" or "bypass" in low_path or "direct_model_save" in low_path:
            unverified.append("normal_ui_api_config_reachability_unverified")
        else:
            confirmed.append(f"config_creation_path:{config_creation_path}")
        if stage_verification["update_scheduled"] is True:
            confirmed.append("stage_update_scheduled_confirmed")
        elif stage_verification["update_scheduled"] is None:
            unverified.append("stage_update_scheduled_unverified")
        if stage_verification["sync_completed"] is True:
            confirmed.append("stage_sync_completed_confirmed")
        else:
            unverified.append("stage_sync_completed_unverified")
        if stage_verification["data_changed"] is True:
            confirmed.append("stage_data_changed_confirmed")
        else:
            unverified.append("stage_data_changed_unverified")
        unverified.append("vulnerability_eligibility_and_impact_require_separate_assessment")
    elif verdict == "inconclusive" and int(parsed.get("failed_count") or 0) > 0:
        unverified.append("assertion_failure_root_cause_uninspected")
        unverified.append("setup_or_assertion_failure_not_vulnerability_proof")
    elif verdict in {"skipped", "not_executed", "timeout", "environment_failure"}:
        unverified.append(f"non_conclusive_execution:{verdict}")

    for item in marker_data.get("confirmed_conditions") or ():
        confirmed.append(str(item))
    for item in ctx_arg.get("confirmed_conditions") or ():
        confirmed.append(str(item))
    for item in marker_data.get("unverified_conditions") or ():
        unverified.append(str(item))
    for item in ctx_arg.get("unverified_conditions") or ():
        unverified.append(str(item))

    confirmed = list(dict.fromkeys(confirmed))
    unverified = list(dict.fromkeys(unverified))

    if verdict == "anomaly_observed":
        all_e2e_confirmed = (
            "normal_ui_api_config_reachability_unverified" not in unverified
            and stage_verification["update_scheduled"] is True
            and stage_verification["sync_completed"] is True
            and stage_verification["data_changed"] is True
        )
        summary_ja = (
            "通常設定経路での異常挙動・更新予約・同期完了・データ変更を確認済み（脆弱性該当性と影響評価は別判定）"
            if all_e2e_confirmed
            else "照合等の指定した異常挙動は再現したが、通常設定での到達と実害（同期完了・データ変更）は未確認"
        )
    elif verdict == "hypothesis_falsified":
        summary_ja = "指定したテスト条件では防御境界が守られたことを確認済み"
    elif verdict == "baseline_failed":
        summary_ja = "正常系（ベースライン）が不成立のため、防御確認・異常再現とも未成立"
    elif verdict == "inconclusive":
        summary_ja = (
            "失敗したアサーションと原因を確認するまで inconclusive"
            "（セットアップ失敗やアサーション失敗を脆弱性の証拠にしない）"
        )
    elif verdict == "smoke_passed":
        summary_ja = "公式 smoke チェックが成功"
    elif verdict == "env_check_passed":
        summary_ja = "環境確認テストが成功（防御確認や異常再現は別実行）"
    elif verdict == "baseline_passed":
        summary_ja = "正常系（ベースライン）チェックのみ成功"
    else:
        summary_ja = (
            f"未確定状態（verdict={verdict}）のため、防御成功にも異常再現にも数えない"
        )

    conclusion_status = {
        "confirmed_conditions": confirmed,
        "unverified_conditions": unverified,
        "finding_qualification": "separate_assessment_required_not_judged_from_pass_count",
        "summary_ja": summary_ja,
    }
    return execution_context, conclusion_status


def _parse_pytest_counts_line(line: str) -> dict[str, int]:
    counts = {"passed": 0, "failed": 0, "skipped": 0, "error": 0}
    for num_str, label in _COUNT_TOKEN_RE.findall(line):
        num = int(num_str)
        low = label.lower()
        if low == "passed":
            counts["passed"] += num
        elif low == "failed":
            counts["failed"] += num
        elif low == "skipped":
            counts["skipped"] += num
        elif low.startswith("error"):
            counts["error"] += num
    return counts


def _parse_pytest_output(
    text: str,
    *,
    requested_selectors: tuple[str, ...],
    operation: str,
) -> dict[str, Any]:
    """Extract collection, summary counts, and per-selector statuses from pytest output."""
    if operation == "run_smoke":
        collected_matches = [int(m) for m in _COLLECTED_RE.findall(text)]
        positive_collections = [c for c in collected_matches if c > 0]
        collected_count = sum(positive_collections)
        passed = 0
        failed = 0
        skipped = 0
        error = 0
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("====") and " in " in stripped and (
                "passed" in stripped or "failed" in stripped or "skipped" in stripped or "error" in stripped
            ):
                parsed = _parse_pytest_counts_line(stripped)
                passed += parsed["passed"]
                failed += parsed["failed"]
                skipped += parsed["skipped"]
                error += parsed["error"]
        expected_exit4 = "ERROR: file or directory not found: /nonexistent-oss-scanner-test.py" in text
        return {
            "collected_count": collected_count,
            "passed_count": passed,
            "failed_count": failed,
            "skipped_count": skipped,
            "error_count": error,
            "selector_outcomes": {
                "smoke_session_collections": positive_collections,
                "negative_exit4_check": expected_exit4,
            },
        }

    collected_matches = [int(m) for m in _COLLECTED_RE.findall(text)]
    collected_count = collected_matches[-1] if collected_matches else 0
    passed = 0
    failed = 0
    skipped = 0
    error = 0
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("====") and " in " in stripped and (
            "passed" in stripped
            or "failed" in stripped
            or "skipped" in stripped
            or "error" in stripped
            or "no tests ran" in stripped
        ):
            counts = _parse_pytest_counts_line(stripped)
            passed = counts["passed"]
            failed = counts["failed"]
            skipped = counts["skipped"]
            error = counts["error"]

    raw_item_statuses: dict[str, str] = {}
    for nodeid, status_tok in _ITEM_RESULT_RE.findall(text):
        raw_item_statuses[nodeid.strip()] = status_tok.lower()
    for status_tok, nodeid in _SHORT_SUMMARY_RE.findall(text):
        raw_item_statuses[nodeid.strip()] = status_tok.lower()

    selector_outcomes: dict[str, str] = {}
    for sel in requested_selectors:
        if sel in raw_item_statuses:
            selector_outcomes[sel] = raw_item_statuses[sel]
            continue
        # Match normalized suffix if container path prefix (/src/) differs slightly.
        normalized = sel.lstrip("/")
        matched_status = None
        for nodeid, st in raw_item_statuses.items():
            if nodeid == sel or nodeid.lstrip("/") == normalized or normalized.endswith(nodeid) or nodeid.endswith(normalized):
                matched_status = st
                break
        selector_outcomes[sel] = matched_status or "not_run"

    return {
        "collected_count": collected_count,
        "passed_count": passed,
        "failed_count": failed,
        "skipped_count": skipped,
        "error_count": error,
        "selector_outcomes": selector_outcomes,
    }


def _classify_verdict(
    *,
    operation: str,
    outcome: SubprocessOutcome,
    exit_code: int | None,
    cleanup_confirmed: bool,
    parsed: Mapping[str, Any],
    positive_selectors: tuple[str, ...],
    negative_selectors: tuple[str, ...],
    anomaly_repro_selectors: tuple[str, ...] = (),
    env_check_selectors: tuple[str, ...] = (),
    has_valid_baseline_ref: bool = False,
) -> _VerdictResult:
    """Classify run outcome strictly by selector roles without conflating failures with defense/repro."""
    collected = int(parsed["collected_count"])
    passed = int(parsed["passed_count"])
    failed = int(parsed["failed_count"])
    skipped = int(parsed["skipped_count"])
    error = int(parsed["error_count"])
    sel_outcomes = parsed["selector_outcomes"]

    if outcome == SubprocessOutcome.TIMEOUT:
        return _VerdictResult(
            verdict="timeout",
            verdict_reason="Execution exceeded bounded wall-clock timeout and was terminated.",
        )
    if outcome == SubprocessOutcome.CANCELLED:
        return _VerdictResult(
            verdict="not_executed",
            verdict_reason="Execution was cancelled before completion.",
        )
    if not cleanup_confirmed:
        return _VerdictResult(
            verdict="environment_failure",
            verdict_reason="Child process or Docker container cleanup could not be confirmed.",
        )

    if operation == "run_smoke":
        if exit_code == 0 and passed > 0 and failed == 0 and error == 0 and skipped == 0:
            return _VerdictResult(
                verdict="smoke_passed",
                verdict_reason=f"Official scanner smoke passed ({passed} checks passed across smoke sessions).",
                positive_passed=passed,
            )
        return _VerdictResult(
            verdict="environment_failure",
            verdict_reason=(
                f"Official scanner smoke failed (exit_code={exit_code}, passed={passed}, "
                f"failed={failed}, skipped={skipped}, error={error})."
            ),
        )

    pos_passed = sum(1 for s in positive_selectors if sel_outcomes.get(s) == "passed")
    pos_failed = sum(1 for s in positive_selectors if sel_outcomes.get(s) in {"failed", "error"})
    neg_passed = sum(1 for s in negative_selectors if sel_outcomes.get(s) == "passed")
    neg_failed = sum(1 for s in negative_selectors if sel_outcomes.get(s) in {"failed", "error"})
    anom_passed = sum(1 for s in anomaly_repro_selectors if sel_outcomes.get(s) == "passed")
    anom_failed = sum(1 for s in anomaly_repro_selectors if sel_outcomes.get(s) in {"failed", "error"})
    env_passed = sum(1 for s in env_check_selectors if sel_outcomes.get(s) == "passed")
    env_failed = sum(1 for s in env_check_selectors if sel_outcomes.get(s) in {"failed", "error"})

    base_counts = dict(
        positive_passed=pos_passed,
        positive_failed=pos_failed,
        negative_passed=neg_passed,
        negative_failed=neg_failed,
        anomaly_repro_passed=anom_passed,
        anomaly_repro_failed=anom_failed,
        env_check_passed=env_passed,
        env_check_failed=env_failed,
    )

    if exit_code in {125, 126, 127}:
        return _VerdictResult(
            verdict="environment_failure",
            verdict_reason=f"Container or test runner environment failed (outcome={outcome.value}, exit_code={exit_code}).",
            **base_counts,
        )

    # Pytest exit codes >= 2 indicate internal error, usage error, interrupted, or zero items collected.
    if exit_code is None or exit_code >= 2 or error > 0:
        if collected == 0 and (exit_code in {0, 5} or "collected 0 items" in str(parsed)):
            return _VerdictResult(
                verdict="not_executed",
                verdict_reason="Pytest collected 0 items; no product test cases executed.",
                **base_counts,
            )
        return _VerdictResult(
            verdict="environment_failure",
            verdict_reason=f"Product test runner encountered environment/setup failure (exit_code={exit_code}, errors={error}).",
            **base_counts,
        )

    if collected == 0 or (passed == 0 and failed == 0 and skipped == 0 and error == 0):
        return _VerdictResult(
            verdict="not_executed",
            verdict_reason="Pytest collected 0 items; no product test cases executed.",
            **base_counts,
        )

    has_skips = skipped > 0 or any(v == "skipped" for v in sel_outcomes.values() if isinstance(v, str))
    if has_skips:
        if passed == 0 and failed == 0:
            return _VerdictResult(
                verdict="skipped",
                verdict_reason=(
                    f"Selected product tests were skipped (skipped={skipped}); "
                    "skipping is neither defense success nor anomaly reproduction."
                ),
                **base_counts,
            )
        return _VerdictResult(
            verdict="inconclusive",
            verdict_reason=(
                f"Test execution included skipped items (skipped={skipped}); "
                "refusing to count partial execution as defense success or anomaly reproduction."
            ),
            **base_counts,
        )

    # Critical baseline guard: failed positive control invalidates both defense checks and anomaly observations.
    if pos_failed > 0:
        return _VerdictResult(
            verdict="baseline_failed",
            verdict_reason=(
                "Baseline positive control failed; boundary defense or anomaly reproduction "
                "cannot be concluded when normal operation fails."
            ),
            **base_counts,
        )

    # P0 rule: Any assertion failure requires root-cause inspection -> inconclusive (never auto-proof of vulnerability).
    if failed > 0 or neg_failed > 0 or anom_failed > 0 or env_failed > 0:
        return _VerdictResult(
            verdict="inconclusive",
            verdict_reason=(
                "One or more test assertions failed; inspect the failed assertion and root cause "
                "before concluding boundary failure or vulnerability reproduction. Setup or assertion "
                "failure is not proof of a vulnerability."
            ),
            **base_counts,
        )

    if passed > 0 and exit_code == 0:
        if (
            env_check_selectors
            and not positive_selectors
            and not negative_selectors
            and not anomaly_repro_selectors
            and env_passed >= len(env_check_selectors)
        ):
            return _VerdictResult(
                verdict="env_check_passed",
                verdict_reason=f"Environment check test(s) passed ({env_passed} passed).",
                **base_counts,
            )

        baseline_ok = pos_passed >= 1 or has_valid_baseline_ref
        if (negative_selectors or anomaly_repro_selectors) and not baseline_ok:
            return _VerdictResult(
                verdict="baseline_failed",
                verdict_reason=(
                    "No passing positive control established (in this run or via baseline_evidence_ref); "
                    "refusing to classify defense success or anomaly reproduction without a verified baseline."
                ),
                **base_counts,
            )

        if anomaly_repro_selectors and anom_passed >= 1:
            if anom_passed < len(anomaly_repro_selectors):
                return _VerdictResult(
                    verdict="inconclusive",
                    verdict_reason="Not all requested anomaly_repro selectors completed and passed.",
                    **base_counts,
                )
            return _VerdictResult(
                verdict="anomaly_observed",
                verdict_reason=(
                    "Baseline positive control and anomaly reproduction test(s) passed: specified "
                    "anomalous behavior was observed under test conditions. Vulnerability qualification, "
                    "normal-configuration reachability, and real impact require separate assessment."
                ),
                **base_counts,
            )

        if negative_selectors and neg_passed >= 1:
            if neg_passed < len(negative_selectors):
                return _VerdictResult(
                    verdict="inconclusive",
                    verdict_reason="Not all requested defense_check selectors completed and passed.",
                    **base_counts,
                )
            return _VerdictResult(
                verdict="hypothesis_falsified",
                verdict_reason=(
                    "Positive control and defense check test(s) passed under test conditions "
                    "(boundary defended under tested conditions)."
                ),
                **base_counts,
            )

        if positive_selectors and pos_passed >= 1:
            return _VerdictResult(
                verdict="baseline_passed",
                verdict_reason=f"Positive baseline check(s) passed ({pos_passed} passed).",
                **base_counts,
            )

        return _VerdictResult(
            verdict="inconclusive",
            verdict_reason=(
                "Executed tests succeeded but no selector roles were assigned; assign test roles "
                "(positive_control / defense_check / anomaly_repro / env_check) before classifying outcome."
            ),
            **base_counts,
        )

    return _VerdictResult(
        verdict="environment_failure",
        verdict_reason=f"Unclassified test outcome (exit_code={exit_code}, passed={passed}, failed={failed}, skipped={skipped}).",
        **base_counts,
    )


def _encode_bounded_evidence_json(payload: dict[str, Any], max_bytes: int) -> tuple[bytes, bool]:
    """Encode JSON evidence, trimming ``log_excerpt`` cleanly to stay within ``max_bytes``."""
    raw = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
    if len(raw) <= max_bytes:
        return raw, bool(payload.get("log_truncated", False))

    bounded = dict(payload)
    bounded["log_truncated"] = True
    excerpt = str(bounded.get("log_excerpt") or "")
    lo, hi = 0, len(excerpt)
    best_bytes: bytes | None = None
    while lo <= hi:
        mid = (lo + hi) // 2
        bounded["log_excerpt"] = excerpt[:mid]
        candidate = json.dumps(bounded, indent=2, ensure_ascii=False).encode("utf-8")
        if len(candidate) <= max_bytes:
            best_bytes = candidate
            lo = mid + 1
        else:
            hi = mid - 1

    if best_bytes is not None:
        return best_bytes, True

    bounded["log_excerpt"] = ""
    candidate = json.dumps(bounded, indent=2, ensure_ascii=False).encode("utf-8")
    if len(candidate) <= max_bytes:
        return candidate, True
    if "execution_context" in bounded and isinstance(bounded["execution_context"], dict):
        bounded["execution_context"] = {
            **bounded["execution_context"],
            "scenario_comparisons": [],
            "state_diff": {},
        }
        candidate = json.dumps(bounded, indent=2, ensure_ascii=False).encode("utf-8")
        if len(candidate) <= max_bytes:
            return candidate, True
    bounded["selector_outcomes"] = {}
    return json.dumps(bounded, ensure_ascii=False).encode("utf-8")[:max_bytes], True


def _resolve_plan_selector_groups(
    *,
    profile: VdpTargetProfile,
    raw_selectors: tuple[str, ...],
    allowed_set: set[str],
    arguments: Mapping[str, Any],
) -> tuple[
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    dict[str, str],
]:
    """Validate and resolve per-selector roles without allowing silent role inversion."""
    pos_arg = arguments.get("positive_selectors")
    neg_arg = arguments.get("negative_selectors")
    anom_arg = arguments.get("anomaly_repro_selectors")
    env_arg = arguments.get("env_check_selectors")
    roles_arg = arguments.get("selector_roles")

    profile_roles = profile.resolve_selector_roles()
    dual_pos_neg = set(profile.positive_selectors) & set(profile.negative_selectors)
    raw_set = set(raw_selectors)

    def _validate_arg_list(arg_val: Any, label: str) -> tuple[str, ...] | None:
        if arg_val is None:
            return None
        cleaned = tuple(str(x).strip() for x in arg_val)
        for s in cleaned:
            if s not in allowed_set or (raw_selectors and s not in raw_set):
                raise ScopeDeniedError(
                    f"{label} {s!r} must be allowlisted and included in test_selectors.",
                    code="selector_not_allowlisted",
                )
        return cleaned

    pos_list = _validate_arg_list(pos_arg, "positive_selector")
    neg_list = _validate_arg_list(neg_arg, "negative_selector")
    anom_list = _validate_arg_list(anom_arg, "anomaly_repro_selector")
    env_list = _validate_arg_list(env_arg, "env_check_selector")

    caller_roles: dict[str, str] = {}
    if isinstance(roles_arg, Mapping):
        for raw_s, raw_r in roles_arg.items():
            sel = str(raw_s).strip()
            role = str(raw_r).strip()
            if sel not in allowed_set or (raw_selectors and sel not in raw_set):
                raise ScopeDeniedError(
                    f"selector_roles key {sel!r} must be allowlisted and included in test_selectors.",
                    code="selector_not_allowlisted",
                )
            if role not in VALID_SELECTOR_ROLES:
                raise ScopeDeniedError(
                    f"Unsupported selector role {role!r} for {sel!r}.",
                    code="selector_role_conflict",
                )
            caller_roles[sel] = role

    def _check_profile_conflict(sel: str, requested_role: str) -> None:
        registered = profile_roles.get(sel)
        if registered is None:
            return
        if sel in dual_pos_neg and requested_role in {"positive_control", "defense_check"}:
            return
        if registered != requested_role:
            raise ScopeDeniedError(
                f"Selector {sel!r} is registered with role {registered!r} and cannot be run as {requested_role!r}.",
                code="selector_role_conflict",
                details={"selector": sel, "registered_role": registered, "requested_role": requested_role},
            )

    for sel, role in caller_roles.items():
        _check_profile_conflict(sel, role)
    for role, group in (
        ("positive_control", pos_list or ()),
        ("defense_check", neg_list or ()),
        ("anomaly_repro", anom_list or ()),
        ("env_check", env_list or ()),
    ):
        for sel in group:
            _check_profile_conflict(sel, role)
            prev = caller_roles.get(sel)
            if prev is not None and prev != role and sel not in dual_pos_neg:
                raise ScopeDeniedError(
                    f"Conflicting roles {prev!r} and {role!r} supplied for selector {sel!r}.",
                    code="selector_role_conflict",
                )
            caller_roles.setdefault(sel, role)

    effective_roles: dict[str, str] = {}
    for sel in raw_selectors:
        role = caller_roles.get(sel) or profile_roles.get(sel)
        if role is not None:
            effective_roles[sel] = role

    pos_selectors = (
        pos_list
        if pos_list is not None
        else tuple(
            s
            for s in raw_selectors
            if (s in profile.positive_selectors or effective_roles.get(s) == "positive_control")
            and effective_roles.get(s) not in {"anomaly_repro", "env_check"}
        )
    )
    neg_selectors = (
        neg_list
        if neg_list is not None
        else tuple(
            s
            for s in raw_selectors
            if (s in profile.negative_selectors or effective_roles.get(s) == "defense_check")
            and effective_roles.get(s) not in {"anomaly_repro", "env_check"}
        )
    )
    anom_selectors = (
        anom_list
        if anom_list is not None
        else tuple(
            s
            for s in raw_selectors
            if s in profile.anomaly_repro_selectors or effective_roles.get(s) == "anomaly_repro"
        )
    )
    env_selectors = (
        env_list
        if env_list is not None
        else tuple(
            s
            for s in raw_selectors
            if s in profile.env_check_selectors or effective_roles.get(s) == "env_check"
        )
    )
    return pos_selectors, neg_selectors, anom_selectors, env_selectors, effective_roles


def run_vdp_environment_check(
    profile: VdpTargetProfile,
    *,
    runner: SubprocessRunner | None = None,
    docker_bin: str | None = None,
    git_bin: str | None = None,
    overlay_bundle: str | None = None,
    include_host_paths: bool = False,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    """Run fast non-destructive preflight checks for profile, Docker image, checkout, and overlays."""
    sub_runner = runner or SubprocessRunner()
    now = (clock or (lambda: datetime.now(UTC)))()
    checks: dict[str, str] = {
        "profile": "ok",
        "docker_image": "ok",
        "service_images": "ok" if profile.services else "skipped",
        "checkout": "skipped",
        "overlays": "ok",
    }
    checked_services: dict[str, dict[str, Any]] = {}
    issues: list[dict[str, str]] = []

    if profile.expires_at is not None and now >= profile.expires_at:
        checks["profile"] = "failed"
        issues.append(
            {
                "component": "profile",
                "code": "target_profile_expired",
                "cause": f"Profile {profile.profile_name!r} expired at {profile.expires_at.isoformat()}.",
                "remediation": (
                    f"Re-register {profile.profile_name!r} with a future --expires-at using "
                    "`ctf-mcp-admin register-vdp-profile`."
                ),
            }
        )

    # 1. Docker CLI + daemon + pinned image digest
    resolved_docker = docker_bin.strip() if docker_bin is not None else (shutil.which("docker") or "")
    if not resolved_docker:
        checks["docker_image"] = "failed"
        issues.append(
            {
                "component": "docker_image",
                "code": "docker_cli_missing",
                "cause": "Docker CLI is not available on PATH / configured host.",
                "remediation": "Install/enable Docker CLI in the execution host environment.",
            }
        )
    else:
        inspect_res = sub_runner.run(
            [resolved_docker, "image", "inspect", "--format", "{{.Id}}", profile.image_ref],
            timeout_seconds=15.0,
            max_output_bytes=4096,
        )
        if inspect_res.outcome != SubprocessOutcome.COMPLETED or inspect_res.returncode != 0:
            err_msg = inspect_res.stderr.decode("utf-8", errors="replace").strip() or "docker image inspect failed"
            checks["docker_image"] = "failed"
            issues.append(
                {
                    "component": "docker_image",
                    "code": "docker_image_unavailable",
                    "cause": f"Could not inspect {profile.image_ref!r}: {err_msg[:200]}",
                    "remediation": (
                        f"Ensure Docker daemon is running and image {profile.image_ref!r} "
                        f"({profile.expected_image_digest}) is built or loaded."
                    ),
                }
            )
        else:
            observed_digest = inspect_res.stdout.decode("utf-8", errors="replace").strip().lower()
            if observed_digest != profile.expected_image_digest:
                checks["docker_image"] = "failed"
                issues.append(
                    {
                        "component": "docker_image",
                        "code": "image_digest_mismatch",
                        "cause": (
                            f"Image {profile.image_ref!r} digest {observed_digest!r} "
                            f"mismatches pinned {profile.expected_image_digest!r}."
                        ),
                        "remediation": (
                            "Rebuild/tag the pinned scanner image or register an explicit profile revision "
                            "if the image update is intentional."
                        ),
                    }
                )

    # 1b. Declared internal service images (when profile.services is configured)
    for svc in profile.services:
        if not resolved_docker:
            checks["service_images"] = "failed"
            checked_services[svc.name] = {"status": "failed", "code": "docker_cli_missing"}
            continue
        svc_insp = sub_runner.run(
            [resolved_docker, "image", "inspect", "--format", "{{.Id}}", svc.image_ref],
            timeout_seconds=15.0,
            max_output_bytes=4096,
        )
        if svc_insp.outcome != SubprocessOutcome.COMPLETED or svc_insp.returncode != 0:
            err_msg = svc_insp.stderr.decode("utf-8", errors="replace").strip() or "docker image inspect failed"
            checks["service_images"] = "failed"
            checked_services[svc.name] = {
                "status": "failed",
                "code": "service_image_unavailable",
                "image_ref": svc.image_ref,
            }
            issues.append(
                {
                    "component": f"service:{svc.name}",
                    "code": "service_image_unavailable",
                    "cause": f"Could not inspect service image {svc.image_ref!r}: {err_msg[:200]}",
                    "remediation": (
                        f"Ensure service image {svc.image_ref!r} ({svc.expected_image_digest}) is built or loaded."
                    ),
                }
            )
        else:
            obs_svc_digest = svc_insp.stdout.decode("utf-8", errors="replace").strip().lower()
            if obs_svc_digest != svc.expected_image_digest:
                checks["service_images"] = "failed"
                checked_services[svc.name] = {
                    "status": "failed",
                    "code": "service_image_digest_mismatch",
                    "image_ref": svc.image_ref,
                    "observed_digest": obs_svc_digest,
                }
                issues.append(
                    {
                        "component": f"service:{svc.name}",
                        "code": "service_image_digest_mismatch",
                        "cause": (
                            f"Service {svc.name!r} image {svc.image_ref!r} digest {obs_svc_digest!r} "
                            f"mismatches pinned {svc.expected_image_digest!r}."
                        ),
                        "remediation": "Rebuild/tag the pinned service image or register an explicit profile revision.",
                    }
                )
            else:
                checked_services[svc.name] = {
                    "status": "ok",
                    "image_ref": svc.image_ref,
                    "image_digest": obs_svc_digest,
                    "publish_ports": False,
                }

    # 2. Local checkout commit & clean tracked tree (when configured)
    resolved_git = git_bin.strip() if git_bin is not None else (shutil.which("git") or "")
    if profile.checkout_dir is not None:
        if not profile.checkout_dir.exists():
            checks["checkout"] = "failed"
            loc = str(profile.checkout_dir) if include_host_paths else "<checkout_dir>"
            issues.append(
                {
                    "component": "checkout",
                    "code": "checkout_dir_missing",
                    "cause": f"Configured checkout directory {loc} does not exist.",
                    "remediation": (
                        f"Clone/checkout commit {profile.expected_source_commit} at the pinned checkout_dir "
                        "or clear --checkout-dir if checking out elsewhere."
                    ),
                }
            )
        elif not resolved_git:
            checks["checkout"] = "failed"
            issues.append(
                {
                    "component": "checkout",
                    "code": "git_cli_missing",
                    "cause": "Git CLI is unavailable to verify checkout commit.",
                    "remediation": "Install `git` on the execution host.",
                }
            )
        else:
            head_res = sub_runner.run(
                [resolved_git, "-C", str(profile.checkout_dir), "rev-parse", "HEAD"],
                timeout_seconds=10.0,
                max_output_bytes=4096,
            )
            actual_head = head_res.stdout.decode("utf-8", errors="replace").strip().lower()
            if head_res.outcome != SubprocessOutcome.COMPLETED or head_res.returncode != 0:
                checks["checkout"] = "failed"
                issues.append(
                    {
                        "component": "checkout",
                        "code": "checkout_git_error",
                        "cause": "Unable to read HEAD commit from configured checkout_dir.",
                        "remediation": "Verify checkout_dir is a valid Git worktree.",
                    }
                )
            elif actual_head != profile.expected_source_commit:
                checks["checkout"] = "failed"
                issues.append(
                    {
                        "component": "checkout",
                        "code": "source_commit_mismatch",
                        "cause": (
                            f"Checkout HEAD {actual_head!r} mismatches pinned {profile.expected_source_commit!r}."
                        ),
                        "remediation": f"Run `git checkout {profile.expected_source_commit}` in checkout_dir.",
                    }
                )
            else:
                dirty_res = sub_runner.run(
                    [resolved_git, "-C", str(profile.checkout_dir), "status", "--porcelain", "--untracked-files=no"],
                    timeout_seconds=10.0,
                    max_output_bytes=8192,
                )
                if dirty_res.returncode == 0 and dirty_res.stdout.strip():
                    checks["checkout"] = "failed"
                    issues.append(
                        {
                            "component": "checkout",
                            "code": "checkout_dirty",
                            "cause": "Pinned source checkout has uncommitted tracked modifications.",
                            "remediation": "Restore clean tracked tree (`git checkout -- .`) before product testing.",
                        }
                    )
                else:
                    checks["checkout"] = "ok"

    # 3. Overlay bundle integrity checks
    target_bundles = (
        [overlay_bundle]
        if overlay_bundle is not None
        else sorted(profile.allowed_overlays.keys())
    )
    checked_overlays: dict[str, dict[str, Any]] = {}
    for bname in target_bundles:
        spec = profile.allowed_overlays.get(bname)
        if spec is None:
            checks["overlays"] = "failed"
            checked_overlays[bname] = {"status": "failed", "code": "overlay_not_allowlisted"}
            issues.append(
                {
                    "component": f"overlay:{bname}",
                    "code": "overlay_not_allowlisted",
                    "cause": f"Overlay bundle {bname!r} is not allowlisted in profile {profile.profile_name!r}.",
                    "remediation": "Specify an allowlisted overlay_bundle or register this bundle via `ctf-mcp-admin register-vdp-profile`.",
                }
            )
            continue
        try:
            real_dir, observed = _inspect_overlay_directory(spec, require_exists=True)
        except ScopeDeniedError as exc:
            checks["overlays"] = "failed"
            err_detail = str(exc) if include_host_paths else redact_sensitive_text(str(exc))
            checked_overlays[bname] = {"status": "failed", "code": exc.code, "details": exc.details}
            issues.append(
                {
                    "component": f"overlay:{bname}",
                    "code": exc.code,
                    "cause": err_detail,
                    "remediation": (
                        f"Restore expected files for bundle {bname!r}, or run "
                        f"`ctf-mcp-admin register-vdp-profile --profile-name {profile.profile_name} "
                        f"--overlay-bundle {bname} --dry-run` if the update is intentional."
                    ),
                }
            )
            continue
        if real_dir is None:
            checks["overlays"] = "failed"
            loc = str(spec.host_dir) if include_host_paths else "<overlay_host_dir>"
            checked_overlays[bname] = {"status": "failed", "code": "overlay_missing"}
            issues.append(
                {
                    "component": f"overlay:{bname}",
                    "code": "overlay_missing",
                    "cause": (
                        f"Overlay bundle {bname!r} directory or pinned file(s) missing at {loc}."
                    ),
                    "remediation": (
                        f"Ensure overlay files {sorted(spec.allowed_files.keys())} exist in {loc}."
                    ),
                }
            )
        else:
            entry_info: dict[str, Any] = {
                "status": "ok",
                "file_hashes": observed,
            }
            if include_host_paths:
                entry_info["host_dir"] = str(real_dir)
            checked_overlays[bname] = entry_info

    healthy = (
        checks["profile"] == "ok"
        and checks["docker_image"] == "ok"
        and checks["service_images"] in {"ok", "skipped"}
        and checks["checkout"] in {"ok", "skipped"}
        and checks["overlays"] == "ok"
    )
    resolved_roles = profile.resolve_selector_roles()
    return {
        "schema": "vdp-environment-check/1",
        "checked_at": now.isoformat(),
        "profile_name": profile.profile_name,
        "profile_revision": profile.profile_revision,
        "network_mode": profile.network_mode,
        "runner_mode": profile.runner_mode,
        "expected_source_commit": profile.expected_source_commit,
        "expected_image_digest": profile.expected_image_digest,
        "healthy": healthy,
        "checks": checks,
        "checked_services": checked_services,
        "checked_overlays": checked_overlays,
        "active_tests": [
            {"selector": s, "role": resolved_roles.get(s, "unassigned")}
            for s in profile.allowed_test_selectors
        ],
        "issues": issues,
    }


class VdpProductTestAdapter(BaseAdapter):
    """Server-validated Docker scanner adapter for bounded VDP real-code verification."""

    def __init__(
        self,
        *,
        descriptor: CapabilityDescriptor | None = None,
        evidence_vault: EvidenceVaultPort | None = None,
        runner: SubprocessRunner | None = None,
        profiles: Mapping[str, VdpTargetProfile] | None = None,
        vault_root: str | Path | None = None,
        docker_bin: str | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        desc = descriptor or create_vdp_product_test_descriptor()
        super().__init__(
            desc,
            runner=runner,
            evidence_vault=evidence_vault,
            require_running_state=True,
        )
        default_profile = build_default_weblate_profile()
        self._profiles: dict[str, VdpTargetProfile] = (
            {k: v for k, v in profiles.items()}
            if profiles is not None
            else {default_profile.profile_name: default_profile}
        )
        self._vault_root: Path | None = Path(vault_root) if vault_root is not None else None
        self._docker_bin = docker_bin
        self._clock = clock or (lambda: datetime.now(UTC))
        self._preflight_lock = threading.Lock()
        self._preflight_plans: dict[str, _ValidatedPlan] = {}

    def get_profiles(self) -> dict[str, VdpTargetProfile]:
        """Return merged built-in and operator-registered VDP target profiles."""
        merged = dict(self._profiles)
        if self._vault_root is not None:
            merged.update(load_registered_vdp_profiles(self._vault_root))
        return merged

    def register_profile(self, profile: VdpTargetProfile) -> VdpTargetProfile:
        """Validate, cache, and optionally persist an operator-approved VDP target profile."""
        validated = validate_vdp_profile_registration(profile)
        self._profiles[validated.profile_name] = validated
        if self._vault_root is not None:
            save_registered_vdp_profile(self._vault_root, validated)
        return validated

    def list_public_profiles(self) -> list[dict[str, Any]]:
        """Return sanitized public summaries of all active VDP profiles."""
        return [
            prof.to_public_summary()
            for _, prof in sorted(self.get_profiles().items())
        ]

    def _build_invocation(
        self,
        action: ActionRecord,
        *,
        artifact_paths: dict[str, Path],
    ) -> tuple[list[str], dict[str, str] | None, Path | None]:
        del action, artifact_paths
        raise NotImplementedError(
            "VdpProductTestAdapter executes via execute_with_capture."
        )

    def _resolve_docker_bin(self) -> str | None:
        if self._docker_bin is not None:
            candidate = self._docker_bin.strip()
            return candidate or None
        return shutil.which("docker")

    def _validate_and_build_plan(
        self,
        *,
        operation: str,
        arguments: Mapping[str, Any],
        policy: ScopePolicy,
        require_overlay_exists: bool,
    ) -> _ValidatedPlan:
        if policy.mode != RunMode.VDP:
            raise ScopeDeniedError(
                f"vdp.test requires run mode 'vdp', got {policy.mode.value!r}.",
                code="scope_denied",
            )
        if policy.external_submission:
            raise ScopeDeniedError(
                "vdp.test forbids external_submission=True scopes.",
                code="scope_denied",
            )

        profile_name = str(arguments.get("target_profile") or "").strip()
        all_profiles = self.get_profiles()
        profile = all_profiles.get(profile_name)
        if profile is None:
            hint_profile = next(
                (p for p in all_profiles.values() if p.profile_revision == profile_name),
                None,
            )
            if hint_profile is not None:
                raise ScopeDeniedError(
                    (
                        f"target_profile {profile_name!r} is a profile_revision, not a profile_name. "
                        f"Pass target_profile={hint_profile.profile_name!r} instead."
                    ),
                    code="target_profile_denied",
                    details={
                        "target_profile": profile_name,
                        "hint_profile_name": hint_profile.profile_name,
                        "profile_revision": hint_profile.profile_revision,
                    },
                )
            raise ScopeDeniedError(
                f"target_profile {profile_name!r} is not allowlisted on this host.",
                code="target_profile_denied",
            )
        if operation != "check_environment" and profile.expires_at is not None and self._clock() >= profile.expires_at:
            raise ScopeDeniedError(
                f"target_profile {profile_name!r} expired at {profile.expires_at.isoformat()}.",
                code="target_profile_expired",
            )

        if operation in {"describe_profile", "check_environment"}:
            if operation == "check_environment":
                net_arg = arguments.get("network_mode")
                if net_arg is not None:
                    req_net = str(net_arg).strip().lower()
                    if req_net not in VALID_VDP_NETWORK_MODES or req_net != profile.network_mode:
                        raise ScopeDeniedError(
                            f"vdp.test profile {profile.profile_name!r} requires network_mode={profile.network_mode!r}, got {net_arg!r}.",
                            code="network_mode_denied",
                        )
            overlay_arg = arguments.get("overlay_bundle")
            overlay_bundle_opt = str(overlay_arg).strip() if overlay_arg else None
            if overlay_bundle_opt is not None and overlay_bundle_opt not in profile.allowed_overlays:
                raise ScopeDeniedError(
                    f"overlay_bundle {overlay_bundle_opt!r} is not allowlisted for profile {profile_name!r}.",
                    code="overlay_not_allowlisted",
                )
            return _ValidatedPlan(
                profile_name=profile.profile_name,
                profile_revision=profile.profile_revision,
                operation=operation,
                image_ref=profile.image_ref,
                image_digest=profile.expected_image_digest,
                source_commit=profile.expected_source_commit,
                test_selectors=(),
                positive_selectors=(),
                negative_selectors=(),
                anomaly_repro_selectors=(),
                env_check_selectors=(),
                selector_roles={},
                test_context={},
                overlay_bundle=overlay_bundle_opt,
                overlay_host_dir=None,
                overlay_container_target=None,
                overlay_file_hashes={},
                cpus=profile.max_cpus,
                memory_mb=profile.max_memory_mb,
                timeout_seconds=profile.max_timeout_seconds,
                network_mode=profile.network_mode,
                services=profile.services,
                runner_mode=profile.runner_mode,
                pytest_executable=profile.pytest_executable,
                smoke_selectors=profile.smoke_selectors,
                baseline_evidence_ref=None,
            )

        raw_net_mode = arguments.get("network_mode")
        network_mode = (
            profile.network_mode
            if raw_net_mode is None or not str(raw_net_mode).strip()
            else str(raw_net_mode).strip().lower()
        )
        if network_mode not in VALID_VDP_NETWORK_MODES or network_mode != profile.network_mode:
            raise ScopeDeniedError(
                f"vdp.test profile {profile.profile_name!r} requires network_mode={profile.network_mode!r}, got {network_mode!r}.",
                code="network_mode_denied",
            )

        source_commit = str(arguments.get("source_commit") or "").strip().lower()
        if source_commit != profile.expected_source_commit:
            raise ScopeDeniedError(
                f"source_commit {source_commit!r} does not match pinned commit {profile.expected_source_commit!r}.",
                code="source_commit_mismatch",
            )

        image_digest = str(arguments.get("image_digest") or "").strip().lower()
        if image_digest != profile.expected_image_digest:
            raise ScopeDeniedError(
                f"image_digest {image_digest!r} does not match pinned image {profile.expected_image_digest!r}.",
                code="image_digest_mismatch",
            )

        raw_selectors = tuple(str(x).strip() for x in (arguments.get("test_selectors") or ()))
        if operation == "run_smoke":
            if raw_selectors:
                raise ScopeDeniedError(
                    "run_smoke does not accept custom test_selectors.",
                    code="selector_not_allowlisted",
                )
            if profile.runner_mode == "direct_pytest" and not profile.smoke_selectors:
                raise ScopeDeniedError(
                    "run_smoke with runner_mode='direct_pytest' requires registered smoke_selectors.",
                    code="selector_not_allowlisted",
                )
        elif operation == "run_pytest":
            if not raw_selectors:
                raise ScopeDeniedError(
                    "run_pytest requires at least one allowlisted selector in test_selectors.",
                    code="selector_not_allowlisted",
                )
        else:
            raise ScopeDeniedError(
                f"Unsupported vdp.test operation {operation!r}.",
                code="capability_denied",
            )

        allowed_set = set(profile.allowed_test_selectors)
        needs_overlay = False
        for sel in raw_selectors:
            if not sel or sel.startswith("-") or ".." in sel or "\\" in sel:
                raise ScopeDeniedError(
                    f"Malformed or unsafe test selector {sel!r}.",
                    code="selector_not_allowlisted",
                )
            if sel not in allowed_set:
                raise ScopeDeniedError(
                    f"Test selector {sel!r} is not allowlisted for profile {profile_name!r}.",
                    code="selector_not_allowlisted",
                )
            if sel.startswith(_OVERLAY_CONTAINER_PREFIX):
                needs_overlay = True
        if operation == "run_smoke" and profile.runner_mode == "direct_pytest":
            if any(sel.startswith(_OVERLAY_CONTAINER_PREFIX) for sel in profile.smoke_selectors):
                needs_overlay = True

        overlay_bundle_raw = arguments.get("overlay_bundle")
        overlay_bundle = str(overlay_bundle_raw).strip() if overlay_bundle_raw else None
        if needs_overlay and not overlay_bundle:
            if len(profile.allowed_overlays) == 1 and operation == "run_smoke":
                overlay_bundle = next(iter(profile.allowed_overlays))
            else:
                raise ScopeDeniedError(
                    "Selectors under /src/vdp-test-overlay/ require an allowlisted overlay_bundle.",
                    code="overlay_not_allowlisted",
                )

        overlay_host_dir: str | None = None
        overlay_container_target: str | None = None
        overlay_file_hashes: dict[str, str] = {}
        if overlay_bundle is not None:
            overlay_spec = profile.allowed_overlays.get(overlay_bundle)
            if overlay_spec is None:
                raise ScopeDeniedError(
                    f"overlay_bundle {overlay_bundle!r} is not allowlisted for profile {profile_name!r}.",
                    code="overlay_not_allowlisted",
                )
            real_dir, hashes = _inspect_overlay_directory(
                overlay_spec,
                require_exists=require_overlay_exists,
            )
            if real_dir is not None:
                overlay_host_dir = str(real_dir)
                overlay_container_target = overlay_spec.container_target
                overlay_file_hashes = hashes

        pos_selectors, neg_selectors, anom_selectors, env_selectors, effective_roles = (
            _resolve_plan_selector_groups(
                profile=profile,
                raw_selectors=raw_selectors,
                allowed_set=allowed_set,
                arguments=arguments,
            )
        )
        raw_ctx = arguments.get("test_context")
        test_context = redact_structure(dict(raw_ctx)) if isinstance(raw_ctx, Mapping) else {}

        cpus = min(
            int(arguments.get("cpus") or profile.max_cpus),
            profile.max_cpus,
        )
        memory_mb = min(
            int(arguments.get("memory_mb") or profile.max_memory_mb),
            profile.max_memory_mb,
        )
        timeout_seconds = min(
            int(arguments.get("timeout_seconds") or profile.max_timeout_seconds),
            profile.max_timeout_seconds,
        )
        baseline_ref = arguments.get("baseline_evidence_ref")

        return _ValidatedPlan(
            profile_name=profile.profile_name,
            profile_revision=profile.profile_revision,
            operation=operation,
            image_ref=profile.image_ref,
            image_digest=profile.expected_image_digest,
            source_commit=profile.expected_source_commit,
            test_selectors=raw_selectors,
            positive_selectors=pos_selectors,
            negative_selectors=neg_selectors,
            anomaly_repro_selectors=anom_selectors,
            env_check_selectors=env_selectors,
            selector_roles=effective_roles,
            test_context=test_context,
            overlay_bundle=overlay_bundle,
            overlay_host_dir=overlay_host_dir,
            overlay_container_target=overlay_container_target,
            overlay_file_hashes=overlay_file_hashes,
            cpus=cpus,
            memory_mb=memory_mb,
            timeout_seconds=timeout_seconds,
            network_mode=network_mode,
            services=profile.services,
            runner_mode=profile.runner_mode,
            pytest_executable=profile.pytest_executable,
            smoke_selectors=profile.smoke_selectors,
            baseline_evidence_ref=str(baseline_ref).strip() if baseline_ref else None,
        )

    def preflight_request(
        self,
        *,
        run_id: str,
        operation: str,
        arguments: Mapping[str, Any],
        policy: ScopePolicy,
    ) -> _ValidatedPlan:
        """Validate pinned profile, digest, commit, network_mode, selectors, and overlay before budget/action mutation."""
        del run_id
        return self._validate_and_build_plan(
            operation=operation,
            arguments=arguments,
            policy=policy,
            require_overlay_exists=False,
        )

    def bind_preflight_target(
        self,
        action_id: str,
        target: Any,
        policy: ScopePolicy,
    ) -> None:
        del policy
        if isinstance(target, _ValidatedPlan):
            with self._preflight_lock:
                self._preflight_plans[action_id] = target

    def clear_preflight(self, action_id: str) -> None:
        with self._preflight_lock:
            self._preflight_plans.pop(action_id, None)

    def _store_json_evidence(
        self,
        *,
        action: ActionRecord,
        payload: dict[str, Any],
        max_bytes: int,
        force_incomplete_reason: str | None = None,
        source_hashes: tuple[str, ...],
    ) -> tuple[bytes, bool, str | None, tuple[EvidenceRef, ...]]:
        encoded, was_trimmed = _encode_bounded_evidence_json(payload, max_bytes)
        capture_complete = force_incomplete_reason is None and not was_trimmed
        omission_reason = force_incomplete_reason or (
            "output_truncated_at_max_output_bytes" if was_trimmed else None
        )
        refs: tuple[EvidenceRef, ...] = ()
        if self._evidence_vault is not None:
            manifest = self._evidence_vault.store_raw(
                run_id=action.run_id,
                owner_principal_id=action.principal_id,
                action_id=action.action_id,
                data=encoded,
                media_type="application/json; charset=utf-8",
                capture_complete=capture_complete,
                omission_reason=omission_reason,
                source_artifact_hashes=source_hashes,
                adapter_revision=self._descriptor.adapter_commit,
                sanitized_args_sha256=action.canonical_args_sha256,
            )
            refs = (
                EvidenceRef(
                    id=manifest.evidence_id,
                    sha256=manifest.view_sha256,
                    kind="tool_output",
                ),
            )
        return encoded, capture_complete, omission_reason, refs

    def _ensure_container_removed(
        self,
        docker_bin: str,
        container_name: str,
        *,
        remove_volumes: bool = False,
    ) -> bool:
        """Ensure named container no longer exists, forcing removal if needed."""
        rm_argv = [docker_bin, "rm", "-f", *(["-v"] if remove_volumes else ()), container_name]
        for _ in range(3):
            ps_res = self._runner.run(
                [docker_bin, "ps", "-aq", "--filter", f"name=^/{container_name}$"],
                timeout_seconds=10.0,
                max_output_bytes=8192,
            )
            if ps_res.outcome == SubprocessOutcome.COMPLETED and ps_res.returncode == 0:
                if not ps_res.stdout.decode("utf-8", errors="replace").strip():
                    return True
            self._runner.run(
                rm_argv,
                timeout_seconds=15.0,
                max_output_bytes=8192,
            )
            time.sleep(0.1)
        ps_final = self._runner.run(
            [docker_bin, "ps", "-aq", "--filter", f"name=^/{container_name}$"],
            timeout_seconds=10.0,
            max_output_bytes=8192,
        )
        return (
            ps_final.outcome == SubprocessOutcome.COMPLETED
            and ps_final.returncode == 0
            and not ps_final.stdout.decode("utf-8", errors="replace").strip()
        )

    def _ensure_network_removed(self, docker_bin: str, network_name: str) -> bool:
        """Ensure dedicated internal Docker network is removed after execution."""
        for _ in range(3):
            ls_res = self._runner.run(
                [docker_bin, "network", "ls", "-q", "--filter", f"name=^{network_name}$"],
                timeout_seconds=10.0,
                max_output_bytes=4096,
            )
            if ls_res.outcome == SubprocessOutcome.COMPLETED and ls_res.returncode == 0:
                if not ls_res.stdout.decode("utf-8", errors="replace").strip():
                    return True
            self._runner.run(
                [docker_bin, "network", "rm", network_name],
                timeout_seconds=15.0,
                max_output_bytes=4096,
            )
            time.sleep(0.1)
        ls_final = self._runner.run(
            [docker_bin, "network", "ls", "-q", "--filter", f"name=^{network_name}$"],
            timeout_seconds=10.0,
            max_output_bytes=4096,
        )
        return (
            ls_final.outcome == SubprocessOutcome.COMPLETED
            and ls_final.returncode == 0
            and not ls_final.stdout.decode("utf-8", errors="replace").strip()
        )

    def _verify_container_no_published_ports(self, docker_bin: str, container_name: str) -> tuple[bool, int]:
        """Inspect container PortBindings and verify zero host ports are published."""
        insp = self._runner.run(
            [docker_bin, "inspect", "--format", "{{json .HostConfig.PortBindings}}", container_name],
            timeout_seconds=10.0,
            max_output_bytes=4096,
        )
        if insp.outcome != SubprocessOutcome.COMPLETED or insp.returncode != 0:
            return False, -1
        raw = insp.stdout.decode("utf-8", errors="replace").strip()
        try:
            parsed = json.loads(raw) if raw else {}
        except Exception:
            return False, -1
        if parsed is None:
            return True, 0
        if isinstance(parsed, Mapping):
            non_empty = {k: v for k, v in parsed.items() if v}
            return len(non_empty) == 0, len(non_empty)
        return False, -1

    def _build_synthetic_subprocess_result(
        self,
        *,
        outcome: SubprocessOutcome,
        returncode: int | None,
        data: bytes,
        wall_ms: int,
        capture_complete: bool,
        omission_reason: str | None,
        cleanup_confirmed: bool,
        cleanup_detail: str | None = None,
        process_start_id: str | None = None,
        cpu_ms: int | None = None,
        peak_rss_bytes: int | None = None,
    ) -> SubprocessResult:
        return SubprocessResult(
            outcome=outcome,
            returncode=returncode,
            stdout=data,
            stderr=b"",
            wall_ms=wall_ms,
            output_bytes=len(data),
            bytes_observed=len(data),
            capture_complete=capture_complete,
            omission_reason=omission_reason,
            cleanup_confirmed=cleanup_confirmed,
            cleanup_detail=cleanup_detail,
            process_start_id=process_start_id,
            cpu_ms=cpu_ms,
            peak_rss_bytes=peak_rss_bytes,
        )

    def _has_valid_baseline_evidence(
        self,
        *,
        action: ActionRecord,
        plan: _ValidatedPlan,
    ) -> bool:
        """Check whether ``baseline_evidence_ref`` points to a complete passing positive baseline."""
        if not plan.baseline_evidence_ref or self._evidence_vault is None:
            return False
        read_fn = getattr(self._evidence_vault, "read_view_bytes", None)
        if not callable(read_fn):
            return False
        try:
            view, raw = read_fn(
                run_id=action.run_id,
                principal_id=action.principal_id,
                evidence_id=plan.baseline_evidence_ref,
            )
            if not getattr(view, "capture_complete", False):
                return False
            parsed = json.loads(raw.decode("utf-8", errors="strict"))
        except Exception:
            return False
        if not isinstance(parsed, dict):
            return False
        return (
            parsed.get("schema") == "vdp-product-test-evidence/1"
            and parsed.get("source_commit") == plan.source_commit
            and parsed.get("image_digest") == plan.image_digest
            and parsed.get("network_mode") == plan.network_mode
            and int(parsed.get("positive_passed") or 0) >= 1
            and int(parsed.get("positive_failed") or 0) == 0
        )

    def execute_with_capture(
        self,
        action: ActionRecord,
        *,
        artifact_paths: dict[str, Any] | None = None,
        source_artifact_hashes: Sequence[str] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> AdapterExecutionOutcome:
        del artifact_paths
        validate_action_request_inputs(
            self._descriptor,
            action,
            require_running=self._require_running_state,
        )
        with self._preflight_lock:
            plan = self._preflight_plans.get(action.action_id)
        if plan is None:
            # Direct call outside controller: enforce VDP defaults fail-closed.
            fallback_policy = ScopePolicy(
                scope_revision=action.scope_revision,
                scope_sha256="0" * 64,
                mode=RunMode.VDP,
                task_id="direct-vdp-test",
                authorization_reference="direct-adapter-validation",
                allowed_execution_classes=(ExecutionClass.DYNAMIC,),
                allowed_capabilities=(VDP_PRODUCT_TEST_CAPABILITY_NAME,),
                network_enabled=False,
                external_submission=False,
            )
            plan = self._validate_and_build_plan(
                operation=action.operation,
                arguments=action.sanitized_args,
                policy=fallback_policy,
                require_overlay_exists=(action.operation != "check_environment"),
            )

        profile = self.get_profiles()[plan.profile_name]
        started_at = self._clock().isoformat()
        timeout_cap, max_bytes = self.compute_effective_limits(action)
        eff_timeout = min(timeout_cap, float(plan.timeout_seconds))

        if plan.operation == "describe_profile":
            desc_payload: dict[str, Any] = {
                "schema": "vdp-profile-description/1",
                **profile.to_public_summary(),
            }
            encoded, capture_complete, omission_reason, evidence_refs = self._store_json_evidence(
                action=action,
                payload=desc_payload,
                max_bytes=max_bytes,
                force_incomplete_reason=None,
                source_hashes=(),
            )
            envelope = ResultEnvelope(
                run_id=action.run_id,
                action_id=action.action_id,
                status=EnvelopeStatus.OK,
                summary=(
                    f"vdp.test:describe_profile profile={profile.profile_name} "
                    f"revision={profile.profile_revision} "
                    f"selectors={len(profile.allowed_test_selectors)} "
                    f"overlays={len(profile.allowed_overlays)}."
                ),
                evidence=evidence_refs,
                truncated=not capture_complete,
                next_cursor=None,
                error=None,
                usage=UsageMetrics(wall_ms=0, output_bytes=len(encoded)),
                provenance=ProvenanceInfo(
                    adapter_revision=self._descriptor.adapter_commit,
                    scope_revision=action.scope_revision,
                ),
            )
            norm_sub = self._build_synthetic_subprocess_result(
                outcome=SubprocessOutcome.COMPLETED,
                returncode=0,
                data=encoded,
                wall_ms=0,
                capture_complete=capture_complete,
                omission_reason=omission_reason,
                cleanup_confirmed=True,
            )
            return AdapterExecutionOutcome(
                envelope=envelope,
                subprocess_result=norm_sub,
                captured_bytes=encoded,
                capture_complete=capture_complete,
                omission_reason=omission_reason,
                cleanup_confirmed=True,
            )

        if plan.operation == "check_environment":
            env_report = run_vdp_environment_check(
                profile,
                runner=self._runner,
                docker_bin=self._resolve_docker_bin(),
                git_bin=shutil.which("git"),
                overlay_bundle=plan.overlay_bundle,
                include_host_paths=False,
                clock=self._clock,
            )
            encoded, capture_complete, omission_reason, evidence_refs = self._store_json_evidence(
                action=action,
                payload=env_report,
                max_bytes=max_bytes,
                force_incomplete_reason=None,
                source_hashes=(),
            )
            if env_report["healthy"]:
                summary = (
                    f"vdp.test:check_environment ok "
                    f"(profile={profile.profile_name} revision={profile.profile_revision}, "
                    f"overlays={len(env_report['checked_overlays'])}, "
                    f"tests={len(env_report['active_tests'])})."
                )
            else:
                issue_codes = ", ".join(item["code"] for item in env_report["issues"])
                summary = (
                    f"vdp.test:check_environment unhealthy "
                    f"(profile={profile.profile_name}, issues=[{issue_codes}]). "
                    "Inspect evidence for cause and remediation."
                )
            envelope = ResultEnvelope(
                run_id=action.run_id,
                action_id=action.action_id,
                status=EnvelopeStatus.OK,
                summary=summary,
                evidence=evidence_refs,
                truncated=not capture_complete,
                next_cursor=None,
                error=None,
                usage=UsageMetrics(wall_ms=0, output_bytes=len(encoded)),
                provenance=ProvenanceInfo(
                    adapter_revision=self._descriptor.adapter_commit,
                    scope_revision=action.scope_revision,
                ),
            )
            norm_sub = self._build_synthetic_subprocess_result(
                outcome=SubprocessOutcome.COMPLETED,
                returncode=0,
                data=encoded,
                wall_ms=0,
                capture_complete=capture_complete,
                omission_reason=omission_reason,
                cleanup_confirmed=True,
            )
            return AdapterExecutionOutcome(
                envelope=envelope,
                subprocess_result=norm_sub,
                captured_bytes=encoded,
                capture_complete=capture_complete,
                omission_reason=omission_reason,
                cleanup_confirmed=True,
            )

        # Verify overlay directory live on disk before starting container.
        overlay_mount_dir: str | None = plan.overlay_host_dir
        overlay_file_hashes: dict[str, str] = dict(plan.overlay_file_hashes)
        if plan.overlay_bundle is not None:
            overlay_spec = profile.allowed_overlays[plan.overlay_bundle]
            real_dir, live_hashes = _inspect_overlay_directory(
                overlay_spec,
                require_exists=True,
            )
            if real_dir is None:
                return self._finish_with_early_outcome(
                    action=action,
                    plan=plan,
                    started_at=started_at,
                    max_bytes=max_bytes,
                    verdict="environment_failure",
                    verdict_reason=(
                        f"Missing approved test overlay directory or files for {plan.overlay_bundle!r}."
                    ),
                    status=EnvelopeStatus.TOOL_ERROR,
                    error_code="BLOCKED_ENV",
                    error_message=(
                        f"Test overlay bundle {plan.overlay_bundle!r} is missing on the execution host."
                    ),
                    sub_outcome=SubprocessOutcome.FAILED,
                )
            overlay_mount_dir = str(real_dir)
            overlay_file_hashes = live_hashes

        docker_bin = self._resolve_docker_bin()
        if not docker_bin:
            return self._finish_with_early_outcome(
                action=action,
                plan=plan,
                started_at=started_at,
                max_bytes=max_bytes,
                verdict="environment_failure",
                verdict_reason="Docker CLI is unavailable on the execution host.",
                status=EnvelopeStatus.TOOL_ERROR,
                error_code="BLOCKED_ENV",
                error_message="Docker CLI is missing on the execution host.",
                sub_outcome=SubprocessOutcome.FAILED,
            )

        # Verify pinned checkout SHA if configured and present locally.
        git_bin = shutil.which("git")
        if profile.checkout_dir is not None and profile.checkout_dir.exists() and git_bin:
            git_res = self._runner.run(
                [git_bin, "-C", str(profile.checkout_dir), "rev-parse", "HEAD"],
                timeout_seconds=10.0,
                max_output_bytes=4096,
            )
            actual_commit = git_res.stdout.decode("utf-8", errors="replace").strip().lower()
            if git_res.returncode == 0 and actual_commit and actual_commit != profile.expected_source_commit:
                return self._finish_with_early_outcome(
                    action=action,
                    plan=plan,
                    started_at=started_at,
                    max_bytes=max_bytes,
                    verdict="not_executed",
                    verdict_reason=(
                        f"Local checkout HEAD {actual_commit!r} does not match pinned commit {profile.expected_source_commit!r}."
                    ),
                    status=EnvelopeStatus.DENIED,
                    error_code="source_commit_mismatch",
                    error_message=(
                        f"Checkout HEAD {actual_commit!r} mismatches pinned {profile.expected_source_commit!r}."
                    ),
                    sub_outcome=SubprocessOutcome.FAILED,
                )

        # Inspect Docker image digest on live daemon.
        inspect_res = self._runner.run(
            [docker_bin, "image", "inspect", "--format", "{{.Id}}", plan.image_ref],
            timeout_seconds=15.0,
            max_output_bytes=4096,
        )
        if inspect_res.outcome != SubprocessOutcome.COMPLETED or inspect_res.returncode != 0:
            err_msg = inspect_res.stderr.decode("utf-8", errors="replace").strip() or "docker image inspect failed"
            return self._finish_with_early_outcome(
                action=action,
                plan=plan,
                started_at=started_at,
                max_bytes=max_bytes,
                verdict="environment_failure",
                verdict_reason=f"Pinned scanner image {plan.image_ref!r} unavailable: {err_msg[:180]}",
                status=EnvelopeStatus.TOOL_ERROR,
                error_code="BLOCKED_ENV",
                error_message=f"Pinned scanner image {plan.image_ref!r} could not be inspected: {err_msg[:180]}",
                sub_outcome=SubprocessOutcome.FAILED,
            )

        observed_digest = inspect_res.stdout.decode("utf-8", errors="replace").strip().lower()
        if observed_digest != plan.image_digest:
            return self._finish_with_early_outcome(
                action=action,
                plan=plan,
                started_at=started_at,
                max_bytes=max_bytes,
                verdict="not_executed",
                verdict_reason=(
                    f"Docker image {plan.image_ref!r} digest {observed_digest!r} mismatches pinned {plan.image_digest!r}."
                ),
                status=EnvelopeStatus.DENIED,
                error_code="image_digest_mismatch",
                error_message=(
                    f"Image digest mismatch: observed {observed_digest!r}, expected {plan.image_digest!r}."
                ),
                sub_outcome=SubprocessOutcome.FAILED,
            )

        if plan.network_mode == "isolated_internal_services":
            # Verify every pinned service image digest live before creating network or containers.
            for svc in plan.services:
                svc_inspect = self._runner.run(
                    [docker_bin, "image", "inspect", "--format", "{{.Id}}", svc.image_ref],
                    timeout_seconds=15.0,
                    max_output_bytes=4096,
                )
                if svc_inspect.outcome != SubprocessOutcome.COMPLETED or svc_inspect.returncode != 0:
                    err_msg = svc_inspect.stderr.decode("utf-8", errors="replace").strip() or "docker image inspect failed"
                    return self._finish_with_early_outcome(
                        action=action,
                        plan=plan,
                        started_at=started_at,
                        max_bytes=max_bytes,
                        verdict="environment_failure",
                        verdict_reason=f"Pinned service image {svc.image_ref!r} unavailable: {err_msg[:180]}",
                        status=EnvelopeStatus.TOOL_ERROR,
                        error_code="BLOCKED_ENV",
                        error_message=f"Pinned service image {svc.image_ref!r} could not be inspected: {err_msg[:180]}",
                        sub_outcome=SubprocessOutcome.FAILED,
                    )
                obs_svc_digest = svc_inspect.stdout.decode("utf-8", errors="replace").strip().lower()
                if obs_svc_digest != svc.expected_image_digest:
                    return self._finish_with_early_outcome(
                        action=action,
                        plan=plan,
                        started_at=started_at,
                        max_bytes=max_bytes,
                        verdict="not_executed",
                        verdict_reason=(
                            f"Service {svc.name!r} image {svc.image_ref!r} digest {obs_svc_digest!r} "
                            f"mismatches pinned {svc.expected_image_digest!r}."
                        ),
                        status=EnvelopeStatus.DENIED,
                        error_code="service_image_digest_mismatch",
                        error_message=(
                            f"Service {svc.name!r} image digest mismatch: observed {obs_svc_digest!r}, "
                            f"expected {svc.expected_image_digest!r}."
                        ),
                        sub_outcome=SubprocessOutcome.FAILED,
                    )

        container_name = f"ctf-vdp-{action.action_id[:16]}-{uuid4().hex[:8]}"
        network_name: str | None = None
        internal_flag_verified = False
        service_containers: list[tuple[VdpServiceSpec, str]] = []
        service_exec_records: list[dict[str, Any]] = []
        total_published_ports = 0
        published_ports_verified_none = True
        pre_run_error: tuple[str, str, EnvelopeStatus, str, str] | None = None

        sub_res = self._build_synthetic_subprocess_result(
            outcome=SubprocessOutcome.FAILED,
            returncode=125,
            data=b"",
            wall_ms=0,
            capture_complete=True,
            omission_reason=None,
            cleanup_confirmed=True,
        )
        container_cleanup_confirmed = True
        service_cleanup_confirmed = True
        network_cleanup_confirmed = True
        main_started = False

        try:
            if plan.network_mode == "isolated_internal_services":
                network_name = f"ctf-vdp-net-{action.action_id[:12]}-{uuid4().hex[:8]}"
                net_create = self._runner.run(
                    [
                        docker_bin,
                        "network",
                        "create",
                        "--driver",
                        "bridge",
                        "--internal",
                        "--label",
                        "ctf-vdp-harness=true",
                        "--label",
                        f"ctf-vdp-action={action.action_id}",
                        network_name,
                    ],
                    timeout_seconds=15.0,
                    max_output_bytes=4096,
                )
                if net_create.outcome != SubprocessOutcome.COMPLETED or net_create.returncode != 0:
                    err_txt = net_create.stderr.decode("utf-8", errors="replace").strip() or "docker network create failed"
                    pre_run_error = (
                        "environment_failure",
                        f"Failed to create internal Docker network: {err_txt[:180]}",
                        EnvelopeStatus.TOOL_ERROR,
                        "network_isolation_failed",
                        f"Failed to create isolated internal network: {err_txt[:180]}",
                    )
                else:
                    net_insp = self._runner.run(
                        [docker_bin, "network", "inspect", "--format", "{{.Internal}}", network_name],
                        timeout_seconds=10.0,
                        max_output_bytes=1024,
                    )
                    internal_flag_verified = (
                        net_insp.outcome == SubprocessOutcome.COMPLETED
                        and net_insp.returncode == 0
                        and net_insp.stdout.decode("utf-8", errors="replace").strip().lower() == "true"
                    )
                    if not internal_flag_verified:
                        pre_run_error = (
                            "environment_failure",
                            "Dedicated Docker network failed internal=true verification; aborting before starting containers.",
                            EnvelopeStatus.TOOL_ERROR,
                            "network_isolation_failed",
                            "Internal Docker network isolation check failed (Internal!=true).",
                        )

                if pre_run_error is None:
                    deadline_mono = time.monotonic() + eff_timeout
                    for svc in plan.services:
                        if cancel_event is not None and cancel_event.is_set():
                            pre_run_error = (
                                "not_executed",
                                "Execution was cancelled before service startup.",
                                EnvelopeStatus.CANCELLED,
                                "action_cancelled",
                                "Execution cancelled before service startup.",
                            )
                            break
                        svc_cname = f"ctf-vdp-svc-{svc.name[:12]}-{action.action_id[:8]}-{uuid4().hex[:6]}"
                        service_containers.append((svc, svc_cname))
                        svc_argv: list[str] = [
                            docker_bin,
                            "run",
                            "-d",
                            "--init",
                            "--name",
                            svc_cname,
                            "--network",
                            network_name,
                            "--network-alias",
                            svc.name,
                            "--cpus",
                            str(svc.cpus),
                            "--memory",
                            f"{svc.memory_mb}m",
                            "--label",
                            "ctf-vdp-harness=true",
                            "--label",
                            f"ctf-vdp-action={action.action_id}",
                        ]
                        for ek, ev in sorted(svc.env.items()):
                            svc_argv.extend(["-e", f"{ek}={ev}"])
                        if svc.entrypoint:
                            svc_argv.extend(["--entrypoint", svc.entrypoint])
                        svc_argv.append(svc.expected_image_digest)
                        svc_argv.extend(svc.command)

                        svc_run = self._runner.run(
                            svc_argv,
                            timeout_seconds=min(30.0, max(5.0, deadline_mono - time.monotonic())),
                            max_output_bytes=8192,
                            cancel_event=cancel_event,
                        )
                        if svc_run.outcome != SubprocessOutcome.COMPLETED or svc_run.returncode != 0:
                            err_txt = (svc_run.stderr + svc_run.stdout).decode("utf-8", errors="replace").strip()
                            service_exec_records.append(
                                {
                                    "service_name": svc.name,
                                    "service_kind": svc.service_kind,
                                    "image_ref": svc.image_ref,
                                    "image_digest": svc.expected_image_digest,
                                    "internal_port": svc.internal_port,
                                    "cpus": svc.cpus,
                                    "memory_mb": svc.memory_mb,
                                    "published_ports_verified_none": True,
                                    "ready_verified": False,
                                }
                            )
                            pre_run_error = (
                                "environment_failure",
                                f"Dependency service {svc.name!r} failed to start: {err_txt[:180]}",
                                EnvelopeStatus.TOOL_ERROR,
                                "service_startup_failed",
                                f"Service {svc.name!r} failed to start.",
                            )
                            break

                        ports_ok, port_cnt = self._verify_container_no_published_ports(docker_bin, svc_cname)
                        if not ports_ok:
                            published_ports_verified_none = False
                            if port_cnt > 0:
                                total_published_ports += port_cnt
                            service_exec_records.append(
                                {
                                    "service_name": svc.name,
                                    "service_kind": svc.service_kind,
                                    "image_ref": svc.image_ref,
                                    "image_digest": svc.expected_image_digest,
                                    "internal_port": svc.internal_port,
                                    "cpus": svc.cpus,
                                    "memory_mb": svc.memory_mb,
                                    "published_ports_verified_none": False,
                                    "ready_verified": False,
                                }
                            )
                            pre_run_error = (
                                "environment_failure",
                                f"Dependency service {svc.name!r} exposed published ports or failed port inspection.",
                                EnvelopeStatus.TOOL_ERROR,
                                "network_isolation_failed",
                                f"Service {svc.name!r} violated no-published-ports invariant.",
                            )
                            break

                        ready_ok = True
                        if svc.readiness_command:
                            ready_ok = False
                            ready_deadline = min(
                                deadline_mono,
                                time.monotonic() + float(svc.readiness_timeout_seconds),
                            )
                            while time.monotonic() < ready_deadline:
                                if cancel_event is not None and cancel_event.is_set():
                                    break
                                r_res = self._runner.run(
                                    [docker_bin, "exec", svc_cname, *svc.readiness_command],
                                    timeout_seconds=min(5.0, max(1.0, ready_deadline - time.monotonic())),
                                    max_output_bytes=4096,
                                    cancel_event=cancel_event,
                                )
                                if r_res.outcome == SubprocessOutcome.COMPLETED and r_res.returncode == 0:
                                    ready_ok = True
                                    break
                                st_res = self._runner.run(
                                    [docker_bin, "inspect", "--format", "{{.State.Running}}", svc_cname],
                                    timeout_seconds=5.0,
                                    max_output_bytes=512,
                                )
                                if (
                                    st_res.outcome == SubprocessOutcome.COMPLETED
                                    and st_res.returncode == 0
                                    and st_res.stdout.decode("utf-8", errors="replace").strip().lower() == "false"
                                ):
                                    break
                                time.sleep(0.25)

                        service_exec_records.append(
                            {
                                "service_name": svc.name,
                                "service_kind": svc.service_kind,
                                "image_ref": svc.image_ref,
                                "image_digest": svc.expected_image_digest,
                                "internal_port": svc.internal_port,
                                "cpus": svc.cpus,
                                "memory_mb": svc.memory_mb,
                                "published_ports_verified_none": True,
                                "ready_verified": ready_ok,
                            }
                        )
                        if not ready_ok:
                            pre_run_error = (
                                "environment_failure",
                                f"Dependency service {svc.name!r} did not pass readiness probe within {svc.readiness_timeout_seconds}s.",
                                EnvelopeStatus.TOOL_ERROR,
                                "service_readiness_failed",
                                f"Service {svc.name!r} failed readiness check.",
                            )
                            break

            if pre_run_error is None:
                target_net = network_name if network_name is not None else "none"
                argv: list[str] = [
                    docker_bin,
                    "run",
                    "--rm",
                    "--init",
                    "--name",
                    container_name,
                    "--network",
                    target_net,
                    "--cpus",
                    str(plan.cpus),
                    "--memory",
                    f"{plan.memory_mb}m",
                    "--user",
                    "0",
                    "--workdir",
                    "/src",
                ]
                for svc in plan.services:
                    for ek, ev in sorted(svc.client_env.items()):
                        argv.extend(["-e", f"{ek}={ev}"])
                if overlay_mount_dir is not None and plan.overlay_container_target is not None:
                    argv.extend(
                        [
                            "--mount",
                            f"type=bind,source={overlay_mount_dir},target={plan.overlay_container_target},readonly",
                        ]
                    )
                if plan.runner_mode == "direct_pytest":
                    pytest_bin = plan.pytest_executable or DEFAULT_DIRECT_PYTEST_EXECUTABLE
                    argv.extend(["--entrypoint", pytest_bin, plan.image_digest])
                    if plan.operation == "run_smoke":
                        argv.extend(["-v", "-rA", "--maxfail=1", *plan.smoke_selectors])
                    else:
                        argv.extend(["-v", "-rA", "--maxfail=1", *plan.test_selectors])
                else:
                    argv.extend(["--entrypoint", "bash", plan.image_digest])
                    if plan.operation == "run_smoke":
                        argv.append(".oss-scanner/smoke")
                    else:
                        argv.extend([".oss-scanner/test", "-n", "0", "--maxfail=1", "-v", "-rA", *plan.test_selectors])

                main_started = True
                sub_res = self._runner.run(
                    argv,
                    timeout_seconds=eff_timeout,
                    max_output_bytes=max_bytes,
                    cancel_event=cancel_event,
                )
        finally:
            if main_started or plan.network_mode == "none":
                container_cleanup_confirmed = self._ensure_container_removed(
                    docker_bin,
                    container_name,
                    remove_volumes=(plan.network_mode == "isolated_internal_services"),
                )
            for idx, (_, svc_cname) in enumerate(reversed(service_containers)):
                svc_clean = self._ensure_container_removed(docker_bin, svc_cname, remove_volumes=True)
                service_cleanup_confirmed = service_cleanup_confirmed and svc_clean
                rec_idx = len(service_containers) - 1 - idx
                if rec_idx < len(service_exec_records):
                    service_exec_records[rec_idx]["container_cleanup_confirmed"] = svc_clean
            if network_name is not None:
                network_cleanup_confirmed = self._ensure_network_removed(docker_bin, network_name)

        finished_at = self._clock().isoformat()
        combined_raw = (
            pre_run_error[4]
            if pre_run_error is not None
            else (sub_res.stdout + sub_res.stderr).decode("utf-8", errors="replace")
        )
        combined_redacted = redact_sensitive_text(combined_raw)
        overall_cleanup = bool(
            sub_res.cleanup_confirmed
            and container_cleanup_confirmed
            and service_cleanup_confirmed
            and network_cleanup_confirmed
        )

        parsed = _parse_pytest_output(
            combined_redacted,
            requested_selectors=plan.test_selectors,
            operation=plan.operation,
        )
        marker_data = _extract_evidence_markers(combined_redacted) if plan.operation == "run_pytest" else {}
        has_valid_baseline_ref = self._has_valid_baseline_evidence(action=action, plan=plan)
        if pre_run_error is not None:
            verdict_res = _VerdictResult(
                verdict=pre_run_error[0] if overall_cleanup else "environment_failure",
                verdict_reason=(
                    pre_run_error[1]
                    if overall_cleanup
                    else f"{pre_run_error[1]} Cleanup verification failed."
                ),
            )
        else:
            verdict_res = _classify_verdict(
                operation=plan.operation,
                outcome=sub_res.outcome,
                exit_code=sub_res.returncode,
                cleanup_confirmed=overall_cleanup,
                parsed=parsed,
                positive_selectors=plan.positive_selectors,
                negative_selectors=plan.negative_selectors,
                anomaly_repro_selectors=plan.anomaly_repro_selectors,
                env_check_selectors=plan.env_check_selectors,
                has_valid_baseline_ref=has_valid_baseline_ref,
            )
        verdict = verdict_res.verdict
        verdict_reason = verdict_res.verdict_reason
        execution_context, conclusion_status = _build_execution_context_and_conclusion(
            plan=plan,
            verdict_res=verdict_res,
            parsed=parsed,
            marker_data=marker_data,
        )

        raw_truncated = not sub_res.capture_complete or sub_res.outcome == SubprocessOutcome.OUTPUT_LIMIT_EXCEEDED
        evidence_payload: dict[str, Any] = {
            "schema": "vdp-product-test-evidence/1",
            "profile_name": plan.profile_name,
            "profile_revision": plan.profile_revision,
            "execution_provenance": "harness_docker_isolated",
            "operation": plan.operation,
            "started_at": started_at,
            "finished_at": finished_at,
            "wall_ms": sub_res.wall_ms,
            "image_ref": plan.image_ref,
            "image_digest": plan.image_digest,
            "source_commit": plan.source_commit,
            "network_mode": plan.network_mode,
            "runner_mode": plan.runner_mode,
            "network_isolation": (
                {
                    "mode": "isolated_internal_services",
                    "network_name": network_name,
                    "internal_flag_verified": internal_flag_verified,
                    "external_egress_blocked": internal_flag_verified,
                    "published_ports_count": total_published_ports,
                    "published_ports_verified_none": published_ports_verified_none,
                }
                if plan.network_mode == "isolated_internal_services"
                else {
                    "mode": "none",
                    "network_name": None,
                    "internal_flag_verified": True,
                    "external_egress_blocked": True,
                    "published_ports_count": 0,
                    "published_ports_verified_none": True,
                }
            ),
            "services_executed": service_exec_records,
            "cpus": plan.cpus,
            "memory_mb": plan.memory_mb,
            "timeout_seconds": int(eff_timeout),
            "timed_out": sub_res.outcome == SubprocessOutcome.TIMEOUT,
            "exit_code": sub_res.returncode,
            "collected_count": parsed["collected_count"],
            "passed_count": parsed["passed_count"],
            "failed_count": parsed["failed_count"],
            "skipped_count": parsed["skipped_count"],
            "error_count": parsed["error_count"],
            "positive_selectors": list(plan.positive_selectors),
            "negative_selectors": list(plan.negative_selectors),
            "anomaly_repro_selectors": list(plan.anomaly_repro_selectors),
            "env_check_selectors": list(plan.env_check_selectors),
            "selector_roles": dict(plan.selector_roles),
            "positive_passed": verdict_res.positive_passed,
            "positive_failed": verdict_res.positive_failed,
            "negative_passed": verdict_res.negative_passed,
            "negative_failed": verdict_res.negative_failed,
            "anomaly_repro_passed": verdict_res.anomaly_repro_passed,
            "anomaly_repro_failed": verdict_res.anomaly_repro_failed,
            "env_check_passed": verdict_res.env_check_passed,
            "env_check_failed": verdict_res.env_check_failed,
            "selector_outcomes": parsed["selector_outcomes"],
            "overlay_bundle": plan.overlay_bundle,
            "overlay_file_hashes": overlay_file_hashes,
            "baseline_evidence_ref": plan.baseline_evidence_ref,
            "synthetic_data_only": True,
            "async_behavior_unverified": True,
            "verdict": verdict,
            "verdict_reason": verdict_reason,
            "execution_context": execution_context,
            "conclusion_status": conclusion_status,
            "container_cleanup_confirmed": container_cleanup_confirmed,
            "service_cleanup_confirmed": service_cleanup_confirmed,
            "network_cleanup_confirmed": network_cleanup_confirmed,
            "process_cleanup_confirmed": sub_res.cleanup_confirmed,
            "log_truncated": raw_truncated,
            "log_excerpt": combined_redacted,
        }

        force_incomplete = (
            sub_res.omission_reason or "output_truncated_at_max_output_bytes"
            if raw_truncated
            else None
        )
        src_hashes = tuple(dict.fromkeys([*(source_artifact_hashes or ()), *overlay_file_hashes.values()]))
        encoded, capture_complete, omission_reason, evidence_refs = self._store_json_evidence(
            action=action,
            payload=evidence_payload,
            max_bytes=max_bytes,
            force_incomplete_reason=force_incomplete,
            source_hashes=src_hashes,
        )

        # Normalize envelope status against bounded execution + cleanup + verdict.
        if not overall_cleanup:
            env_status = EnvelopeStatus.TOOL_ERROR
            err = ErrorDetail(
                code="cleanup_unconfirmed",
                message=sub_res.cleanup_detail or "Docker container or subprocess cleanup could not be confirmed.",
                retryable=False,
            )
            truncated = True
        elif sub_res.outcome == SubprocessOutcome.TIMEOUT:
            env_status = EnvelopeStatus.TIMEOUT
            err = ErrorDetail(
                code="action_timeout",
                message=verdict_reason,
                retryable=False,
            )
            truncated = True
        elif sub_res.outcome == SubprocessOutcome.CANCELLED:
            env_status = EnvelopeStatus.CANCELLED
            err = ErrorDetail(
                code="action_cancelled",
                message=verdict_reason,
                retryable=False,
            )
            truncated = True
        elif sub_res.outcome == SubprocessOutcome.OUTPUT_LIMIT_EXCEEDED:
            env_status = EnvelopeStatus.PARTIAL
            err = ErrorDetail(
                code="output_limit_exceeded",
                message=verdict_reason,
                retryable=False,
            )
            truncated = True
        elif pre_run_error is not None:
            env_status = pre_run_error[2]
            err = ErrorDetail(
                code=pre_run_error[3],
                message=verdict_reason,
                retryable=False,
            )
            truncated = not capture_complete
        elif verdict == "environment_failure":
            env_status = EnvelopeStatus.TOOL_ERROR
            err = ErrorDetail(
                code="environment_failure",
                message=verdict_reason,
                retryable=False,
            )
            truncated = not capture_complete
        else:
            # Structured verdict ("smoke_passed", "hypothesis_falsified", "anomaly_observed",
            # "inconclusive", "baseline_failed", "skipped", "not_executed", "baseline_passed",
            # "env_check_passed") is preserved in OK envelope.
            env_status = EnvelopeStatus.OK
            err = None
            truncated = not capture_complete

        summary = (
            f"vdp.test:{action.operation} verdict={verdict} "
            f"(exit={sub_res.returncode}, collected={parsed['collected_count']}, "
            f"passed={parsed['passed_count']}, failed={parsed['failed_count']}, "
            f"skipped={parsed['skipped_count']}, cleanup={overall_cleanup}). "
            f"{conclusion_status['summary_ja']}"
        )
        envelope = ResultEnvelope(
            run_id=action.run_id,
            action_id=action.action_id,
            status=env_status,
            summary=summary,
            evidence=evidence_refs,
            truncated=truncated,
            next_cursor=None,
            error=err,
            usage=UsageMetrics(
                wall_ms=sub_res.wall_ms,
                output_bytes=len(encoded),
                peak_rss_bytes=sub_res.peak_rss_bytes,
                cpu_ms=sub_res.cpu_ms,
            ),
            provenance=ProvenanceInfo(
                adapter_revision=self._descriptor.adapter_commit,
                scope_revision=action.scope_revision,
            ),
        )
        norm_sub = self._build_synthetic_subprocess_result(
            outcome=sub_res.outcome,
            returncode=sub_res.returncode,
            data=encoded,
            wall_ms=sub_res.wall_ms,
            capture_complete=capture_complete,
            omission_reason=omission_reason,
            cleanup_confirmed=overall_cleanup,
            cleanup_detail=sub_res.cleanup_detail,
            process_start_id=sub_res.process_start_id,
            cpu_ms=sub_res.cpu_ms,
            peak_rss_bytes=sub_res.peak_rss_bytes,
        )
        return AdapterExecutionOutcome(
            envelope=envelope,
            subprocess_result=norm_sub,
            captured_bytes=encoded,
            capture_complete=capture_complete,
            omission_reason=omission_reason,
            cleanup_confirmed=overall_cleanup,
        )

    def _finish_with_early_outcome(
        self,
        *,
        action: ActionRecord,
        plan: _ValidatedPlan,
        started_at: str,
        max_bytes: int,
        verdict: str,
        verdict_reason: str,
        status: EnvelopeStatus,
        error_code: str,
        error_message: str,
        sub_outcome: SubprocessOutcome,
    ) -> AdapterExecutionOutcome:
        verdict_res = _VerdictResult(verdict=verdict, verdict_reason=verdict_reason)
        execution_context, conclusion_status = _build_execution_context_and_conclusion(
            plan=plan,
            verdict_res=verdict_res,
            parsed={"collected_count": 0, "passed_count": 0, "failed_count": 0, "skipped_count": 0, "error_count": 0},
            marker_data={},
        )
        payload: dict[str, Any] = {
            "schema": "vdp-product-test-evidence/1",
            "profile_name": plan.profile_name,
            "profile_revision": plan.profile_revision,
            "execution_provenance": "harness_docker_isolated",
            "operation": plan.operation,
            "started_at": started_at,
            "finished_at": self._clock().isoformat(),
            "wall_ms": 0,
            "image_ref": plan.image_ref,
            "image_digest": plan.image_digest,
            "source_commit": plan.source_commit,
            "network_mode": plan.network_mode,
            "runner_mode": plan.runner_mode,
            "network_isolation": {
                "mode": plan.network_mode,
                "network_name": None,
                "internal_flag_verified": plan.network_mode == "none",
                "external_egress_blocked": plan.network_mode == "none",
                "published_ports_count": 0,
                "published_ports_verified_none": True,
            },
            "services_executed": [],
            "cpus": plan.cpus,
            "memory_mb": plan.memory_mb,
            "timeout_seconds": plan.timeout_seconds,
            "timed_out": False,
            "exit_code": None,
            "collected_count": 0,
            "passed_count": 0,
            "failed_count": 0,
            "skipped_count": 0,
            "error_count": 0,
            "positive_selectors": list(plan.positive_selectors),
            "negative_selectors": list(plan.negative_selectors),
            "anomaly_repro_selectors": list(plan.anomaly_repro_selectors),
            "env_check_selectors": list(plan.env_check_selectors),
            "selector_roles": dict(plan.selector_roles),
            "positive_passed": 0,
            "positive_failed": 0,
            "negative_passed": 0,
            "negative_failed": 0,
            "anomaly_repro_passed": 0,
            "anomaly_repro_failed": 0,
            "env_check_passed": 0,
            "env_check_failed": 0,
            "selector_outcomes": {},
            "overlay_bundle": plan.overlay_bundle,
            "overlay_file_hashes": plan.overlay_file_hashes,
            "baseline_evidence_ref": plan.baseline_evidence_ref,
            "synthetic_data_only": True,
            "async_behavior_unverified": True,
            "verdict": verdict,
            "verdict_reason": verdict_reason,
            "execution_context": execution_context,
            "conclusion_status": conclusion_status,
            "container_cleanup_confirmed": True,
            "service_cleanup_confirmed": True,
            "network_cleanup_confirmed": True,
            "process_cleanup_confirmed": True,
            "log_truncated": False,
            "log_excerpt": redact_sensitive_text(error_message),
        }
        encoded, capture_complete, omission_reason, evidence_refs = self._store_json_evidence(
            action=action,
            payload=payload,
            max_bytes=max_bytes,
            force_incomplete_reason=None,
            source_hashes=tuple(plan.overlay_file_hashes.values()),
        )
        envelope = ResultEnvelope(
            run_id=action.run_id,
            action_id=action.action_id,
            status=status,
            summary=f"vdp.test:{action.operation} verdict={verdict}: {error_message}",
            evidence=evidence_refs,
            truncated=not capture_complete,
            next_cursor=None,
            error=ErrorDetail(code=error_code, message=error_message, retryable=False),
            usage=UsageMetrics(wall_ms=0, output_bytes=len(encoded)),
            provenance=ProvenanceInfo(
                adapter_revision=self._descriptor.adapter_commit,
                scope_revision=action.scope_revision,
            ),
        )
        norm_sub = self._build_synthetic_subprocess_result(
            outcome=sub_outcome,
            returncode=1,
            data=encoded,
            wall_ms=0,
            capture_complete=capture_complete,
            omission_reason=omission_reason,
            cleanup_confirmed=True,
        )
        return AdapterExecutionOutcome(
            envelope=envelope,
            subprocess_result=norm_sub,
            captured_bytes=encoded,
            capture_complete=capture_complete,
            omission_reason=omission_reason,
            cleanup_confirmed=True,
        )


__all__ = [
    "DEFAULT_VDP_TEST_MAX_CPUS",
    "DEFAULT_VDP_TEST_MAX_MEMORY_MB",
    "DEFAULT_VDP_TEST_MAX_OUTPUT_BYTES",
    "DEFAULT_VDP_TEST_TIMEOUT_SECONDS",
    "DEFAULT_DIRECT_PYTEST_EXECUTABLE",
    "MAX_VDP_SERVICES_PER_PROFILE",
    "MAX_VDP_TOTAL_CPUS",
    "MAX_VDP_TOTAL_MEMORY_MB",
    "VALID_SELECTOR_ROLES",
    "VALID_VDP_NETWORK_MODES",
    "VALID_VDP_RUNNER_MODES",
    "VALID_VDP_SERVICE_KINDS",
    "VDP_PROFILES_RELPATH",
    "VDP_PRODUCT_TEST_ADAPTER_COMMIT",
    "VDP_PRODUCT_TEST_ADAPTER_ID",
    "VDP_PRODUCT_TEST_ARG_SCHEMA",
    "VDP_PRODUCT_TEST_CAPABILITY_NAME",
    "VDP_PRODUCT_TEST_OPERATIONS",
    "WEBLATE_2026_11_2_IMAGE_DIGEST",
    "WEBLATE_2026_11_2_IMAGE_REF",
    "WEBLATE_2026_11_2_PROFILE_NAME",
    "WEBLATE_2026_11_2_PROFILE_REVISION",
    "WEBLATE_2026_11_2_SOURCE_COMMIT",
    "WEBLATE_W01_OVERLAY_BUNDLE",
    "WEBLATE_W01_TEST_FILE_SHA256",
    "WEBLATE_W02_OVERLAY_BUNDLE",
    "WEBLATE_W02_TEST_FILE_SHA256",
    "VdpOverlaySpec",
    "VdpProductTestAdapter",
    "VdpServiceSpec",
    "VdpTargetProfile",
    "build_default_weblate_profile",
    "compute_vdp_profile_digest",
    "create_vdp_product_test_descriptor",
    "load_registered_vdp_profiles",
    "run_vdp_environment_check",
    "save_registered_vdp_profile",
    "validate_vdp_profile_registration",
    "validate_vdp_selector_format",
]
