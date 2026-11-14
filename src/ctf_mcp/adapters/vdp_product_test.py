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

import hashlib
import json
import os
import re
import shutil
import stat
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

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
    ProvenanceInfo,
    ResultEnvelope,
    RunMode,
    ScopeDeniedError,
    ScopePolicy,
    StrictModel,
    UsageMetrics,
)
from ctf_mcp.fs_guard import safe_read_bounded, safe_write_atomic

VDP_PRODUCT_TEST_CAPABILITY_NAME = "vdp.test"
VDP_PRODUCT_TEST_ADAPTER_ID = "ctf-vdp-product-test"
VDP_PRODUCT_TEST_ADAPTER_COMMIT = "p8vdp01a2b3c4d5e"
VDP_PRODUCT_TEST_OPERATIONS: tuple[str, ...] = (
    "describe_profile",
    "run_smoke",
    "run_pytest",
)
VDP_PROFILES_RELPATH = "_vdp/profiles.json"

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


class VdpTargetProfile(StrictModel):
    """Pinned product source/image/selector policy enforced server-side."""

    profile_name: str = Field(min_length=1)
    profile_revision: str = Field(default=WEBLATE_2026_11_2_PROFILE_REVISION, min_length=1)
    image_ref: str = Field(min_length=1)
    expected_image_digest: str = Field(pattern="^sha256:[0-9a-f]{64}$")
    expected_source_commit: str = Field(pattern="^[0-9a-f]{40}$")
    checkout_dir: Path | None = None
    allowed_test_selectors: tuple[str, ...]
    positive_selectors: tuple[str, ...] = ()
    negative_selectors: tuple[str, ...] = ()
    allowed_overlays: dict[str, VdpOverlaySpec] = Field(default_factory=dict)
    max_cpus: int = Field(default=DEFAULT_VDP_TEST_MAX_CPUS, ge=1)
    max_memory_mb: int = Field(default=DEFAULT_VDP_TEST_MAX_MEMORY_MB, ge=512)
    max_timeout_seconds: int = Field(default=DEFAULT_VDP_TEST_TIMEOUT_SECONDS, ge=5)
    max_output_bytes: int = Field(default=DEFAULT_VDP_TEST_MAX_OUTPUT_BYTES, ge=1024)
    expires_at: datetime | None = None

    def to_public_summary(self) -> dict[str, Any]:
        """Return sanitized profile metadata omitting internal host directory paths."""
        return {
            "profile_name": self.profile_name,
            "profile_revision": self.profile_revision,
            "image_ref": self.image_ref,
            "expected_image_digest": self.expected_image_digest,
            "expected_source_commit": self.expected_source_commit,
            "network_mode": "none",
            "allowed_test_selectors": list(self.allowed_test_selectors),
            "positive_selectors": list(self.positive_selectors),
            "negative_selectors": list(self.negative_selectors),
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
    """Validate strict selector, digest, commit, overlay SHA-256, and bound constraints before saving."""
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

    for sel in cleaned_pos:
        if sel not in allowed_set:
            raise ContractViolationError(
                f"positive_selector {sel!r} must be present in allowed_test_selectors."
            )
    for sel in cleaned_neg:
        if sel not in allowed_set:
            raise ContractViolationError(
                f"negative_selector {sel!r} must be present in allowed_test_selectors."
            )

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

    return profile.model_copy(
        update={
            "allowed_test_selectors": cleaned_allowed,
            "positive_selectors": cleaned_pos,
            "negative_selectors": cleaned_neg,
            "allowed_overlays": normalized_overlays,
        }
    )


def load_registered_vdp_profiles(vault_root: str | Path) -> dict[str, VdpTargetProfile]:
    """Load operator-registered VDP target profiles from ``<vault_root>/_vdp/profiles.json``."""
    vault_path = Path(vault_root)
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


def save_registered_vdp_profile(
    vault_root: str | Path,
    profile: VdpTargetProfile,
) -> Path:
    """Validate and atomically persist an operator-registered ``VdpTargetProfile`` under ``vault_root``."""
    validated = validate_vdp_profile_registration(profile)
    vault_path = Path(vault_root)
    vault_path.mkdir(parents=True, exist_ok=True)
    existing = load_registered_vdp_profiles(vault_path)
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
    overlay_bundle: str | None = None
    overlay_host_dir: str | None = None
    overlay_container_target: str | None = None
    overlay_file_hashes: dict[str, str] = Field(default_factory=dict)
    cpus: int
    memory_mb: int
    timeout_seconds: int
    network_mode: str = "none"
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
) -> tuple[str, str, int, int, int, int]:
    """Classify run outcome without conflating baseline failures with defense success."""
    collected = int(parsed["collected_count"])
    passed = int(parsed["passed_count"])
    failed = int(parsed["failed_count"])
    skipped = int(parsed["skipped_count"])
    error = int(parsed["error_count"])
    sel_outcomes = parsed["selector_outcomes"]

    if outcome == SubprocessOutcome.TIMEOUT:
        return (
            "timeout",
            "Execution exceeded bounded wall-clock timeout and was terminated.",
            0,
            0,
            0,
            0,
        )
    if outcome == SubprocessOutcome.CANCELLED:
        return (
            "not_executed",
            "Execution was cancelled before completion.",
            0,
            0,
            0,
            0,
        )
    if not cleanup_confirmed:
        return (
            "environment_failure",
            "Child process or Docker container cleanup could not be confirmed.",
            0,
            0,
            0,
            0,
        )

    if operation == "run_smoke":
        if exit_code == 0 and passed > 0 and failed == 0 and error == 0 and skipped == 0:
            return (
                "smoke_passed",
                f"Official scanner smoke passed ({passed} checks passed across smoke sessions).",
                passed,
                0,
                0,
                0,
            )
        return (
            "environment_failure",
            f"Official scanner smoke failed (exit_code={exit_code}, passed={passed}, failed={failed}, skipped={skipped}, error={error}).",
            0,
            0,
            0,
            0,
        )

    pos_passed = sum(1 for s in positive_selectors if sel_outcomes.get(s) == "passed")
    pos_failed = sum(1 for s in positive_selectors if sel_outcomes.get(s) in {"failed", "error"})
    neg_passed = sum(1 for s in negative_selectors if sel_outcomes.get(s) == "passed")
    neg_failed = sum(1 for s in negative_selectors if sel_outcomes.get(s) in {"failed", "error"})

    # Pytest exit codes >= 2 indicate internal error, usage error, interrupted, or zero items collected.
    if exit_code is None or exit_code >= 2 or error > 0:
        if collected == 0 and (exit_code in {0, 5} or "collected 0 items" in str(parsed)):
            return (
                "not_executed",
                "Pytest collected 0 items; no product test cases executed.",
                pos_passed,
                pos_failed,
                neg_passed,
                neg_failed,
            )
        return (
            "environment_failure",
            f"Product test runner encountered environment/setup failure (exit_code={exit_code}, errors={error}).",
            pos_passed,
            pos_failed,
            neg_passed,
            neg_failed,
        )

    if collected == 0:
        return (
            "not_executed",
            "Pytest collected 0 items; no product test cases executed.",
            pos_passed,
            pos_failed,
            neg_passed,
            neg_failed,
        )

    if skipped > 0 or any(v == "skipped" for v in sel_outcomes.values() if isinstance(v, str)):
        return (
            "skipped",
            f"At least one selected test was skipped (skipped={skipped}); skipped checks do not establish defense.",
            pos_passed,
            pos_failed,
            neg_passed,
            neg_failed,
        )

    # Critical guard (Requirement 4): if positive control failed or was absent while evaluating negative controls,
    # NEVER classify negative no-change as defense success / hypothesis_falsified.
    if pos_failed > 0:
        return (
            "baseline_failed",
            "Positive control failed; negative no-change cannot be classified as defense success.",
            pos_passed,
            pos_failed,
            neg_passed,
            neg_failed,
        )

    if negative_selectors and pos_passed == 0:
        return (
            "baseline_failed",
            "No passing positive control established; negative test pass cannot count as defense success.",
            pos_passed,
            pos_failed,
            neg_passed,
            neg_failed,
        )

    if neg_failed > 0 and pos_passed >= 1 and error == 0:
        return (
            "deviation_reproduced",
            "Positive control passed and negative permission check failed (deviation reproduced under synthetic test settings).",
            pos_passed,
            pos_failed,
            neg_passed,
            neg_failed,
        )

    if (
        negative_selectors
        and pos_passed >= 1
        and pos_failed == 0
        and neg_passed >= 1
        and neg_failed == 0
        and exit_code == 0
    ):
        return (
            "hypothesis_falsified",
            "Positive control and negative permission controls passed under synthetic test settings (hypothesis falsified).",
            pos_passed,
            pos_failed,
            neg_passed,
            neg_failed,
        )

    if positive_selectors and not negative_selectors and pos_passed >= 1 and failed == 0 and exit_code == 0:
        return (
            "baseline_passed",
            f"Positive baseline check(s) passed ({pos_passed} passed).",
            pos_passed,
            pos_failed,
            neg_passed,
            neg_failed,
        )

    return (
        "environment_failure",
        f"Unclassified test outcome (exit_code={exit_code}, passed={passed}, failed={failed}, skipped={skipped}).",
        pos_passed,
        pos_failed,
        neg_passed,
        neg_failed,
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

    # Extreme tiny cap fallback: clear excerpt and selector details if needed, then clamp safely.
    bounded["log_excerpt"] = ""
    candidate = json.dumps(bounded, indent=2, ensure_ascii=False).encode("utf-8")
    if len(candidate) <= max_bytes:
        return candidate, True
    bounded["selector_outcomes"] = {}
    return json.dumps(bounded, ensure_ascii=False).encode("utf-8")[:max_bytes], True


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
        profile = self.get_profiles().get(profile_name)
        if profile is None:
            raise ScopeDeniedError(
                f"target_profile {profile_name!r} is not allowlisted on this host.",
                code="target_profile_denied",
            )
        if profile.expires_at is not None and self._clock() >= profile.expires_at:
            raise ScopeDeniedError(
                f"target_profile {profile_name!r} expired at {profile.expires_at.isoformat()}.",
                code="target_profile_expired",
            )

        if operation == "describe_profile":
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
                overlay_bundle=None,
                overlay_host_dir=None,
                overlay_container_target=None,
                overlay_file_hashes={},
                cpus=profile.max_cpus,
                memory_mb=profile.max_memory_mb,
                timeout_seconds=profile.max_timeout_seconds,
                network_mode="none",
                baseline_evidence_ref=None,
            )

        network_mode = str(arguments.get("network_mode") or "none").strip().lower()
        if network_mode != "none":
            raise ScopeDeniedError(
                f"vdp.test requires network_mode='none', got {network_mode!r}.",
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

        overlay_bundle_raw = arguments.get("overlay_bundle")
        overlay_bundle = str(overlay_bundle_raw).strip() if overlay_bundle_raw else None
        if needs_overlay and not overlay_bundle:
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

        pos_arg = arguments.get("positive_selectors")
        neg_arg = arguments.get("negative_selectors")
        if pos_arg is not None:
            pos_selectors = tuple(str(x).strip() for x in pos_arg)
            for s in pos_selectors:
                if s not in allowed_set or (raw_selectors and s not in raw_selectors):
                    raise ScopeDeniedError(
                        f"positive_selector {s!r} must be allowlisted and included in test_selectors.",
                        code="selector_not_allowlisted",
                    )
        else:
            pos_selectors = tuple(s for s in raw_selectors if s in set(profile.positive_selectors))

        if neg_arg is not None:
            neg_selectors = tuple(str(x).strip() for x in neg_arg)
            for s in neg_selectors:
                if s not in allowed_set or (raw_selectors and s not in raw_selectors):
                    raise ScopeDeniedError(
                        f"negative_selector {s!r} must be allowlisted and included in test_selectors.",
                        code="selector_not_allowlisted",
                    )
        else:
            neg_selectors = tuple(s for s in raw_selectors if s in set(profile.negative_selectors))

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
            overlay_bundle=overlay_bundle,
            overlay_host_dir=overlay_host_dir,
            overlay_container_target=overlay_container_target,
            overlay_file_hashes=overlay_file_hashes,
            cpus=cpus,
            memory_mb=memory_mb,
            timeout_seconds=timeout_seconds,
            network_mode="none",
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

    def _ensure_container_removed(self, docker_bin: str, container_name: str) -> bool:
        """Ensure named container no longer exists, forcing removal if needed."""
        for _ in range(2):
            ps_res = self._runner.run(
                [docker_bin, "ps", "-aq", "--filter", f"name=^/{container_name}$"],
                timeout_seconds=10.0,
                max_output_bytes=8192,
            )
            if ps_res.outcome == SubprocessOutcome.COMPLETED and ps_res.returncode == 0:
                if not ps_res.stdout.decode("utf-8", errors="replace").strip():
                    return True
            self._runner.run(
                [docker_bin, "rm", "-f", container_name],
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
                require_overlay_exists=True,
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

        container_name = f"ctf-vdp-{action.action_id[:16]}-{uuid4().hex[:8]}"
        argv: list[str] = [
            docker_bin,
            "run",
            "--rm",
            "--init",
            "--name",
            container_name,
            "--network",
            "none",
            "--cpus",
            str(plan.cpus),
            "--memory",
            f"{plan.memory_mb}m",
            "--user",
            "0",
            "--workdir",
            "/src",
            "--entrypoint",
            "bash",
        ]
        if overlay_mount_dir is not None and plan.overlay_container_target is not None:
            argv.extend(
                [
                    "--mount",
                    f"type=bind,source={overlay_mount_dir},target={plan.overlay_container_target},readonly",
                ]
            )
        argv.append(plan.image_digest)
        if plan.operation == "run_smoke":
            argv.append(".oss-scanner/smoke")
        else:
            argv.extend([".oss-scanner/test", "-n", "0", "--maxfail=1", "-v", "-rA", *plan.test_selectors])

        sub_res: SubprocessResult
        container_cleanup_confirmed = True
        try:
            sub_res = self._runner.run(
                argv,
                timeout_seconds=eff_timeout,
                max_output_bytes=max_bytes,
                cancel_event=cancel_event,
            )
        finally:
            container_cleanup_confirmed = self._ensure_container_removed(docker_bin, container_name)

        finished_at = self._clock().isoformat()
        combined_raw = (sub_res.stdout + sub_res.stderr).decode("utf-8", errors="replace")
        overall_cleanup = bool(sub_res.cleanup_confirmed and container_cleanup_confirmed)

        parsed = _parse_pytest_output(
            combined_raw,
            requested_selectors=plan.test_selectors,
            operation=plan.operation,
        )
        verdict, verdict_reason, pos_passed, pos_failed, neg_passed, neg_failed = _classify_verdict(
            operation=plan.operation,
            outcome=sub_res.outcome,
            exit_code=sub_res.returncode,
            cleanup_confirmed=overall_cleanup,
            parsed=parsed,
            positive_selectors=plan.positive_selectors,
            negative_selectors=plan.negative_selectors,
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
            "positive_passed": pos_passed,
            "positive_failed": pos_failed,
            "negative_passed": neg_passed,
            "negative_failed": neg_failed,
            "selector_outcomes": parsed["selector_outcomes"],
            "overlay_bundle": plan.overlay_bundle,
            "overlay_file_hashes": overlay_file_hashes,
            "baseline_evidence_ref": plan.baseline_evidence_ref,
            "synthetic_data_only": True,
            "async_behavior_unverified": True,
            "verdict": verdict,
            "verdict_reason": verdict_reason,
            "container_cleanup_confirmed": container_cleanup_confirmed,
            "process_cleanup_confirmed": sub_res.cleanup_confirmed,
            "log_truncated": raw_truncated,
            "log_excerpt": combined_raw,
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
        elif verdict == "environment_failure":
            env_status = EnvelopeStatus.TOOL_ERROR
            err = ErrorDetail(
                code="environment_failure",
                message=verdict_reason,
                retryable=False,
            )
            truncated = not capture_complete
        else:
            # Structured verdict ("smoke_passed", "hypothesis_falsified", "deviation_reproduced",
            # "baseline_failed", "skipped", "not_executed", "baseline_passed") is preserved in OK envelope.
            env_status = EnvelopeStatus.OK
            err = None
            truncated = not capture_complete

        summary = (
            f"vdp.test:{action.operation} verdict={verdict} "
            f"(exit={sub_res.returncode}, collected={parsed['collected_count']}, "
            f"passed={parsed['passed_count']}, failed={parsed['failed_count']}, "
            f"skipped={parsed['skipped_count']}, cleanup={overall_cleanup})."
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
            "positive_passed": 0,
            "positive_failed": 0,
            "negative_passed": 0,
            "negative_failed": 0,
            "selector_outcomes": {},
            "overlay_bundle": plan.overlay_bundle,
            "overlay_file_hashes": plan.overlay_file_hashes,
            "baseline_evidence_ref": plan.baseline_evidence_ref,
            "synthetic_data_only": True,
            "async_behavior_unverified": True,
            "verdict": verdict,
            "verdict_reason": verdict_reason,
            "container_cleanup_confirmed": True,
            "process_cleanup_confirmed": True,
            "log_truncated": False,
            "log_excerpt": error_message,
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
    "VdpTargetProfile",
    "build_default_weblate_profile",
    "create_vdp_product_test_descriptor",
    "load_registered_vdp_profiles",
    "save_registered_vdp_profile",
    "validate_vdp_profile_registration",
    "validate_vdp_selector_format",
]
