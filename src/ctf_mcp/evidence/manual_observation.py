"""Out-of-harness manual isolated observation provenance import helpers.

Allows operators to record manual isolated verification runs (for example,
containerized PostgreSQL + internal network runs executed outside ``vdp.test``)
with pinned test-code hashes, target/image digests, passed/failed controls,
unverified conditions, and cleanup confirmations.

Security invariant:
    Imported records ALWAYS carry
    ``execution_provenance="manual_isolated_observation"``,
    ``verification_tier="manual_isolated_observation_not_harness_verified"``,
    and ``promoted_to_vdp_product_test=False``, and are rejected if passed to
    ``VdpProductTestVerifier`` (``vdp.product_test``).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import ConfigDict, Field, model_validator

from ctf_mcp.contracts import (
    SHA256_PATTERN,
    ContractViolationError,
    PathSecurityError,
    StrictModel,
)
from ctf_mcp.evidence.redaction import scan_sensitive_markers

MANUAL_OBSERVATION_SCHEMA = "vdp-manual-observation/1"
MANUAL_OBSERVATION_PROVENANCE = "manual_isolated_observation"
MANUAL_OBSERVATION_VERIFICATION_TIER = "manual_isolated_observation_not_harness_verified"
NOT_EXECUTED_VIA_HARNESS_CONDITION = "not_executed_via_harness_vdp_test"

_SHA256_RE = re.compile(SHA256_PATTERN)
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MAX_MANUAL_TEST_FILE_BYTES = 1_048_576


class ManualIsolationDeclaration(StrictModel):
    """Operator-declared isolation properties for a manual verification run."""

    synthetic_data_only: bool
    external_egress_blocked: bool
    published_ports_none: bool
    network_description: str = Field(min_length=1, max_length=240)


class ManualControlRecord(StrictModel):
    """Control or observation case recorded during a manual isolated run."""

    control_name: str = Field(min_length=1, max_length=160)
    role: Literal["positive_control", "negative_control", "defense_check", "anomaly_observation"]
    outcome: Literal["passed", "failed", "observed", "blocked", "not_run"]
    summary: str = Field(min_length=1, max_length=500)


class ManualCleanupConfirmation(StrictModel):
    """Operator-declared post-run cleanup confirmation for containers, DBs, and networks."""

    containers_removed: bool
    databases_removed: bool
    networks_removed: bool
    confirmed_by: str = Field(min_length=1, max_length=120)
    confirmed_at: datetime
    verification_note: str = Field(min_length=1, max_length=500)
    attestation_scope: Literal["operator_declared_manual_cleanup"] = "operator_declared_manual_cleanup"


class ManualObservationRecord(StrictModel):
    """Provenance record for an isolated observation executed outside ``vdp.test``."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_version: Literal["vdp-manual-observation/1"] = Field(
        default=MANUAL_OBSERVATION_SCHEMA,
        alias="schema",
    )
    observation_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{1,80}$")
    execution_provenance: Literal["manual_isolated_observation"] = MANUAL_OBSERVATION_PROVENANCE
    verification_tier: Literal["manual_isolated_observation_not_harness_verified"] = (
        MANUAL_OBSERVATION_VERIFICATION_TIER
    )
    promoted_to_vdp_product_test: Literal[False] = False
    observed_at: datetime
    target_name: str = Field(min_length=1, max_length=120)
    target_version: str = Field(min_length=1, max_length=80)
    pinned_source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    pinned_image_digests: dict[str, str]
    environment_summary: str = Field(min_length=1, max_length=400)
    isolation_declared: ManualIsolationDeclaration
    test_code_hashes: dict[str, str]
    execution_summary: str = Field(min_length=1, max_length=2000)
    exit_code: int | None = None
    controls: tuple[ManualControlRecord, ...] = Field(min_length=1, max_length=32)
    impact_boundaries: tuple[str, ...] = ()
    unverified_conditions: tuple[str, ...] = ()
    cleanup_confirmation: ManualCleanupConfirmation
    raw_log_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    notes: str = Field(default="", max_length=1000)

    @model_validator(mode="after")
    def _validate_provenance_and_secrecy(self) -> ManualObservationRecord:
        if not self.pinned_image_digests:
            raise ValueError("pinned_image_digests must pin at least one image digest.")
        for img_name, digest in self.pinned_image_digests.items():
            if not str(img_name).strip():
                raise ValueError("Image key in pinned_image_digests must be non-empty.")
            if not _DIGEST_RE.fullmatch(str(digest).strip().lower()):
                raise ValueError(
                    f"pinned_image_digests[{img_name!r}] must match sha256:<64-hex>."
                )

        if not self.test_code_hashes:
            raise ValueError("test_code_hashes must pin at least one manual test file hash.")
        for fname, digest in self.test_code_hashes.items():
            if not _SAFE_FILENAME_RE.fullmatch(fname) or ".." in fname:
                raise ValueError(f"Invalid filename {fname!r} in test_code_hashes.")
            if not _SHA256_RE.fullmatch(str(digest).strip().lower()):
                raise ValueError(
                    f"test_code_hashes[{fname!r}] must be a lowercase 64-hex SHA-256."
                )

        serialized = json.dumps(
            self.model_dump(mode="json", by_alias=True),
            ensure_ascii=False,
            sort_keys=True,
        )
        matched = scan_sensitive_markers(serialized)
        if matched:
            raise ContractViolationError(
                "Manual observation payload contains forbidden sensitive markers.",
                details={"matched_rules": list(matched)},
            )
        return self


def normalize_manual_observation(record: ManualObservationRecord) -> ManualObservationRecord:
    """Ensure canonical lowercase digests and explicit non-harness limitation tag."""
    norm_images = {
        str(k).strip(): str(v).strip().lower()
        for k, v in sorted(record.pinned_image_digests.items())
    }
    norm_hashes = {
        str(k).strip(): str(v).strip().lower()
        for k, v in sorted(record.test_code_hashes.items())
    }
    unverified = list(dict.fromkeys(str(x).strip() for x in record.unverified_conditions if str(x).strip()))
    if NOT_EXECUTED_VIA_HARNESS_CONDITION not in unverified:
        unverified.insert(0, NOT_EXECUTED_VIA_HARNESS_CONDITION)
    return record.model_copy(
        update={
            "pinned_image_digests": norm_images,
            "test_code_hashes": norm_hashes,
            "unverified_conditions": tuple(unverified),
        }
    )


def hash_manual_test_file(path: Path, *, max_bytes: int = _MAX_MANUAL_TEST_FILE_BYTES) -> tuple[str, str]:
    """Safely read and SHA-256 hash a regular non-symlink local manual test or log file."""
    try:
        st = os.lstat(path)
    except FileNotFoundError as exc:
        raise PathSecurityError(f"Manual file {path!s} does not exist.") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise PathSecurityError(f"Manual file {path.name!r} must be a regular non-symlink file.")
    if not _SAFE_FILENAME_RE.fullmatch(path.name) or ".." in path.name:
        raise PathSecurityError(f"Unsafe manual filename {path.name!r}.")
    digest = hashlib.sha256()
    total = 0
    with open(path, "rb") as handle:
        fst = os.fstat(handle.fileno())
        if fst.st_ino != st.st_ino or fst.st_dev != st.st_dev:
            raise PathSecurityError(f"Manual file {path.name!r} changed during read.")
        while chunk := handle.read(65_536):
            total += len(chunk)
            if total > max_bytes:
                raise ContractViolationError(
                    f"Manual file {path.name!r} exceeds bounded read limit ({max_bytes} bytes)."
                )
            digest.update(chunk)
    return path.name, digest.hexdigest()


def serialize_manual_observation(record: ManualObservationRecord) -> bytes:
    """Validate, normalize, secrecy-check, and serialize a manual observation record."""
    normalized = normalize_manual_observation(record)
    payload = normalized.model_dump(mode="json", by_alias=True)
    rendered = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    matched = scan_sensitive_markers(rendered)
    if matched:
        raise ContractViolationError(
            "Serialized manual observation contains forbidden sensitive markers.",
            details={"matched_rules": list(matched)},
        )
    return rendered.encode("utf-8")


__all__ = [
    "MANUAL_OBSERVATION_PROVENANCE",
    "MANUAL_OBSERVATION_SCHEMA",
    "MANUAL_OBSERVATION_VERIFICATION_TIER",
    "NOT_EXECUTED_VIA_HARNESS_CONDITION",
    "ManualCleanupConfirmation",
    "ManualControlRecord",
    "ManualIsolationDeclaration",
    "ManualObservationRecord",
    "hash_manual_test_file",
    "normalize_manual_observation",
    "serialize_manual_observation",
]
