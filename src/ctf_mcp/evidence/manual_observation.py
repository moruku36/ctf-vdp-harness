"""Out-of-harness manual isolated observation provenance import helpers.

Allows operators to record manual isolated verification runs (for example,
containerized PostgreSQL + internal network runs executed outside ``vdp.test``)
with pinned test-code hashes, target/image digests, executor/method metadata,
positive/negative controls, before/after state summaries, unverified conditions,
opaque private evidence references, and cleanup confirmations.

Security invariant:
    Imported records ALWAYS carry
    ``execution_provenance="manual_isolated_observation"``,
    ``verification_tier="manual_isolated_observation_not_harness_verified"``,
    and ``promoted_to_vdp_product_test=False``, and are rejected if passed to
    ``VdpProductTestVerifier`` (``vdp.product_test``).
    Neither CLI nor MCP intake fetches arbitrary external URLs or host paths.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime
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

MAX_MANUAL_OBSERVATION_SERIALIZED_BYTES = 32_768
_MAX_MANUAL_TEST_FILE_BYTES = 1_048_576
_MAX_PINNED_IMAGES = 16
_MAX_TEST_HASH_ENTRIES = 32
_MAX_PRIVATE_REFS = 16
_MAX_STRING_LIST_ITEMS = 32
_MAX_LIST_ITEM_CHARS = 400

_SHA256_RE = re.compile(SHA256_PATTERN)
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SAFE_REF_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,95}$")
_URL_SCHEME_RE = re.compile(r"(?i)\b(?:https?|ftp|file|ssh|sftp|data)://")
_PATH_TRAVERSAL_RE = re.compile(
    r"(?:^|[\s\"'(=\\/])\.\.(?:[\\/\s\"')]|$)|(?:[\\/]\.\.)|(?:\.\.[\\/])"
)
_ABS_PATH_RE = re.compile(
    r"(?:^|[\s\"'(=])(?:/(?:etc|home|root|var|tmp|proc|sys|opt|srv|usr|dev|boot|Users|mnt)/|"
    r"[A-Za-z]:[/\\]|\\\\[A-Za-z0-9._-]+\\)"
)
_RAW_LOG_MARKERS: tuple[str, ...] = (
    "traceback (most recent call last):",
    "http/1.1 ",
    "http/1.0 ",
    "http/2 ",
    "set-cookie:",
    "cookie:",
    "authorization:",
    "-----begin ",
)


def _assert_safe_text_value(
    value: str,
    *,
    field_name: str,
    forbid_urls: bool = False,
) -> None:
    if _PATH_TRAVERSAL_RE.search(value):
        raise PathSecurityError(
            f"Field {field_name!r} contains forbidden path traversal sequence."
        )
    if _ABS_PATH_RE.search(value):
        raise PathSecurityError(
            f"Field {field_name!r} contains a forbidden host filesystem path."
        )
    if forbid_urls and _URL_SCHEME_RE.search(value):
        raise ContractViolationError(
            f"Field {field_name!r} must not contain external or file URLs; use opaque SHA-256 references."
        )


def _detect_raw_log_markers(rendered_json: str) -> tuple[str, ...]:
    lowered = rendered_json.lower()
    return tuple(marker for marker in _RAW_LOG_MARKERS if marker in lowered)


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


class ManualPrivateEvidenceRef(StrictModel):
    """Opaque, redacted reference to a private out-of-harness artifact (digest + kind only)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ref_id: str = Field(min_length=2, max_length=96)
    sha256: str = Field(pattern=SHA256_PATTERN)
    kind: Literal[
        "log_digest",
        "test_script_digest",
        "db_snapshot_digest",
        "http_trace_digest",
        "artifact_digest",
        "other",
    ] = "other"
    description: str = Field(min_length=1, max_length=240)

    @model_validator(mode="after")
    def _validate_ref(self) -> ManualPrivateEvidenceRef:
        rid = self.ref_id.strip()
        if (
            not _SAFE_REF_ID_RE.fullmatch(rid)
            or ".." in rid
            or "/" in rid
            or "\\" in rid
            or "->" in rid
            or "symlink" in rid.lower()
            or _URL_SCHEME_RE.search(rid)
        ):
            raise ValueError(
                f"Private evidence ref_id {self.ref_id!r} must be an opaque safe identifier without paths, URLs, or symlinks."
            )
        try:
            _assert_safe_text_value(
                self.description,
                field_name="private_evidence_refs.description",
                forbid_urls=True,
            )
        except (PathSecurityError, ContractViolationError) as exc:
            raise ValueError(str(exc)) from exc
        return self


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
    intake_channel: Literal["cli", "mcp"] = "cli"
    observed_at: datetime
    target_name: str = Field(min_length=1, max_length=120)
    target_version: str = Field(min_length=1, max_length=80)
    pinned_source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    pinned_image_digests: dict[str, str]
    environment_summary: str = Field(min_length=1, max_length=400)
    isolation_declared: ManualIsolationDeclaration
    test_code_hashes: dict[str, str]
    executed_by: str | None = Field(default=None, min_length=1, max_length=120)
    execution_method: str | None = Field(default=None, min_length=1, max_length=160)
    execution_summary: str = Field(min_length=1, max_length=2000)
    before_state: str | None = Field(default=None, min_length=1, max_length=1000)
    after_state: str | None = Field(default=None, min_length=1, max_length=1000)
    exit_code: int | None = None
    controls: tuple[ManualControlRecord, ...] = Field(min_length=1, max_length=32)
    impact_boundaries: tuple[str, ...] = Field(default=(), max_length=_MAX_STRING_LIST_ITEMS)
    unverified_conditions: tuple[str, ...] = Field(default=(), max_length=_MAX_STRING_LIST_ITEMS)
    cleanup_confirmation: ManualCleanupConfirmation
    private_evidence_refs: tuple[ManualPrivateEvidenceRef, ...] = Field(
        default=(),
        max_length=_MAX_PRIVATE_REFS,
    )
    raw_log_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    notes: str = Field(default="", max_length=1000)

    @model_validator(mode="after")
    def _validate_provenance_and_secrecy(self) -> ManualObservationRecord:
        if ".." in self.observation_id:
            raise PathSecurityError("observation_id must not contain '..'.")

        if not self.pinned_image_digests or len(self.pinned_image_digests) > _MAX_PINNED_IMAGES:
            raise ContractViolationError(
                f"pinned_image_digests must contain 1..{_MAX_PINNED_IMAGES} image digests."
            )
        for img_name, digest in self.pinned_image_digests.items():
            clean_img = str(img_name).strip()
            if not clean_img or len(clean_img) > 160:
                raise ContractViolationError(
                    "Image key in pinned_image_digests must be 1..160 non-empty characters."
                )
            if (
                ".." in clean_img
                or "\\" in clean_img
                or "->" in clean_img
                or "symlink" in clean_img.lower()
                or _URL_SCHEME_RE.search(clean_img)
                or _ABS_PATH_RE.search(clean_img)
            ):
                raise PathSecurityError(
                    f"Unsafe image key {img_name!r} in pinned_image_digests."
                )
            if not _DIGEST_RE.fullmatch(str(digest).strip().lower()):
                raise ContractViolationError(
                    f"pinned_image_digests[{img_name!r}] must match sha256:<64-hex>."
                )

        if not self.test_code_hashes or len(self.test_code_hashes) > _MAX_TEST_HASH_ENTRIES:
            raise ContractViolationError(
                f"test_code_hashes must contain 1..{_MAX_TEST_HASH_ENTRIES} pinned manual test file hashes."
            )
        for fname, digest in self.test_code_hashes.items():
            if (
                not _SAFE_FILENAME_RE.fullmatch(fname)
                or ".." in fname
                or "symlink" in fname.lower()
            ):
                raise PathSecurityError(f"Invalid filename {fname!r} in test_code_hashes.")
            if not _SHA256_RE.fullmatch(str(digest).strip().lower()):
                raise ContractViolationError(
                    f"test_code_hashes[{fname!r}] must be a lowercase 64-hex SHA-256."
                )

        text_fields: list[tuple[str, str]] = [
            ("target_name", self.target_name),
            ("target_version", self.target_version),
            ("environment_summary", self.environment_summary),
            ("execution_summary", self.execution_summary),
            ("isolation_declared.network_description", self.isolation_declared.network_description),
            ("cleanup_confirmation.confirmed_by", self.cleanup_confirmation.confirmed_by),
            ("cleanup_confirmation.verification_note", self.cleanup_confirmation.verification_note),
            ("notes", self.notes),
        ]
        if self.executed_by is not None:
            text_fields.append(("executed_by", self.executed_by))
        if self.execution_method is not None:
            text_fields.append(("execution_method", self.execution_method))
        if self.before_state is not None:
            text_fields.append(("before_state", self.before_state))
        if self.after_state is not None:
            text_fields.append(("after_state", self.after_state))
        for idx, ctrl in enumerate(self.controls):
            text_fields.append((f"controls[{idx}].control_name", ctrl.control_name))
            text_fields.append((f"controls[{idx}].summary", ctrl.summary))
        for idx, boundary in enumerate(self.impact_boundaries):
            if not str(boundary).strip() or len(boundary) > _MAX_LIST_ITEM_CHARS:
                raise ContractViolationError(
                    f"impact_boundaries[{idx}] must be 1..{_MAX_LIST_ITEM_CHARS} non-empty chars."
                )
            text_fields.append((f"impact_boundaries[{idx}]", boundary))
        for idx, cond in enumerate(self.unverified_conditions):
            if not str(cond).strip() or len(cond) > _MAX_LIST_ITEM_CHARS:
                raise ContractViolationError(
                    f"unverified_conditions[{idx}] must be 1..{_MAX_LIST_ITEM_CHARS} non-empty chars."
                )
            text_fields.append((f"unverified_conditions[{idx}]", cond))

        for field_name, val in text_fields:
            _assert_safe_text_value(val, field_name=field_name, forbid_urls=False)

        serialized = json.dumps(
            self.model_dump(mode="json", by_alias=True),
            ensure_ascii=False,
            sort_keys=True,
        )
        encoded_len = len(serialized.encode("utf-8"))
        if encoded_len > MAX_MANUAL_OBSERVATION_SERIALIZED_BYTES:
            raise ContractViolationError(
                f"Manual observation payload ({encoded_len} bytes) exceeds limit ({MAX_MANUAL_OBSERVATION_SERIALIZED_BYTES} bytes)."
            )
        matched = scan_sensitive_markers(serialized)
        if matched:
            raise ContractViolationError(
                "Manual observation payload contains forbidden sensitive markers.",
                details={"matched_rules": list(matched)},
            )
        raw_markers = _detect_raw_log_markers(serialized)
        if raw_markers:
            raise ContractViolationError(
                "Manual observation payload contains raw logs or HTTP transcript markers; store redacted summaries and SHA-256 digests instead.",
                details={"matched_raw_markers": list(raw_markers)},
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
    norm_refs = tuple(
        ManualPrivateEvidenceRef(
            ref_id=ref.ref_id.strip(),
            sha256=ref.sha256.strip().lower(),
            kind=ref.kind,
            description=ref.description.strip(),
        )
        for ref in record.private_evidence_refs
    )
    unverified = list(dict.fromkeys(str(x).strip() for x in record.unverified_conditions if str(x).strip()))
    if NOT_EXECUTED_VIA_HARNESS_CONDITION not in unverified:
        unverified.insert(0, NOT_EXECUTED_VIA_HARNESS_CONDITION)
    return record.model_copy(
        update={
            "pinned_image_digests": norm_images,
            "test_code_hashes": norm_hashes,
            "private_evidence_refs": norm_refs,
            "unverified_conditions": tuple(unverified),
            "executed_by": record.executed_by.strip() if record.executed_by is not None else None,
            "execution_method": (
                record.execution_method.strip() if record.execution_method is not None else None
            ),
            "before_state": record.before_state.strip() if record.before_state is not None else None,
            "after_state": record.after_state.strip() if record.after_state is not None else None,
            "raw_log_sha256": (
                record.raw_log_sha256.strip().lower() if record.raw_log_sha256 is not None else None
            ),
        }
    )


def validate_manual_observation_for_intake(
    record: ManualObservationRecord,
    *,
    strict_intake: bool = False,
    intake_channel: Literal["cli", "mcp"] | None = None,
) -> ManualObservationRecord:
    """Validate manual observation for CLI or strict MCP intake and normalize provenance fields."""
    eff_record = (
        record.model_copy(update={"intake_channel": intake_channel})
        if intake_channel is not None and intake_channel != record.intake_channel
        else record
    )
    if strict_intake:
        missing: list[str] = []
        if not eff_record.executed_by or not eff_record.executed_by.strip():
            missing.append("executed_by")
        if not eff_record.execution_method or not eff_record.execution_method.strip():
            missing.append("execution_method")
        if not eff_record.before_state or not eff_record.before_state.strip():
            missing.append("before_state")
        if not eff_record.after_state or not eff_record.after_state.strip():
            missing.append("after_state")
        if not any(item.strip() for item in eff_record.unverified_conditions):
            missing.append("unverified_conditions")
        if not eff_record.private_evidence_refs:
            missing.append("private_evidence_refs")
        if missing:
            raise ContractViolationError(
                f"Strict manual observation intake is missing required provenance field(s): {', '.join(missing)}.",
                details={"missing_fields": missing},
            )

        roles = {ctrl.role for ctrl in eff_record.controls}
        if "positive_control" not in roles or not (roles & {"defense_check", "negative_control"}):
            raise ContractViolationError(
                "Strict manual observation intake requires both a 'positive_control' and at least one 'defense_check' or 'negative_control'."
            )

        iso = eff_record.isolation_declared
        if not (iso.synthetic_data_only and iso.external_egress_blocked and iso.published_ports_none):
            raise ContractViolationError(
                "Strict manual observation intake requires synthetic_data_only=True, external_egress_blocked=True, and published_ports_none=True."
            )

        url_checked: list[tuple[str, str]] = [
            ("target_name", eff_record.target_name),
            ("target_version", eff_record.target_version),
            ("environment_summary", eff_record.environment_summary),
            ("executed_by", eff_record.executed_by or ""),
            ("execution_method", eff_record.execution_method or ""),
            ("execution_summary", eff_record.execution_summary),
            ("before_state", eff_record.before_state or ""),
            ("after_state", eff_record.after_state or ""),
            ("isolation_declared.network_description", iso.network_description),
            ("cleanup_confirmation.verification_note", eff_record.cleanup_confirmation.verification_note),
            ("notes", eff_record.notes),
        ]
        for idx, ctrl in enumerate(eff_record.controls):
            url_checked.append((f"controls[{idx}].summary", ctrl.summary))
        for idx, boundary in enumerate(eff_record.impact_boundaries):
            url_checked.append((f"impact_boundaries[{idx}]", boundary))
        for idx, cond in enumerate(eff_record.unverified_conditions):
            url_checked.append((f"unverified_conditions[{idx}]", cond))
        for field_name, val in url_checked:
            if val:
                _assert_safe_text_value(val, field_name=field_name, forbid_urls=True)

    return normalize_manual_observation(eff_record)


def hash_manual_test_file(path: Path, *, max_bytes: int = _MAX_MANUAL_TEST_FILE_BYTES) -> tuple[str, str]:
    """Safely read and SHA-256 hash a regular non-symlink local manual test or log file."""
    if ".." in path.parts:
        raise PathSecurityError(f"Unsafe manual file path containing traversal: {path!s}.")
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
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise PathSecurityError(f"Failed to safely open manual file {path.name!r}: {exc}") from exc
    with os.fdopen(fd, "rb", closefd=True) as handle:
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


def read_bounded_manual_json_file(
    path: Path,
    *,
    max_bytes: int = MAX_MANUAL_OBSERVATION_SERIALIZED_BYTES,
) -> dict[str, Any]:
    """Safely read a regular non-symlink local JSON manifest file within bounded size."""
    if ".." in path.parts:
        raise PathSecurityError(f"Unsafe manifest path containing traversal: {path!s}.")
    try:
        st = os.lstat(path)
    except FileNotFoundError as exc:
        raise PathSecurityError(f"Manifest file {path!s} does not exist.") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise PathSecurityError(f"Manifest file {path.name!r} must be a regular non-symlink file.")
    if not _SAFE_FILENAME_RE.fullmatch(path.name) or ".." in path.name:
        raise PathSecurityError(f"Unsafe manifest filename {path.name!r}.")
    if st.st_size > max_bytes:
        raise ContractViolationError(
            f"Manifest file {path.name!r} ({st.st_size} bytes) exceeds limit ({max_bytes} bytes)."
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise PathSecurityError(f"Failed to safely open manifest {path.name!r}: {exc}") from exc
    with os.fdopen(fd, "rb", closefd=True) as handle:
        fst = os.fstat(handle.fileno())
        if fst.st_ino != st.st_ino or fst.st_dev != st.st_dev:
            raise PathSecurityError(f"Manifest file {path.name!r} changed during read.")
        raw = handle.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ContractViolationError(
            f"Manifest file {path.name!r} exceeds bounded read limit ({max_bytes} bytes)."
        )
    try:
        parsed = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractViolationError(f"Manifest file {path.name!r} is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ContractViolationError("--manifest-json must contain a JSON object.")
    return parsed


def serialize_manual_observation(record: ManualObservationRecord) -> bytes:
    """Validate, normalize, secrecy-check, and serialize a manual observation record."""
    normalized = normalize_manual_observation(record)
    payload = normalized.model_dump(mode="json", by_alias=True)
    rendered = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    rendered_bytes = rendered.encode("utf-8")
    if len(rendered_bytes) > MAX_MANUAL_OBSERVATION_SERIALIZED_BYTES:
        raise ContractViolationError(
            f"Serialized manual observation ({len(rendered_bytes)} bytes) exceeds limit ({MAX_MANUAL_OBSERVATION_SERIALIZED_BYTES} bytes)."
        )
    matched = scan_sensitive_markers(rendered)
    if matched:
        raise ContractViolationError(
            "Serialized manual observation contains forbidden sensitive markers.",
            details={"matched_rules": list(matched)},
        )
    raw_markers = _detect_raw_log_markers(rendered)
    if raw_markers:
        raise ContractViolationError(
            "Serialized manual observation contains raw logs or HTTP transcript markers.",
            details={"matched_raw_markers": list(raw_markers)},
        )
    return rendered_bytes


__all__ = [
    "MANUAL_OBSERVATION_PROVENANCE",
    "MANUAL_OBSERVATION_SCHEMA",
    "MANUAL_OBSERVATION_VERIFICATION_TIER",
    "MAX_MANUAL_OBSERVATION_SERIALIZED_BYTES",
    "NOT_EXECUTED_VIA_HARNESS_CONDITION",
    "ManualCleanupConfirmation",
    "ManualControlRecord",
    "ManualIsolationDeclaration",
    "ManualObservationRecord",
    "ManualPrivateEvidenceRef",
    "hash_manual_test_file",
    "normalize_manual_observation",
    "read_bounded_manual_json_file",
    "serialize_manual_observation",
    "validate_manual_observation_for_intake",
]
