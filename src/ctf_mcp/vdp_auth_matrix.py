"""Bounded, human-authored authorization matrix runner for VDP overlays and CLI.

Connects human-defined ``(actor, resource, action, entrypoint)`` expectation pairs
to ``vdp.test`` / overlay test runs while enforcing:

- Strict allowlisting of actors, resources, actions, and entrypoints.
- Explicit expectation grounding (``https://`` reference URL or ``file:line``)
  and explicit ``policy_source_kind="human_documented_policy"`` (never treating
  observed runtime output as policy).
- Paired positive (``allow``) and negative (``deny``) controls per ``pair_group``
  so broken baselines block defense claims rather than hiding regressions.
- Multi-layer redacted diffing across HTTP status, ``Location`` header, JSON
  keys, synthetic markers, persistent DB state, Git revisions, and task queue
  enqueueing — without storing raw HTTP bodies, cookies, or bearer tokens.
- Fail-closed combination, wall-clock, and output-byte limits.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Literal

from pydantic import ConfigDict, Field, model_validator

from ctf_mcp.contracts import (
    BoundsExceededError,
    ContractViolationError,
    PathSecurityError,
    StrictModel,
)
from ctf_mcp.vdp_boundary_map import BoundaryDiffMap
from ctf_mcp.vdp_fixtures import (
    emit_vdp_evidence_marker,
    redact_sensitive_text,
    redact_structure,
)

AUTH_MATRIX_COMMAND = "vdp-auth-matrix"
AUTH_MATRIX_SCHEMA = "vdp-auth-matrix/1"
AUTH_MATRIX_CANDIDATE_SCHEMA = "vdp-auth-matrix-candidates/1"
AUTH_MATRIX_RESULT_SCHEMA = "vdp-auth-matrix-result/1"
INVESTIGATION_CANDIDATE_ONLY_POLICY: Literal["investigation_candidate_only"] = (
    "investigation_candidate_only"
)

MAX_MATRIX_COMBINATIONS = 64
MAX_MATRIX_RUNTIME_SECONDS = 30.0
MAX_MATRIX_OUTPUT_BYTES = 32_768
_MAX_MATRIX_INPUT_FILE_BYTES = 65_536

VALID_ENTRYPOINT_KINDS: tuple[str, ...] = ("ui", "api", "webhook", "async")
VALID_COMPARED_FIELDS: tuple[str, ...] = (
    "http_status",
    "location_header",
    "json_keys",
    "synthetic_markers",
    "db_state",
    "git_revision",
    "queue_enqueued",
)

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,80}$")
_PAIR_GROUP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")
_HTTPS_BASIS_RE = re.compile(r"^https://[^\s/@]+(?::\d+)?(?:/[^\s]*)?$")
_FILE_LINE_BASIS_RE = re.compile(r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*:[1-9][0-9]*$")
_SECRET_SCAN_RE = re.compile(
    r"(?:SYNTHETIC_SECRET(?:_[A-Za-z0-9._:/=+-]+)?|"
    r"CTF_SENSITIVE_MARKER(?:[:_=-][A-Za-z0-9._:/=+-]+)?|"
    r"sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|"
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)",
    re.IGNORECASE,
)


def _assert_clean_no_secret(value: str, *, field_name: str) -> None:
    if redact_sensitive_text(value) != value or _SECRET_SCAN_RE.search(value):
        raise ContractViolationError(
            f"Field {field_name!r} contains forbidden secret or credential markers."
        )


def _validate_expectation_basis(value: str) -> str:
    clean = value.strip()
    if not clean or len(clean) > 300:
        raise ValueError("expectation_basis must be 1..300 non-empty chars.")
    if ".." in clean or "\\" in clean:
        raise ValueError("expectation_basis must not contain path traversal or backslashes.")
    if clean.startswith("/"):
        raise ValueError("expectation_basis must use a relative file:line path or https:// URL.")
    if clean.lower().startswith("http://"):
        raise ValueError("expectation_basis URLs must use https://, not plaintext http://.")
    if "@" in clean and "://" in clean:
        raise ValueError("expectation_basis URL must not include embedded credentials.")
    if _HTTPS_BASIS_RE.fullmatch(clean) or _FILE_LINE_BASIS_RE.fullmatch(clean):
        return clean
    raise ValueError(
        "expectation_basis must be a relative 'path/file.py:line' reference or an 'https://' documentation URL."
    )


def _read_bounded_json_file(path: Path, *, max_bytes: int = _MAX_MATRIX_INPUT_FILE_BYTES) -> dict[str, Any]:
    """Read a regular non-symlink UTF-8 JSON object within strict size bounds."""
    if ".." in path.parts:
        raise PathSecurityError(f"Unsafe path containing traversal: {path!s}.")
    try:
        st = os.lstat(path)
    except FileNotFoundError as exc:
        raise PathSecurityError(f"Input JSON file {path!s} does not exist.") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise PathSecurityError(f"Input JSON file {path.name!r} must be a regular non-symlink file.")
    if st.st_size > max_bytes:
        raise BoundsExceededError(
            f"Input JSON file {path.name!r} ({st.st_size} bytes) exceeds limit ({max_bytes} bytes)."
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise PathSecurityError(f"Failed to safely open {path.name!r}: {exc}") from exc
    with os.fdopen(fd, "rb", closefd=True) as handle:
        fst = os.fstat(handle.fileno())
        if fst.st_ino != st.st_ino or fst.st_dev != st.st_dev:
            raise PathSecurityError(f"Input file {path.name!r} changed during read.")
        raw = handle.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise BoundsExceededError(
            f"Input JSON file {path.name!r} exceeds bounded read limit ({max_bytes} bytes)."
        )
    try:
        parsed = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractViolationError(f"Invalid UTF-8 JSON in {path.name!r}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ContractViolationError(f"Input file {path.name!r} must contain a JSON object.")
    return parsed


def _write_bounded_json_file(path: Path, payload: Mapping[str, Any]) -> None:
    if ".." in path.parts:
        raise PathSecurityError(f"Unsafe output path containing traversal: {path!s}.")
    if path.exists():
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise PathSecurityError(f"Output path {path.name!r} must not be a symlink.")
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    tmp_path = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp_path, flags, 0o600)
    with os.fdopen(fd, "wb", closefd=True) as handle:
        handle.write(rendered)
    os.replace(tmp_path, path)


class AuthMatrixAllowlist(StrictModel):
    """Explicitly permitted dimensions for a single bounded authorization matrix run."""

    actors: tuple[str, ...] = Field(min_length=1, max_length=32)
    resources: tuple[str, ...] = Field(min_length=1, max_length=32)
    actions: tuple[str, ...] = Field(min_length=1, max_length=32)
    entrypoints: tuple[Literal["ui", "api", "webhook", "async"], ...] = Field(min_length=1, max_length=4)

    @model_validator(mode="after")
    def _validate_items(self) -> AuthMatrixAllowlist:
        for group_name, values in (
            ("actors", self.actors),
            ("resources", self.resources),
            ("actions", self.actions),
        ):
            for item in values:
                if not _ID_RE.fullmatch(item):
                    raise ContractViolationError(
                        f"Allowlist entry {item!r} in {group_name} has invalid identifier syntax."
                    )
        return self


class AuthMatrixRunLimits(StrictModel):
    """Hard per-run caps on combination count, wall-clock time, and evidence output size."""

    max_combinations: int = Field(default=32, ge=1, le=MAX_MATRIX_COMBINATIONS)
    max_runtime_seconds: float = Field(default=15.0, gt=0.0, le=MAX_MATRIX_RUNTIME_SECONDS)
    max_output_bytes: int = Field(default=16_384, ge=512, le=MAX_MATRIX_OUTPUT_BYTES)


class AuthMatrixCase(StrictModel):
    """One grounded authorization expectation row in a human-authored matrix."""

    case_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{1,80}$")
    pair_group: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")
    actor: str = Field(min_length=1, max_length=64)
    resource: str = Field(min_length=1, max_length=64)
    action: str = Field(min_length=1, max_length=64)
    entrypoint: Literal["ui", "api", "webhook", "async"]
    expected_decision: Literal["allow", "deny"]
    required_preconfiguration: str = Field(min_length=1, max_length=400)
    expectation_basis: str = Field(min_length=1, max_length=300)
    compared_fields: tuple[
        Literal[
            "http_status",
            "location_header",
            "json_keys",
            "synthetic_markers",
            "db_state",
            "git_revision",
            "queue_enqueued",
        ],
        ...,
    ] = Field(min_length=1, max_length=7)
    expected_statuses: tuple[int, ...] = Field(default=(), max_length=16)
    forbidden_synthetic_markers: tuple[str, ...] = Field(default=(), max_length=16)
    forbidden_json_keys: tuple[str, ...] = Field(default=(), max_length=16)
    forbid_db_mutation: bool = False
    forbid_git_revision_change: bool = False
    forbid_queue_enqueue: bool = False
    candidate_ref: str | None = Field(default=None, max_length=120)

    @model_validator(mode="after")
    def _validate_case(self) -> AuthMatrixCase:
        _validate_expectation_basis(self.expectation_basis)
        for status_code in self.expected_statuses:
            if status_code < 100 or status_code > 599:
                raise ContractViolationError(f"Invalid HTTP status code {status_code} in {self.case_id!r}.")
        _assert_clean_no_secret(self.required_preconfiguration, field_name="required_preconfiguration")
        _assert_clean_no_secret(self.expectation_basis, field_name="expectation_basis")
        for marker in self.forbidden_synthetic_markers:
            if not marker.strip() or len(marker) > 120:
                raise ContractViolationError("forbidden_synthetic_markers entries must be 1..120 chars.")
            _assert_clean_no_secret(marker, field_name="forbidden_synthetic_markers")
        for jkey in self.forbidden_json_keys:
            if not jkey.strip() or len(jkey) > 120:
                raise ContractViolationError("forbidden_json_keys entries must be 1..120 chars.")
        return self


class AuthMatrixSpec(StrictModel):
    """Complete human-authored authorization matrix specification."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_version: Literal["vdp-auth-matrix/1"] = Field(
        default=AUTH_MATRIX_SCHEMA,
        alias="schema",
    )
    matrix_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{1,80}$")
    target_name: str = Field(min_length=1, max_length=120)
    authored_by: str = Field(min_length=1, max_length=120)
    policy_source_kind: Literal["human_documented_policy"] = "human_documented_policy"
    allowlist: AuthMatrixAllowlist
    limits: AuthMatrixRunLimits = Field(default_factory=AuthMatrixRunLimits)
    cases: tuple[AuthMatrixCase, ...] = Field(min_length=2, max_length=MAX_MATRIX_COMBINATIONS)
    notes: str = Field(default="", max_length=500)

    @model_validator(mode="after")
    def _validate_matrix(self) -> AuthMatrixSpec:
        if len(self.cases) > self.limits.max_combinations:
            raise BoundsExceededError(
                f"Matrix has {len(self.cases)} cases, exceeding max_combinations={self.limits.max_combinations}."
            )
        _assert_clean_no_secret(self.target_name, field_name="target_name")
        _assert_clean_no_secret(self.authored_by, field_name="authored_by")
        _assert_clean_no_secret(self.notes, field_name="notes")

        seen_ids: set[str] = set()
        group_decisions: dict[str, set[str]] = {}
        allowed_actors = set(self.allowlist.actors)
        allowed_resources = set(self.allowlist.resources)
        allowed_actions = set(self.allowlist.actions)
        allowed_entrypoints = set(self.allowlist.entrypoints)

        for case in self.cases:
            if case.case_id in seen_ids:
                raise ContractViolationError(f"Duplicate matrix case_id {case.case_id!r}.")
            seen_ids.add(case.case_id)

            if case.actor not in allowed_actors:
                raise ContractViolationError(
                    f"Case {case.case_id!r} actor {case.actor!r} is not in allowlist.actors."
                )
            if case.resource not in allowed_resources:
                raise ContractViolationError(
                    f"Case {case.case_id!r} resource {case.resource!r} is not in allowlist.resources."
                )
            if case.action not in allowed_actions:
                raise ContractViolationError(
                    f"Case {case.case_id!r} action {case.action!r} is not in allowlist.actions."
                )
            if case.entrypoint not in allowed_entrypoints:
                raise ContractViolationError(
                    f"Case {case.case_id!r} entrypoint {case.entrypoint!r} is not in allowlist.entrypoints."
                )
            group_decisions.setdefault(case.pair_group, set()).add(case.expected_decision)

        for grp, decisions in group_decisions.items():
            if decisions != {"allow", "deny"}:
                raise ContractViolationError(
                    f"Pair group {grp!r} must include both 'allow' (positive control) and 'deny' expectations, got {sorted(decisions)!r}."
                )
        return self


class AuthMatrixObservation(StrictModel):
    """Bounded, redacted multi-layer observation returned by a matrix case executor."""

    http_status: int | None = None
    location_header: str | None = Field(default=None, max_length=300)
    json_keys: tuple[str, ...] = Field(default=(), max_length=64)
    observed_synthetic_markers: tuple[str, ...] = Field(default=(), max_length=32)
    db_state_before: dict[str, str | int | bool | None] = Field(default_factory=dict)
    db_state_after: dict[str, str | int | bool | None] = Field(default_factory=dict)
    git_revision_before: str | None = Field(default=None, max_length=80)
    git_revision_after: str | None = Field(default=None, max_length=80)
    queue_enqueued_before: tuple[str, ...] = Field(default=(), max_length=32)
    queue_enqueued_after: tuple[str, ...] = Field(default=(), max_length=32)


def _collect_json_keys(obj: Any, *, prefix: str = "", depth: int = 0, out: set[str]) -> None:
    if depth >= 4 or len(out) >= 64:
        return
    if isinstance(obj, Mapping):
        for k, v in obj.items():
            clean_k = str(k).strip()
            if not clean_k:
                continue
            full_k = f"{prefix}.{clean_k}" if prefix else clean_k
            out.add(full_k[:120])
            if len(out) >= 64:
                return
            _collect_json_keys(v, prefix=full_k, depth=depth + 1, out=out)
    elif isinstance(obj, (list, tuple)):
        for item in obj[:16]:
            if len(out) >= 64:
                return
            _collect_json_keys(item, prefix=prefix, depth=depth + 1, out=out)


def _scan_markers_in_value(value: Any, markers: Sequence[str], found: set[str], depth: int = 0) -> None:
    if depth > 6 or len(found) >= 32:
        return
    if isinstance(value, str):
        low = value.lower()
        for m in markers:
            if m.lower() in low:
                found.add(m)
    elif isinstance(value, Mapping):
        for k, v in value.items():
            _scan_markers_in_value(str(k), markers, found, depth + 1)
            _scan_markers_in_value(v, markers, found, depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value[:32]:
            _scan_markers_in_value(item, markers, found, depth + 1)


def _sanitize_scalar_state(raw: Mapping[str, Any] | None) -> dict[str, str | int | bool | None]:
    if not raw:
        return {}
    cleaned = redact_structure(dict(raw))
    out: dict[str, str | int | bool | None] = {}
    for k in sorted(cleaned.keys())[:16]:
        v = cleaned[k]
        if v is None or isinstance(v, (bool, int)):
            out[str(k)[:64]] = v
        else:
            out[str(k)[:64]] = redact_sensitive_text(str(v))[:160]
    return out


def extract_bounded_observation(
    *,
    http_status: int | None = None,
    headers: Mapping[str, str] | None = None,
    json_body: Any = None,
    raw_text: str | None = None,
    watched_markers: Sequence[str] = (),
    db_state_before: Mapping[str, Any] | None = None,
    db_state_after: Mapping[str, Any] | None = None,
    git_revision_before: str | None = None,
    git_revision_after: str | None = None,
    queue_enqueued_before: Sequence[str] = (),
    queue_enqueued_after: Sequence[str] = (),
) -> AuthMatrixObservation:
    """Build a bounded, redacted ``AuthMatrixObservation`` without persisting raw bodies or tokens.

    Cookies, Authorization headers, and raw JSON values are intentionally excluded; only
    sorted JSON key names, redacted ``Location`` headers, matched synthetic marker names,
    and redacted DB/Git/queue metadata are returned.
    """
    loc_val: str | None = None
    if headers:
        for hk, hv in headers.items():
            if str(hk).strip().lower() == "location":
                loc_val = redact_sensitive_text(str(hv).strip())[:300]
                break

    keys_set: set[str] = set()
    if json_body is not None:
        _collect_json_keys(json_body, out=keys_set)

    found_markers: set[str] = set()
    clean_watched = tuple(str(m).strip() for m in watched_markers if str(m).strip())[:32]
    if clean_watched:
        if loc_val:
            _scan_markers_in_value(loc_val, clean_watched, found_markers)
        if json_body is not None:
            _scan_markers_in_value(json_body, clean_watched, found_markers)
        if raw_text:
            _scan_markers_in_value(raw_text[:8192], clean_watched, found_markers)

    return AuthMatrixObservation(
        http_status=http_status,
        location_header=loc_val,
        json_keys=tuple(sorted(keys_set)),
        observed_synthetic_markers=tuple(sorted(found_markers)),
        db_state_before=_sanitize_scalar_state(db_state_before),
        db_state_after=_sanitize_scalar_state(db_state_after),
        git_revision_before=redact_sensitive_text(git_revision_before)[:80] if git_revision_before else None,
        git_revision_after=redact_sensitive_text(git_revision_after)[:80] if git_revision_after else None,
        queue_enqueued_before=tuple(redact_sensitive_text(str(q))[:120] for q in list(queue_enqueued_before)[:32]),
        queue_enqueued_after=tuple(redact_sensitive_text(str(q))[:120] for q in list(queue_enqueued_after)[:32]),
    )


class AuthMatrixCaseResult(StrictModel):
    """Per-case outcome with bounded redacted diff and non-final status."""

    case_id: str
    pair_group: str
    actor: str
    resource: str
    action: str
    entrypoint: Literal["ui", "api", "webhook", "async"]
    expected_decision: Literal["allow", "deny"]
    outcome: Literal[
        "positive_passed",
        "positive_failed",
        "defense_held",
        "investigation_candidate",
        "baseline_blocked",
        "skipped_limit",
    ]
    mismatch_reasons: tuple[str, ...] = ()
    redacted_diff: dict[str, Any] = Field(default_factory=dict)
    expectation_basis: str
    candidate_ref: str | None = None


class AuthMatrixPairSummary(StrictModel):
    """Summary for one paired positive/negative authorization group."""

    pair_group: str
    positive_ok: bool
    defense_held_count: int
    investigation_candidate_count: int
    baseline_blocked_count: int
    skipped_count: int


class AuthMatrixRunResult(StrictModel):
    """Structured result emitted by ``AuthMatrixRunner`` (never declares confirmed vulnerabilities)."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_version: Literal["vdp-auth-matrix-result/1"] = Field(
        default=AUTH_MATRIX_RESULT_SCHEMA,
        alias="schema",
    )
    matrix_id: str
    target_name: str
    policy_source_kind: Literal["human_documented_policy"] = "human_documented_policy"
    status_policy: Literal["investigation_candidate_only"] = INVESTIGATION_CANDIDATE_ONLY_POLICY
    total_cases: int = Field(ge=0)
    executed_cases: int = Field(ge=0)
    positive_passed: int = Field(ge=0)
    positive_failed: int = Field(ge=0)
    defense_held: int = Field(ge=0)
    investigation_candidates: int = Field(ge=0)
    baseline_blocked: int = Field(ge=0)
    skipped_limit: int = Field(ge=0)
    timed_out: bool = False
    output_truncated: bool = False
    wall_ms: int = Field(ge=0)
    pair_summaries: tuple[AuthMatrixPairSummary, ...] = ()
    case_results: tuple[AuthMatrixCaseResult, ...] = ()


def _key_matches(observed_key: str, forbidden: str) -> bool:
    return (
        observed_key == forbidden
        or observed_key.endswith(f".{forbidden}")
        or forbidden in observed_key.split(".")
    )


def _evaluate_allow_case(case: AuthMatrixCase, obs: AuthMatrixObservation) -> tuple[list[str], dict[str, Any]]:
    reasons: list[str] = []
    diff: dict[str, Any] = {}
    if "http_status" in case.compared_fields:
        if case.expected_statuses:
            if obs.http_status not in case.expected_statuses:
                reasons.append("positive_unexpected_http_status")
                diff["http_status"] = {
                    "observed": obs.http_status,
                    "expected": list(case.expected_statuses),
                }
        elif obs.http_status is None or obs.http_status >= 400:
            reasons.append("positive_request_failed")
            diff["http_status"] = {"observed": obs.http_status, "expected": "<400"}
    return reasons, redact_structure(diff)


def _evaluate_deny_case(case: AuthMatrixCase, obs: AuthMatrixObservation) -> tuple[list[str], dict[str, Any]]:
    reasons: list[str] = []
    diff: dict[str, Any] = {}
    fields = set(case.compared_fields)

    if "http_status" in fields:
        if case.expected_statuses:
            if obs.http_status not in case.expected_statuses:
                reasons.append("unexpected_http_status")
                diff["http_status"] = {
                    "observed": obs.http_status,
                    "expected": list(case.expected_statuses),
                }
        elif obs.http_status is not None and 200 <= obs.http_status < 400:
            reasons.append("unexpected_allow_status")
            diff["http_status"] = {"observed": obs.http_status, "expected": "deny (>=400)"}

    if "location_header" in fields and obs.location_header:
        low_loc = obs.location_header.lower()
        leaked_loc_markers = [
            m for m in case.forbidden_synthetic_markers if m.lower() in low_loc
        ]
        if leaked_loc_markers:
            reasons.append("location_header_marker_leak")
            diff["location_header"] = {
                "location": redact_sensitive_text(obs.location_header)[:300],
                "matched_markers": leaked_loc_markers,
            }

    if "json_keys" in fields and case.forbidden_json_keys and obs.json_keys:
        leaked_keys = [
            ok
            for ok in obs.json_keys
            if any(_key_matches(ok, fk) for fk in case.forbidden_json_keys)
        ]
        if leaked_keys:
            reasons.append("json_key_leak")
            diff["json_keys"] = sorted(set(leaked_keys))

    if "synthetic_markers" in fields and case.forbidden_synthetic_markers and obs.observed_synthetic_markers:
        forbidden_set = {m.lower() for m in case.forbidden_synthetic_markers}
        matched = [
            m for m in obs.observed_synthetic_markers if m.lower() in forbidden_set
        ]
        if matched:
            reasons.append("synthetic_marker_leak")
            diff["synthetic_markers"] = matched

    if "db_state" in fields and case.forbid_db_mutation:
        if obs.db_state_before != obs.db_state_after:
            reasons.append("unexpected_db_mutation")
            changed: dict[str, dict[str, Any]] = {}
            all_keys = sorted(set(obs.db_state_before.keys()) | set(obs.db_state_after.keys()))
            for k in all_keys[:16]:
                vb = obs.db_state_before.get(k)
                va = obs.db_state_after.get(k)
                if vb != va:
                    changed[k] = {"before": vb, "after": va}
            diff["db_state_diff"] = changed

    if "git_revision" in fields and case.forbid_git_revision_change:
        if obs.git_revision_before != obs.git_revision_after:
            reasons.append("unexpected_git_revision_change")
            diff["git_revision_diff"] = {
                "before": obs.git_revision_before,
                "after": obs.git_revision_after,
            }

    if "queue_enqueued" in fields and case.forbid_queue_enqueue:
        before_q = tuple(obs.queue_enqueued_before)
        after_q = tuple(obs.queue_enqueued_after)
        if len(after_q) > len(before_q) or (after_q != before_q and after_q):
            reasons.append("unexpected_queue_enqueue")
            appended = (
                list(after_q[len(before_q):])
                if len(after_q) >= len(before_q) and after_q[: len(before_q)] == before_q
                else list(after_q)
            )
            diff["queue_enqueued_diff"] = {"added": appended}

    return reasons, redact_structure(diff)


class AuthMatrixRunner:
    """Execute a bounded human-authored ``AuthMatrixSpec`` against an isolated fixture executor."""

    def __init__(
        self,
        matrix: AuthMatrixSpec,
        executor: Callable[[AuthMatrixCase], AuthMatrixObservation],
    ) -> None:
        self.matrix = matrix
        self.executor = executor

    def run(self) -> AuthMatrixRunResult:
        start = time.monotonic()
        max_rt = self.matrix.limits.max_runtime_seconds
        max_bytes = self.matrix.limits.max_output_bytes

        grouped_cases: dict[str, list[AuthMatrixCase]] = {}
        for case in self.matrix.cases:
            grouped_cases.setdefault(case.pair_group, []).append(case)

        case_results: list[AuthMatrixCaseResult] = []
        pair_summaries: list[AuthMatrixPairSummary] = []

        pos_passed = 0
        pos_failed = 0
        def_held = 0
        candidates = 0
        blocked = 0
        skipped = 0
        executed = 0
        timed_out = False

        for grp, members in grouped_cases.items():
            allows = [c for c in members if c.expected_decision == "allow"]
            denies = [c for c in members if c.expected_decision == "deny"]

            grp_pos_ok = True
            grp_def = 0
            grp_cand = 0
            grp_blk = 0
            grp_skip = 0

            for case in allows:
                if (time.monotonic() - start) >= max_rt:
                    timed_out = True
                    grp_pos_ok = False
                    skipped += 1
                    grp_skip += 1
                    case_results.append(
                        AuthMatrixCaseResult(
                            case_id=case.case_id,
                            pair_group=grp,
                            actor=case.actor,
                            resource=case.resource,
                            action=case.action,
                            entrypoint=case.entrypoint,
                            expected_decision=case.expected_decision,
                            outcome="skipped_limit",
                            mismatch_reasons=("runtime_limit_exceeded",),
                            redacted_diff={},
                            expectation_basis=case.expectation_basis,
                            candidate_ref=case.candidate_ref,
                        )
                    )
                    continue

                obs = self.executor(case)
                executed += 1
                reasons, diff = _evaluate_allow_case(case, obs)
                if reasons:
                    grp_pos_ok = False
                    pos_failed += 1
                    outcome: Literal["positive_passed", "positive_failed"] = "positive_failed"
                else:
                    pos_passed += 1
                    outcome = "positive_passed"
                case_results.append(
                    AuthMatrixCaseResult(
                        case_id=case.case_id,
                        pair_group=grp,
                        actor=case.actor,
                        resource=case.resource,
                        action=case.action,
                        entrypoint=case.entrypoint,
                        expected_decision=case.expected_decision,
                        outcome=outcome,
                        mismatch_reasons=tuple(reasons),
                        redacted_diff=diff,
                        expectation_basis=case.expectation_basis,
                        candidate_ref=case.candidate_ref,
                    )
                )

            for case in denies:
                if timed_out or (time.monotonic() - start) >= max_rt:
                    timed_out = True
                    skipped += 1
                    grp_skip += 1
                    case_results.append(
                        AuthMatrixCaseResult(
                            case_id=case.case_id,
                            pair_group=grp,
                            actor=case.actor,
                            resource=case.resource,
                            action=case.action,
                            entrypoint=case.entrypoint,
                            expected_decision=case.expected_decision,
                            outcome="skipped_limit",
                            mismatch_reasons=("runtime_limit_exceeded",),
                            redacted_diff={},
                            expectation_basis=case.expectation_basis,
                            candidate_ref=case.candidate_ref,
                        )
                    )
                    continue

                if not grp_pos_ok:
                    blocked += 1
                    grp_blk += 1
                    case_results.append(
                        AuthMatrixCaseResult(
                            case_id=case.case_id,
                            pair_group=grp,
                            actor=case.actor,
                            resource=case.resource,
                            action=case.action,
                            entrypoint=case.entrypoint,
                            expected_decision=case.expected_decision,
                            outcome="baseline_blocked",
                            mismatch_reasons=("pair_group_positive_control_failed",),
                            redacted_diff={},
                            expectation_basis=case.expectation_basis,
                            candidate_ref=case.candidate_ref,
                        )
                    )
                    continue

                obs = self.executor(case)
                executed += 1
                reasons, diff = _evaluate_deny_case(case, obs)
                if reasons:
                    candidates += 1
                    grp_cand += 1
                    deny_outcome: Literal["defense_held", "investigation_candidate"] = "investigation_candidate"
                else:
                    def_held += 1
                    grp_def += 1
                    deny_outcome = "defense_held"
                case_results.append(
                    AuthMatrixCaseResult(
                        case_id=case.case_id,
                        pair_group=grp,
                        actor=case.actor,
                        resource=case.resource,
                        action=case.action,
                        entrypoint=case.entrypoint,
                        expected_decision=case.expected_decision,
                        outcome=deny_outcome,
                        mismatch_reasons=tuple(reasons),
                        redacted_diff=diff,
                        expectation_basis=case.expectation_basis,
                        candidate_ref=case.candidate_ref,
                    )
                )

            pair_summaries.append(
                AuthMatrixPairSummary(
                    pair_group=grp,
                    positive_ok=grp_pos_ok,
                    defense_held_count=grp_def,
                    investigation_candidate_count=grp_cand,
                    baseline_blocked_count=grp_blk,
                    skipped_count=grp_skip,
                )
            )

        wall_ms = int((time.monotonic() - start) * 1000)
        result = AuthMatrixRunResult(
            matrix_id=self.matrix.matrix_id,
            target_name=self.matrix.target_name,
            total_cases=len(self.matrix.cases),
            executed_cases=executed,
            positive_passed=pos_passed,
            positive_failed=pos_failed,
            defense_held=def_held,
            investigation_candidates=candidates,
            baseline_blocked=blocked,
            skipped_limit=skipped,
            timed_out=timed_out,
            output_truncated=False,
            wall_ms=wall_ms,
            pair_summaries=tuple(pair_summaries),
            case_results=tuple(case_results),
        )

        encoded_len = len(result.model_dump_json(by_alias=True).encode("utf-8"))
        if encoded_len > max_bytes:
            compacted_cases = tuple(
                cr.model_copy(update={"redacted_diff": {"truncated": True}})
                for cr in case_results
            )
            result = result.model_copy(
                update={
                    "output_truncated": True,
                    "case_results": compacted_cases,
                }
            )
            if len(result.model_dump_json(by_alias=True).encode("utf-8")) > max_bytes:
                kept: list[AuthMatrixCaseResult] = []
                for cr in compacted_cases:
                    trial = result.model_copy(update={"case_results": tuple(kept + [cr])})
                    if len(trial.model_dump_json(by_alias=True).encode("utf-8")) <= max_bytes:
                        kept.append(cr)
                    else:
                        break
                result = result.model_copy(update={"case_results": tuple(kept)})
            if len(result.model_dump_json(by_alias=True).encode("utf-8")) > max_bytes:
                result = result.model_copy(update={"pair_summaries": ()})
        return result


def assert_auth_matrix_positive_controls(result: AuthMatrixRunResult) -> None:
    """Fail if any positive control failed or zero positive controls passed."""
    failed_ids = [cr.case_id for cr in result.case_results if cr.outcome == "positive_failed"]
    if failed_ids or result.positive_failed > 0 or result.positive_passed == 0:
        raise AssertionError(
            f"Authorization matrix positive control baseline failed: passed={result.positive_passed}, "
            f"failed={result.positive_failed}, cases={failed_ids}"
        )


def assert_auth_matrix_defense_checks(result: AuthMatrixRunResult) -> None:
    """Require healthy positive controls and zero authorization boundary mismatches."""
    assert_auth_matrix_positive_controls(result)
    anomalies = [
        f"{cr.case_id}:{','.join(cr.mismatch_reasons)}"
        for cr in result.case_results
        if cr.outcome == "investigation_candidate"
    ]
    if anomalies or result.investigation_candidates > 0 or result.baseline_blocked > 0 or result.timed_out:
        raise AssertionError(
            f"Authorization matrix defense checks did not all hold: anomalies={anomalies}, "
            f"blocked={result.baseline_blocked}, timed_out={result.timed_out}"
        )


def assert_auth_matrix_anomaly_candidates(
    result: AuthMatrixRunResult,
    *,
    min_candidates: int = 1,
) -> None:
    """Require healthy positive controls and at least ``min_candidates`` observed boundary mismatches."""
    assert_auth_matrix_positive_controls(result)
    if result.investigation_candidates < min_candidates:
        raise AssertionError(
            f"Expected >= {min_candidates} authorization matrix investigation candidate(s), "
            f"observed {result.investigation_candidates}."
        )


def emit_auth_matrix_evidence_marker(
    result: AuthMatrixRunResult,
    *,
    sender_auth_state: str = "matrix_paired_actors",
    config_creation_path: str = "human_authored_auth_matrix",
    target_component: str | None = None,
    unverified_conditions: Sequence[str] = (),
) -> dict[str, Any]:
    """Emit a redacted ``VDP_EVIDENCE_MARKER`` summarizing an ``AuthMatrixRunResult``."""
    confirmed: list[str] = []
    if result.positive_passed >= 1 and result.positive_failed == 0:
        confirmed.append("auth_matrix_positive_controls_passed")
    if result.investigation_candidates == 0 and result.positive_failed == 0 and not result.timed_out:
        confirmed.append("auth_matrix_defense_boundaries_held")
    if result.investigation_candidates > 0:
        confirmed.append("auth_matrix_boundary_mismatch_observed_as_candidate")

    unverified = list(
        dict.fromkeys(
            [
                "auth_matrix_checks_bounded_to_human_defined_matrix",
                *[str(x).strip() for x in unverified_conditions if str(x).strip()],
            ]
        )
    )
    if result.timed_out:
        unverified.append("auth_matrix_truncated_by_runtime_cap")
    if result.output_truncated:
        unverified.append("auth_matrix_case_diffs_truncated_by_output_cap")

    candidate_cases = [
        {
            "case_id": cr.case_id,
            "pair_group": cr.pair_group,
            "entrypoint": cr.entrypoint,
            "mismatch_reasons": list(cr.mismatch_reasons),
            "redacted_diff": cr.redacted_diff,
            "expectation_basis": cr.expectation_basis,
            "candidate_ref": cr.candidate_ref,
        }
        for cr in result.case_results
        if cr.outcome == "investigation_candidate"
    ]
    payload: dict[str, Any] = {
        "sender_auth_state": sender_auth_state,
        "config_creation_path": config_creation_path,
        "target_component": target_component or result.target_name,
        "state_diff": {
            "matrix_id": result.matrix_id,
            "candidate_count": result.investigation_candidates,
            "positive_passed": result.positive_passed,
            "defense_held": result.defense_held,
        },
        "auth_matrix_summary": {
            "schema": result.schema_version,
            "matrix_id": result.matrix_id,
            "target_name": result.target_name,
            "policy_source_kind": result.policy_source_kind,
            "status_policy": result.status_policy,
            "total_cases": result.total_cases,
            "executed_cases": result.executed_cases,
            "positive_passed": result.positive_passed,
            "positive_failed": result.positive_failed,
            "defense_held": result.defense_held,
            "investigation_candidates": result.investigation_candidates,
            "baseline_blocked": result.baseline_blocked,
            "skipped_limit": result.skipped_limit,
            "timed_out": result.timed_out,
            "output_truncated": result.output_truncated,
            "candidate_cases": candidate_cases,
        },
        "confirmed_conditions": confirmed,
        "unverified_conditions": unverified,
    }
    clean = redact_structure(payload)
    emit_vdp_evidence_marker(clean)
    return clean


class AuthMatrixCandidateItem(StrictModel):
    """Unconfirmed matrix candidate derived from ``vdp-boundary-map`` static diffs/gaps."""

    candidate_id: str
    status: Literal["investigation_candidate"] = "investigation_candidate"
    source_kind: Literal["cross_path_diff", "test_coverage_gap"]
    entrypoint_id: str
    entrypoint_kind: Literal["ui", "api", "webhook", "async"]
    category_or_gap_type: str
    expectation_basis_hint: str
    recommended_compared_fields: tuple[str, ...]
    summary: str
    human_review_required: Literal[True] = True
    suggested_pair_group: str


class AuthMatrixCandidateDraft(StrictModel):
    """Human-reviewable candidate draft produced from ``vdp-boundary-map`` JSON."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_version: Literal["vdp-auth-matrix-candidates/1"] = Field(
        default=AUTH_MATRIX_CANDIDATE_SCHEMA,
        alias="schema",
    )
    feature: str
    status_policy: Literal["investigation_candidate_only"] = INVESTIGATION_CANDIDATE_ONLY_POLICY
    policy_source_requirement: Literal["requires_human_documented_policy"] = (
        "requires_human_documented_policy"
    )
    total_candidates: int = Field(ge=0)
    candidates: tuple[AuthMatrixCandidateItem, ...] = ()
    matrix_template_stub: dict[str, Any] = Field(default_factory=dict)


def _recommend_fields_for_category(cat: str) -> tuple[str, ...]:
    low = cat.lower()
    fields: list[str] = ["http_status", "location_header", "json_keys", "synthetic_markers"]
    if "update" in low or "scoping" in low or "sink" in low or "permission" in low:
        fields.extend(["db_state", "queue_enqueued"])
    return tuple(fields)


def import_boundary_map_to_matrix_candidates(
    boundary_map: BoundaryDiffMap | Mapping[str, Any],
) -> AuthMatrixCandidateDraft:
    """Convert ``vdp-boundary-map`` findings/gaps into reviewable matrix candidates (never confirmed vulns)."""
    parsed_map = (
        boundary_map
        if isinstance(boundary_map, BoundaryDiffMap)
        else BoundaryDiffMap.model_validate(boundary_map)
    )
    items: list[AuthMatrixCandidateItem] = []

    for diff in parsed_map.cross_path_diffs:
        basis_hint = diff.evidence_locations[0] if diff.evidence_locations else "unknown:1"
        items.append(
            AuthMatrixCandidateItem(
                candidate_id=diff.finding_id,
                source_kind="cross_path_diff",
                entrypoint_id=diff.compared_entrypoint_id,
                entrypoint_kind=diff.compared_kind.value,  # type: ignore[arg-type]
                category_or_gap_type=diff.category.value,
                expectation_basis_hint=basis_hint,
                recommended_compared_fields=_recommend_fields_for_category(diff.category.value),
                summary=redact_sensitive_text(diff.summary)[:400],
                suggested_pair_group=f"grp-{diff.finding_id[:40]}",
            )
        )

    for gap in parsed_map.test_coverage_gaps:
        basis_hint = gap.evidence_locations[0] if gap.evidence_locations else gap.entrypoint_location
        items.append(
            AuthMatrixCandidateItem(
                candidate_id=gap.gap_id,
                source_kind="test_coverage_gap",
                entrypoint_id=gap.entrypoint_id,
                entrypoint_kind=gap.kind.value,  # type: ignore[arg-type]
                category_or_gap_type=gap.gap_type.value,
                expectation_basis_hint=basis_hint,
                recommended_compared_fields=_recommend_fields_for_category(gap.gap_type.value),
                summary=redact_sensitive_text(gap.summary)[:400],
                suggested_pair_group=f"grp-{gap.gap_id[:40]}",
            )
        )

    stub = {
        "schema": AUTH_MATRIX_SCHEMA,
        "matrix_id": f"matrix-{parsed_map.feature[:40]}",
        "target_name": parsed_map.feature,
        "authored_by": "<HUMAN_REVIEWER_REQUIRED>",
        "policy_source_kind": "human_documented_policy",
        "allowlist": {
            "actors": ["<AUTHORIZED_ACTOR>", "<UNAUTHORIZED_ACTOR>"],
            "resources": ["<TARGET_RESOURCE>"],
            "actions": ["<TARGET_ACTION>"],
            "entrypoints": sorted({it.entrypoint_kind for it in items}) or ["api"],
        },
        "limits": {
            "max_combinations": 32,
            "max_runtime_seconds": 15.0,
            "max_output_bytes": 16384,
        },
        "cases_to_review": [
            {
                "candidate_ref": it.candidate_id,
                "pair_group": it.suggested_pair_group,
                "entrypoint": it.entrypoint_kind,
                "expectation_basis": it.expectation_basis_hint,
                "compared_fields": list(it.recommended_compared_fields),
                "human_action_required": "Add explicit allow + deny cases with required_preconfiguration and expectation_basis.",
            }
            for it in items[:MAX_MATRIX_COMBINATIONS]
        ],
    }

    return AuthMatrixCandidateDraft(
        feature=parsed_map.feature,
        total_candidates=len(items),
        candidates=tuple(items),
        matrix_template_stub=stub,
    )


def register_auth_matrix_subparser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    *,
    command_name: str = AUTH_MATRIX_COMMAND,
    parents: Sequence[argparse.ArgumentParser] = (),
) -> argparse.ArgumentParser:
    """Register the ``vdp-auth-matrix`` CLI subcommand."""
    parser = subparsers.add_parser(
        command_name,
        parents=list(parents),
        help="Validate a human-authored authorization matrix JSON or import candidates from vdp-boundary-map.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--validate-matrix",
        type=Path,
        default=None,
        help="Path to human-authored AuthMatrixSpec JSON to validate.",
    )
    group.add_argument(
        "--from-boundary-map",
        type=Path,
        default=None,
        help="Path to vdp-boundary-map JSON report to convert into candidate matrix stubs.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional output JSON path when using --from-boundary-map.",
    )
    return parser


def handle_auth_matrix_cli(args: argparse.Namespace, env: Mapping[str, str] | None = None) -> int:
    """Handle ``ctf-mcp-admin vdp-auth-matrix`` safely without mutating run state or scanning."""
    _ = env
    if getattr(args, "validate_matrix", None) is not None:
        raw = _read_bounded_json_file(Path(args.validate_matrix))
        spec = AuthMatrixSpec.model_validate(raw)
        summary = {
            "valid": True,
            "schema": spec.schema_version,
            "matrix_id": spec.matrix_id,
            "target_name": spec.target_name,
            "policy_source_kind": spec.policy_source_kind,
            "case_count": len(spec.cases),
            "pair_groups": sorted({c.pair_group for c in spec.cases}),
            "allowlist": spec.allowlist.model_dump(mode="json"),
            "limits": spec.limits.model_dump(mode="json"),
        }
        sys.stdout.write(json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
        return 0

    raw_map = _read_bounded_json_file(Path(args.from_boundary_map))
    draft = import_boundary_map_to_matrix_candidates(raw_map)
    out_payload = draft.model_dump(mode="json", by_alias=True)
    if getattr(args, "output", None) is not None:
        _write_bounded_json_file(Path(args.output), out_payload)
    sys.stdout.write(json.dumps(out_payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    return 0


__all__ = [
    "AUTH_MATRIX_CANDIDATE_SCHEMA",
    "AUTH_MATRIX_COMMAND",
    "AUTH_MATRIX_RESULT_SCHEMA",
    "AUTH_MATRIX_SCHEMA",
    "INVESTIGATION_CANDIDATE_ONLY_POLICY",
    "MAX_MATRIX_COMBINATIONS",
    "MAX_MATRIX_OUTPUT_BYTES",
    "MAX_MATRIX_RUNTIME_SECONDS",
    "VALID_COMPARED_FIELDS",
    "VALID_ENTRYPOINT_KINDS",
    "AuthMatrixAllowlist",
    "AuthMatrixCandidateDraft",
    "AuthMatrixCandidateItem",
    "AuthMatrixCase",
    "AuthMatrixCaseResult",
    "AuthMatrixObservation",
    "AuthMatrixPairSummary",
    "AuthMatrixRunLimits",
    "AuthMatrixRunResult",
    "AuthMatrixRunner",
    "AuthMatrixSpec",
    "assert_auth_matrix_anomaly_candidates",
    "assert_auth_matrix_defense_checks",
    "assert_auth_matrix_positive_controls",
    "emit_auth_matrix_evidence_marker",
    "extract_bounded_observation",
    "handle_auth_matrix_cli",
    "import_boundary_map_to_matrix_candidates",
    "register_auth_matrix_subparser",
]
