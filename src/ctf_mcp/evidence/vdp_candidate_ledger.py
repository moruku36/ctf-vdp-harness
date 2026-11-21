"""VDP candidate known-issue and precondition checkpoint ledger.

Tracks human-imported external research (e.g., public issues, PRs, fix commits,
advisories) at two mandatory gates:
1. ``pre_heavy_test``: before heavy isolated product-test execution.
2. ``pre_submission``: immediately before rendering a human VDP disclosure draft.

Security & scientific invariants:
- External searches are performed by the researcher/connectors; this harness NEVER
  queries remote websites automatically and NEVER treats zero search hits as
  proof of "no duplicate" (``zero_search_results_does_not_prove_no_duplicate``).
- Every candidate records who created required preconfigurations, what an attacker
  controls, real-world prevalence (``common`` / ``unverified`` / ``rare_special_setup``),
  and observed impact cap.
- Candidates remain bounded assessment records (``auto_promoted_to_confirmed_vulnerability=False``)
  and NEVER auto-promote to confirmed vulnerabilities or preempt maintainer triage.
"""

from __future__ import annotations

import errno
import json
import os
import re
import stat
import sys
import threading
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

if sys.platform == "win32":
    import msvcrt
else:
    msvcrt = None  # type: ignore[assignment]

try:
    import fcntl
except ImportError:
    fcntl = None  # type: ignore[assignment]

from pydantic import Field, model_validator

from ctf_mcp.contracts import (
    ContractViolationError,
    PathSecurityError,
    StrictModel,
)
from ctf_mcp.evidence.manual_observation import read_bounded_manual_json_file
from ctf_mcp.evidence.redaction import scan_sensitive_markers
from ctf_mcp.fs_guard import _is_reparse_or_symlink, safe_read_bounded, safe_write_atomic

VDP_CANDIDATE_CHECKPOINTS_RELPATH = "_vdp/candidate_checkpoints.json"
VDP_CANDIDATE_CHECKPOINT_SCHEMA = "vdp-candidate-checkpoint/1"
ZERO_HITS_DISCLAIMER = "zero_search_results_does_not_prove_no_duplicate"
MAX_CANDIDATE_JSON_BYTES = 262_144

VALID_CANDIDATE_STATUSES: tuple[str, ...] = (
    "investigation_candidate",
    "blocked_known_issue",
    "closed_falsified",
    "ready_for_human_draft_review",
)
VALID_CHECKPOINT_GATES: tuple[str, ...] = ("pre_heavy_test", "pre_submission")
VALID_DUPLICATE_DISPOSITIONS: tuple[str, ...] = (
    "proceed_unconfirmed_candidate",
    "blocked_likely_duplicate",
    "blocked_already_fixed",
    "needs_recheck",
)
VALID_PRECONFIG_CREATORS: tuple[str, ...] = (
    "owner_or_admin",
    "project_maintainer",
    "attacker_self_service",
    "default_install",
    "unknown",
)
VALID_PREVALENCE_VALUES: tuple[str, ...] = ("common", "unverified", "rare_special_setup")

_CANDIDATE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_COMMIT_HEX_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")

_VAULT_THREAD_LOCKS_GUARD = threading.Lock()
_VAULT_THREAD_LOCKS: dict[Path, threading.Lock] = {}


def validate_https_url(url: str, *, field_name: str = "report_url") -> str:
    """Validate an HTTPS URL with zero embedded credentials, whitespace, or sensitive markers."""
    cleaned = str(url).strip()
    if not cleaned or len(cleaned) > 512:
        raise ContractViolationError(f"{field_name} must be 1..512 characters.")
    if any(ch.isspace() or ch == "\x00" for ch in cleaned):
        raise ContractViolationError(f"{field_name} must not contain whitespace or NUL bytes.")
    parsed = urlsplit(cleaned)
    if parsed.scheme.lower() != "https" or not parsed.netloc:
        raise ContractViolationError(f"{field_name} must use https:// with a valid host.")
    if parsed.username or parsed.password or "@" in parsed.netloc:
        raise ContractViolationError(f"{field_name} must not embed credentials.")
    matched = scan_sensitive_markers(cleaned)
    if matched:
        raise ContractViolationError(
            f"{field_name} contains forbidden sensitive markers.",
            details={"matched_rules": list(matched)},
        )
    return cleaned


def _get_vault_thread_lock(lock_path: Path) -> threading.Lock:
    with _VAULT_THREAD_LOCKS_GUARD:
        lock = _VAULT_THREAD_LOCKS.get(lock_path)
        if lock is None:
            lock = threading.Lock()
            _VAULT_THREAD_LOCKS[lock_path] = lock
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
                    raise TimeoutError("Timed out acquiring lock for VDP vault store.") from exc
                time.sleep(0.01)


def _release_file_lock(fd: int) -> None:
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return
    if sys.platform == "win32" and msvcrt is not None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)


@contextmanager
def _vdp_vault_lock(vault_path: Path, lock_filename: str) -> Iterator[None]:
    """Acquire process- and thread-level lock under non-symlink ``<vault_root>/_vdp``."""
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
    if _is_reparse_or_symlink(vdp_st) or not stat.S_ISDIR(vdp_st.st_mode):
        raise PathSecurityError("Vault _vdp directory must be a non-symlink directory.")

    lock_path = Path(os.path.realpath(vdp_dir, strict=True)) / lock_filename
    thread_lock = _get_vault_thread_lock(lock_path)
    with thread_lock:
        try:
            existing_lock_st = os.lstat(lock_path)
        except FileNotFoundError:
            existing_lock_st = None
        if existing_lock_st is not None and (
            _is_reparse_or_symlink(existing_lock_st) or not stat.S_ISREG(existing_lock_st.st_mode)
        ):
            raise PathSecurityError("VDP vault lockfile cannot be a symlink or special file.")
        open_flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(lock_path, open_flags, 0o600)
        try:
            _acquire_file_lock(fd)
            try:
                yield
            finally:
                _release_file_lock(fd)
        finally:
            os.close(fd)


def _normalize_utc_datetime(dt: datetime, *, field_name: str) -> datetime:
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ContractViolationError(f"{field_name} must be a timezone-aware timestamp.")
    return dt.astimezone(UTC)


def _strip_nonempty(value: str, *, field_name: str, max_len: int) -> str:
    cleaned = str(value).strip()
    if not cleaned or len(cleaned) > max_len:
        raise ContractViolationError(f"{field_name} must be 1..{max_len} non-empty characters.")
    return cleaned


def _assert_no_sensitive_markers(model_obj: StrictModel, *, context_label: str) -> None:
    serialized = json.dumps(model_obj.model_dump(mode="json"), ensure_ascii=False, sort_keys=True)
    matched = scan_sensitive_markers(serialized)
    if matched:
        raise ContractViolationError(
            f"{context_label} contains forbidden sensitive markers.",
            details={"matched_rules": list(matched)},
        )


class KnownIssueReference(StrictModel):
    """Single public issue, PR, fix commit, or advisory reviewed against a candidate."""

    ref_url: str
    ref_kind: Literal["issue", "pull_request", "fix_commit", "advisory", "release_note", "other"]
    ref_id: str = Field(min_length=1, max_length=128)
    target_version_relation: Literal[
        "affects_pinned_version",
        "fixed_in_later_version",
        "fixed_in_pinned_version",
        "different_component",
        "unclear",
    ]
    same_root_cause_judgment: Literal[
        "same_cause_and_impact",
        "different_cause_or_impact",
        "partial_overlap",
        "needs_review",
    ]
    human_rationale: str = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def _validate_reference(self) -> KnownIssueReference:
        clean_url = validate_https_url(self.ref_url, field_name="ref_url")
        clean_id = _strip_nonempty(self.ref_id, field_name="ref_id", max_len=128)
        clean_rationale = _strip_nonempty(
            self.human_rationale,
            field_name="human_rationale",
            max_len=500,
        )
        object.__setattr__(self, "ref_url", clean_url)
        object.__setattr__(self, "ref_id", clean_id)
        object.__setattr__(self, "human_rationale", clean_rationale)
        _assert_no_sensitive_markers(self, context_label="KnownIssueReference")
        return self


class KnownIssueCheckpoint(StrictModel):
    """Human-imported external known-issue search checkpoint at one VDP gate."""

    gate: Literal["pre_heavy_test", "pre_submission"]
    checked_at: datetime
    checked_by: str = Field(min_length=1, max_length=120)
    search_source: str = Field(min_length=1, max_length=120)
    search_queries: tuple[str, ...] = Field(min_length=1, max_length=20)
    references_reviewed: tuple[KnownIssueReference, ...] = Field(default=(), max_length=32)
    zero_hits_observed: bool
    no_duplicate_claimed: Literal[False] = False
    zero_hits_disclaimer: str | None = None
    duplicate_disposition: Literal[
        "proceed_unconfirmed_candidate",
        "blocked_likely_duplicate",
        "blocked_already_fixed",
        "needs_recheck",
    ]
    max_age_hours: int = Field(default=72, ge=1, le=720)
    notes: str = Field(default="", max_length=500)

    @model_validator(mode="after")
    def _validate_checkpoint(self) -> KnownIssueCheckpoint:
        norm_dt = _normalize_utc_datetime(self.checked_at, field_name="checked_at")
        clean_by = _strip_nonempty(self.checked_by, field_name="checked_by", max_len=120)
        clean_src = _strip_nonempty(self.search_source, field_name="search_source", max_len=120)
        clean_queries = tuple(
            _strip_nonempty(q, field_name=f"search_queries[{idx}]", max_len=240)
            for idx, q in enumerate(self.search_queries)
        )
        clean_notes = self.notes.strip()

        expected_zero = len(self.references_reviewed) == 0
        if self.zero_hits_observed != expected_zero:
            raise ContractViolationError(
                "zero_hits_observed must strictly match whether references_reviewed is empty."
            )

        if self.zero_hits_observed:
            if self.zero_hits_disclaimer is not None and self.zero_hits_disclaimer != ZERO_HITS_DISCLAIMER:
                raise ContractViolationError(
                    f"zero_hits_disclaimer must equal {ZERO_HITS_DISCLAIMER!r} when zero_hits_observed is True."
                )
            eff_disclaimer: str | None = ZERO_HITS_DISCLAIMER
        else:
            if self.zero_hits_disclaimer is not None:
                raise ContractViolationError(
                    "zero_hits_disclaimer must be omitted/null when references_reviewed is non-empty."
                )
            eff_disclaimer = None

        blocking_rel = {
            "affects_pinned_version",
            "fixed_in_later_version",
            "fixed_in_pinned_version",
        }
        if self.duplicate_disposition == "proceed_unconfirmed_candidate":
            for ref in self.references_reviewed:
                if (
                    ref.same_root_cause_judgment == "same_cause_and_impact"
                    and ref.target_version_relation in blocking_rel
                ):
                    raise ContractViolationError(
                        f"Cannot proceed when reference {ref.ref_id!r} has same_cause_and_impact "
                        f"and target_version_relation={ref.target_version_relation!r}; use blocked_likely_duplicate "
                        "or blocked_already_fixed."
                    )

        object.__setattr__(self, "checked_at", norm_dt)
        object.__setattr__(self, "checked_by", clean_by)
        object.__setattr__(self, "search_source", clean_src)
        object.__setattr__(self, "search_queries", clean_queries)
        object.__setattr__(self, "zero_hits_disclaimer", eff_disclaimer)
        object.__setattr__(self, "notes", clean_notes)
        _assert_no_sensitive_markers(self, context_label="KnownIssueCheckpoint")
        return self


class CandidatePreconditions(StrictModel):
    """Per-candidate real-world exploitability and preconfiguration requirements."""

    preconfig_created_by: Literal[
        "owner_or_admin",
        "project_maintainer",
        "attacker_self_service",
        "default_install",
        "unknown",
    ]
    attacker_controls: str = Field(min_length=1, max_length=400)
    real_world_prevalence: Literal["common", "unverified", "rare_special_setup"]
    observed_impact_cap: str = Field(min_length=1, max_length=400)
    preconfig_notes: str = Field(default="", max_length=500)
    basis_refs: tuple[str, ...] = Field(default=(), max_length=16)

    @model_validator(mode="after")
    def _validate_preconditions(self) -> CandidatePreconditions:
        clean_ctrl = _strip_nonempty(
            self.attacker_controls,
            field_name="attacker_controls",
            max_len=400,
        )
        clean_cap = _strip_nonempty(
            self.observed_impact_cap,
            field_name="observed_impact_cap",
            max_len=400,
        )
        clean_notes = self.preconfig_notes.strip()
        clean_refs = tuple(
            dict.fromkeys(
                _strip_nonempty(ref, field_name=f"basis_refs[{idx}]", max_len=240)
                for idx, ref in enumerate(self.basis_refs)
            )
        )
        object.__setattr__(self, "attacker_controls", clean_ctrl)
        object.__setattr__(self, "observed_impact_cap", clean_cap)
        object.__setattr__(self, "preconfig_notes", clean_notes)
        object.__setattr__(self, "basis_refs", clean_refs)
        _assert_no_sensitive_markers(self, context_label="CandidatePreconditions")
        return self


class VdpCandidateCheckpointRecord(StrictModel):
    """Persisted candidate ledger entry with two-gate known-issue checkpoints."""

    schema_version: Literal["vdp-candidate-checkpoint/1"] = VDP_CANDIDATE_CHECKPOINT_SCHEMA
    candidate_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    run_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=200)
    target_name: str = Field(min_length=1, max_length=120)
    target_version: str = Field(min_length=1, max_length=120)
    pinned_source_commit: str
    status: Literal[
        "investigation_candidate",
        "blocked_known_issue",
        "closed_falsified",
        "ready_for_human_draft_review",
    ] = "investigation_candidate"
    auto_promoted_to_confirmed_vulnerability: Literal[False] = False
    finding_qualification: Literal[
        "separate_assessment_required_not_judged_from_pass_count"
    ] = "separate_assessment_required_not_judged_from_pass_count"
    external_search_performed_by_harness: Literal[False] = False
    preconditions: CandidatePreconditions
    pre_heavy_test_checkpoint: KnownIssueCheckpoint | None = None
    pre_submission_checkpoint: KnownIssueCheckpoint | None = None
    evidence_ids: tuple[str, ...] = Field(default=(), max_length=64)
    first_candidate_observed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    history: tuple[dict[str, Any], ...] = ()

    @model_validator(mode="after")
    def _validate_record(self) -> VdpCandidateCheckpointRecord:
        if ".." in self.candidate_id or ".." in self.run_id:
            raise PathSecurityError("candidate_id and run_id must not contain '..'.")
        commit_clean = str(self.pinned_source_commit).strip().lower()
        if not _COMMIT_HEX_RE.fullmatch(commit_clean):
            raise ContractViolationError(
                "pinned_source_commit must be 7..64 hexadecimal characters."
            )
        clean_title = _strip_nonempty(self.title, field_name="title", max_len=200)
        clean_target = _strip_nonempty(self.target_name, field_name="target_name", max_len=120)
        clean_version = _strip_nonempty(self.target_version, field_name="target_version", max_len=120)

        norm_created = _normalize_utc_datetime(self.created_at, field_name="created_at")
        norm_updated = _normalize_utc_datetime(self.updated_at, field_name="updated_at")
        norm_first = (
            _normalize_utc_datetime(
                self.first_candidate_observed_at,
                field_name="first_candidate_observed_at",
            )
            if self.first_candidate_observed_at is not None
            else None
        )

        if (
            self.pre_heavy_test_checkpoint is not None
            and self.pre_heavy_test_checkpoint.gate != "pre_heavy_test"
        ):
            raise ContractViolationError(
                "pre_heavy_test_checkpoint must have gate='pre_heavy_test'."
            )
        if (
            self.pre_submission_checkpoint is not None
            and self.pre_submission_checkpoint.gate != "pre_submission"
        ):
            raise ContractViolationError(
                "pre_submission_checkpoint must have gate='pre_submission'."
            )

        blocking_dispositions = {"blocked_likely_duplicate", "blocked_already_fixed"}
        has_blocking_cp = any(
            cp is not None and cp.duplicate_disposition in blocking_dispositions
            for cp in (self.pre_heavy_test_checkpoint, self.pre_submission_checkpoint)
        )
        if has_blocking_cp and self.status == "ready_for_human_draft_review":
            raise ContractViolationError(
                "Blocked candidate cannot have status='ready_for_human_draft_review'."
            )

        clean_evidence = tuple(
            dict.fromkeys(
                _strip_nonempty(eid, field_name=f"evidence_ids[{idx}]", max_len=128)
                for idx, eid in enumerate(self.evidence_ids)
            )
        )

        object.__setattr__(self, "pinned_source_commit", commit_clean)
        object.__setattr__(self, "title", clean_title)
        object.__setattr__(self, "target_name", clean_target)
        object.__setattr__(self, "target_version", clean_version)
        object.__setattr__(self, "created_at", norm_created)
        object.__setattr__(self, "updated_at", norm_updated)
        object.__setattr__(self, "first_candidate_observed_at", norm_first)
        object.__setattr__(self, "evidence_ids", clean_evidence)
        _assert_no_sensitive_markers(self, context_label="VdpCandidateCheckpointRecord")
        return self


class CandidateGateEvaluation(StrictModel):
    """Deterministic readiness & staleness evaluation for a VDP candidate checkpoint gate."""

    candidate_id: str
    run_id: str
    gate: Literal["pre_heavy_test", "pre_submission"]
    evaluated_at: datetime
    ready: bool
    stale_recheck_required: bool
    recheck_prompt: str | None = None
    blocked_reason: str | None = None
    missing_items: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    checkpoint_age_hours: float | None = None
    auto_promoted_to_confirmed_vulnerability: Literal[False] = False


def read_bounded_candidate_json_file(
    path: Path,
    *,
    max_bytes: int = MAX_CANDIDATE_JSON_BYTES,
) -> dict[str, Any]:
    """Read a regular non-symlink local candidate JSON file within bounded size."""
    return read_bounded_manual_json_file(path, max_bytes=max_bytes)


def _store_key(run_id: str, candidate_id: str) -> str:
    return f"{run_id}::{candidate_id}"


def _load_vdp_candidate_checkpoints_unlocked(
    vault_path: Path,
) -> dict[str, VdpCandidateCheckpointRecord]:
    target = vault_path / VDP_CANDIDATE_CHECKPOINTS_RELPATH
    if not target.exists():
        return {}
    raw = safe_read_bounded(
        vault_path,
        VDP_CANDIDATE_CHECKPOINTS_RELPATH,
        max_bytes=4 * 1024 * 1024,
        allow_truncate=False,
    )
    payload = json.loads(raw.data.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ContractViolationError("VDP candidate checkpoints store must be a JSON object.")
    items = payload.get("candidates") or {}
    if not isinstance(items, Mapping):
        raise ContractViolationError("VDP candidate checkpoints 'candidates' field must be an object.")
    loaded: dict[str, VdpCandidateCheckpointRecord] = {}
    for k, v in items.items():
        rec = VdpCandidateCheckpointRecord.model_validate(v)
        expected_k = _store_key(rec.run_id, rec.candidate_id)
        if str(k) != expected_k:
            raise ContractViolationError(
                f"Candidate checkpoint store key {k!r} does not match record identity {expected_k!r}."
            )
        loaded[expected_k] = rec
    return loaded


def load_vdp_candidate_checkpoints(
    vault_root: str | Path,
) -> dict[str, VdpCandidateCheckpointRecord]:
    """Load persisted candidate checkpoint records keyed by ``<run_id>::<candidate_id>``."""
    vault_path = Path(vault_root)
    if not (vault_path / VDP_CANDIDATE_CHECKPOINTS_RELPATH).exists():
        return {}
    with _vdp_vault_lock(vault_path, "candidate_checkpoints.json.lock"):
        return _load_vdp_candidate_checkpoints_unlocked(vault_path)


def get_vdp_candidate_checkpoint(
    vault_root: str | Path,
    *,
    run_id: str,
    candidate_id: str,
) -> VdpCandidateCheckpointRecord | None:
    """Fetch a single candidate checkpoint record for ``(run_id, candidate_id)`` if present."""
    all_recs = load_vdp_candidate_checkpoints(vault_root)
    return all_recs.get(_store_key(run_id, candidate_id))


def list_vdp_candidate_checkpoints(
    vault_root: str | Path,
    *,
    run_id: str | None = None,
) -> list[VdpCandidateCheckpointRecord]:
    """List persisted candidate checkpoint records, optionally filtered by ``run_id``."""
    all_recs = load_vdp_candidate_checkpoints(vault_root)
    items = [
        rec
        for _, rec in sorted(all_recs.items())
        if run_id is None or rec.run_id == run_id
    ]
    return items


def save_vdp_candidate_checkpoint(
    vault_root: str | Path,
    record: VdpCandidateCheckpointRecord,
) -> Path:
    """Atomically validate and persist a candidate checkpoint record under ``_vdp/``."""
    validated = VdpCandidateCheckpointRecord.model_validate(record)
    vault_path = Path(vault_root)
    vault_path.mkdir(parents=True, exist_ok=True)
    with _vdp_vault_lock(vault_path, "candidate_checkpoints.json.lock"):
        existing = _load_vdp_candidate_checkpoints_unlocked(vault_path)
        existing[_store_key(validated.run_id, validated.candidate_id)] = validated
        data = {
            "schema_version": "vdp-candidate-checkpoints/1",
            "external_search_performed_by_harness": False,
            "auto_promotion_to_confirmed_vulnerability": False,
            "candidates": {
                k: v.model_dump(mode="json")
                for k, v in sorted(existing.items())
            },
        }
        return safe_write_atomic(
            vault_path,
            VDP_CANDIDATE_CHECKPOINTS_RELPATH,
            (json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"),
            overwrite=True,
            create_parents=True,
        )


def evaluate_candidate_gate(
    record: VdpCandidateCheckpointRecord,
    *,
    gate: Literal["pre_heavy_test", "pre_submission"],
    now: datetime | None = None,
) -> CandidateGateEvaluation:
    """Evaluate gate readiness, blocking known issues, and stale-reference recheck needs."""
    if gate not in VALID_CHECKPOINT_GATES:
        raise ContractViolationError(f"Unsupported checkpoint gate {gate!r}.")
    eff_now = _normalize_utc_datetime(now or datetime.now(UTC), field_name="now")

    missing_items: list[str] = []
    warnings: list[str] = []
    blocked_reason: str | None = None
    stale_recheck_required = False
    recheck_prompt: str | None = None
    checkpoint_age_hours: float | None = None

    if record.preconditions.real_world_prevalence == "unverified":
        warnings.append("real_world_prevalence_unverified")
    if record.preconditions.preconfig_created_by == "unknown":
        warnings.append("preconfig_creator_unknown")
    if not record.preconditions.basis_refs:
        warnings.append("precondition_basis_refs_missing")

    if record.status == "closed_falsified":
        blocked_reason = "candidate_closed_falsified"
    elif record.status == "blocked_known_issue":
        blocked_reason = "candidate_blocked_known_issue"

    def _inspect_checkpoint(cp: KnownIssueCheckpoint) -> float:
        nonlocal blocked_reason, stale_recheck_required, recheck_prompt
        age_seconds = (eff_now - cp.checked_at).total_seconds()
        age_hours = round(age_seconds / 3600.0, 3)
        if age_seconds < 0:
            warnings.append(f"{cp.gate}_checked_at_in_future")
        elif age_seconds > cp.max_age_hours * 3600:
            stale_recheck_required = True
            recheck_prompt = (
                f"Known-issue checkpoint '{cp.gate}' is stale ({age_hours:.1f}h > "
                f"{cp.max_age_hours}h max_age_hours); re-run external known-issue search and "
                f"record a refreshed '{cp.gate}' checkpoint before proceeding."
            )
        if cp.duplicate_disposition in {"blocked_likely_duplicate", "blocked_already_fixed"}:
            if blocked_reason is None:
                blocked_reason = f"{cp.gate}:{cp.duplicate_disposition}"
        elif cp.duplicate_disposition == "needs_recheck":
            stale_recheck_required = True
            if recheck_prompt is None:
                recheck_prompt = (
                    f"Known-issue checkpoint '{cp.gate}' has disposition='needs_recheck'; "
                    "re-verify public issues/PRs/fix commits and record an updated checkpoint."
                )
        if cp.zero_hits_observed and ZERO_HITS_DISCLAIMER not in warnings:
            warnings.append(ZERO_HITS_DISCLAIMER)
        return age_hours

    if gate == "pre_heavy_test":
        if record.pre_heavy_test_checkpoint is None:
            missing_items.append("pre_heavy_test_checkpoint")
        else:
            checkpoint_age_hours = _inspect_checkpoint(record.pre_heavy_test_checkpoint)
    else:
        pre_heavy = record.pre_heavy_test_checkpoint
        pre_sub = record.pre_submission_checkpoint
        if pre_heavy is None:
            missing_items.append("pre_heavy_test_checkpoint")
        elif pre_heavy.duplicate_disposition in {"blocked_likely_duplicate", "blocked_already_fixed"}:
            if blocked_reason is None:
                blocked_reason = f"pre_heavy_test:{pre_heavy.duplicate_disposition}"
        if pre_sub is None:
            missing_items.append("pre_submission_checkpoint")
        else:
            checkpoint_age_hours = _inspect_checkpoint(pre_sub)
            if pre_heavy is not None and pre_sub.checked_at < pre_heavy.checked_at:
                stale_recheck_required = True
                warnings.append("pre_submission_older_than_pre_heavy_test")
                if recheck_prompt is None:
                    recheck_prompt = (
                        "pre_submission_checkpoint timestamp is older than pre_heavy_test_checkpoint; "
                        "re-verify public issues/PRs/fix commits before submission."
                    )

    ready = blocked_reason is None and not missing_items and not stale_recheck_required
    return CandidateGateEvaluation(
        candidate_id=record.candidate_id,
        run_id=record.run_id,
        gate=gate,
        evaluated_at=eff_now,
        ready=ready,
        stale_recheck_required=stale_recheck_required,
        recheck_prompt=recheck_prompt,
        blocked_reason=blocked_reason,
        missing_items=tuple(missing_items),
        warnings=tuple(warnings),
        checkpoint_age_hours=checkpoint_age_hours,
        auto_promoted_to_confirmed_vulnerability=False,
    )


def summarize_vdp_candidate_metrics(
    records: Sequence[VdpCandidateCheckpointRecord],
    *,
    run_created_at: datetime | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Compute non-preemptive operational metrics across a run's candidate ledger."""
    eff_now = _normalize_utc_datetime(now or datetime.now(UTC), field_name="now")
    by_status = {status: 0 for status in VALID_CANDIDATE_STATUSES}
    missing_pre_heavy = 0
    missing_pre_sub = 0
    stale_pre_sub = 0
    blocked_count = 0
    zero_hits_unproven = 0
    unverified_prevalence = 0
    missing_basis_refs = 0
    observed_times: list[datetime] = []

    for rec in records:
        by_status[rec.status] = by_status.get(rec.status, 0) + 1
        if rec.status == "blocked_known_issue":
            blocked_count += 1
        if rec.pre_heavy_test_checkpoint is None:
            missing_pre_heavy += 1
        if rec.pre_submission_checkpoint is None:
            missing_pre_sub += 1
        else:
            eval_sub = evaluate_candidate_gate(rec, gate="pre_submission", now=eff_now)
            if eval_sub.stale_recheck_required:
                stale_pre_sub += 1
        if any(
            cp is not None and cp.zero_hits_observed
            for cp in (rec.pre_heavy_test_checkpoint, rec.pre_submission_checkpoint)
        ):
            zero_hits_unproven += 1
        if rec.preconditions.real_world_prevalence == "unverified":
            unverified_prevalence += 1
        if not rec.preconditions.basis_refs:
            missing_basis_refs += 1
        if rec.first_candidate_observed_at is not None:
            observed_times.append(rec.first_candidate_observed_at)

    time_to_first_candidate_seconds: float | None = None
    if run_created_at is not None and observed_times:
        norm_start = _normalize_utc_datetime(run_created_at, field_name="run_created_at")
        delta = (min(observed_times) - norm_start).total_seconds()
        time_to_first_candidate_seconds = round(max(0.0, delta), 3)

    return {
        "total_candidates": len(records),
        "by_status": by_status,
        "missing_pre_heavy_test_gate_count": missing_pre_heavy,
        "missing_pre_submission_gate_count": missing_pre_sub,
        "stale_pre_submission_count": stale_pre_sub,
        "blocked_known_issue_count": blocked_count,
        "zero_hits_unproven_count": zero_hits_unproven,
        "unverified_prevalence_count": unverified_prevalence,
        "missing_basis_refs_count": missing_basis_refs,
        "time_to_first_candidate_seconds": time_to_first_candidate_seconds,
        "auto_confirmed_vulnerability_count": 0,
        "maintainer_triage_preempted": False,
    }


__all__ = [
    "MAX_CANDIDATE_JSON_BYTES",
    "VALID_CANDIDATE_STATUSES",
    "VALID_CHECKPOINT_GATES",
    "VALID_DUPLICATE_DISPOSITIONS",
    "VALID_PRECONFIG_CREATORS",
    "VALID_PREVALENCE_VALUES",
    "VDP_CANDIDATE_CHECKPOINTS_RELPATH",
    "VDP_CANDIDATE_CHECKPOINT_SCHEMA",
    "ZERO_HITS_DISCLAIMER",
    "CandidateGateEvaluation",
    "CandidatePreconditions",
    "KnownIssueCheckpoint",
    "KnownIssueReference",
    "VdpCandidateCheckpointRecord",
    "evaluate_candidate_gate",
    "get_vdp_candidate_checkpoint",
    "list_vdp_candidate_checkpoints",
    "load_vdp_candidate_checkpoints",
    "read_bounded_candidate_json_file",
    "save_vdp_candidate_checkpoint",
    "summarize_vdp_candidate_metrics",
    "validate_https_url",
]
