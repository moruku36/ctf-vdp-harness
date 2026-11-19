"""VDP submission draft generation and manual submission status persistence.

Generates human-reviewable VDP disclosure drafts aligned with
``templates/vdp-submission-draft(.ja).md`` while keeping:
- Zero automatic external submission (``automatic_submission=False`` always).
- Clear provenance separation between harness-verified ``vdp.product_test``
  evidence and ``manual_isolated_observation`` records.
- Fail-closed redaction checks via ``assert_report_clean``.
- Atomic, lock-serialized persistence under ``<vault_root>/_vdp/submissions.json``.
"""

from __future__ import annotations

import errno
import hmac
import json
import os
import re
import sqlite3
import stat
import sys
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
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
    SHA256_PATTERN,
    ConfigurationError,
    ContractViolationError,
    EvidenceAccessDeniedError,
    EvidenceNotFoundError,
    FindingState,
    PathSecurityError,
    StrictModel,
    sha256_bytes,
    validate_finding_transition,
)
from ctf_mcp.evidence.export import assert_report_clean
from ctf_mcp.evidence.manual_observation import (
    MANUAL_OBSERVATION_PROVENANCE,
    MANUAL_OBSERVATION_SCHEMA,
)
from ctf_mcp.evidence.redaction import scan_sensitive_markers
from ctf_mcp.evidence.vault import EvidenceVault
from ctf_mcp.fs_guard import _is_reparse_or_symlink, safe_read_bounded, safe_write_atomic
from ctf_mcp.storage import Storage

VDP_SUBMISSIONS_RELPATH = "_vdp/submissions.json"
VDP_SUBMISSIONS_LOCK_RELPATH = "_vdp/submissions.json.lock"
VALID_TRIAGE_STATUSES: tuple[str, ...] = (
    "not_submitted",
    "unconfirmed",
    "triaged",
    "duplicate",
    "informative",
    "accepted",
    "resolved",
)

_SUBMISSIONS_THREAD_LOCKS_GUARD = threading.Lock()
_SUBMISSIONS_THREAD_LOCKS: dict[Path, threading.Lock] = {}
_FINDING_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,64}$")


def validate_report_url(url: str) -> str:
    """Validate an HTTPS report URL with zero embedded credentials or control chars."""
    cleaned = str(url).strip()
    if not cleaned or len(cleaned) > 512:
        raise ContractViolationError("report_url must be 1..512 characters.")
    if any(ch.isspace() or ch == "\x00" for ch in cleaned):
        raise ContractViolationError("report_url must not contain whitespace or NUL bytes.")
    parsed = urlsplit(cleaned)
    if parsed.scheme.lower() != "https" or not parsed.netloc:
        raise ContractViolationError("report_url must use https:// with a valid host.")
    if parsed.username or parsed.password or "@" in parsed.netloc:
        raise ContractViolationError("report_url must not embed credentials.")
    matched = scan_sensitive_markers(cleaned)
    if matched:
        raise ContractViolationError(
            "report_url contains forbidden sensitive markers.",
            details={"matched_rules": list(matched)},
        )
    return cleaned


class VdpAiDisclosure(StrictModel):
    """Explicit AI-use disclosure metadata included in VDP submission drafts."""

    ai_used: bool = True
    client_model_label: str = Field(min_length=1, max_length=160)
    assistance_scope: str = Field(min_length=1, max_length=500)
    human_reviewed_by: str = Field(min_length=1, max_length=120)
    human_review_confirmed: bool = True


class VdpDraftSpec(StrictModel):
    """Operator-supplied technical facts & evidence IDs for rendering a VDP draft."""

    finding_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{1,64}$")
    title: str = Field(min_length=1, max_length=200)
    target_name: str = Field(min_length=1, max_length=120)
    affected_version: str = Field(min_length=1, max_length=80)
    pinned_source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    location: str = Field(min_length=1, max_length=240)
    preconditions: str = Field(min_length=1, max_length=500)
    observation: str = Field(min_length=1, max_length=1500)
    reproduction_steps: tuple[str, ...] = Field(min_length=1, max_length=30)
    impact_hypothesis: str = Field(min_length=1, max_length=1000)
    impact_boundaries: tuple[str, ...] = Field(min_length=1, max_length=30)
    unverified_conditions: tuple[str, ...] = ()
    severity_assessment: str = Field(default="operator-assessment-required", max_length=120)
    evidence_ids: tuple[str, ...] = Field(min_length=1, max_length=30)
    ai_disclosure: VdpAiDisclosure
    duplicate_check_note: str = Field(default="operator-check-required", max_length=300)

    @model_validator(mode="after")
    def _validate_clean(self) -> VdpDraftSpec:
        serialized = json.dumps(self.model_dump(mode="json"), ensure_ascii=False)
        matched = scan_sensitive_markers(serialized)
        if matched:
            raise ContractViolationError(
                "VDP draft specification contains forbidden sensitive markers.",
                details={"matched_rules": list(matched)},
            )
        return self


class VdpSubmissionRecord(StrictModel):
    """Persisted manual VDP submission status & draft provenance record."""

    finding_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{1,64}$")
    run_id: str = Field(min_length=1)
    title: str = Field(min_length=1, max_length=200)
    target_name: str = Field(min_length=1, max_length=120)
    affected_version: str = Field(min_length=1, max_length=80)
    pinned_source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    state: FindingState
    triage_status: Literal[
        "not_submitted",
        "unconfirmed",
        "triaged",
        "duplicate",
        "informative",
        "accepted",
        "resolved",
    ] = "not_submitted"
    automatic_submission: Literal[False] = False
    evidence_ids: tuple[str, ...] = Field(min_length=1)
    evidence_provenance_summary: tuple[dict[str, Any], ...] = ()
    draft_relpath: str | None = None
    draft_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    report_url: str | None = None
    report_ref: str | None = Field(default=None, max_length=160)
    submitted_at: datetime | None = None
    recorded_by: str | None = Field(default=None, max_length=120)
    recorded_at: datetime
    notes: str = Field(default="", max_length=1000)
    history: tuple[dict[str, Any], ...] = ()

    @model_validator(mode="after")
    def _validate_submission_invariants(self) -> VdpSubmissionRecord:
        if self.report_url is not None:
            validate_report_url(self.report_url)
        if self.state in {FindingState.SUBMITTED, FindingState.ACCEPTED}:
            if not self.report_url or self.submitted_at is None or not (self.recorded_by or "").strip():
                raise ValueError(
                    "Submitted/accepted VDP records require report_url, submitted_at, and recorded_by."
                )
        serialized = json.dumps(self.model_dump(mode="json"), ensure_ascii=False)
        matched = scan_sensitive_markers(serialized)
        if matched:
            raise ContractViolationError(
                "VDP submission record contains forbidden sensitive markers.",
                details={"matched_rules": list(matched)},
            )
        return self


class VdpDraftExportResult(StrictModel):
    """Outcome of rendering and writing a VDP submission draft."""

    run_id: str
    finding_id: str
    language: Literal["ja", "en"]
    markdown: str
    draft_sha256: str = Field(pattern=SHA256_PATTERN)
    output_path: str | None = None
    submission_record: VdpSubmissionRecord
    exported_at: datetime


def _get_submissions_thread_lock(lock_path: Path) -> threading.Lock:
    with _SUBMISSIONS_THREAD_LOCKS_GUARD:
        lock = _SUBMISSIONS_THREAD_LOCKS.get(lock_path)
        if lock is None:
            lock = threading.Lock()
            _SUBMISSIONS_THREAD_LOCKS[lock_path] = lock
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
                    raise TimeoutError("Timed out acquiring lock for VDP submissions store.") from exc
                time.sleep(0.01)


def _release_file_lock(fd: int) -> None:
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return
    if sys.platform == "win32" and msvcrt is not None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)


@contextmanager
def _vdp_submissions_lock(vault_path: Path) -> Iterator[None]:
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

    lock_path = Path(os.path.realpath(vdp_dir, strict=True)) / "submissions.json.lock"
    thread_lock = _get_submissions_thread_lock(lock_path)
    with thread_lock:
        try:
            existing_lock_st = os.lstat(lock_path)
        except FileNotFoundError:
            existing_lock_st = None
        if existing_lock_st is not None and (
            _is_reparse_or_symlink(existing_lock_st) or not stat.S_ISREG(existing_lock_st.st_mode)
        ):
            raise PathSecurityError("VDP submissions lockfile cannot be a symlink or special file.")
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


def _load_vdp_submissions_unlocked(vault_path: Path) -> dict[str, VdpSubmissionRecord]:
    target = vault_path / VDP_SUBMISSIONS_RELPATH
    if not target.exists():
        return {}
    raw = safe_read_bounded(
        vault_path,
        VDP_SUBMISSIONS_RELPATH,
        max_bytes=2 * 1024 * 1024,
        allow_truncate=False,
    )
    payload = json.loads(raw.data.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ContractViolationError("VDP submissions store must be a JSON object.")
    items = payload.get("submissions") or {}
    if not isinstance(items, Mapping):
        raise ContractViolationError("VDP submissions 'submissions' field must be an object.")
    return {
        str(k): VdpSubmissionRecord.model_validate(v)
        for k, v in items.items()
    }


def load_vdp_submissions(vault_root: str | Path) -> dict[str, VdpSubmissionRecord]:
    """Load persisted manual VDP submission records keyed by ``finding_id``."""
    vault_path = Path(vault_root)
    if not (vault_path / VDP_SUBMISSIONS_RELPATH).exists():
        return {}
    with _vdp_submissions_lock(vault_path):
        return _load_vdp_submissions_unlocked(vault_path)


def save_vdp_submission(vault_root: str | Path, record: VdpSubmissionRecord) -> Path:
    """Atomically validate and persist a manual VDP submission status record."""
    vault_path = Path(vault_root)
    vault_path.mkdir(parents=True, exist_ok=True)
    with _vdp_submissions_lock(vault_path):
        existing = _load_vdp_submissions_unlocked(vault_path)
        existing[record.finding_id] = record
        data = {
            "schema_version": "vdp-submissions/1",
            "automatic_submission": False,
            "submissions": {
                k: v.model_dump(mode="json")
                for k, v in sorted(existing.items())
            },
        }
        return safe_write_atomic(
            vault_path,
            VDP_SUBMISSIONS_RELPATH,
            (json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"),
            overwrite=True,
            create_parents=True,
        )


def _clean_cell(val: str) -> str:
    return str(val).replace("\r", " ").replace("\n", " ").replace("|", "\\|").strip()


def _summarize_evidence_for_draft(
    *,
    conn: sqlite3.Connection,
    vault: EvidenceVault,
    run_id: str,
    principal_id: str,
    evidence_ids: Sequence[str],
) -> tuple[list[dict[str, Any]], list[tuple[str, str, str, str]], list[str]]:
    ver_rows = conn.execute(
        "SELECT verifier_id, verifier_revision, status, evidence_ids_json FROM verifications WHERE run_id = ?",
        (run_id,),
    ).fetchall()
    verified_by_vdp: set[str] = set()
    for vr in ver_rows:
        if str(vr["verifier_id"]) == "vdp.product_test" and str(vr["status"]) == "passed":
            for eid in json.loads(str(vr["evidence_ids_json"])):
                verified_by_vdp.add(str(eid))

    provenance_rows: list[dict[str, Any]] = []
    controls_rows: list[tuple[str, str, str, str]] = []
    discovered_unverified: list[str] = []

    for eid in dict.fromkeys(evidence_ids):
        obj_row = conn.execute(
            "SELECT evidence_id, run_id, owner_principal_id, media_type FROM evidence_objects WHERE evidence_id = ?",
            (eid,),
        ).fetchone()
        if obj_row is None:
            raise EvidenceNotFoundError(f"Referenced evidence {eid!r} was not found.")
        if str(obj_row["run_id"]) != run_id or str(obj_row["owner_principal_id"]) != principal_id:
            raise EvidenceAccessDeniedError(
                f"Evidence {eid!r} is not owned by run {run_id!r} and principal {principal_id!r}."
            )
        view_row = conn.execute(
            """
            SELECT view_sha256, storage_relpath
            FROM evidence_views
            WHERE evidence_id = ? AND run_id = ? AND revoked_at IS NULL
            ORDER BY created_at DESC LIMIT 1
            """,
            (eid, run_id),
        ).fetchone()
        if view_row is None:
            raise ContractViolationError(f"Evidence {eid!r} has no active unrevoked view.")
        blob = safe_read_bounded(
            vault.vault_root,
            str(view_row["storage_relpath"]),
            max_bytes=vault.max_evidence_bytes,
            allow_truncate=False,
        )
        if not hmac.compare_digest(sha256_bytes(blob.data), str(view_row["view_sha256"]).lower()):
            raise ContractViolationError(f"Evidence {eid!r} failed SHA-256 integrity verification.")

        parsed: dict[str, Any] | None = None
        try:
            cand = json.loads(blob.data.decode("utf-8", errors="strict"))
            if isinstance(cand, dict):
                parsed = cand
        except Exception:
            parsed = None

        if parsed is not None and parsed.get("schema") == MANUAL_OBSERVATION_SCHEMA:
            for item in parsed.get("unverified_conditions") or ():
                if str(item).strip() and str(item).strip() not in discovered_unverified:
                    discovered_unverified.append(str(item).strip())
            for ctrl in parsed.get("controls") or ():
                if isinstance(ctrl, Mapping):
                    controls_rows.append(
                        (
                            str(ctrl.get("control_name") or "manual_control"),
                            str(ctrl.get("role") or "observation"),
                            str(ctrl.get("outcome") or "observed"),
                            f"{eid}: {ctrl.get('summary') or ''}",
                        )
                    )
            cleanup = parsed.get("cleanup_confirmation") or {}
            cleanup_ok = bool(
                isinstance(cleanup, Mapping)
                and cleanup.get("containers_removed")
                and cleanup.get("databases_removed")
                and cleanup.get("networks_removed")
            )
            provenance_rows.append(
                {
                    "evidence_id": eid,
                    "schema": MANUAL_OBSERVATION_SCHEMA,
                    "execution_provenance": MANUAL_OBSERVATION_PROVENANCE,
                    "vdp_product_test_verified": False,
                    "verification_tier": "manual_isolated_observation_not_harness_verified",
                    "test_code_hashes": dict(parsed.get("test_code_hashes") or {}),
                    "cleanup_confirmed": cleanup_ok,
                    "blob_sha256": str(view_row["view_sha256"]),
                }
            )
        elif parsed is not None and parsed.get("schema") == "vdp-product-test-evidence/1":
            conc = parsed.get("conclusion_status") or {}
            if isinstance(conc, Mapping):
                for item in conc.get("unverified_conditions") or ():
                    if str(item).strip() and str(item).strip() not in discovered_unverified:
                        discovered_unverified.append(str(item).strip())
            sel_roles = parsed.get("selector_roles") or {}
            sel_outcomes = parsed.get("selector_outcomes") or {}
            for sel, st in sel_outcomes.items():
                if isinstance(st, str):
                    controls_rows.append(
                        (
                            str(sel),
                            str(sel_roles.get(sel) or parsed.get("operation") or "pytest"),
                            st,
                            f"{eid}: verdict={parsed.get('verdict')} network={parsed.get('network_mode')}",
                        )
                    )
            is_verified = eid in verified_by_vdp
            cleanup_ok = bool(
                parsed.get("container_cleanup_confirmed")
                and parsed.get("process_cleanup_confirmed")
                and parsed.get("service_cleanup_confirmed", True)
                and parsed.get("network_cleanup_confirmed", True)
            )
            provenance_rows.append(
                {
                    "evidence_id": eid,
                    "schema": "vdp-product-test-evidence/1",
                    "execution_provenance": str(parsed.get("execution_provenance") or "harness_docker_isolated"),
                    "vdp_product_test_verified": is_verified,
                    "verification_tier": (
                        "harness_vdp_product_test_passed"
                        if is_verified
                        else "harness_unverified_or_non_passed"
                    ),
                    "network_mode": parsed.get("network_mode"),
                    "overlay_file_hashes": dict(parsed.get("overlay_file_hashes") or {}),
                    "cleanup_confirmed": cleanup_ok,
                    "blob_sha256": str(view_row["view_sha256"]),
                }
            )
        else:
            provenance_rows.append(
                {
                    "evidence_id": eid,
                    "schema": str(parsed.get("schema")) if parsed else str(obj_row["media_type"]),
                    "execution_provenance": "other_evidence",
                    "vdp_product_test_verified": False,
                    "verification_tier": "not_vdp_product_test_evidence",
                    "cleanup_confirmed": None,
                    "blob_sha256": str(view_row["view_sha256"]),
                }
            )

    return provenance_rows, controls_rows, discovered_unverified


def export_vdp_submission_draft(
    *,
    storage: Storage,
    vault: EvidenceVault,
    vault_root: Path,
    export_root: Path | None,
    run_id: str,
    principal_id: str,
    draft: VdpDraftSpec,
    language: Literal["ja", "en"] = "ja",
    output_relpath: str | None = None,
    overwrite: bool = False,
    forbidden_literals: Sequence[str] = (),
    clock: Callable[[], datetime] | None = None,
) -> VdpDraftExportResult:
    """Render a human-reviewable VDP submission draft and persist ``report-ready`` state."""
    if language not in {"ja", "en"}:
        raise ConfigurationError(f"Unsupported draft language: {language!r}.")
    if output_relpath is not None and export_root is None:
        raise ConfigurationError("output_relpath requires export_root to be configured.")

    now = (clock or (lambda: datetime.now(UTC)))()
    with storage.read_connection() as conn:
        run_row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if run_row is None:
            raise EvidenceNotFoundError(f"Run {run_id!r} not found.")
        if str(run_row["owner_principal_id"]) != principal_id:
            raise EvidenceAccessDeniedError(
                f"Principal {principal_id!r} is not authorized to export draft for run {run_id!r}."
            )
        scope_row = conn.execute(
            "SELECT scope_revision, policy_json FROM scopes WHERE run_id = ? AND scope_revision = ?",
            (run_id, str(run_row["scope_revision"])),
        ).fetchone()
        auth_ref = "recorded"
        if scope_row is not None:
            try:
                pol = json.loads(str(scope_row["policy_json"]))
                if isinstance(pol, dict) and pol.get("authorization_reference"):
                    auth_ref = str(pol["authorization_reference"])
            except json.JSONDecodeError:
                pass
        prov_rows, ctrl_rows, ev_unverified = _summarize_evidence_for_draft(
            conn=conn,
            vault=vault,
            run_id=run_id,
            principal_id=principal_id,
            evidence_ids=draft.evidence_ids,
        )

    existing_map = load_vdp_submissions(vault_root)
    prior = existing_map.get(draft.finding_id)
    if prior is not None and prior.state in {FindingState.SUBMITTED, FindingState.ACCEPTED}:
        next_state = prior.state
    else:
        next_state = FindingState.REPORT_READY

    merged_unverified = list(
        dict.fromkeys(
            [*(str(x).strip() for x in draft.unverified_conditions if str(x).strip()), *ev_unverified]
        )
    )
    steps_md = [f"{idx}. {step}" for idx, step in enumerate(draft.reproduction_steps, start=1)]
    ctrl_md = [
        f"| {_clean_cell(name)} | {_clean_cell(role)} | {_clean_cell(outcome)} | {_clean_cell(detail)} |"
        for name, role, outcome, detail in ctrl_rows
    ] or (["| (記録なし) | - | - | - |"] if language == "ja" else ["| (none) | - | - | - |"])

    prov_md: list[str] = []
    for pr in prov_rows:
        eid = pr["evidence_id"]
        ep = pr["execution_provenance"]
        if ep == MANUAL_OBSERVATION_PROVENANCE:
            tier_label = (
                "手動・隔離環境での観測（`vdp.product_test` 未検証）"
                if language == "ja"
                else "manual isolated observation (`vdp.product_test` NOT verified)"
            )
            hashes_str = json.dumps(pr.get("test_code_hashes") or {}, sort_keys=True, ensure_ascii=False)
        else:
            tier_label = (
                "vdp.product_test 検証済み"
                if pr.get("vdp_product_test_verified")
                else f"未検証 ({pr.get('verification_tier')})"
            ) if language == "ja" else (
                "vdp.product_test passed"
                if pr.get("vdp_product_test_verified")
                else f"unverified ({pr.get('verification_tier')})"
            )
            hashes_str = json.dumps(pr.get("overlay_file_hashes") or {}, sort_keys=True, ensure_ascii=False)
        prov_md.append(
            f"| {_clean_cell(eid)} | {_clean_cell(ep)} | {_clean_cell(tier_label)} | "
            f"`hashes={_clean_cell(hashes_str)}`, `cleanup={pr.get('cleanup_confirmed')}`, `sha256={pr.get('blob_sha256')}` |"
        )

    boundaries_md = [f"- {b}" for b in draft.impact_boundaries]
    unverified_md = [f"- `{u}`" for u in merged_unverified] or (
        ["- (特記なし)"] if language == "ja" else ["- (none)"]
    )

    rep_url_display = (prior.report_url if prior and prior.report_url else "not-submitted")
    rep_ref_display = (prior.report_ref if prior and prior.report_ref else "none")
    triage_display = (prior.triage_status if prior else "not_submitted")

    if language == "ja":
        lines = [
            f"# VDP提出用下書き: {draft.title}",
            "",
            "人が内容・再現性・影響の限界・秘匿状態を確認したうえで手動提出するための下書きです。自動提出機能は無効です。",
            "",
            "## 提出前確認と状態",
            f"- Finding ID / Run ID / 提出状態：`finding_id={draft.finding_id}`, `run_id={run_id}`, `state={next_state.value}`, `triage_status={triage_display}`",
            "- 自動提出：`disabled`（手動提出のみ）",
            f"- 重複・既報確認メモ：{draft.duplicate_check_note}",
            f"- 報告URL・報告参照ID：`report_url={rep_url_display}`, `report_ref={rep_ref_display}`",
            "",
            "## 対象と固定版",
            f"- 対象製品・影響版・固定ソースコミット：`target={draft.target_name}`, `version={draft.affected_version}`, `commit={draft.pinned_source_commit}`",
            f"- スコープ版・認可参照：`scope={run_row['scope_revision']}`, `auth={auth_ref}`",
            "",
            "## 概要と再現手順（合成データ・隔離環境前提）",
            f"- 位置：`{draft.location}`",
            f"- 前提条件：{draft.preconditions}",
            f"- 観測された挙動：{draft.observation}",
            "- 再現手順：",
            *steps_md,
            "",
            "## 成功・失敗した対照試験",
            "| 対象／対照 | 役割 | 結果 | 証拠ID・詳細 |",
            "|---|---|---|---|",
            *ctrl_md,
            "",
            "## 影響と影響の限界",
            f"- 想定される影響（仮説）：{draft.impact_hypothesis}",
            "- 確認できた範囲・成立しなかった範囲（影響の限界）：",
            *boundaries_md,
            f"- 暫定重要度評価（運用者判断）：`{draft.severity_assessment}`",
            "",
            "## 未確認条件と評価の限界",
            *unverified_md,
            "",
            "## AI利用の開示",
            f"- AI利用：`{draft.ai_disclosure.ai_used}` / クライアント・モデル：`{draft.ai_disclosure.client_model_label}`",
            f"- AI支援範囲：{draft.ai_disclosure.assistance_scope}",
            f"- 人によるレビュー確認：`reviewed_by={draft.ai_disclosure.human_reviewed_by}`, `confirmed={draft.ai_disclosure.human_review_confirmed}`",
            "",
            "## 証拠の来歴（ハーネス実行 vs 手動・隔離環境での観測）",
            "| 証拠ID | 来歴区分 | `vdp.product_test` 検証状態 | テストコード／オーバーレイハッシュ・後片付け確認 |",
            "|---|---|---|---|",
            *prov_md,
        ]
    else:
        lines = [
            f"# VDP Submission Draft: {draft.title}",
            "",
            "Human-reviewed draft for manual disclosure. Automatic external submission is disabled.",
            "",
            "## Pre-Submission Status",
            f"- Finding ID / Run ID / State: `finding_id={draft.finding_id}`, `run_id={run_id}`, `state={next_state.value}`, `triage_status={triage_display}`",
            "- Automatic submission: `disabled` (manual submission only)",
            f"- Duplicate check note: {draft.duplicate_check_note}",
            f"- Report URL / Reference ID: `report_url={rep_url_display}`, `report_ref={rep_ref_display}`",
            "",
            "## Target & Pinned Revisions",
            f"- Target / version / pinned commit: `target={draft.target_name}`, `version={draft.affected_version}`, `commit={draft.pinned_source_commit}`",
            f"- Scope revision / authorization ref: `scope={run_row['scope_revision']}`, `auth={auth_ref}`",
            "",
            "## Summary & Reproduction Steps (Synthetic Data / Isolated Environment)",
            f"- Location: `{draft.location}`",
            f"- Preconditions: {draft.preconditions}",
            f"- Observed behavior: {draft.observation}",
            "- Reproduction steps:",
            *steps_md,
            "",
            "## Passed & Failed Controls",
            "| Control | Role | Outcome | Evidence ID / Summary |",
            "|---|---|---|---|",
            *ctrl_md,
            "",
            "## Impact & Impact Boundaries",
            f"- Impact hypothesis: {draft.impact_hypothesis}",
            "- Verified boundaries & non-reproduced scope:",
            *boundaries_md,
            f"- Operator severity assessment: `{draft.severity_assessment}`",
            "",
            "## Unverified Conditions & Limitations",
            *unverified_md,
            "",
            "## AI Usage Disclosure",
            f"- AI used: `{draft.ai_disclosure.ai_used}` / Client/Model: `{draft.ai_disclosure.client_model_label}`",
            f"- Assistance scope: {draft.ai_disclosure.assistance_scope}",
            f"- Human review confirmation: `reviewed_by={draft.ai_disclosure.human_reviewed_by}`, `confirmed={draft.ai_disclosure.human_review_confirmed}`",
            "",
            "## Evidence Provenance (Harness-Executed vs Manual Isolated Observation)",
            "| Evidence ID | Provenance | `vdp.product_test` Verification | Test/Overlay Hashes & Cleanup Confirmation |",
            "|---|---|---|---|",
            *prov_md,
        ]

    rendered = "\n".join(lines) + "\n"
    assert_report_clean(rendered, forbidden_literals=forbidden_literals)
    draft_sha = sha256_bytes(rendered.encode("utf-8"))

    out_path_str: str | None = None
    if output_relpath is not None:
        assert export_root is not None
        written = safe_write_atomic(
            export_root,
            output_relpath,
            rendered.encode("utf-8"),
            overwrite=overwrite,
            create_parents=True,
        )
        out_path_str = str(written)

    history = list(prior.history) if prior is not None else []
    history.append(
        {
            "event": "draft_exported",
            "state": next_state.value,
            "draft_sha256": draft_sha,
            "draft_relpath": output_relpath,
            "at": now.isoformat(),
        }
    )
    record = VdpSubmissionRecord(
        finding_id=draft.finding_id,
        run_id=run_id,
        title=draft.title,
        target_name=draft.target_name,
        affected_version=draft.affected_version,
        pinned_source_commit=draft.pinned_source_commit,
        state=next_state,
        triage_status=prior.triage_status if prior is not None else "not_submitted",
        automatic_submission=False,
        evidence_ids=tuple(dict.fromkeys(draft.evidence_ids)),
        evidence_provenance_summary=tuple(prov_rows),
        draft_relpath=output_relpath,
        draft_sha256=draft_sha,
        report_url=prior.report_url if prior is not None else None,
        report_ref=prior.report_ref if prior is not None else None,
        submitted_at=prior.submitted_at if prior is not None else None,
        recorded_by=prior.recorded_by if prior is not None else None,
        recorded_at=now,
        notes=prior.notes if prior is not None else "",
        history=tuple(history),
    )
    save_vdp_submission(vault_root, record)
    return VdpDraftExportResult(
        run_id=run_id,
        finding_id=draft.finding_id,
        language=language,
        markdown=rendered,
        draft_sha256=draft_sha,
        output_path=out_path_str,
        submission_record=record,
        exported_at=now,
    )


def record_manual_vdp_submission(
    *,
    vault_root: Path,
    run_id: str,
    finding_id: str,
    target_state: FindingState,
    report_url: str,
    recorded_by: str,
    report_ref: str | None = None,
    triage_status: Literal[
        "not_submitted",
        "unconfirmed",
        "triaged",
        "duplicate",
        "informative",
        "accepted",
        "resolved",
    ] = "unconfirmed",
    submitted_at: datetime | None = None,
    notes: str = "",
    clock: Callable[[], datetime] | None = None,
) -> VdpSubmissionRecord:
    """Record manual external VDP submission status & report URL (no auto-submission)."""
    if not _FINDING_ID_RE.fullmatch(finding_id):
        raise ContractViolationError(f"Invalid finding_id {finding_id!r}.")
    if target_state not in {FindingState.SUBMITTED, FindingState.ACCEPTED}:
        raise ContractViolationError(
            "Manual submission recording only accepts target_state='submitted' or 'accepted'."
        )
    clean_url = validate_report_url(report_url)
    clean_actor = str(recorded_by).strip()
    if not clean_actor:
        raise ContractViolationError("recorded_by must be non-empty.")

    now = (clock or (lambda: datetime.now(UTC)))()
    existing_map = load_vdp_submissions(vault_root)
    prior = existing_map.get(finding_id)
    if prior is None or prior.run_id != run_id:
        raise EvidenceNotFoundError(
            f"VDP draft record for finding {finding_id!r} in run {run_id!r} was not found; export draft first."
        )
    if prior.state != target_state:
        validate_finding_transition(prior.state, target_state)

    eff_submitted_at = submitted_at or prior.submitted_at or now
    history = list(prior.history)
    history.append(
        {
            "event": "manual_submission_recorded",
            "from_state": prior.state.value,
            "to_state": target_state.value,
            "triage_status": triage_status,
            "report_url": clean_url,
            "report_ref": report_ref,
            "recorded_by": clean_actor,
            "at": now.isoformat(),
        }
    )
    updated = prior.model_copy(
        update={
            "state": target_state,
            "triage_status": triage_status,
            "report_url": clean_url,
            "report_ref": report_ref.strip() if report_ref else prior.report_ref,
            "submitted_at": eff_submitted_at,
            "recorded_by": clean_actor,
            "recorded_at": now,
            "notes": notes.strip() if notes.strip() else prior.notes,
            "history": tuple(history),
        }
    )
    save_vdp_submission(vault_root, updated)
    return updated


__all__ = [
    "VALID_TRIAGE_STATUSES",
    "VDP_SUBMISSIONS_RELPATH",
    "VdpAiDisclosure",
    "VdpDraftExportResult",
    "VdpDraftSpec",
    "VdpSubmissionRecord",
    "export_vdp_submission_draft",
    "load_vdp_submissions",
    "record_manual_vdp_submission",
    "save_vdp_submission",
    "validate_report_url",
]
