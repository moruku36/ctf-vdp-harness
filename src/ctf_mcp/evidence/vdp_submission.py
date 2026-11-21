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

import hmac
import json
import re
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

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
from ctf_mcp.evidence.vdp_candidate_ledger import (
    ZERO_HITS_DISCLAIMER,
    CandidateGateEvaluation,
    VdpCandidateCheckpointRecord,
    _vdp_vault_lock,
    evaluate_candidate_gate,
    get_vdp_candidate_checkpoint,
    validate_https_url,
)
from ctf_mcp.fs_guard import safe_read_bounded, safe_write_atomic
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

_FINDING_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,64}$")


def validate_report_url(url: str) -> str:
    """Validate an HTTPS report URL with zero embedded credentials or control chars."""
    return validate_https_url(url, field_name="report_url")


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
    candidate_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

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
    candidate_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
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


def _vdp_submissions_lock(vault_path: Path):
    return _vdp_vault_lock(vault_path, "submissions.json.lock")


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


def _render_candidate_checkpoint_section(
    *,
    candidate: VdpCandidateCheckpointRecord | None,
    gate_eval: CandidateGateEvaluation | None,
    language: Literal["ja", "en"],
) -> list[str]:
    if candidate is None:
        return []
    pre = candidate.preconditions
    checkpoints = [
        ("pre_heavy_test", candidate.pre_heavy_test_checkpoint),
        ("pre_submission", candidate.pre_submission_checkpoint),
    ]
    ref_rows: list[str] = []
    cp_lines: list[str] = []
    has_zero_hits = False
    for gate_name, cp in checkpoints:
        if cp is None:
            cp_lines.append(f"- `{gate_name}`: missing")
            continue
        if cp.zero_hits_observed:
            has_zero_hits = True
        queries_str = ", ".join(f"`{q}`" for q in cp.search_queries)
        cp_lines.append(
            f"- `{gate_name}`: `checked_at={cp.checked_at.isoformat()}`, "
            f"`checked_by={cp.checked_by}`, `source={cp.search_source}`, "
            f"`queries=[{queries_str}]`, `disposition={cp.duplicate_disposition}`, "
            f"`zero_hits_observed={cp.zero_hits_observed}`"
        )
        for ref in cp.references_reviewed:
            ref_rows.append(
                f"| {_clean_cell(gate_name)} | {_clean_cell(ref.ref_kind)} | {_clean_cell(ref.ref_id)} | "
                f"{_clean_cell(ref.target_version_relation)} | {_clean_cell(ref.same_root_cause_judgment)} | "
                f"{_clean_cell(ref.human_rationale)} | {_clean_cell(ref.ref_url)} |"
            )

    warnings_str = ", ".join(gate_eval.warnings) if gate_eval and gate_eval.warnings else "none"
    basis_str = ", ".join(f"`{b}`" for b in pre.basis_refs) if pre.basis_refs else "none"

    if language == "ja":
        if not ref_rows:
            ref_rows = ["| - | - | (参照なし / 検索結果0件) | - | - | 重複なしを自動断定しない | - |"]
        lines = [
            "",
            "## 既知問題チェックポイントと成立条件",
            f"- 候補ID / 状態：`candidate_id={candidate.candidate_id}`, `status={candidate.status}`, `auto_promoted_to_confirmed_vulnerability=False`, `external_search_performed_by_harness=False`",
            f"- 事前設定の作成主体：`preconfig_created_by={pre.preconfig_created_by}`",
            f"- 攻撃者が制御する入力：{pre.attacker_controls}",
            f"- 実運用での一般的成立性：`real_world_prevalence={pre.real_world_prevalence}`",
            f"- 観測された影響上限：{pre.observed_impact_cap}",
            f"- 根拠参照：{basis_str}",
            f"- ゲート警告：`{warnings_str}`",
            *cp_lines,
        ]
        if has_zero_hits:
            lines.append(
                f"- 検索結果0件に関する注記：`{ZERO_HITS_DISCLAIMER}`（検索結果0件は「重複なし」「未修正」を自動証明しません）"
            )
        lines.extend(
            [
                "",
                "| ゲート | 種別 | 参照ID | 対象版との関係 | 同一原因／影響の人間判断 | 判断根拠 | 参照URL |",
                "|---|---|---|---|---|---|---|",
                *ref_rows,
            ]
        )
        return lines

    if not ref_rows:
        ref_rows = ["| - | - | (no hits recorded) | - | - | zero hits do not prove no duplicate | - |"]
    lines = [
        "",
        "## Known-Issue Checkpoints & Preconditions",
        f"- Candidate ID / Status: `candidate_id={candidate.candidate_id}`, `status={candidate.status}`, `auto_promoted_to_confirmed_vulnerability=False`, `external_search_performed_by_harness=False`",
        f"- Preconfiguration creator: `preconfig_created_by={pre.preconfig_created_by}`",
        f"- Attacker-controlled input: {pre.attacker_controls}",
        f"- Real-world prevalence: `real_world_prevalence={pre.real_world_prevalence}`",
        f"- Observed impact cap: {pre.observed_impact_cap}",
        f"- Basis references: {basis_str}",
        f"- Gate warnings: `{warnings_str}`",
        *cp_lines,
    ]
    if has_zero_hits:
        lines.append(
            f"- Zero-hits limitation: `{ZERO_HITS_DISCLAIMER}` (zero search hits never auto-prove no duplicate or unpatched state)."
        )
    lines.extend(
        [
            "",
            "| Gate | Kind | Ref ID | Version Relation | Human Root-Cause Judgment | Rationale | URL |",
            "|---|---|---|---|---|---|---|",
            *ref_rows,
        ]
    )
    return lines


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

    candidate_record: VdpCandidateCheckpointRecord | None = None
    candidate_gate_eval: CandidateGateEvaluation | None = None
    candidate_unverified: list[str] = []
    if draft.candidate_id is not None:
        candidate_record = get_vdp_candidate_checkpoint(
            vault_root,
            run_id=run_id,
            candidate_id=draft.candidate_id,
        )
        if candidate_record is None:
            raise EvidenceNotFoundError(
                f"VDP candidate checkpoint {draft.candidate_id!r} for run {run_id!r} was not found."
            )
        if candidate_record.target_name != draft.target_name:
            raise ContractViolationError(
                f"Candidate {draft.candidate_id!r} target_name {candidate_record.target_name!r} "
                f"does not match draft target_name {draft.target_name!r}."
            )
        if (
            len(candidate_record.pinned_source_commit) == 40
            and candidate_record.pinned_source_commit != draft.pinned_source_commit.lower()
        ):
            raise ContractViolationError(
                f"Candidate {draft.candidate_id!r} pinned_source_commit "
                f"{candidate_record.pinned_source_commit!r} does not match draft commit "
                f"{draft.pinned_source_commit.lower()!r}."
            )
        candidate_gate_eval = evaluate_candidate_gate(
            candidate_record,
            gate="pre_submission",
            now=now,
        )
        if not candidate_gate_eval.ready:
            details_parts = []
            if candidate_gate_eval.blocked_reason:
                details_parts.append(f"blocked={candidate_gate_eval.blocked_reason}")
            if candidate_gate_eval.missing_items:
                details_parts.append(f"missing={list(candidate_gate_eval.missing_items)}")
            if candidate_gate_eval.recheck_prompt:
                details_parts.append(candidate_gate_eval.recheck_prompt)
            raise ContractViolationError(
                f"Candidate {draft.candidate_id!r} failed pre_submission known-issue gate: "
                + "; ".join(details_parts),
                details=candidate_gate_eval.model_dump(mode="json"),
            )
        if (
            candidate_record.pre_submission_checkpoint is not None
            and candidate_record.pre_submission_checkpoint.zero_hits_observed
        ):
            candidate_unverified.append(ZERO_HITS_DISCLAIMER)
        if candidate_record.preconditions.real_world_prevalence == "unverified":
            candidate_unverified.append("real_world_prevalence_unverified")
        if candidate_record.preconditions.preconfig_created_by == "unknown":
            candidate_unverified.append("preconfig_creator_unknown")

    existing_map = load_vdp_submissions(vault_root)
    prior = existing_map.get(draft.finding_id)
    if prior is not None and prior.state in {FindingState.SUBMITTED, FindingState.ACCEPTED}:
        next_state = prior.state
    else:
        next_state = FindingState.REPORT_READY

    merged_unverified = list(
        dict.fromkeys(
            [
                *(str(x).strip() for x in draft.unverified_conditions if str(x).strip()),
                *ev_unverified,
                *candidate_unverified,
            ]
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

    lines.extend(
        _render_candidate_checkpoint_section(
            candidate=candidate_record,
            gate_eval=candidate_gate_eval,
            language=language,
        )
    )
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
        candidate_id=draft.candidate_id,
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
