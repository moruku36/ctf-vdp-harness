"""Integration tests for PR-C: two-gate VDP candidate known-issue & precondition checkpoints."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from ctf_mcp.cli import admin_main
from ctf_mcp.contracts import (
    BudgetSpec,
    ContractViolationError,
    EvidenceAccessDeniedError,
    EvidenceNotFoundError,
    ExecutionClass,
    PathSecurityError,
    PrincipalContext,
    RunMode,
    ScopeDeniedError,
    ScopePolicy,
    canonical_digest,
)
from ctf_mcp.controller import create_default_controller
from ctf_mcp.evidence.manual_observation import (
    ManualCleanupConfirmation,
    ManualControlRecord,
    ManualIsolationDeclaration,
    ManualObservationRecord,
)
from ctf_mcp.evidence.vdp_candidate_ledger import (
    MAX_CANDIDATE_JSON_BYTES,
    ZERO_HITS_DISCLAIMER,
    CandidatePreconditions,
    KnownIssueCheckpoint,
    KnownIssueReference,
    VdpCandidateCheckpointRecord,
    evaluate_candidate_gate,
)
from ctf_mcp.evidence.vdp_submission import VdpAiDisclosure, VdpDraftSpec
from ctf_mcp.mcp_diagnostics import collect_mcp_diagnostics
from ctf_mcp.storage import Storage

SYNTH_COMMIT = "0123456789abcdef0123456789abcdef01234567"
SYNTH_DIGEST = "sha256:" + ("a" * 64)
HMAC_SECRET = "pr-c-synthetic-hmac-secret-value-998877665544"


def _make_principal(principal_id: str = "local-operator") -> PrincipalContext:
    return PrincipalContext(
        principal_id=principal_id,
        auth_method="stdio_local",
        client_kind="OPERATOR_SELECTED",
        model_label="pr-c-test-client",
    )


def _make_scope(
    *,
    mode: RunMode = RunMode.VDP,
    task_id: str = "task-pr-c-synth",
    scope_revision: str = "scope-pr-c-v1",
) -> ScopePolicy:
    now = datetime.now(UTC)
    caps = ["analysis.query", "vdp.test"] if mode == RunMode.VDP else ["analysis.query"]
    classes = ["static", "dynamic"] if mode == RunMode.VDP else ["static"]
    payload = {
        "mode": mode.value,
        "task_id": task_id,
        "scope_revision": scope_revision,
        "authorization_reference": "owned-synthetic-pr-c",
        "allowed_capabilities": caps,
        "allowed_execution_classes": classes,
        "expires_at": (now + timedelta(hours=2)).isoformat(),
        "network_enabled": False,
        "allowed_targets": [],
        "external_submission": False,
    }
    return ScopePolicy(
        scope_revision=scope_revision,
        scope_sha256=canonical_digest(payload),
        mode=mode,
        task_id=task_id,
        authorization_reference="owned-synthetic-pr-c",
        allowed_execution_classes=tuple(ExecutionClass(c) for c in classes),
        allowed_capabilities=tuple(caps),
        expires_at=now + timedelta(hours=2),
        network_enabled=False,
        allowed_targets=(),
        external_submission=False,
    )


def _seed_controller(tmp_path: Path):
    db_path = tmp_path / "harness.db"
    vault_root = tmp_path / "vault"
    storage = Storage(db_path)
    ctrl = create_default_controller(
        storage=storage,
        vault_root=vault_root,
        export_root=vault_root / "_exports",
        cursor_hmac_key=HMAC_SECRET.encode("utf-8"),
        allow_dynamic=True,
        include_vdp_product_test=True,
        enable_local_verifier=True,
        initialize=True,
    )
    return db_path, vault_root, ctrl


def _seed_manual_evidence(ctrl, *, principal: PrincipalContext, run_id: str, obs_id: str = "obs-synth-01") -> str:
    receipt = ctrl.import_manual_observation(
        principal=principal,
        run_id=run_id,
        observation=ManualObservationRecord(
            observation_id=obs_id,
            observed_at=datetime.now(UTC),
            target_name="synthetic-app",
            target_version="2026.11.2",
            pinned_source_commit=SYNTH_COMMIT,
            pinned_image_digests={"scanner": SYNTH_DIGEST},
            environment_summary="Isolated synthetic container and database fixture.",
            isolation_declared=ManualIsolationDeclaration(
                synthetic_data_only=True,
                external_egress_blocked=True,
                published_ports_none=True,
                network_description="isolated internal bridge",
            ),
            test_code_hashes={"synth_test.py": "b" * 64},
            execution_summary="Synthetic observation recorded bounded identifier leakage.",
            exit_code=0,
            controls=(
                ManualControlRecord(
                    control_name="authorized_baseline_200",
                    role="positive_control",
                    outcome="passed",
                    summary="Authorized request succeeded.",
                ),
                ManualControlRecord(
                    control_name="direct_private_403",
                    role="defense_check",
                    outcome="passed",
                    summary="Direct unauthorized object read returned 403.",
                ),
            ),
            cleanup_confirmation=ManualCleanupConfirmation(
                containers_removed=True,
                databases_removed=True,
                networks_removed=True,
                confirmed_by="operator",
                confirmed_at=datetime.now(UTC),
                verification_note="Removed synthetic container, DB, and network.",
            ),
        ),
    )
    return receipt.evidence_id


def _default_preconditions(
    *,
    creator: str = "owner_or_admin",
    prevalence: str = "common",
    basis_refs: tuple[str, ...] = ("app/views.py:42", "https://docs.example.invalid/model"),
) -> CandidatePreconditions:
    return CandidatePreconditions(
        preconfig_created_by=creator,  # type: ignore[arg-type]
        attacker_controls="Public child endpoint query parameters and anonymous GET path.",
        real_world_prevalence=prevalence,  # type: ignore[arg-type]
        observed_impact_cap="Identifier exposure in Location header only; content access denied (401/404).",
        preconfig_notes="Requires synthetic public-child/private-parent link configured by owner.",
        basis_refs=basis_refs,
    )


def test_two_gate_candidate_lifecycle_cli_draft_and_metrics(tmp_path: Path, capsys) -> None:
    db_path, vault_root, ctrl = _seed_controller(tmp_path)
    principal = _make_principal()
    run_id = "run-pr-c-lifecycle"
    ctrl.create_run(
        principal=principal,
        run_id=run_id,
        task_id="task-pr-c-synth",
        mode=RunMode.VDP,
        scope=_make_scope(),
        budget=BudgetSpec(run_budget_seconds=300, max_tool_calls=20, max_evidence_bytes_per_run=5_000_000),
    )
    ev_id = _seed_manual_evidence(ctrl, principal=principal, run_id=run_id)
    cli_env = {
        "CTF_MCP_CURSOR_HMAC_KEY": HMAC_SECRET,
        "CTF_MCP_ALLOW_DYNAMIC": "1",
        "CTF_MCP_PROFILE": "vdp",
    }

    now = datetime.now(UTC)
    pre_heavy_payload = {
        "candidate_id": "CAND-SYNTH-01",
        "title": "Public child webhook redirect leaks private parent identifier",
        "target_name": "synthetic-app",
        "target_version": "2026.11.2",
        "pinned_source_commit": SYNTH_COMMIT,
        "status": "investigation_candidate",
        "preconditions": _default_preconditions().model_dump(mode="json"),
        "checkpoint": {
            "gate": "pre_heavy_test",
            "checked_at": (now - timedelta(hours=2)).isoformat(),
            "checked_by": "researcher-a",
            "search_source": "external_github_connector",
            "search_queries": ["synthetic-app child webhook redirect", "location header slug"],
            "references_reviewed": [
                {
                    "ref_url": "https://example.invalid/org/repo/issues/101",
                    "ref_kind": "issue",
                    "ref_id": "ISSUE-101",
                    "target_version_relation": "different_component",
                    "same_root_cause_judgment": "different_cause_or_impact",
                    "human_rationale": "Addresses unrelated email notification template path.",
                },
                {
                    "ref_url": "https://example.invalid/org/repo/commit/abcdef1",
                    "ref_kind": "fix_commit",
                    "ref_id": "abcdef1",
                    "target_version_relation": "fixed_in_later_version",
                    "same_root_cause_judgment": "different_cause_or_impact",
                    "human_rationale": "Patched API serializer only; webhook redirect handler remains distinct.",
                },
            ],
            "zero_hits_observed": False,
            "duplicate_disposition": "proceed_unconfirmed_candidate",
            "max_age_hours": 72,
            "notes": "Verified before running heavy isolated product tests.",
        },
        "evidence_ids": [ev_id],
        "first_candidate_observed_at": (now - timedelta(minutes=30)).isoformat(),
    }
    pre_heavy_path = tmp_path / "cand_pre_heavy.json"
    pre_heavy_path.write_text(json.dumps(pre_heavy_payload, indent=2), encoding="utf-8")

    rc1 = admin_main(
        [
            "record-vdp-candidate",
            "--db-path",
            str(db_path),
            "--vault-root",
            str(vault_root),
            "--run-id",
            run_id,
            "--candidate-json",
            str(pre_heavy_path),
        ],
        env=cli_env,
    )
    assert rc1 == 0
    rec1_out = json.loads(capsys.readouterr().out)
    assert rec1_out["external_search_performed_by_harness"] is False
    assert rec1_out["auto_promoted_to_confirmed_vulnerability"] is False
    assert rec1_out["gates"]["pre_heavy_test"]["ready"] is True
    assert rec1_out["gates"]["pre_submission"]["ready"] is False
    assert "pre_submission_checkpoint" in rec1_out["gates"]["pre_submission"]["missing_items"]

    # Gate checks via CLI exit code (0 = ready, 1 = not ready)
    rc_gate_heavy = admin_main(
        [
            "check-vdp-candidate-gate",
            "--db-path",
            str(db_path),
            "--vault-root",
            str(vault_root),
            "--run-id",
            run_id,
            "--candidate-id",
            "CAND-SYNTH-01",
            "--gate",
            "pre_heavy_test",
        ],
        env=cli_env,
    )
    assert rc_gate_heavy == 0
    _ = json.loads(capsys.readouterr().out)

    rc_gate_sub_missing = admin_main(
        [
            "check-vdp-candidate-gate",
            "--db-path",
            str(db_path),
            "--vault-root",
            str(vault_root),
            "--run-id",
            run_id,
            "--candidate-id",
            "CAND-SYNTH-01",
            "--gate",
            "pre_submission",
        ],
        env=cli_env,
    )
    assert rc_gate_sub_missing == 1
    gate_missing_out = json.loads(capsys.readouterr().out)
    assert gate_missing_out["ready"] is False

    # Exporting draft linked to candidate BEFORE pre_submission gate must fail closed
    draft_spec = {
        "finding_id": "FIND-SYNTH-01",
        "candidate_id": "CAND-SYNTH-01",
        "title": "Public linked child endpoint leaks private parent identifier",
        "target_name": "synthetic-app",
        "affected_version": "2026.11.2",
        "pinned_source_commit": SYNTH_COMMIT,
        "location": "app/views.py:42",
        "preconditions": "Public child linked to private parent.",
        "observation": "Redirect Location exposes private parent slug while content endpoints deny.",
        "reproduction_steps": [
            "Provision synthetic linked components.",
            "Request public child redirect endpoint anonymously.",
            "Confirm private endpoints return 401/404.",
        ],
        "impact_hypothesis": "Exposes private component slug only.",
        "impact_boundaries": ["No translation or repository contents disclosed."],
        "unverified_conditions": ["Production CDN caching not tested."],
        "severity_assessment": "Low (synthetic review pending)",
        "evidence_ids": [ev_id],
        "ai_disclosure": {
            "ai_used": True,
            "client_model_label": "Codex",
            "assistance_scope": "Synthesized fixture tests and draft summary.",
            "human_reviewed_by": "operator",
            "human_review_confirmed": True,
        },
        "duplicate_check_note": "Checked at pre_heavy_test and pre_submission gates.",
    }
    draft_path = tmp_path / "draft.json"
    draft_path.write_text(json.dumps(draft_spec, indent=2), encoding="utf-8")

    with pytest.raises(ContractViolationError, match="pre_submission"):
        ctrl.export_vdp_submission_draft(
            principal=principal,
            run_id=run_id,
            draft=VdpDraftSpec.model_validate(draft_spec),
            language="ja",
        )

    # Record pre_submission checkpoint & transition status to ready_for_human_draft_review
    pre_sub_payload = dict(pre_heavy_payload)
    pre_sub_payload["status"] = "ready_for_human_draft_review"
    pre_sub_payload["checkpoint"] = {
        "gate": "pre_submission",
        "checked_at": (now - timedelta(minutes=5)).isoformat(),
        "checked_by": "researcher-a",
        "search_source": "external_github_connector",
        "search_queries": ["synthetic-app child webhook redirect", "pull request redirect view"],
        "references_reviewed": [
            {
                "ref_url": "https://example.invalid/org/repo/pull/205",
                "ref_kind": "pull_request",
                "ref_id": "PR-205",
                "target_version_relation": "different_component",
                "same_root_cause_judgment": "different_cause_or_impact",
                "human_rationale": "PR-205 updates OAuth callback URL validation; distinct component.",
            }
        ],
        "zero_hits_observed": False,
        "duplicate_disposition": "proceed_unconfirmed_candidate",
        "max_age_hours": 48,
        "notes": "Re-checked right before rendering human review draft.",
    }
    pre_sub_path = tmp_path / "cand_pre_sub.json"
    pre_sub_path.write_text(json.dumps(pre_sub_payload, indent=2), encoding="utf-8")

    rc2 = admin_main(
        [
            "record-vdp-candidate",
            "--db-path",
            str(db_path),
            "--vault-root",
            str(vault_root),
            "--run-id",
            run_id,
            "--candidate-json",
            str(pre_sub_path),
        ],
        env=cli_env,
    )
    assert rc2 == 0
    rec2_out = json.loads(capsys.readouterr().out)
    assert rec2_out["record"]["status"] == "ready_for_human_draft_review"
    assert rec2_out["record"]["pre_heavy_test_checkpoint"]["gate"] == "pre_heavy_test"
    assert rec2_out["record"]["pre_submission_checkpoint"]["gate"] == "pre_submission"
    assert rec2_out["gates"]["pre_submission"]["ready"] is True

    # Export Japanese and English drafts now succeed cleanly
    rc_ja = admin_main(
        [
            "export-vdp-draft",
            "--db-path",
            str(db_path),
            "--vault-root",
            str(vault_root),
            "--run-id",
            run_id,
            "--draft-json",
            str(draft_path),
            "--language",
            "ja",
            "--output-relpath",
            "drafts/cand-01.ja.md",
        ],
        env=cli_env,
    )
    assert rc_ja == 0
    _ = json.loads(capsys.readouterr().out)
    ja_md = (vault_root / "_exports" / "drafts" / "cand-01.ja.md").read_text(encoding="utf-8")
    assert "## 既知問題チェックポイントと成立条件" in ja_md
    assert "CAND-SYNTH-01" in ja_md
    assert "ISSUE-101" in ja_md
    assert "PR-205" in ja_md
    assert "preconfig_created_by=owner_or_admin" in ja_md
    assert "real_world_prevalence=common" in ja_md
    assert "auto_promoted_to_confirmed_vulnerability=False" in ja_md

    rc_en = admin_main(
        [
            "export-vdp-draft",
            "--db-path",
            str(db_path),
            "--vault-root",
            str(vault_root),
            "--run-id",
            run_id,
            "--draft-json",
            str(draft_path),
            "--language",
            "en",
            "--output-relpath",
            "drafts/cand-01.en.md",
        ],
        env=cli_env,
    )
    assert rc_en == 0
    _ = json.loads(capsys.readouterr().out)
    en_md = (vault_root / "_exports" / "drafts" / "cand-01.en.md").read_text(encoding="utf-8")
    assert "## Known-Issue Checkpoints & Preconditions" in en_md
    assert "PR-205" in en_md

    # Verify list-vdp-candidates & describe_run metrics
    rc_list = admin_main(
        [
            "list-vdp-candidates",
            "--db-path",
            str(db_path),
            "--vault-root",
            str(vault_root),
            "--run-id",
            run_id,
        ],
        env=cli_env,
    )
    assert rc_list == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed["external_search_performed_by_harness"] is False
    assert listed["auto_promoted_to_confirmed_vulnerability"] is False
    assert len(listed["candidates"]) == 1
    assert listed["metrics"]["total_candidates"] == 1
    assert listed["metrics"]["maintainer_triage_preempted"] is False
    assert listed["metrics"]["time_to_first_candidate_seconds"] == 0.0

    described = ctrl.describe_run(principal=principal, run_id=run_id)
    assert len(described["vdp_candidate_checkpoints"]) == 1
    assert described["vdp_candidate_metrics"]["auto_confirmed_vulnerability_count"] == 0
    assert described["vdp_candidate_metrics"]["maintainer_triage_preempted"] is False


def test_zero_hits_never_auto_claims_no_duplicate_and_propagates_limitation(tmp_path: Path) -> None:
    _, vault_root, ctrl = _seed_controller(tmp_path)
    principal = _make_principal()
    run_id = "run-pr-c-zero-hits"
    ctrl.create_run(
        principal=principal,
        run_id=run_id,
        task_id="task-pr-c-zero",
        mode=RunMode.VDP,
        scope=_make_scope(task_id="task-pr-c-zero"),
        budget=BudgetSpec(run_budget_seconds=300, max_tool_calls=20, max_evidence_bytes_per_run=5_000_000),
    )
    ev_id = _seed_manual_evidence(ctrl, principal=principal, run_id=run_id, obs_id="obs-zero-01")

    now = datetime.now(UTC)
    pre_heavy_zero = KnownIssueCheckpoint(
        gate="pre_heavy_test",
        checked_at=now - timedelta(hours=1),
        checked_by="researcher-z",
        search_source="external_github_connector",
        search_queries=("unique_internal_endpoint_keyword",),
        references_reviewed=(),
        zero_hits_observed=True,
        duplicate_disposition="proceed_unconfirmed_candidate",
    )
    assert pre_heavy_zero.no_duplicate_claimed is False
    assert pre_heavy_zero.zero_hits_disclaimer == ZERO_HITS_DISCLAIMER

    pre_sub_zero = KnownIssueCheckpoint(
        gate="pre_submission",
        checked_at=now - timedelta(minutes=5),
        checked_by="researcher-z",
        search_source="manual_repo_search",
        search_queries=("unique_internal_endpoint_keyword",),
        references_reviewed=(),
        zero_hits_observed=True,
        duplicate_disposition="proceed_unconfirmed_candidate",
    )

    preconditions = _default_preconditions(creator="unknown", prevalence="unverified", basis_refs=())
    ctrl.record_vdp_candidate_checkpoint(
        principal=principal,
        run_id=run_id,
        candidate_id="CAND-ZERO-01",
        title="Candidate with zero external search matches",
        target_name="synthetic-app",
        target_version="2026.11.2",
        pinned_source_commit=SYNTH_COMMIT,
        preconditions=preconditions,
        checkpoint=pre_heavy_zero,
    )
    rec = ctrl.record_vdp_candidate_checkpoint(
        principal=principal,
        run_id=run_id,
        candidate_id="CAND-ZERO-01",
        title="Candidate with zero external search matches",
        target_name="synthetic-app",
        target_version="2026.11.2",
        pinned_source_commit=SYNTH_COMMIT,
        preconditions=preconditions,
        checkpoint=pre_sub_zero,
    )
    gate_eval = evaluate_candidate_gate(rec, gate="pre_submission", now=now)
    assert gate_eval.ready is True
    assert ZERO_HITS_DISCLAIMER in gate_eval.warnings
    assert "real_world_prevalence_unverified" in gate_eval.warnings
    assert "preconfig_creator_unknown" in gate_eval.warnings
    assert "precondition_basis_refs_missing" in gate_eval.warnings

    res = ctrl.export_vdp_submission_draft(
        principal=principal,
        run_id=run_id,
        draft=VdpDraftSpec(
            finding_id="FIND-ZERO-01",
            candidate_id="CAND-ZERO-01",
            title="Zero-hits candidate draft",
            target_name="synthetic-app",
            affected_version="2026.11.2",
            pinned_source_commit=SYNTH_COMMIT,
            location="app/endpoints.py:12",
            preconditions="Unknown creator.",
            observation="Synthetic behavior observed.",
            reproduction_steps=["Run synthetic reproduction."],
            impact_hypothesis="Bounded impact.",
            impact_boundaries=["Limited to synthetic setup."],
            severity_assessment="Informative pending human review",
            evidence_ids=(ev_id,),
            ai_disclosure=VdpAiDisclosure(
                client_model_label="Codex",
                assistance_scope="Drafting",
                human_reviewed_by="operator",
            ),
        ),
        language="en",
    )
    assert ZERO_HITS_DISCLAIMER in res.markdown
    assert "real_world_prevalence_unverified" in res.markdown
    assert "zero hits do not prove no duplicate" in res.markdown

    # Inconsistent zero_hits_observed or attempts to force no_duplicate_claimed=True fail closed
    with pytest.raises(ContractViolationError, match="zero_hits_observed"):
        KnownIssueCheckpoint(
            gate="pre_heavy_test",
            checked_at=now,
            checked_by="researcher-z",
            search_source="external_github_connector",
            search_queries=("q1",),
            references_reviewed=(),
            zero_hits_observed=False,
            duplicate_disposition="proceed_unconfirmed_candidate",
        )
    with pytest.raises((ValidationError, ValueError)):
        KnownIssueCheckpoint(
            gate="pre_heavy_test",
            checked_at=now,
            checked_by="researcher-z",
            search_source="external_github_connector",
            search_queries=("q1",),
            references_reviewed=(),
            zero_hits_observed=True,
            no_duplicate_claimed=True,  # type: ignore[arg-type]
            duplicate_disposition="proceed_unconfirmed_candidate",
        )


def test_duplicate_or_fixed_issue_blocks_candidate_and_prevents_proceed_contradiction(tmp_path: Path) -> None:
    _, _, ctrl = _seed_controller(tmp_path)
    principal = _make_principal()
    run_id = "run-pr-c-blocked"
    ctrl.create_run(
        principal=principal,
        run_id=run_id,
        task_id="task-pr-c-blocked",
        mode=RunMode.VDP,
        scope=_make_scope(task_id="task-pr-c-blocked"),
        budget=BudgetSpec(run_budget_seconds=300, max_tool_calls=20, max_evidence_bytes_per_run=5_000_000),
    )
    ev_id = _seed_manual_evidence(ctrl, principal=principal, run_id=run_id, obs_id="obs-dup-01")

    now = datetime.now(UTC)
    same_cause_ref = KnownIssueReference(
        ref_url="https://example.invalid/org/repo/issues/999",
        ref_kind="issue",
        ref_id="ISSUE-999",
        target_version_relation="fixed_in_pinned_version",
        same_root_cause_judgment="same_cause_and_impact",
        human_rationale="Public upstream issue #999 fixed exact root cause before release.",
    )
    with pytest.raises(ContractViolationError, match="same_cause_and_impact"):
        KnownIssueCheckpoint(
            gate="pre_heavy_test",
            checked_at=now,
            checked_by="researcher-b",
            search_source="external_github_connector",
            search_queries=("redirect leak",),
            references_reviewed=(same_cause_ref,),
            zero_hits_observed=False,
            duplicate_disposition="proceed_unconfirmed_candidate",
        )

    blocked_cp = KnownIssueCheckpoint(
        gate="pre_heavy_test",
        checked_at=now,
        checked_by="researcher-b",
        search_source="external_github_connector",
        search_queries=("redirect leak",),
        references_reviewed=(same_cause_ref,),
        zero_hits_observed=False,
        duplicate_disposition="blocked_already_fixed",
    )
    rec = ctrl.record_vdp_candidate_checkpoint(
        principal=principal,
        run_id=run_id,
        candidate_id="CAND-DUP-01",
        title="Already fixed candidate",
        target_name="synthetic-app",
        target_version="2026.11.2",
        pinned_source_commit=SYNTH_COMMIT,
        preconditions=_default_preconditions(),
        checkpoint=blocked_cp,
    )
    assert rec.status == "blocked_known_issue"
    gate_eval = evaluate_candidate_gate(rec, gate="pre_heavy_test", now=now)
    assert gate_eval.ready is False
    assert gate_eval.blocked_reason == "candidate_blocked_known_issue"

    with pytest.raises(ContractViolationError, match="blocked"):
        ctrl.export_vdp_submission_draft(
            principal=principal,
            run_id=run_id,
            draft=VdpDraftSpec(
                finding_id="FIND-DUP-01",
                candidate_id="CAND-DUP-01",
                title="Blocked duplicate draft",
                target_name="synthetic-app",
                affected_version="2026.11.2",
                pinned_source_commit=SYNTH_COMMIT,
                location="app/views.py:10",
                preconditions="Linked component.",
                observation="Synthetic behavior.",
                reproduction_steps=["Step 1."],
                impact_hypothesis="Limited.",
                impact_boundaries=["Bounded."],
                evidence_ids=(ev_id,),
                ai_disclosure=VdpAiDisclosure(
                    client_model_label="Codex",
                    assistance_scope="Drafting",
                    human_reviewed_by="operator",
                ),
            ),
        )


def test_stale_and_skipped_gates_require_recheck_and_block_draft(tmp_path: Path) -> None:
    _, _, ctrl = _seed_controller(tmp_path)
    principal = _make_principal()
    run_id = "run-pr-c-stale"
    ctrl.create_run(
        principal=principal,
        run_id=run_id,
        task_id="task-pr-c-stale",
        mode=RunMode.VDP,
        scope=_make_scope(task_id="task-pr-c-stale"),
        budget=BudgetSpec(run_budget_seconds=300, max_tool_calls=20, max_evidence_bytes_per_run=5_000_000),
    )
    ev_id = _seed_manual_evidence(ctrl, principal=principal, run_id=run_id, obs_id="obs-stale-01")
    now = datetime.now(UTC)

    # Skipped pre_heavy_test gate + only pre_submission cannot satisfy pre_submission gate
    stale_sub_cp = KnownIssueCheckpoint(
        gate="pre_submission",
        checked_at=now - timedelta(hours=30),
        checked_by="researcher-c",
        search_source="external_github_connector",
        search_queries=("q1",),
        references_reviewed=(),
        zero_hits_observed=True,
        duplicate_disposition="proceed_unconfirmed_candidate",
        max_age_hours=24,
    )
    rec_skipped = ctrl.record_vdp_candidate_checkpoint(
        principal=principal,
        run_id=run_id,
        candidate_id="CAND-STALE-01",
        title="Skipped pre_heavy and expired pre_submission",
        target_name="synthetic-app",
        target_version="2026.11.2",
        pinned_source_commit=SYNTH_COMMIT,
        preconditions=_default_preconditions(),
        checkpoint=stale_sub_cp,
    )
    eval_skipped = evaluate_candidate_gate(rec_skipped, gate="pre_submission", now=now)
    assert eval_skipped.ready is False
    assert eval_skipped.stale_recheck_required is True
    assert eval_skipped.recheck_prompt is not None
    assert "pre_heavy_test_checkpoint" in eval_skipped.missing_items

    # Even after filling pre_heavy_test, expired pre_submission still prompts recheck and blocks draft
    ctrl.record_vdp_candidate_checkpoint(
        principal=principal,
        run_id=run_id,
        candidate_id="CAND-STALE-01",
        title="Skipped pre_heavy and expired pre_submission",
        target_name="synthetic-app",
        target_version="2026.11.2",
        pinned_source_commit=SYNTH_COMMIT,
        preconditions=_default_preconditions(),
        checkpoint=KnownIssueCheckpoint(
            gate="pre_heavy_test",
            checked_at=now - timedelta(hours=40),
            checked_by="researcher-c",
            search_source="external_github_connector",
            search_queries=("q1",),
            references_reviewed=(),
            zero_hits_observed=True,
            duplicate_disposition="proceed_unconfirmed_candidate",
            max_age_hours=72,
        ),
    )
    gate_stale = ctrl.evaluate_vdp_candidate_gate(
        principal=principal,
        run_id=run_id,
        candidate_id="CAND-STALE-01",
        gate="pre_submission",
    )
    assert gate_stale.ready is False
    assert gate_stale.stale_recheck_required is True
    assert gate_stale.recheck_prompt is not None and "stale" in gate_stale.recheck_prompt

    with pytest.raises(ContractViolationError, match="stale"):
        ctrl.export_vdp_submission_draft(
            principal=principal,
            run_id=run_id,
            draft=VdpDraftSpec(
                finding_id="FIND-STALE-01",
                candidate_id="CAND-STALE-01",
                title="Stale draft attempt",
                target_name="synthetic-app",
                affected_version="2026.11.2",
                pinned_source_commit=SYNTH_COMMIT,
                location="app/views.py:99",
                preconditions="Linked.",
                observation="Observed.",
                reproduction_steps=["Step 1."],
                impact_hypothesis="Bounded.",
                impact_boundaries=["Limited."],
                evidence_ids=(ev_id,),
                ai_disclosure=VdpAiDisclosure(
                    client_model_label="Codex",
                    assistance_scope="Drafting",
                    human_reviewed_by="operator",
                ),
            ),
        )

    # Refreshing pre_submission unblocks the gate
    ctrl.record_vdp_candidate_checkpoint(
        principal=principal,
        run_id=run_id,
        candidate_id="CAND-STALE-01",
        title="Refreshed candidate",
        target_name="synthetic-app",
        target_version="2026.11.2",
        pinned_source_commit=SYNTH_COMMIT,
        preconditions=_default_preconditions(),
        checkpoint=KnownIssueCheckpoint(
            gate="pre_submission",
            checked_at=now - timedelta(minutes=2),
            checked_by="researcher-c",
            search_source="external_github_connector",
            search_queries=("q1", "recent PRs"),
            references_reviewed=(),
            zero_hits_observed=True,
            duplicate_disposition="proceed_unconfirmed_candidate",
            max_age_hours=24,
        ),
        status="ready_for_human_draft_review",
    )
    refreshed = ctrl.evaluate_vdp_candidate_gate(
        principal=principal,
        run_id=run_id,
        candidate_id="CAND-STALE-01",
        gate="pre_submission",
    )
    assert refreshed.ready is True
    assert refreshed.stale_recheck_required is False

    # Backward compatibility: exporting draft without candidate_id still works directly
    legacy_res = ctrl.export_vdp_submission_draft(
        principal=principal,
        run_id=run_id,
        draft=VdpDraftSpec(
            finding_id="FIND-LEGACY-01",
            title="Legacy draft without candidate_id",
            target_name="synthetic-app",
            affected_version="2026.11.2",
            pinned_source_commit=SYNTH_COMMIT,
            location="app/views.py:1",
            preconditions="Owner setup.",
            observation="Synthetic observation.",
            reproduction_steps=["Run test."],
            impact_hypothesis="Low.",
            impact_boundaries=["Isolated fixture."],
            evidence_ids=(ev_id,),
            ai_disclosure=VdpAiDisclosure(
                client_model_label="Codex",
                assistance_scope="Drafting",
                human_reviewed_by="operator",
            ),
        ),
        language="en",
    )
    assert legacy_res.submission_record.candidate_id is None


def test_negative_security_anti_promotion_closed_run_and_diagnostics(tmp_path: Path) -> None:
    db_path, vault_root, ctrl = _seed_controller(tmp_path)
    principal = _make_principal()
    vdp_run = "run-pr-c-vdp"
    ctf_run = "run-pr-c-ctf"
    ctrl.create_run(
        principal=principal,
        run_id=vdp_run,
        task_id="task-vdp",
        mode=RunMode.VDP,
        scope=_make_scope(mode=RunMode.VDP, task_id="task-vdp"),
        budget=BudgetSpec(run_budget_seconds=300, max_tool_calls=20, max_evidence_bytes_per_run=5_000_000),
    )
    ctrl.create_run(
        principal=principal,
        run_id=ctf_run,
        task_id="task-ctf",
        mode=RunMode.OFFLINE_CTF,
        scope=_make_scope(mode=RunMode.OFFLINE_CTF, task_id="task-ctf", scope_revision="scope-ctf-1"),
        budget=BudgetSpec(run_budget_seconds=300, max_tool_calls=20, max_evidence_bytes_per_run=5_000_000),
    )

    now = datetime.now(UTC)

    # Anti-auto-promotion: invalid status or flags rejected
    with pytest.raises((ValidationError, ValueError)):
        VdpCandidateCheckpointRecord(
            candidate_id="CAND-BAD-STATUS",
            run_id=vdp_run,
            title="Attempted auto promotion",
            target_name="synthetic-app",
            target_version="2026.11.2",
            pinned_source_commit=SYNTH_COMMIT,
            status="confirmed_vulnerability",  # type: ignore[arg-type]
            preconditions=_default_preconditions(),
            created_at=now,
            updated_at=now,
        )
    with pytest.raises((ValidationError, ValueError)):
        VdpCandidateCheckpointRecord(
            candidate_id="CAND-BAD-PROMO",
            run_id=vdp_run,
            title="Attempted promo flag",
            target_name="synthetic-app",
            target_version="2026.11.2",
            pinned_source_commit=SYNTH_COMMIT,
            auto_promoted_to_confirmed_vulnerability=True,  # type: ignore[arg-type]
            preconditions=_default_preconditions(),
            created_at=now,
            updated_at=now,
        )

    # Sensitive marker & credential URL rejections
    with pytest.raises(ContractViolationError, match="credentials"):
        KnownIssueReference(
            ref_url="https://user:pass@example.invalid/issues/1",
            ref_kind="issue",
            ref_id="ISSUE-1",
            target_version_relation="different_component",
            same_root_cause_judgment="different_cause_or_impact",
            human_rationale="Credentialed URL must be rejected.",
        )
    with pytest.raises(ContractViolationError, match="sensitive"):
        CandidatePreconditions(
            preconfig_created_by="owner_or_admin",
            attacker_controls="Authorization: Bearer synthetic_leaked_secret_token_value_123456",
            real_world_prevalence="common",
            observed_impact_cap="None",
        )

    # Non-VDP run rejected
    with pytest.raises(ScopeDeniedError):
        ctrl.record_vdp_candidate_checkpoint(
            principal=principal,
            run_id=ctf_run,
            candidate_id="CAND-CTF-01",
            title="Not VDP run",
            target_name="synthetic-app",
            target_version="2026.11.2",
            pinned_source_commit=SYNTH_COMMIT,
            preconditions=_default_preconditions(),
        )

    # Premature ready_for_human_draft_review without checkpoints rejected
    with pytest.raises(ContractViolationError, match="ready_for_human_draft_review"):
        ctrl.record_vdp_candidate_checkpoint(
            principal=principal,
            run_id=vdp_run,
            candidate_id="CAND-PREMATURE-01",
            title="Premature status",
            target_name="synthetic-app",
            target_version="2026.11.2",
            pinned_source_commit=SYNTH_COMMIT,
            preconditions=_default_preconditions(),
            status="ready_for_human_draft_review",
        )

    # Nonexistent / cross-run evidence_id rejected
    with pytest.raises(EvidenceNotFoundError):
        ctrl.record_vdp_candidate_checkpoint(
            principal=principal,
            run_id=vdp_run,
            candidate_id="CAND-NOEV-01",
            title="Missing evidence",
            target_name="synthetic-app",
            target_version="2026.11.2",
            pinned_source_commit=SYNTH_COMMIT,
            preconditions=_default_preconditions(),
            evidence_ids=("ev-does-not-exist",),
        )

    vdp_run_2 = "run-pr-c-vdp-2"
    ctrl.create_run(
        principal=principal,
        run_id=vdp_run_2,
        task_id="task-vdp-2",
        mode=RunMode.VDP,
        scope=_make_scope(mode=RunMode.VDP, task_id="task-vdp-2", scope_revision="scope-v2"),
        budget=BudgetSpec(run_budget_seconds=300, max_tool_calls=20, max_evidence_bytes_per_run=5_000_000),
    )
    other_ev = _seed_manual_evidence(ctrl, principal=principal, run_id=vdp_run_2, obs_id="obs-other-01")
    with pytest.raises(EvidenceAccessDeniedError):
        ctrl.record_vdp_candidate_checkpoint(
            principal=principal,
            run_id=vdp_run,
            candidate_id="CAND-CROSS-01",
            title="Cross-run evidence",
            target_name="synthetic-app",
            target_version="2026.11.2",
            pinned_source_commit=SYNTH_COMMIT,
            preconditions=_default_preconditions(),
            evidence_ids=(other_ev,),
        )

    # Symlink & oversized JSON rejected via CLI
    real_json = tmp_path / "real_cand.json"
    real_json.write_text("{}", encoding="utf-8")
    symlink_json = tmp_path / "link_cand.json"
    symlink_json.symlink_to(real_json)
    rc_sym = admin_main(
        [
            "record-vdp-candidate",
            "--db-path",
            str(db_path),
            "--vault-root",
            str(vault_root),
            "--run-id",
            vdp_run,
            "--candidate-json",
            str(symlink_json),
        ],
        env={"CTF_MCP_CURSOR_HMAC_KEY": HMAC_SECRET, "CTF_MCP_ALLOW_DYNAMIC": "1", "CTF_MCP_PROFILE": "vdp"},
    )
    assert rc_sym == 2

    oversized_json = tmp_path / "big_cand.json"
    oversized_json.write_text("{" + (" " * (MAX_CANDIDATE_JSON_BYTES + 100)) + "}", encoding="utf-8")
    rc_big = admin_main(
        [
            "record-vdp-candidate",
            "--db-path",
            str(db_path),
            "--vault-root",
            str(vault_root),
            "--run-id",
            vdp_run,
            "--candidate-json",
            str(oversized_json),
        ],
        env={"CTF_MCP_CURSOR_HMAC_KEY": HMAC_SECRET, "CTF_MCP_ALLOW_DYNAMIC": "1", "CTF_MCP_PROFILE": "vdp"},
    )
    assert rc_big == 2

    # Closed run rejected
    ctrl.close_run(principal=principal, run_id=vdp_run)
    with pytest.raises(ScopeDeniedError, match="closed"):
        ctrl.record_vdp_candidate_checkpoint(
            principal=principal,
            run_id=vdp_run,
            candidate_id="CAND-CLOSED-01",
            title="Closed run attempt",
            target_name="synthetic-app",
            target_version="2026.11.2",
            pinned_source_commit=SYNTH_COMMIT,
            preconditions=_default_preconditions(),
        )

    # Diagnostics surfaces new CLI commands cleanly without altering MCP schema parity
    diag = collect_mcp_diagnostics(
        env={
            "CTF_MCP_DB_PATH": str(db_path),
            "CTF_MCP_VAULT_ROOT": str(vault_root),
            "CTF_MCP_CURSOR_HMAC_KEY": HMAC_SECRET,
            "CTF_MCP_ALLOW_DYNAMIC": "1",
            "CTF_MCP_PROFILE": "vdp",
        },
        active_run_id=vdp_run_2,
        check_docker=False,
    )
    assert diag["healthy"] is True
    cli_cmds = set(diag["surface_summary"]["cli_admin_only_commands"])
    assert {"record-vdp-candidate", "check-vdp-candidate-gate", "list-vdp-candidates"}.issubset(cli_cmds)


def test_candidate_cross_run_isolation_needs_recheck_and_draft_mismatch(tmp_path: Path) -> None:
    _, _, ctrl = _seed_controller(tmp_path)
    principal = _make_principal()
    run_a = "run-pr-c-iso-a"
    run_b = "run-pr-c-iso-b"
    ctrl.create_run(
        principal=principal,
        run_id=run_a,
        task_id="task-a",
        mode=RunMode.VDP,
        scope=_make_scope(task_id="task-a", scope_revision="scope-a"),
        budget=BudgetSpec(run_budget_seconds=300, max_tool_calls=20, max_evidence_bytes_per_run=5_000_000),
    )
    ctrl.create_run(
        principal=principal,
        run_id=run_b,
        task_id="task-b",
        mode=RunMode.VDP,
        scope=_make_scope(task_id="task-b", scope_revision="scope-b"),
        budget=BudgetSpec(run_budget_seconds=300, max_tool_calls=20, max_evidence_bytes_per_run=5_000_000),
    )
    ev_a = _seed_manual_evidence(ctrl, principal=principal, run_id=run_a, obs_id="obs-iso-a")
    now = datetime.now(UTC)

    # Timestamp ordering reversal (pre_submission older than pre_heavy_test) triggers recheck
    ctrl.record_vdp_candidate_checkpoint(
        principal=principal,
        run_id=run_a,
        candidate_id="SHARED-ID-01",
        title="Candidate in run A",
        target_name="synthetic-app",
        target_version="2026.11.2",
        pinned_source_commit=SYNTH_COMMIT,
        preconditions=_default_preconditions(),
        checkpoint=KnownIssueCheckpoint(
            gate="pre_heavy_test",
            checked_at=now - timedelta(minutes=10),
            checked_by="researcher-a",
            search_source="external_github_connector",
            search_queries=("q1",),
            references_reviewed=(),
            zero_hits_observed=True,
            duplicate_disposition="proceed_unconfirmed_candidate",
        ),
    )
    rec_reversed = ctrl.record_vdp_candidate_checkpoint(
        principal=principal,
        run_id=run_a,
        candidate_id="SHARED-ID-01",
        title="Candidate in run A",
        target_name="synthetic-app",
        target_version="2026.11.2",
        pinned_source_commit=SYNTH_COMMIT,
        preconditions=_default_preconditions(),
        checkpoint=KnownIssueCheckpoint(
            gate="pre_submission",
            checked_at=now - timedelta(hours=2),
            checked_by="researcher-a",
            search_source="external_github_connector",
            search_queries=("q1",),
            references_reviewed=(),
            zero_hits_observed=True,
            duplicate_disposition="proceed_unconfirmed_candidate",
        ),
    )
    ev_rev = evaluate_candidate_gate(rec_reversed, gate="pre_submission", now=now)
    assert ev_rev.ready is False
    assert ev_rev.stale_recheck_required is True
    assert "pre_submission_older_than_pre_heavy_test" in ev_rev.warnings

    # Same candidate_id in run_b stays completely isolated with needs_recheck disposition
    rec_b = ctrl.record_vdp_candidate_checkpoint(
        principal=principal,
        run_id=run_b,
        candidate_id="SHARED-ID-01",
        title="Candidate in run B",
        target_name="other-synthetic-app",
        target_version="2026.11.2",
        pinned_source_commit="1" * 40,
        preconditions=_default_preconditions(),
        checkpoint=KnownIssueCheckpoint(
            gate="pre_heavy_test",
            checked_at=now - timedelta(minutes=5),
            checked_by="researcher-b",
            search_source="external_github_connector",
            search_queries=("q2",),
            references_reviewed=(),
            zero_hits_observed=True,
            duplicate_disposition="needs_recheck",
        ),
    )
    ev_b = evaluate_candidate_gate(rec_b, gate="pre_heavy_test", now=now)
    assert ev_b.ready is False
    assert ev_b.stale_recheck_required is True
    assert len(ctrl.list_vdp_candidate_checkpoints(principal=principal, run_id=run_a)) == 1
    assert len(ctrl.list_vdp_candidate_checkpoints(principal=principal, run_id=run_b)) == 1

    # Draft target_name mismatch & unknown candidate_id rejected cleanly
    ctrl.record_vdp_candidate_checkpoint(
        principal=principal,
        run_id=run_a,
        candidate_id="SHARED-ID-01",
        title="Candidate in run A",
        target_name="synthetic-app",
        target_version="2026.11.2",
        pinned_source_commit=SYNTH_COMMIT,
        preconditions=_default_preconditions(),
        checkpoint=KnownIssueCheckpoint(
            gate="pre_submission",
            checked_at=now - timedelta(minutes=1),
            checked_by="researcher-a",
            search_source="external_github_connector",
            search_queries=("q1",),
            references_reviewed=(),
            zero_hits_observed=True,
            duplicate_disposition="proceed_unconfirmed_candidate",
        ),
    )
    with pytest.raises(ContractViolationError, match="target_name"):
        ctrl.export_vdp_submission_draft(
            principal=principal,
            run_id=run_a,
            draft=VdpDraftSpec(
                finding_id="FIND-MISMATCH-01",
                candidate_id="SHARED-ID-01",
                title="Mismatched target",
                target_name="wrong-target",
                affected_version="2026.11.2",
                pinned_source_commit=SYNTH_COMMIT,
                location="app/views.py:5",
                preconditions="Owner setup.",
                observation="Synthetic observation.",
                reproduction_steps=["Step 1."],
                impact_hypothesis="Bounded.",
                impact_boundaries=["Limited."],
                evidence_ids=(ev_a,),
                ai_disclosure=VdpAiDisclosure(
                    client_model_label="Codex",
                    assistance_scope="Drafting",
                    human_reviewed_by="operator",
                ),
            ),
        )
    with pytest.raises(EvidenceNotFoundError):
        ctrl.export_vdp_submission_draft(
            principal=principal,
            run_id=run_a,
            draft=VdpDraftSpec(
                finding_id="FIND-MISSING-CAND",
                candidate_id="UNKNOWN-CAND-99",
                title="Unknown candidate",
                target_name="synthetic-app",
                affected_version="2026.11.2",
                pinned_source_commit=SYNTH_COMMIT,
                location="app/views.py:5",
                preconditions="Owner setup.",
                observation="Synthetic observation.",
                reproduction_steps=["Step 1."],
                impact_hypothesis="Bounded.",
                impact_boundaries=["Limited."],
                evidence_ids=(ev_a,),
                ai_disclosure=VdpAiDisclosure(
                    client_model_label="Codex",
                    assistance_scope="Drafting",
                    human_reviewed_by="operator",
                ),
            ),
        )
