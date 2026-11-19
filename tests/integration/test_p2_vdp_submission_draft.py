"""Integration tests for P2 human-reviewed VDP submission drafts and manual status recording."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ctf_mcp.adapters.vdp_product_test import WEBLATE_2026_11_2_IMAGE_DIGEST, WEBLATE_2026_11_2_SOURCE_COMMIT
from ctf_mcp.cli import admin_main
from ctf_mcp.contracts import (
    BudgetSpec,
    ContractViolationError,
    ExecutionClass,
    FindingState,
    PrincipalContext,
    RunMode,
    ScopePolicy,
    canonical_digest,
    sha256_bytes,
)
from ctf_mcp.controller import create_default_controller
from ctf_mcp.evidence.manual_observation import (
    ManualCleanupConfirmation,
    ManualControlRecord,
    ManualIsolationDeclaration,
    ManualObservationRecord,
)
from ctf_mcp.evidence.vdp_submission import validate_report_url
from ctf_mcp.storage import Storage


def _make_principal() -> PrincipalContext:
    return PrincipalContext(
        principal_id="local-operator",
        auth_method="stdio_local",
        client_kind="OPERATOR_SELECTED",
        model_label="p2-submission-test",
    )


def _make_scope() -> ScopePolicy:
    now = datetime.now(UTC)
    payload = {
        "mode": "vdp",
        "task_id": "task-p2-sub",
        "scope_revision": "scope-p2-sub-v1",
        "authorization_reference": "owned-p2-sub",
        "allowed_capabilities": ["analysis.query", "vdp.test"],
        "allowed_execution_classes": ["static", "dynamic"],
        "expires_at": (now + timedelta(hours=2)).isoformat(),
        "network_enabled": False,
        "allowed_targets": [],
        "external_submission": False,
    }
    return ScopePolicy(
        scope_revision="scope-p2-sub-v1",
        scope_sha256=canonical_digest(payload),
        mode=RunMode.VDP,
        task_id="task-p2-sub",
        authorization_reference="owned-p2-sub",
        allowed_execution_classes=(ExecutionClass.STATIC, ExecutionClass.DYNAMIC),
        allowed_capabilities=("analysis.query", "vdp.test"),
        expires_at=now + timedelta(hours=2),
        network_enabled=False,
        allowed_targets=(),
        external_submission=False,
    )


def test_export_draft_provenance_separation_and_manual_submission_tracking(tmp_path: Path, capsys) -> None:
    db_path = tmp_path / "harness.db"
    vault_root = tmp_path / "vault"
    storage = Storage(db_path)
    ctrl = create_default_controller(
        storage=storage,
        vault_root=vault_root,
        export_root=vault_root / "_exports",
        cursor_hmac_key=b"s" * 32,
        allow_dynamic=True,
        include_vdp_product_test=True,
        initialize=True,
    )
    principal = _make_principal()
    run_id = "run-p2-draft-01"
    ctrl.create_run(
        principal=principal,
        run_id=run_id,
        task_id="task-p2-sub",
        mode=RunMode.VDP,
        scope=_make_scope(),
        budget=BudgetSpec(run_budget_seconds=300, max_tool_calls=20, max_evidence_bytes_per_run=10_000_000),
    )

    obs_receipt = ctrl.import_manual_observation(
        principal=principal,
        run_id=run_id,
        observation=ManualObservationRecord(
            observation_id="obs-g01-01",
            observed_at=datetime.now(UTC),
            target_name="weblate",
            target_version="2026.11.2",
            pinned_source_commit=WEBLATE_2026_11_2_SOURCE_COMMIT,
            pinned_image_digests={"scanner": WEBLATE_2026_11_2_IMAGE_DIGEST},
            environment_summary="Temporary isolated PostgreSQL + internal network.",
            isolation_declared=ManualIsolationDeclaration(
                synthetic_data_only=True,
                external_egress_blocked=True,
                published_ports_none=True,
                network_description="docker internal bridge",
            ),
            test_code_hashes={"g01_repro.py": "a" * 64},
            execution_summary="Public child git URL returned 301 Location leaking private parent slug; private git 401; web 404.",
            exit_code=0,
            controls=(
                ManualControlRecord(
                    control_name="public_child_200",
                    role="positive_control",
                    outcome="passed",
                    summary="Public component git endpoint served normally.",
                ),
                ManualControlRecord(
                    control_name="private_git_401",
                    role="defense_check",
                    outcome="passed",
                    summary="Direct private git access rejected with 401.",
                ),
            ),
            cleanup_confirmation=ManualCleanupConfirmation(
                containers_removed=True,
                databases_removed=True,
                networks_removed=True,
                confirmed_by="operator",
                confirmed_at=datetime.now(UTC),
                verification_note="Cleaned up synthetic DB, container, and network.",
            ),
        ),
    )

    draft_spec = {
        "finding_id": "G-01-SYNTH",
        "title": "Public linked child git redirect exposes private parent slug in Location",
        "target_name": "weblate",
        "affected_version": "2026.11.2",
        "pinned_source_commit": WEBLATE_2026_11_2_SOURCE_COMMIT,
        "location": "weblate/vcs/views.py",
        "preconditions": "Public child component linked to a private parent component.",
        "observation": "Anonymous GET to public child git URL returned 301 with private project/component slug in Location.",
        "reproduction_steps": [
            "Provision synthetic private parent and linked public child component.",
            "Issue unauthenticated GET to public child git info/refs endpoint and observe 301 Location.",
            "Confirm direct private git access returns 401 and web/API returns 404.",
        ],
        "impact_hypothesis": "Discloses private project and component identifiers (no content or credentials).",
        "impact_boundaries": [
            "Private git object download returned 401.",
            "Private web/API endpoints returned 404.",
        ],
        "unverified_conditions": [
            "Hosted deployment behavior not tested directly.",
        ],
        "severity_assessment": "Low 3.7 (operator-submitted reference)",
        "evidence_ids": [obs_receipt.evidence_id],
        "ai_disclosure": {
            "ai_used": True,
            "client_model_label": "Codex / Antigravity",
            "assistance_scope": "Synthesized test harness and drafted structured summary.",
            "human_reviewed_by": "operator",
            "human_review_confirmed": True,
        },
        "duplicate_check_note": "Checked against W-03 and Weblate issue #22886.",
    }
    draft_json_path = tmp_path / "draft_spec.json"
    draft_json_path.write_text(json.dumps(draft_spec, indent=2), encoding="utf-8")

    # Export Japanese draft via CLI
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
            str(draft_json_path),
            "--language",
            "ja",
            "--output-relpath",
            "drafts/g01-draft.ja.md",
        ],
        env={"CTF_MCP_CURSOR_HMAC_KEY": "s" * 32, "CTF_MCP_ALLOW_DYNAMIC": "1"},
    )
    assert rc_ja == 0
    ja_out = json.loads(capsys.readouterr().out)
    assert ja_out["state"] == FindingState.REPORT_READY.value
    assert ja_out["automatic_submission"] is False

    ja_md = (vault_root / "_exports" / "drafts" / "g01-draft.ja.md").read_text(encoding="utf-8")
    assert "自動提出：`disabled`" in ja_md
    assert "手動・隔離環境での観測" in ja_md
    assert "成功・失敗した対照試験" in ja_md
    assert "AI利用の開示" in ja_md
    assert "not_executed_via_harness_vdp_test" in ja_md

    # Export English draft via CLI
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
            str(draft_json_path),
            "--language",
            "en",
            "--output-relpath",
            "drafts/g01-draft.en.md",
        ],
        env={"CTF_MCP_CURSOR_HMAC_KEY": "s" * 32, "CTF_MCP_ALLOW_DYNAMIC": "1"},
    )
    assert rc_en == 0
    _ = json.loads(capsys.readouterr().out)
    en_md = (vault_root / "_exports" / "drafts" / "g01-draft.en.md").read_text(encoding="utf-8")
    assert "manual isolated observation (`vdp.product_test` NOT verified)" in en_md
    assert "Automatic submission: `disabled`" in en_md

    # Record manual external submission via CLI
    rc_rec = admin_main(
        [
            "record-vdp-submission",
            "--db-path",
            str(db_path),
            "--vault-root",
            str(vault_root),
            "--run-id",
            run_id,
            "--finding-id",
            "G-01-SYNTH",
            "--status",
            "submitted",
            "--report-url",
            "https://example.invalid/reports/4216840",
            "--recorded-by",
            "owner",
            "--report-ref",
            "H1-4216840",
            "--triage-status",
            "unconfirmed",
            "--note",
            "Manually submitted by owner after review.",
        ],
        env={"CTF_MCP_CURSOR_HMAC_KEY": "s" * 32, "CTF_MCP_ALLOW_DYNAMIC": "1"},
    )
    assert rc_rec == 0
    rec_out = json.loads(capsys.readouterr().out)
    assert rec_out["state"] == "submitted"
    assert rec_out["automatic_submission"] is False
    assert rec_out["report_url"] == "https://example.invalid/reports/4216840"
    assert rec_out["report_ref"] == "H1-4216840"

    # List via CLI & check run.describe
    rc_list = admin_main(
        [
            "list-vdp-submissions",
            "--db-path",
            str(db_path),
            "--vault-root",
            str(vault_root),
            "--run-id",
            run_id,
        ],
        env={"CTF_MCP_CURSOR_HMAC_KEY": "s" * 32, "CTF_MCP_ALLOW_DYNAMIC": "1"},
    )
    assert rc_list == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed["automatic_submission"] is False
    assert len(listed["submissions"]) == 1
    assert listed["submissions"][0]["finding_id"] == "G-01-SYNTH"

    described = ctrl.describe_run(principal=principal, run_id=run_id)
    assert len(described["vdp_submissions"]) == 1
    assert described["vdp_submissions"][0]["state"] == "submitted"


def test_validate_report_url_rejects_insecure_and_credentials() -> None:
    assert validate_report_url("https://example.invalid/reports/1") == "https://example.invalid/reports/1"
    with pytest.raises(ContractViolationError, match="https"):
        validate_report_url("http://example.invalid/reports/1")
    with pytest.raises(ContractViolationError, match="credentials"):
        validate_report_url("https://user:pass@example.invalid/reports/1")
