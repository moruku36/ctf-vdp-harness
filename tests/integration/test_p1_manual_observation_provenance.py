"""Integration tests for out-of-harness manual isolated observation provenance."""

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
    PrincipalContext,
    RunMode,
    ScopePolicy,
    VerificationStatus,
    canonical_digest,
)
from ctf_mcp.controller import create_default_controller
from ctf_mcp.evidence.manual_observation import (
    MANUAL_OBSERVATION_PROVENANCE,
    MANUAL_OBSERVATION_VERIFICATION_TIER,
    NOT_EXECUTED_VIA_HARNESS_CONDITION,
    hash_manual_test_file,
)
from ctf_mcp.storage import Storage
from ctf_mcp.verification.vdp_product_test import VdpProductTestVerifier


def _make_principal() -> PrincipalContext:
    return PrincipalContext(
        principal_id="local-operator",
        auth_method="stdio_local",
        client_kind="OPERATOR_SELECTED",
        model_label="p1-manual-test",
    )


def _make_scope() -> ScopePolicy:
    now = datetime.now(UTC)
    payload = {
        "mode": "vdp",
        "task_id": "task-p1-manual",
        "scope_revision": "scope-p1-manual-v1",
        "authorization_reference": "owned-p1-manual",
        "allowed_capabilities": ["analysis.query", "vdp.test"],
        "allowed_execution_classes": ["static", "dynamic"],
        "expires_at": (now + timedelta(hours=2)).isoformat(),
        "network_enabled": False,
        "allowed_targets": [],
        "external_submission": False,
    }
    return ScopePolicy(
        scope_revision="scope-p1-manual-v1",
        scope_sha256=canonical_digest(payload),
        mode=RunMode.VDP,
        task_id="task-p1-manual",
        authorization_reference="owned-p1-manual",
        allowed_execution_classes=(ExecutionClass.STATIC, ExecutionClass.DYNAMIC),
        allowed_capabilities=("analysis.query", "vdp.test"),
        expires_at=now + timedelta(hours=2),
        network_enabled=False,
        allowed_targets=(),
        external_submission=False,
    )


def test_import_manual_observation_cli_and_reject_verifier_escalation(tmp_path: Path, capsys) -> None:
    db_path = tmp_path / "harness.db"
    vault_root = tmp_path / "vault"
    storage = Storage(db_path)
    ctrl = create_default_controller(
        storage=storage,
        vault_root=vault_root,
        export_root=vault_root / "_exports",
        cursor_hmac_key=b"m" * 32,
        allow_dynamic=True,
        include_vdp_product_test=True,
        initialize=True,
        enable_local_verifier=True,
    )
    principal = _make_principal()
    run_id = "run-p1-manual-01"
    ctrl.create_run(
        principal=principal,
        run_id=run_id,
        task_id="task-p1-manual",
        mode=RunMode.VDP,
        scope=_make_scope(),
        budget=BudgetSpec(run_budget_seconds=300, max_tool_calls=20, max_evidence_bytes_per_run=10_000_000),
    )

    test_script = tmp_path / "verify_g01_manual.py"
    test_script.write_text("# synthetic G-01 manual check\nassert True\n", encoding="utf-8")
    fname, fhash = hash_manual_test_file(test_script)
    assert fname == "verify_g01_manual.py"
    assert len(fhash) == 64

    manifest_path = tmp_path / "manual_obs.json"
    manifest_payload = {
        "schema": "vdp-manual-observation/1",
        "observation_id": "g01-manual-obs-20261119",
        "observed_at": "2026-11-19T05:00:00Z",
        "target_name": "weblate",
        "target_version": "2026.11.2",
        "pinned_source_commit": WEBLATE_2026_11_2_SOURCE_COMMIT,
        "pinned_image_digests": {"scanner": WEBLATE_2026_11_2_IMAGE_DIGEST},
        "environment_summary": "Isolated internal Docker network with temporary PostgreSQL and no external egress.",
        "isolation_declared": {
            "synthetic_data_only": True,
            "external_egress_blocked": True,
            "published_ports_none": True,
            "network_description": "docker network create --internal synthetic-net",
        },
        "test_code_hashes": {},
        "execution_summary": "Public linked child git URL returned 301 Location containing private component slug; direct git 401; web/API 404.",
        "exit_code": 0,
        "controls": [
            {
                "control_name": "public_child_git_200",
                "role": "positive_control",
                "outcome": "passed",
                "summary": "Public component clone metadata served cleanly.",
            },
            {
                "control_name": "private_parent_git_401_web_404",
                "role": "defense_check",
                "outcome": "passed",
                "summary": "Direct private git returned 401 and web/API returned 404 without content/token leak.",
            },
            {
                "control_name": "g01_linked_git_301_location",
                "role": "anomaly_observation",
                "outcome": "observed",
                "summary": "Anonymous git info/refs returned 301 with private project/component slug in Location header.",
            },
        ],
        "impact_boundaries": [
            "Only private project/component slug in 301 Location observed; git objects, translations, and credentials were not disclosed.",
        ],
        "unverified_conditions": [
            "Observed on synthetic PostgreSQL setup outside vdp.product_test.",
        ],
        "cleanup_confirmation": {
            "containers_removed": True,
            "databases_removed": True,
            "networks_removed": True,
            "confirmed_by": "operator",
            "confirmed_at": "2026-11-19T05:05:00Z",
            "verification_note": "Confirmed docker ps -a and docker network ls empty after run.",
        },
    }
    manifest_path.write_text(json.dumps(manifest_payload, indent=2), encoding="utf-8")

    rc = admin_main(
        [
            "import-manual-observation",
            "--db-path",
            str(db_path),
            "--vault-root",
            str(vault_root),
            "--run-id",
            run_id,
            "--manifest-json",
            str(manifest_path),
            "--test-file",
            str(test_script),
        ],
        env={"CTF_MCP_CURSOR_HMAC_KEY": "m" * 32, "CTF_MCP_ALLOW_DYNAMIC": "1"},
    )
    assert rc == 0
    cli_out = json.loads(capsys.readouterr().out)
    assert cli_out["execution_provenance"] == MANUAL_OBSERVATION_PROVENANCE
    assert cli_out["verification_tier"] == MANUAL_OBSERVATION_VERIFICATION_TIER
    assert cli_out["promoted_to_vdp_product_test"] is False
    assert cli_out["test_code_hashes"] == {"verify_g01_manual.py": fhash}

    # Verify describe_run surfaces provenance with zero escalation.
    described = ctrl.describe_run(principal=principal, run_id=run_id)
    assert len(described["manual_observations"]) == 1
    obs_entry = described["manual_observations"][0]
    assert obs_entry["evidence_id"] == cli_out["evidence_id"]
    assert obs_entry["execution_provenance"] == MANUAL_OBSERVATION_PROVENANCE
    assert obs_entry["promoted_to_vdp_product_test"] is False
    assert obs_entry["cleanup_confirmed"] is True
    assert NOT_EXECUTED_VIA_HARNESS_CONDITION in obs_entry["unverified_conditions"]

    # Verifier MUST fail closed and never promote manual observation to vdp.product_test.
    verifier = VdpProductTestVerifier(storage=storage, vault_root=vault_root)
    ver = verifier.verify(run_id=run_id, evidence_ids=(cli_out["evidence_id"],))
    assert ver.status == VerificationStatus.FAILED
    assert "manual_observation_cannot_escalate_to_vdp_product_test" in ver.checks_performed


def test_import_manual_observation_rejects_hash_mismatch_and_secrets(tmp_path: Path, capsys) -> None:
    db_path = tmp_path / "harness.db"
    vault_root = tmp_path / "vault"
    storage = Storage(db_path)
    ctrl = create_default_controller(
        storage=storage,
        vault_root=vault_root,
        export_root=vault_root / "_exports",
        cursor_hmac_key=b"m" * 32,
        allow_dynamic=True,
        initialize=True,
    )
    ctrl.create_run(
        principal=_make_principal(),
        run_id="run-p1-man-reject",
        task_id="task-p1-manual",
        mode=RunMode.VDP,
        scope=_make_scope(),
        budget=BudgetSpec(run_budget_seconds=300, max_tool_calls=20, max_evidence_bytes_per_run=10_000_000),
    )

    test_script = tmp_path / "g01_check.py"
    test_script.write_text("assert 1 == 1\n", encoding="utf-8")
    manifest = tmp_path / "bad_hash.json"
    manifest.write_text(
        json.dumps(
            {
                "observation_id": "bad-hash-01",
                "observed_at": "2026-11-19T05:00:00Z",
                "target_name": "weblate",
                "target_version": "2026.11.2",
                "pinned_source_commit": WEBLATE_2026_11_2_SOURCE_COMMIT,
                "pinned_image_digests": {"scanner": WEBLATE_2026_11_2_IMAGE_DIGEST},
                "environment_summary": "isolated test",
                "isolation_declared": {
                    "synthetic_data_only": True,
                    "external_egress_blocked": True,
                    "published_ports_none": True,
                    "network_description": "internal",
                },
                "test_code_hashes": {"g01_check.py": "0" * 64},
                "execution_summary": "summary",
                "controls": [
                    {
                        "control_name": "c1",
                        "role": "positive_control",
                        "outcome": "passed",
                        "summary": "ok",
                    }
                ],
                "cleanup_confirmation": {
                    "containers_removed": True,
                    "databases_removed": True,
                    "networks_removed": True,
                    "confirmed_by": "operator",
                    "confirmed_at": "2026-11-19T05:05:00Z",
                    "verification_note": "ok",
                },
            }
        ),
        encoding="utf-8",
    )
    rc_bad = admin_main(
        [
            "import-manual-observation",
            "--db-path",
            str(db_path),
            "--vault-root",
            str(vault_root),
            "--run-id",
            "run-p1-man-reject",
            "--manifest-json",
            str(manifest),
            "--test-file",
            str(test_script),
        ],
        env={"CTF_MCP_CURSOR_HMAC_KEY": "m" * 32, "CTF_MCP_ALLOW_DYNAMIC": "1"},
    )
    assert rc_bad != 0
    assert "Hash mismatch" in capsys.readouterr().err

    # Also verify fail-closed sensitive marker rejection inside ManualObservationRecord / import_manual_observation.
    from ctf_mcp.evidence.manual_observation import (
        ManualCleanupConfirmation,
        ManualControlRecord,
        ManualIsolationDeclaration,
        ManualObservationRecord,
        serialize_manual_observation,
    )
    with pytest.raises(ContractViolationError, match="sensitive"):
        secret_obs = ManualObservationRecord(
            observation_id="secret-obs-01",
            observed_at=datetime.now(UTC),
            target_name="weblate",
            target_version="2026.11.2",
            pinned_source_commit=WEBLATE_2026_11_2_SOURCE_COMMIT,
            pinned_image_digests={"scanner": WEBLATE_2026_11_2_IMAGE_DIGEST},
            environment_summary="isolated",
            isolation_declared=ManualIsolationDeclaration(
                synthetic_data_only=True,
                external_egress_blocked=True,
                published_ports_none=True,
                network_description="internal",
            ),
            test_code_hashes={"g01_check.py": hash_manual_test_file(test_script)[1]},
            execution_summary="leaked bearer sk-ant-secret-token-1234567890",
            controls=(
                ManualControlRecord(
                    control_name="c1",
                    role="positive_control",
                    outcome="passed",
                    summary="ok",
                ),
            ),
            cleanup_confirmation=ManualCleanupConfirmation(
                containers_removed=True,
                databases_removed=True,
                networks_removed=True,
                confirmed_by="operator",
                confirmed_at=datetime.now(UTC),
                verification_note="ok",
            ),
        )
        serialize_manual_observation(secret_obs)
