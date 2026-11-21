"""Integration and security contract tests for PR-A: typed MCP intake of manual isolated observations."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import anyio
import pytest
from fastmcp import Client

from ctf_mcp.cli import admin_main
from ctf_mcp.config import RuntimeSettings
from ctf_mcp.contracts import (
    BudgetSpec,
    ExecutionClass,
    FindingState,
    PrincipalContext,
    RunMode,
    ScopeDeniedError,
    ScopePolicy,
    VerificationStatus,
    canonical_digest,
)
from ctf_mcp.controller import create_default_controller
from ctf_mcp.evidence.manual_observation import (
    MANUAL_OBSERVATION_PROVENANCE,
    MANUAL_OBSERVATION_SCHEMA,
    MANUAL_OBSERVATION_VERIFICATION_TIER,
    NOT_EXECUTED_VIA_HARNESS_CONDITION,
    ManualCleanupConfirmation,
    ManualControlRecord,
    ManualIsolationDeclaration,
    ManualObservationRecord,
    ManualPrivateEvidenceRef,
)
from ctf_mcp.evidence.vdp_submission import VdpAiDisclosure, VdpDraftSpec
from ctf_mcp.server import create_mcp_server
from ctf_mcp.storage import Storage

_DUMMY_COMMIT = "1" * 40
_DUMMY_DIGEST = "sha256:" + ("2" * 64)
_DUMMY_TEST_HASH = "3" * 64
_DUMMY_REF_HASH = "a" * 64


def _make_principal(pid: str = "operator-synth") -> PrincipalContext:
    return PrincipalContext(
        principal_id=pid,
        auth_method="stdio_local",
        client_kind="OPERATOR_SELECTED",
        model_label="pr-a-synth-test",
    )


def _make_scope(
    *,
    mode: RunMode = RunMode.VDP,
    task_id: str = "task-synth-pr-a",
    scope_revision: str = "scope-synth-v1",
    expires_at: datetime | None = None,
) -> ScopePolicy:
    now = datetime.now(UTC)
    exp = expires_at if expires_at is not None else (now + timedelta(hours=2))
    caps = (
        ("analysis.query", "vdp.test")
        if mode == RunMode.VDP
        else ("analysis.query",)
    )
    classes = (
        (ExecutionClass.STATIC, ExecutionClass.DYNAMIC)
        if mode == RunMode.VDP
        else (ExecutionClass.STATIC,)
    )
    payload = {
        "mode": mode.value,
        "task_id": task_id,
        "scope_revision": scope_revision,
        "authorization_reference": "owned-synthetic-fixture",
        "allowed_capabilities": list(caps),
        "allowed_execution_classes": [c.value for c in classes],
        "expires_at": exp.isoformat(),
        "network_enabled": False,
        "allowed_targets": [],
        "external_submission": False,
    }
    return ScopePolicy(
        scope_revision=scope_revision,
        scope_sha256=canonical_digest(payload),
        mode=mode,
        task_id=task_id,
        authorization_reference="owned-synthetic-fixture",
        allowed_execution_classes=classes,
        allowed_capabilities=caps,
        expires_at=exp,
        network_enabled=False,
        allowed_targets=(),
        external_submission=False,
    )


def _seed_controller(tmp_path: Path, *, mode: RunMode = RunMode.VDP) -> tuple[Any, Storage, Path]:
    db_path = tmp_path / "harness.db"
    vault_root = tmp_path / "vault"
    storage = Storage(db_path)
    ctrl = create_default_controller(
        storage=storage,
        vault_root=vault_root,
        export_root=vault_root / "_exports",
        cursor_hmac_key=b"k" * 32,
        runtime_settings=RuntimeSettings(profile=mode),
        allow_dynamic=(mode == RunMode.VDP),
        include_vdp_product_test=(mode == RunMode.VDP),
        initialize=True,
        enable_local_verifier=True,
    )
    return ctrl, storage, vault_root


def _valid_mcp_args(run_id: str, *, obs_id: str = "synth-obs-001", request_id: str | None = "req-synth-1") -> dict[str, Any]:
    now_iso = datetime.now(UTC).isoformat()
    args: dict[str, Any] = {
        "run_id": run_id,
        "observation_id": obs_id,
        "observed_at": now_iso,
        "target_name": "synth-web-app",
        "target_version": "1.0.0-synth",
        "pinned_source_commit": _DUMMY_COMMIT,
        "pinned_image_digests": {"synth-runner": _DUMMY_DIGEST},
        "environment_summary": "Isolated internal bridge network with temporary container DB and egress blocked.",
        "isolation_declared": {
            "synthetic_data_only": True,
            "external_egress_blocked": True,
            "published_ports_none": True,
            "network_description": "docker internal synthetic network",
        },
        "test_code_hashes": {"test_synth_boundary.py": _DUMMY_TEST_HASH},
        "executed_by": "operator-synth",
        "execution_method": "manual_docker_internal_pytest",
        "execution_summary": "Public synthetic view served 200; restricted resource rejected direct fetch with 403 while redirect Location included synthetic slug.",
        "before_state": "Synthetic tenant seeded with isolated fixture items and default policy.",
        "after_state": "Temporary test containers, DB volume, and internal bridge deleted; state verified clean.",
        "controls": [
            {
                "control_name": "positive_public_fetch",
                "role": "positive_control",
                "outcome": "passed",
                "summary": "Authorized public synthetic resource returned 200.",
            },
            {
                "control_name": "defense_restricted_direct_fetch",
                "role": "defense_check",
                "outcome": "passed",
                "summary": "Unauthorized direct fetch of restricted resource returned 403.",
            },
            {
                "control_name": "anomaly_redirect_slug",
                "role": "anomaly_observation",
                "outcome": "observed",
                "summary": "Synthetic redirect endpoint exposed restricted slug only in Location header.",
            },
        ],
        "impact_boundaries": [
            "Only synthetic slug appeared in redirect header; restricted object body remained denied (403)."
        ],
        "unverified_conditions": [
            "Observed on synthetic fixture data only; hosted production behavior not tested."
        ],
        "cleanup_confirmation": {
            "containers_removed": True,
            "databases_removed": True,
            "networks_removed": True,
            "confirmed_by": "operator-synth",
            "confirmed_at": now_iso,
            "verification_note": "Confirmed zero remaining containers or networks on local host.",
        },
        "private_evidence_refs": [
            {
                "ref_id": "synth-log-digest-01",
                "sha256": _DUMMY_REF_HASH,
                "kind": "log_digest",
                "description": "SHA-256 digest of redacted local manual verification log stored privately.",
            }
        ],
        "exit_code": 0,
        "notes": "Synthetic PR-A acceptance case.",
    }
    if request_id is not None:
        args["request_id"] = request_id
    return args


def _assert_named_objects_closed(node: Any, path: str = "$") -> None:
    if isinstance(node, dict):
        if node.get("type") == "object" and "properties" in node:
            assert node.get("additionalProperties") is False, f"Expected additionalProperties=False at {path}"
        for key, child in node.items():
            _assert_named_objects_closed(child, f"{path}.{key}")
    elif isinstance(node, list):
        for idx, item in enumerate(node):
            _assert_named_objects_closed(item, f"{path}[{idx}]")


def test_pr_a_mcp_e2e_intake_provenance_idempotency_and_verifier_refusal(tmp_path: Path) -> None:
    ctrl, _, vault_root = _seed_controller(tmp_path, mode=RunMode.VDP)
    alice = _make_principal("alice-synth")
    run_id = "run-pr-a-e2e-01"
    ctrl.create_run(
        principal=alice,
        run_id=run_id,
        task_id="task-synth-pr-a",
        mode=RunMode.VDP,
        scope=_make_scope(mode=RunMode.VDP),
        budget=BudgetSpec(run_budget_seconds=300, max_tool_calls=30, max_evidence_bytes_per_run=10_000_000),
    )
    server = create_mcp_server(ctrl, default_stdio_principal=alice, active_run_id=run_id)

    async def _run() -> dict[str, Any]:
        async with Client(server.mcp) as client:
            tools = {t.name: t for t in await client.list_tools()}
            assert "evidence.import_manual_observation" in tools
            schema = tools["evidence.import_manual_observation"].input_schema
            _assert_named_objects_closed(schema)

            valid_args = _valid_mcp_args(run_id, request_id="req-e2e-1")
            res = await client.call_tool("evidence.import_manual_observation", valid_args)
            assert res.is_error is False
            sc = res.structured_content
            assert sc["status"] == "ok"
            assert sc["execution_provenance"] == MANUAL_OBSERVATION_PROVENANCE
            assert sc["verification_tier"] == MANUAL_OBSERVATION_VERIFICATION_TIER
            assert sc["promoted_to_vdp_product_test"] is False
            assert sc["intake_channel"] == "mcp"
            assert sc["private_evidence_ref_count"] == 1
            assert NOT_EXECUTED_VIA_HARNESS_CONDITION in sc["unverified_conditions"]

            evidence_id = sc["evidence_id"]

            # Idempotent replay returns identical evidence_id without duplicating objects
            replay = await client.call_tool("evidence.import_manual_observation", valid_args)
            assert replay.is_error is False
            assert replay.structured_content["evidence_id"] == evidence_id
            assert replay.structured_content["action_id"] == sc["action_id"]

            # Same request_id with changed payload must fail closed (action_conflict)
            conflict_args = _valid_mcp_args(run_id, obs_id="synth-obs-conflict", request_id="req-e2e-1")
            conflict = await client.call_tool("evidence.import_manual_observation", conflict_args, raise_on_error=False)
            assert conflict.is_error is True
            assert conflict.structured_content["error"]["code"] == "action_conflict"

            # Stale expected_revision must fail closed
            stale_args = _valid_mcp_args(run_id, obs_id="synth-obs-stale", request_id="req-e2e-stale")
            stale_args["expected_revision"] = 999
            stale = await client.call_tool("evidence.import_manual_observation", stale_args, raise_on_error=False)
            assert stale.is_error is True
            assert stale.structured_content["error"]["code"] == "action_conflict"

            # Read back stored observation via evidence.read and confirm schema + normalized fields
            read_res = await client.call_tool(
                "evidence.read",
                {"run_id": run_id, "evidence_id": evidence_id, "max_chars": 4000},
            )
            assert read_res.is_error is False
            stored = json.loads(read_res.structured_content["content"])
            assert stored["schema"] == MANUAL_OBSERVATION_SCHEMA
            assert stored["intake_channel"] == "mcp"
            assert stored["executed_by"] == "operator-synth"
            assert stored["execution_method"] == "manual_docker_internal_pytest"
            assert stored["promoted_to_vdp_product_test"] is False
            assert stored["private_evidence_refs"][0]["sha256"] == _DUMMY_REF_HASH
            assert NOT_EXECUTED_VIA_HARNESS_CONDITION in stored["unverified_conditions"]

            # Passing MCP manual observation to vdp.product_test MUST fail escalation
            ver_res = await client.call_tool(
                "run.verify",
                {"run_id": run_id, "verifier_id": "vdp.product_test", "evidence_ids": [evidence_id]},
            )
            assert ver_res.is_error is False
            vsc = ver_res.structured_content
            assert vsc["status"] == VerificationStatus.FAILED.value
            assert "manual_observation_cannot_escalate_to_vdp_product_test" in vsc["checks_performed"]

            # run.describe surfaces visible tool and enriched manual observation metadata
            desc_res = await client.call_tool("run.describe", {"run_id": run_id})
            dsc = desc_res.structured_content
            assert "evidence.import_manual_observation" in dsc["visible_mcp_tools"]
            assert len(dsc["manual_observations"]) == 1
            mo = dsc["manual_observations"][0]
            assert mo["evidence_id"] == evidence_id
            assert mo["intake_channel"] == "mcp"
            assert mo["executed_by"] == "operator-synth"
            assert mo["private_evidence_ref_count"] == 1
            assert mo["promoted_to_vdp_product_test"] is False
            return {"evidence_id": evidence_id}

    out = anyio.run(_run)

    # Confirm VDP draft export integrates MCP observation while preserving separation
    draft = VdpDraftSpec(
        finding_id="SYNTH-PR-A-01",
        title="Synthetic redirect slug exposure on synthetic tenant fixture",
        target_name="synth-web-app",
        affected_version="1.0.0-synth",
        pinned_source_commit=_DUMMY_COMMIT,
        location="synth_app/views.py",
        preconditions="Synthetic public child linked to restricted synthetic parent.",
        observation="Synthetic GET returned 301 Location containing restricted synthetic slug.",
        reproduction_steps=["Run isolated fixture", "Compare positive 200 vs defense 403"],
        impact_hypothesis="Identifier exposure only without unauthorized object content.",
        impact_boundaries=["Direct restricted GET returned 403."],
        unverified_conditions=["Synthetic fixture only."],
        evidence_ids=(out["evidence_id"],),
        ai_disclosure=VdpAiDisclosure(
            ai_used=True,
            client_model_label="synthetic-test",
            assistance_scope="Synthetic test fixture.",
            human_reviewed_by="operator-synth",
            human_review_confirmed=True,
        ),
    )
    exported = ctrl.export_vdp_submission_draft(principal=alice, run_id=run_id, draft=draft, language="ja")
    assert exported.submission_record.automatic_submission is False
    assert exported.submission_record.state == FindingState.REPORT_READY
    draft_md = exported.markdown
    assert out["evidence_id"] in draft_md
    assert "手動・隔離環境での観測" in draft_md


def test_pr_a_scope_closed_run_mode_and_principal_boundaries(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    alice = _make_principal("alice-synth")
    bob = _make_principal("bob-synth")

    # 1. offline_ctf run hides tool and denies direct call
    ctrl_off, _, _ = _seed_controller(tmp_path / "off", mode=RunMode.OFFLINE_CTF)
    ctrl_off.create_run(
        principal=alice,
        run_id="run-off-01",
        task_id="task-synth-pr-a",
        mode=RunMode.OFFLINE_CTF,
        scope=_make_scope(mode=RunMode.OFFLINE_CTF),
        budget=BudgetSpec(run_budget_seconds=120, max_tool_calls=10, max_evidence_bytes_per_run=1_000_000),
    )
    srv_off = create_mcp_server(ctrl_off, default_stdio_principal=alice, active_run_id="run-off-01")

    async def _check_off() -> None:
        async with Client(srv_off.mcp) as client:
            listed = {t.name for t in await client.list_tools()}
            assert "evidence.import_manual_observation" not in listed
            denied = await client.call_tool(
                "evidence.import_manual_observation",
                _valid_mcp_args("run-off-01"),
                raise_on_error=False,
            )
            assert denied.is_error is True
            assert denied.structured_content["status"] == "denied"

    anyio.run(_check_off)

    # 2. Expired scope, revoked scope, closed run, and cross-principal on VDP controller
    ctrl_vdp, _, _ = _seed_controller(tmp_path / "vdp", mode=RunMode.VDP)

    # Expired scope run
    ctrl_vdp.create_run(
        principal=alice,
        run_id="run-vdp-exp",
        task_id="task-synth-pr-a",
        mode=RunMode.VDP,
        scope=_make_scope(mode=RunMode.VDP, expires_at=now - timedelta(minutes=5)),
        budget=BudgetSpec(run_budget_seconds=120, max_tool_calls=10, max_evidence_bytes_per_run=1_000_000),
    )
    # Revoked scope run
    ctrl_vdp.create_run(
        principal=alice,
        run_id="run-vdp-rev",
        task_id="task-synth-pr-a",
        mode=RunMode.VDP,
        scope=_make_scope(mode=RunMode.VDP, scope_revision="scope-rev-1"),
        budget=BudgetSpec(run_budget_seconds=120, max_tool_calls=10, max_evidence_bytes_per_run=1_000_000),
    )
    ctrl_vdp.revoke_scope(principal=alice, run_id="run-vdp-rev", scope_revision="scope-rev-1")

    # Closed VDP run
    ctrl_vdp.create_run(
        principal=alice,
        run_id="run-vdp-closed",
        task_id="task-synth-pr-a",
        mode=RunMode.VDP,
        scope=_make_scope(mode=RunMode.VDP),
        budget=BudgetSpec(run_budget_seconds=120, max_tool_calls=10, max_evidence_bytes_per_run=1_000_000),
    )
    ctrl_vdp.close_run(
        principal=alice,
        run_id="run-vdp-closed",
        child_processes_confirmed_stopped=True,
        import_completed=True,
    )

    srv_vdp = create_mcp_server(ctrl_vdp, default_stdio_principal=alice)

    async def _check_vdp_denials() -> None:
        async with Client(srv_vdp.mcp) as client:
            for rid, expected_code in (
                ("run-vdp-exp", "scope_expired"),
                ("run-vdp-rev", "scope_revoked"),
                ("run-vdp-closed", "tool_denied"),
            ):
                srv_vdp.set_active_run(rid)
                listed = {t.name for t in await client.list_tools()}
                assert "evidence.import_manual_observation" not in listed
                res = await client.call_tool(
                    "evidence.import_manual_observation",
                    _valid_mcp_args(rid, request_id=f"req-{rid}"),
                    raise_on_error=False,
                )
                assert res.is_error is True
                assert res.structured_content["error"]["code"] == expected_code

    anyio.run(_check_vdp_denials)

    # CLI / controller call directly on expired / revoked scope also fails closed
    valid_obs = ManualObservationRecord(
        observation_id="synth-obs-cli-scope",
        observed_at=now,
        target_name="synth-web-app",
        target_version="1.0.0-synth",
        pinned_source_commit=_DUMMY_COMMIT,
        pinned_image_digests={"synth": _DUMMY_DIGEST},
        environment_summary="isolated",
        isolation_declared=ManualIsolationDeclaration(
            synthetic_data_only=True,
            external_egress_blocked=True,
            published_ports_none=True,
            network_description="internal",
        ),
        test_code_hashes={"test_a.py": _DUMMY_TEST_HASH},
        execution_summary="summary",
        controls=(
            ManualControlRecord(
                control_name="pos",
                role="positive_control",
                outcome="passed",
                summary="ok",
            ),
        ),
        cleanup_confirmation=ManualCleanupConfirmation(
            containers_removed=True,
            databases_removed=True,
            networks_removed=True,
            confirmed_by="operator-synth",
            confirmed_at=now,
            verification_note="ok",
        ),
    )
    with pytest.raises(ScopeDeniedError, match="expired"):
        ctrl_vdp.import_manual_observation(principal=alice, run_id="run-vdp-exp", observation=valid_obs)
    with pytest.raises(ScopeDeniedError, match="revoked"):
        ctrl_vdp.import_manual_observation(principal=alice, run_id="run-vdp-rev", observation=valid_obs)

    # Cross-principal denial via MCP
    ctrl_vdp.create_run(
        principal=alice,
        run_id="run-vdp-open",
        task_id="task-synth-pr-a",
        mode=RunMode.VDP,
        scope=_make_scope(mode=RunMode.VDP),
        budget=BudgetSpec(run_budget_seconds=120, max_tool_calls=10, max_evidence_bytes_per_run=1_000_000),
    )
    srv_bob = create_mcp_server(ctrl_vdp, default_stdio_principal=bob)

    async def _check_bob() -> None:
        async with Client(srv_bob.mcp) as client:
            res = await client.call_tool(
                "evidence.import_manual_observation",
                _valid_mcp_args("run-vdp-open"),
                raise_on_error=False,
            )
            assert res.is_error is True
            assert res.structured_content["error"]["code"] == "scope_denied"

    anyio.run(_check_bob)


def test_pr_a_rejects_missing_controls_paths_urls_oversize_raw_logs_and_secrets(tmp_path: Path) -> None:
    ctrl, _, _ = _seed_controller(tmp_path, mode=RunMode.VDP)
    alice = _make_principal("alice-synth")
    run_id = "run-pr-a-neg-01"
    ctrl.create_run(
        principal=alice,
        run_id=run_id,
        task_id="task-synth-pr-a",
        mode=RunMode.VDP,
        scope=_make_scope(mode=RunMode.VDP),
        budget=BudgetSpec(run_budget_seconds=300, max_tool_calls=50, max_evidence_bytes_per_run=10_000_000),
    )
    server = create_mcp_server(ctrl, default_stdio_principal=alice, active_run_id=run_id)

    secret_literal = "sk-synthetic-never-echo-9988776655443322"

    def _mutate(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
        out = json.loads(json.dumps(base))
        out.update(patch)
        return out

    base = _valid_mcp_args(run_id)
    bad_cases: list[tuple[str, dict[str, Any]]] = [
        ("missing_executor", _mutate(base, {"executed_by": ""})),
        ("missing_before_state", _mutate(base, {"before_state": ""})),
        ("missing_after_state", _mutate(base, {"after_state": ""})),
        ("missing_unverified_conditions", _mutate(base, {"unverified_conditions": []})),
        ("missing_private_refs", _mutate(base, {"private_evidence_refs": []})),
        (
            "missing_defense_control",
            _mutate(
                base,
                {
                    "controls": [
                        {
                            "control_name": "pos_only",
                            "role": "positive_control",
                            "outcome": "passed",
                            "summary": "Only positive control provided.",
                        }
                    ]
                },
            ),
        ),
        (
            "non_isolated_egress",
            _mutate(
                base,
                {
                    "isolation_declared": {
                        "synthetic_data_only": True,
                        "external_egress_blocked": False,
                        "published_ports_none": True,
                        "network_description": "bridge",
                    }
                },
            ),
        ),
        ("path_traversal_test_key", _mutate(base, {"test_code_hashes": {"../escape.py": _DUMMY_TEST_HASH}})),
        ("path_traversal_text", _mutate(base, {"before_state": "Read ../etc/shadow via traversal"})),
        ("abs_host_path", _mutate(base, {"after_state": "Inspect /etc/passwd on host"})),
        ("external_url_in_summary", _mutate(base, {"execution_summary": "Fetched https://example.invalid/exfil"})),
        (
            "url_in_private_ref",
            _mutate(
                base,
                {
                    "private_evidence_refs": [
                        {
                            "ref_id": "https://example.invalid/ref",
                            "sha256": _DUMMY_REF_HASH.lower(),
                            "kind": "log_digest",
                            "description": "ref",
                        }
                    ]
                },
            ),
        ),
        (
            "symlink_in_ref_id",
            _mutate(
                base,
                {
                    "private_evidence_refs": [
                        {
                            "ref_id": "symlink_ptr",
                            "sha256": _DUMMY_REF_HASH.lower(),
                            "kind": "log_digest",
                            "description": "digest",
                        }
                    ]
                },
            ),
        ),
        ("raw_http_transcript", _mutate(base, {"execution_summary": "HTTP/1.1 200 OK header captured"})),
        ("raw_traceback", _mutate(base, {"notes": "Traceback (most recent call last): File x"})),
        ("secret_marker", _mutate(base, {"execution_summary": f"Observed {secret_literal} during run"})),
        (
            "oversize_payload",
            _mutate(
                base,
                {
                    "execution_summary": "x" * 1900,
                    "before_state": "y" * 950,
                    "after_state": "z" * 950,
                    "notes": "n" * 950,
                    "controls": [
                        {
                            "control_name": f"pos_{i}",
                            "role": "positive_control" if i == 0 else "defense_check",
                            "outcome": "passed",
                            "summary": f"c{i}-" + ("c" * 480),
                        }
                        for i in range(24)
                    ],
                    "impact_boundaries": [f"b{i}-" + ("b" * 380) for i in range(32)],
                    "unverified_conditions": [f"u{i}-" + ("u" * 380) for i in range(32)],
                },
            ),
        ),
    ]

    async def _run_bad() -> None:
        async with Client(server.mcp) as client:
            ok_res = await client.call_tool("evidence.import_manual_observation", _valid_mcp_args(run_id, obs_id="synth-obs-base-ok", request_id="req-neg-base-ok"))
            assert ok_res.is_error is False
            for label, payload in bad_cases:
                res = await client.call_tool(
                    "evidence.import_manual_observation",
                    payload,
                    raise_on_error=False,
                )
                assert res.is_error is True, f"Expected failure for negative case {label}"
                text_blob = json.dumps(res.structured_content or "", ensure_ascii=False)
                assert secret_literal not in text_blob, f"Secret leaked in error for {label}"

    anyio.run(_run_bad)


def test_pr_a_cli_symlink_oversize_and_legacy_manifest_compatibility(tmp_path: Path, capsys) -> None:
    db_path = tmp_path / "harness.db"
    vault_root = tmp_path / "vault"
    storage = Storage(db_path)
    ctrl = create_default_controller(
        storage=storage,
        vault_root=vault_root,
        export_root=vault_root / "_exports",
        cursor_hmac_key=b"c" * 32,
        allow_dynamic=True,
        initialize=True,
    )
    alice = _make_principal("alice-cli")
    run_id = "run-pr-a-cli-01"
    ctrl.create_run(
        principal=alice,
        run_id=run_id,
        task_id="task-synth-pr-a",
        mode=RunMode.VDP,
        scope=_make_scope(mode=RunMode.VDP),
        budget=BudgetSpec(run_budget_seconds=300, max_tool_calls=20, max_evidence_bytes_per_run=10_000_000),
    )

    real_manifest = tmp_path / "legacy_manifest.json"
    legacy_payload = {
        "observation_id": "legacy-cli-obs-01",
        "observed_at": datetime.now(UTC).isoformat(),
        "target_name": "synth-web-app",
        "target_version": "1.0.0-synth",
        "pinned_source_commit": _DUMMY_COMMIT,
        "pinned_image_digests": {"synth": _DUMMY_DIGEST},
        "environment_summary": "Isolated internal network",
        "isolation_declared": {
            "synthetic_data_only": True,
            "external_egress_blocked": True,
            "published_ports_none": True,
            "network_description": "internal bridge",
        },
        "test_code_hashes": {"legacy_test.py": _DUMMY_TEST_HASH},
        "execution_summary": "Legacy CLI manifest still accepted for backward compatibility.",
        "controls": [
            {
                "control_name": "pos",
                "role": "positive_control",
                "outcome": "passed",
                "summary": "Public synthetic action worked.",
            }
        ],
        "cleanup_confirmation": {
            "containers_removed": True,
            "databases_removed": True,
            "networks_removed": True,
            "confirmed_by": "operator-synth",
            "confirmed_at": datetime.now(UTC).isoformat(),
            "verification_note": "Cleaned up.",
        },
    }
    real_manifest.write_text(json.dumps(legacy_payload), encoding="utf-8")

    # 1. Symlink manifest JSON MUST be rejected
    sym_manifest = tmp_path / "sym_manifest.json"
    os.symlink(real_manifest, sym_manifest)
    rc_sym = admin_main(
        [
            "import-manual-observation",
            "--db-path",
            str(db_path),
            "--vault-root",
            str(vault_root),
            "--run-id",
            run_id,
            "--manifest-json",
            str(sym_manifest),
        ],
        env={"CTF_MCP_CURSOR_HMAC_KEY": "c" * 32, "CTF_MCP_ALLOW_DYNAMIC": "1"},
    )
    assert rc_sym != 0
    assert "non-symlink" in capsys.readouterr().err or "symlink" in capsys.readouterr().err.lower()

    # 2. Oversize manifest JSON (>32 KiB) MUST be rejected
    oversize_manifest = tmp_path / "oversize_manifest.json"
    oversize_manifest.write_text(json.dumps({**legacy_payload, "notes": "a" * 35_000}), encoding="utf-8")
    rc_big = admin_main(
        [
            "import-manual-observation",
            "--db-path",
            str(db_path),
            "--vault-root",
            str(vault_root),
            "--run-id",
            run_id,
            "--manifest-json",
            str(oversize_manifest),
        ],
        env={"CTF_MCP_CURSOR_HMAC_KEY": "c" * 32, "CTF_MCP_ALLOW_DYNAMIC": "1"},
    )
    assert rc_big != 0
    _ = capsys.readouterr()

    # 3. Legacy CLI manifest without PR-A strict fields succeeds unless --strict is requested
    rc_legacy_strict = admin_main(
        [
            "import-manual-observation",
            "--db-path",
            str(db_path),
            "--vault-root",
            str(vault_root),
            "--run-id",
            run_id,
            "--manifest-json",
            str(real_manifest),
            "--strict",
        ],
        env={"CTF_MCP_CURSOR_HMAC_KEY": "c" * 32, "CTF_MCP_ALLOW_DYNAMIC": "1"},
    )
    assert rc_legacy_strict != 0
    _ = capsys.readouterr()

    rc_ok = admin_main(
        [
            "import-manual-observation",
            "--db-path",
            str(db_path),
            "--vault-root",
            str(vault_root),
            "--run-id",
            run_id,
            "--manifest-json",
            str(real_manifest),
        ],
        env={"CTF_MCP_CURSOR_HMAC_KEY": "c" * 32, "CTF_MCP_ALLOW_DYNAMIC": "1"},
    )
    assert rc_ok == 0
    cli_out = json.loads(capsys.readouterr().out)
    assert cli_out["intake_channel"] == "cli"
    assert cli_out["promoted_to_vdp_product_test"] is False
