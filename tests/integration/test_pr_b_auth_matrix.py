"""Integration and security contract tests for PR-B: human-authored VDP authorization matrix."""

from __future__ import annotations

import json
import os
import stat
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ctf_mcp.adapters.runner import SubprocessRunner
from ctf_mcp.adapters.vdp_product_test import (
    WEBLATE_2026_11_2_IMAGE_DIGEST,
    WEBLATE_2026_11_2_SOURCE_COMMIT,
    VdpProductTestAdapter,
    create_vdp_product_test_descriptor,
    load_registered_vdp_profiles,
)
from ctf_mcp.cli import admin_main
from ctf_mcp.config import RuntimeSettings
from ctf_mcp.contracts import (
    ActionRequest,
    BoundsExceededError,
    BudgetSpec,
    ContractViolationError,
    EnvelopeStatus,
    ExecutionClass,
    PrincipalContext,
    RunMode,
    ScopePolicy,
    VerificationStatus,
    canonical_digest,
)
from ctf_mcp.controller import create_default_controller
from ctf_mcp.storage import Storage
from ctf_mcp.vdp_auth_matrix import (
    AUTH_MATRIX_CANDIDATE_SCHEMA,
    AUTH_MATRIX_RESULT_SCHEMA,
    AUTH_MATRIX_SCHEMA,
    INVESTIGATION_CANDIDATE_ONLY_POLICY,
    AuthMatrixCase,
    AuthMatrixObservation,
    AuthMatrixRunner,
    AuthMatrixSpec,
    assert_auth_matrix_anomaly_candidates,
    assert_auth_matrix_defense_checks,
    assert_auth_matrix_positive_controls,
    emit_auth_matrix_evidence_marker,
    extract_bounded_observation,
    import_boundary_map_to_matrix_candidates,
)
from ctf_mcp.vdp_boundary_map import build_boundary_diff_map

_SYNTH_COMMIT = WEBLATE_2026_11_2_SOURCE_COMMIT
_SYNTH_DIGEST = WEBLATE_2026_11_2_IMAGE_DIGEST


class _SyntheticDjangoDrfFixture:
    """In-memory synthetic Django/DRF-style multi-entrypoint fixture with vulnerable/fixed modes."""

    def __init__(self, *, vulnerable: bool, broken_positive: bool = False) -> None:
        self.vulnerable = vulnerable
        self.broken_positive = broken_positive
        self.db_state = {"project_1_sync_count": 0, "project_1_policy": "restricted"}
        self.git_revision = "rev-0001"
        self.queue: list[str] = []

    def handle(self, case: AuthMatrixCase) -> AuthMatrixObservation:
        db_before = dict(self.db_state)
        git_before = self.git_revision
        queue_before = list(self.queue)

        watched = (
            "SYNTH_RESTRICTED_SLUG",
            "SYNTH_RESTRICTED_PARENT",
            "SYNTH_INTERNAL_ONLY",
        )
        raw_secret_headers = {
            "Authorization": "Bearer sk-synth-never-store-1234567890abcdef",
            "Set-Cookie": "sessionid=SYNTH_SECRET_COOKIE_DO_NOT_LOG",
        }

        # Pair 1: restricted project detail API
        if case.resource == "restricted_project_api":
            if case.actor == "owner":
                status = 500 if self.broken_positive else 200
                body = {"slug": "public-ok", "owner_view": True, "secret_note": "SYNTH_SECRET_BODY"}
                return extract_bounded_observation(
                    http_status=status,
                    headers=raw_secret_headers,
                    json_body=body,
                    watched_markers=watched,
                    db_state_before=db_before,
                    db_state_after=dict(self.db_state),
                    git_revision_before=git_before,
                    git_revision_after=self.git_revision,
                    queue_enqueued_before=queue_before,
                    queue_enqueued_after=list(self.queue),
                )
            return extract_bounded_observation(
                http_status=404,
                headers=raw_secret_headers,
                json_body={"detail": "Not found"},
                watched_markers=watched,
                db_state_before=db_before,
                db_state_after=dict(self.db_state),
                git_revision_before=git_before,
                git_revision_after=self.git_revision,
                queue_enqueued_before=queue_before,
                queue_enqueued_after=list(self.queue),
            )

        # Pair 2: shared-link API (same HTTP 200 status, partial field + marker leak when vulnerable)
        if case.resource == "shared_link_api":
            if case.actor == "owner":
                status = 403 if self.broken_positive else 200
                body = {"share_token": "ok", "public_label": "demo"}
                return extract_bounded_observation(
                    http_status=status,
                    headers=raw_secret_headers,
                    json_body=body,
                    watched_markers=watched,
                )
            if self.vulnerable:
                body = {
                    "public_label": "demo",
                    "private_parent_slug": "SYNTH_RESTRICTED_SLUG",
                    "raw_secret": "sk-synth-raw-body-token-9988776655",
                }
            else:
                body = {"public_label": "demo"}
            return extract_bounded_observation(
                http_status=200,
                headers=raw_secret_headers,
                json_body=body,
                watched_markers=watched,
            )

        # Pair 3: public child git redirect (`Location`-only slug leak when vulnerable)
        if case.resource == "linked_git_redirect_ui":
            if case.actor == "member_public":
                status = 404 if self.broken_positive else 200
                return extract_bounded_observation(
                    http_status=status,
                    headers=raw_secret_headers,
                    raw_text="ref: refs/heads/main",
                    watched_markers=watched,
                )
            loc = (
                "/git/SYNTH_RESTRICTED_PARENT/public-child/"
                if self.vulnerable
                else "/projects/public-child/"
            )
            return extract_bounded_observation(
                http_status=301 if self.vulnerable else 404,
                headers={**raw_secret_headers, "Location": loc},
                raw_text="redirect or not found",
                watched_markers=watched,
            )

        # Pair 4: webhook/async repository sync triggering persistent DB + Git + queue side effects
        if case.resource == "repo_sync_webhook":
            if case.actor == "signed_webhook" and not self.broken_positive:
                self.db_state["project_1_sync_count"] += 1
                self.git_revision = f"rev-{self.db_state['project_1_sync_count'] + 1:04d}"
                self.queue.append("synth_app.tasks.sync_repo")
                return extract_bounded_observation(
                    http_status=202,
                    headers=raw_secret_headers,
                    json_body={"scheduled": True},
                    watched_markers=watched,
                    db_state_before=db_before,
                    db_state_after=dict(self.db_state),
                    git_revision_before=git_before,
                    git_revision_after=self.git_revision,
                    queue_enqueued_before=queue_before,
                    queue_enqueued_after=list(self.queue),
                )
            if case.actor == "signed_webhook" and self.broken_positive:
                return extract_bounded_observation(http_status=500)
            if self.vulnerable:
                # Even though HTTP returns 403, pre-check side effects still mutated DB/Git/queue!
                self.db_state["project_1_sync_count"] += 1
                self.git_revision = f"rev-{self.db_state['project_1_sync_count'] + 1:04d}"
                self.queue.append("synth_app.tasks.sync_repo")
            return extract_bounded_observation(
                http_status=403,
                headers=raw_secret_headers,
                json_body={"detail": "Forbidden"},
                watched_markers=watched,
                db_state_before=db_before,
                db_state_after=dict(self.db_state),
                git_revision_before=git_before,
                git_revision_after=self.git_revision,
                queue_enqueued_before=queue_before,
                queue_enqueued_after=list(self.queue),
            )

        raise AssertionError(f"Unexpected synthetic resource {case.resource!r}")


def _build_full_matrix_dict() -> dict[str, Any]:
    return {
        "schema": AUTH_MATRIX_SCHEMA,
        "matrix_id": "synth-drf-matrix-01",
        "target_name": "synth-drf-app",
        "authored_by": "operator-synth",
        "policy_source_kind": "human_documented_policy",
        "allowlist": {
            "actors": ["owner", "outsider", "anonymous", "member_public", "signed_webhook"],
            "resources": [
                "restricted_project_api",
                "shared_link_api",
                "linked_git_redirect_ui",
                "repo_sync_webhook",
            ],
            "actions": ["read", "redirect", "trigger_sync"],
            "entrypoints": ["api", "ui", "webhook", "async"],
        },
        "limits": {
            "max_combinations": 16,
            "max_runtime_seconds": 15.0,
            "max_output_bytes": 16384,
        },
        "cases": [
            {
                "case_id": "c_detail_allow_owner",
                "pair_group": "grp-detail-api",
                "actor": "owner",
                "resource": "restricted_project_api",
                "action": "read",
                "entrypoint": "api",
                "expected_decision": "allow",
                "required_preconfiguration": "Owner account owns restricted synthetic project.",
                "expectation_basis": "synth_app/api.py:24",
                "compared_fields": ["http_status", "db_state"],
                "expected_statuses": [200],
            },
            {
                "case_id": "c_detail_deny_outsider",
                "pair_group": "grp-detail-api",
                "actor": "outsider",
                "resource": "restricted_project_api",
                "action": "read",
                "entrypoint": "api",
                "expected_decision": "deny",
                "required_preconfiguration": "Outsider has no role on restricted synthetic project.",
                "expectation_basis": "https://example.invalid/docs/permissions#project-detail",
                "compared_fields": ["http_status", "synthetic_markers"],
                "expected_statuses": [403, 404],
                "forbidden_synthetic_markers": ["SYNTH_RESTRICTED_SLUG"],
            },
            {
                "case_id": "c_share_allow_owner",
                "pair_group": "grp-shared-link",
                "actor": "owner",
                "resource": "shared_link_api",
                "action": "read",
                "entrypoint": "api",
                "expected_decision": "allow",
                "required_preconfiguration": "Owner creates synthetic public share link.",
                "expectation_basis": "synth_app/api.py:58",
                "compared_fields": ["http_status"],
                "expected_statuses": [200],
            },
            {
                "case_id": "c_share_deny_anon_partial_fields",
                "pair_group": "grp-shared-link",
                "actor": "anonymous",
                "resource": "shared_link_api",
                "action": "read",
                "entrypoint": "api",
                "expected_decision": "deny",
                "required_preconfiguration": "Share link is public while parent project slug is restricted.",
                "expectation_basis": "synth_app/serializers.py:19",
                "compared_fields": ["http_status", "json_keys", "synthetic_markers"],
                "expected_statuses": [200, 403, 404],
                "forbidden_json_keys": ["private_parent_slug"],
                "forbidden_synthetic_markers": ["SYNTH_RESTRICTED_SLUG"],
            },
            {
                "case_id": "c_redirect_allow_public",
                "pair_group": "grp-redirect-location",
                "actor": "member_public",
                "resource": "linked_git_redirect_ui",
                "action": "read",
                "entrypoint": "ui",
                "expected_decision": "allow",
                "required_preconfiguration": "Public child resource enabled cleanly.",
                "expectation_basis": "synth_app/views.py:41",
                "compared_fields": ["http_status"],
                "expected_statuses": [200],
            },
            {
                "case_id": "c_redirect_deny_anon_location",
                "pair_group": "grp-redirect-location",
                "actor": "anonymous",
                "resource": "linked_git_redirect_ui",
                "action": "redirect",
                "entrypoint": "ui",
                "expected_decision": "deny",
                "required_preconfiguration": "Public child points at restricted parent object.",
                "expectation_basis": "synth_app/views.py:48",
                "compared_fields": ["location_header", "synthetic_markers"],
                "expected_statuses": [301, 404],
                "forbidden_synthetic_markers": ["SYNTH_RESTRICTED_PARENT"],
            },
            {
                "case_id": "c_webhook_allow_signed",
                "pair_group": "grp-webhook-sync",
                "actor": "signed_webhook",
                "resource": "repo_sync_webhook",
                "action": "trigger_sync",
                "entrypoint": "webhook",
                "expected_decision": "allow",
                "required_preconfiguration": "Valid synthetic webhook sender triggers repo sync.",
                "expectation_basis": "synth_app/webhooks.py:15",
                "compared_fields": ["http_status", "db_state", "git_revision", "queue_enqueued"],
                "expected_statuses": [200, 202],
            },
            {
                "case_id": "c_webhook_deny_unsigned_side_effects",
                "pair_group": "grp-webhook-sync",
                "actor": "anonymous",
                "resource": "repo_sync_webhook",
                "action": "trigger_sync",
                "entrypoint": "async",
                "expected_decision": "deny",
                "required_preconfiguration": "Unsigned webhook must trigger zero DB, Git, or queue effects.",
                "expectation_basis": "synth_app/webhooks.py:22",
                "compared_fields": ["http_status", "db_state", "git_revision", "queue_enqueued"],
                "expected_statuses": [401, 403],
                "forbid_db_mutation": True,
                "forbid_git_revision_change": True,
                "forbid_queue_enqueue": True,
            },
        ],
    }


def test_pr_b_synthetic_drf_app_vulnerable_vs_fixed_all_leak_classes(capsys) -> None:
    spec = AuthMatrixSpec.model_validate(_build_full_matrix_dict())

    # 1. Vulnerable mode: catches same-status partial JSON leak, Location-only leak, AND DB/Git/queue side-effect leak
    vuln_fixture = _SyntheticDjangoDrfFixture(vulnerable=True)
    vuln_res = AuthMatrixRunner(spec, vuln_fixture.handle).run()
    assert vuln_res.schema_version == AUTH_MATRIX_RESULT_SCHEMA
    assert vuln_res.status_policy == INVESTIGATION_CANDIDATE_ONLY_POLICY
    assert vuln_res.positive_passed == 4
    assert vuln_res.positive_failed == 0
    assert vuln_res.defense_held == 1  # c_detail_deny_outsider held
    assert vuln_res.investigation_candidates == 3
    assert vuln_res.baseline_blocked == 0
    assert vuln_res.timed_out is False

    by_id = {cr.case_id: cr for cr in vuln_res.case_results}
    assert set(by_id["c_share_deny_anon_partial_fields"].mismatch_reasons) == {
        "json_key_leak",
        "synthetic_marker_leak",
    }
    assert set(by_id["c_redirect_deny_anon_location"].mismatch_reasons) == {
        "location_header_marker_leak",
        "synthetic_marker_leak",
    }
    assert set(by_id["c_webhook_deny_unsigned_side_effects"].mismatch_reasons) == {
        "unexpected_db_mutation",
        "unexpected_git_revision_change",
        "unexpected_queue_enqueue",
    }

    assert_auth_matrix_anomaly_candidates(vuln_res, min_candidates=3)
    with pytest.raises(AssertionError):
        assert_auth_matrix_defense_checks(vuln_res)

    # Verify zero secrets or raw bodies persisted in result JSON or VDP_EVIDENCE_MARKER
    marker_payload = emit_auth_matrix_evidence_marker(vuln_res)
    captured_out = capsys.readouterr().out
    serialized_all = vuln_res.model_dump_json() + json.dumps(marker_payload) + captured_out
    assert "sk-synth-" not in serialized_all
    assert "SYNTH_SECRET_BODY" not in serialized_all
    assert "SYNTH_SECRET_COOKIE_DO_NOT_LOG" not in serialized_all

    # 2. Fixed mode: all positive controls pass and every deny expectation holds cleanly
    fixed_fixture = _SyntheticDjangoDrfFixture(vulnerable=False)
    fixed_res = AuthMatrixRunner(spec, fixed_fixture.handle).run()
    assert fixed_res.positive_passed == 4
    assert fixed_res.positive_failed == 0
    assert fixed_res.defense_held == 4
    assert fixed_res.investigation_candidates == 0
    assert_auth_matrix_defense_checks(fixed_res)
    with pytest.raises(AssertionError):
        assert_auth_matrix_anomaly_candidates(fixed_res, min_candidates=1)


def test_pr_b_broken_positive_control_blocks_defense_and_negative_bounds() -> None:
    spec = AuthMatrixSpec.model_validate(_build_full_matrix_dict())

    # Broken positive controls must block deny cases and fail defense/anomaly helpers
    broken = _SyntheticDjangoDrfFixture(vulnerable=False, broken_positive=True)
    res_broken = AuthMatrixRunner(spec, broken.handle).run()
    assert res_broken.positive_failed == 4
    assert res_broken.positive_passed == 0
    assert res_broken.defense_held == 0
    assert res_broken.baseline_blocked == 4
    with pytest.raises(AssertionError):
        assert_auth_matrix_positive_controls(res_broken)
    with pytest.raises(AssertionError):
        assert_auth_matrix_defense_checks(res_broken)
    with pytest.raises(AssertionError):
        assert_auth_matrix_anomaly_candidates(res_broken)

    # Reject non-human policy_source_kind
    bad_policy = _build_full_matrix_dict()
    bad_policy["policy_source_kind"] = "observed_behavior"
    with pytest.raises(ValidationError):
        AuthMatrixSpec.model_validate(bad_policy)

    # Reject out-of-allowlist actor
    bad_actor = _build_full_matrix_dict()
    bad_actor["cases"][1]["actor"] = "unlisted_actor"
    with pytest.raises(ContractViolationError, match="allowlist.actors"):
        AuthMatrixSpec.model_validate(bad_actor)

    # Reject unpaired pair_group (deny-only without allow)
    unpaired = _build_full_matrix_dict()
    unpaired["cases"] = [c for c in unpaired["cases"] if c["pair_group"] == "grp-detail-api"]
    unpaired["cases"][0]["expected_decision"] = "deny"
    with pytest.raises(ContractViolationError, match="both 'allow'"):
        AuthMatrixSpec.model_validate(unpaired)

    # Reject bad expectation_basis (abs host path, .. traversal, plaintext http://)
    for bad_basis in ("/etc/passwd:1", "../secret.py:5", "http://example.invalid/doc"):
        bad_b = _build_full_matrix_dict()
        bad_b["cases"][0]["expectation_basis"] = bad_basis
        with pytest.raises(ValidationError):
            AuthMatrixSpec.model_validate(bad_b)

    # Reject case count exceeding limits.max_combinations
    over_comb = _build_full_matrix_dict()
    over_comb["limits"]["max_combinations"] = 4
    with pytest.raises(BoundsExceededError, match="max_combinations"):
        AuthMatrixSpec.model_validate(over_comb)

    # Enforce runtime limit truncation (timed_out=True, skipped_limit > 0)
    short_rt = _build_full_matrix_dict()
    short_rt["limits"]["max_runtime_seconds"] = 0.01
    short_spec = AuthMatrixSpec.model_validate(short_rt)

    def _slow_exec(case: AuthMatrixCase) -> AuthMatrixObservation:
        time.sleep(0.02)
        return extract_bounded_observation(http_status=200 if case.expected_decision == "allow" else 404)

    rt_res = AuthMatrixRunner(short_spec, _slow_exec).run()
    assert rt_res.timed_out is True
    assert rt_res.skipped_limit > 0

    # Enforce output byte limit truncation cleanly
    tight_out = _build_full_matrix_dict()
    tight_out["limits"]["max_output_bytes"] = 900
    tight_spec = AuthMatrixSpec.model_validate(tight_out)
    tight_res = AuthMatrixRunner(tight_spec, _SyntheticDjangoDrfFixture(vulnerable=True).handle).run()
    assert tight_res.output_truncated is True
    assert len(tight_res.model_dump_json(by_alias=True).encode("utf-8")) <= 900


def test_pr_b_boundary_map_import_and_cli_subcommand(tmp_path: Path, capsys) -> None:
    src_dir = tmp_path / "synth_src"
    src_dir.mkdir()
    (src_dir / "project_views.py").write_text(
        """from django.contrib.auth.decorators import login_required

@login_required
def ui_project_update(request, slug):
    project = Project.objects.filter(owner=request.user, slug=slug).first()
    project.save()
    return "ok"

def webhook_project_sync(request):
    project = Project.objects.get(slug=request.data["slug"])
    project.save()
    return "synced"
""",
        encoding="utf-8",
    )

    bmap = build_boundary_diff_map(feature="project", source_dir=src_dir, baseline_kind="ui")
    bmap_path = tmp_path / "boundary_map.json"
    bmap_path.write_text(bmap.model_dump_json(indent=2), encoding="utf-8")

    # Direct importer keeps candidate-only policy and human review gate
    draft = import_boundary_map_to_matrix_candidates(bmap)
    assert draft.schema_version == AUTH_MATRIX_CANDIDATE_SCHEMA
    assert draft.status_policy == INVESTIGATION_CANDIDATE_ONLY_POLICY
    assert draft.policy_source_requirement == "requires_human_documented_policy"
    assert draft.total_candidates == len(bmap.cross_path_diffs) + len(bmap.test_coverage_gaps)

    # CLI --from-boundary-map writes output atomically
    cand_out = tmp_path / "matrix_candidates.json"
    rc_from = admin_main(
        ["vdp-auth-matrix", "--from-boundary-map", str(bmap_path), "--output", str(cand_out)]
    )
    assert rc_from == 0
    _ = capsys.readouterr()
    parsed_cand = json.loads(cand_out.read_text(encoding="utf-8"))
    assert parsed_cand["schema"] == AUTH_MATRIX_CANDIDATE_SCHEMA
    assert parsed_cand["status_policy"] == "investigation_candidate_only"

    # CLI --validate-matrix succeeds on valid human matrix and rejects symlinks & bad matrices
    matrix_path = tmp_path / "valid_matrix.json"
    matrix_path.write_text(json.dumps(_build_full_matrix_dict(), indent=2), encoding="utf-8")
    rc_val = admin_main(["vdp-auth-matrix", "--validate-matrix", str(matrix_path)])
    assert rc_val == 0
    val_out = json.loads(capsys.readouterr().out)
    assert val_out["valid"] is True
    assert val_out["case_count"] == 8

    sym_matrix = tmp_path / "sym_matrix.json"
    os.symlink(matrix_path, sym_matrix)
    rc_sym = admin_main(["vdp-auth-matrix", "--validate-matrix", str(sym_matrix)])
    assert rc_sym != 0
    _ = capsys.readouterr()

    bad_matrix = tmp_path / "bad_matrix.json"
    bad_dict = _build_full_matrix_dict()
    bad_dict["cases"][0]["expectation_basis"] = "../bad.py:1"
    bad_matrix.write_text(json.dumps(bad_dict), encoding="utf-8")
    rc_bad = admin_main(["vdp-auth-matrix", "--validate-matrix", str(bad_matrix)])
    assert rc_bad != 0
    _ = capsys.readouterr()


def test_pr_b_vdp_test_overlay_integration_vulnerable_and_fixed(tmp_path: Path, capsys) -> None:
    src_repo = Path(__file__).resolve().parents[2] / "src"
    overlay_dir = tmp_path / "overlay_src"
    overlay_dir.mkdir()

    overlay_test = overlay_dir / "test_synth_matrix.py"
    overlay_test.write_text(
        """from __future__ import annotations
import os
from ctf_mcp.vdp_auth_matrix import (
    AuthMatrixCase,
    AuthMatrixObservation,
    AuthMatrixRunner,
    AuthMatrixSpec,
    assert_auth_matrix_anomaly_candidates,
    assert_auth_matrix_defense_checks,
    assert_auth_matrix_positive_controls,
    emit_auth_matrix_evidence_marker,
    extract_bounded_observation,
)

def _matrix_spec() -> AuthMatrixSpec:
    return AuthMatrixSpec.model_validate({
        "schema": "vdp-auth-matrix/1",
        "matrix_id": "overlay-synth-drf-01",
        "target_name": "synth-drf-overlay",
        "authored_by": "operator-synth",
        "policy_source_kind": "human_documented_policy",
        "allowlist": {
            "actors": ["owner", "anonymous"],
            "resources": ["shared_link_api"],
            "actions": ["read"],
            "entrypoints": ["api"],
        },
        "cases": [
            {
                "case_id": "c_allow",
                "pair_group": "grp-share",
                "actor": "owner",
                "resource": "shared_link_api",
                "action": "read",
                "entrypoint": "api",
                "expected_decision": "allow",
                "required_preconfiguration": "Synthetic public share link created.",
                "expectation_basis": "synth_app/serializers.py:12",
                "compared_fields": ["http_status"],
                "expected_statuses": [200],
            },
            {
                "case_id": "c_deny_anon",
                "pair_group": "grp-share",
                "actor": "anonymous",
                "resource": "shared_link_api",
                "action": "read",
                "entrypoint": "api",
                "expected_decision": "deny",
                "required_preconfiguration": "Parent project is private.",
                "expectation_basis": "synth_app/serializers.py:18",
                "compared_fields": ["http_status", "json_keys", "synthetic_markers"],
                "expected_statuses": [200],
                "forbidden_json_keys": ["private_parent_slug"],
                "forbidden_synthetic_markers": ["SYNTH_PRIVATE_SLUG"],
            },
        ],
    })

def _exec_case(case: AuthMatrixCase) -> AuthMatrixObservation:
    is_vuln = os.environ.get("SYNTH_OVERLAY_VULN") == "1"
    if case.actor == "owner":
        return extract_bounded_observation(http_status=200, json_body={"public_slug": "child"})
    body = {"public_slug": "child", "private_parent_slug": "SYNTH_PRIVATE_SLUG"} if is_vuln else {"public_slug": "child"}
    return extract_bounded_observation(http_status=200, json_body=body, watched_markers=("SYNTH_PRIVATE_SLUG",))

def test_positive_matrix_controls() -> None:
    res = AuthMatrixRunner(_matrix_spec(), _exec_case).run()
    assert_auth_matrix_positive_controls(res)
    emit_auth_matrix_evidence_marker(res, config_creation_path="validated_ui_api_clean_repo")

def test_defense_matrix_boundaries() -> None:
    res = AuthMatrixRunner(_matrix_spec(), _exec_case).run()
    assert_auth_matrix_defense_checks(res)
    emit_auth_matrix_evidence_marker(res, config_creation_path="validated_ui_api_clean_repo")

def test_anomaly_matrix_repro() -> None:
    res = AuthMatrixRunner(_matrix_spec(), _exec_case).run()
    assert_auth_matrix_anomaly_candidates(res, min_candidates=1)
    emit_auth_matrix_evidence_marker(res, config_creation_path="validated_ui_api_clean_repo")
""",
        encoding="utf-8",
    )

    # Fake docker executes REAL pytest against overlay_test in isolated subprocess with SYNTH_OVERLAY_VULN env
    fake_docker = tmp_path / "fake-docker"
    vuln_flag_file = tmp_path / "vuln_mode.txt"
    vuln_flag_file.write_text("1", encoding="utf-8")
    fake_git = tmp_path / "fake-git"
    fake_git.write_text(
        f"#!{sys.executable}\nimport sys\nsys.stdout.write({_SYNTH_COMMIT!r} + '\\n')\n",
        encoding="utf-8",
    )
    os.chmod(fake_git, stat.S_IRWXU)

    fake_docker.write_text(
        f"""#!{sys.executable}
import os, subprocess, sys
from pathlib import Path

args = sys.argv[1:]
if args[:2] == ["image", "inspect"]:
    print({_SYNTH_DIGEST!r})
    sys.exit(0)
if args[:1] in (["ps"], ["rm"]):
    sys.exit(0)
if args[:1] == ["run"]:
    assert "--network" in args and "none" in args
    if "-rA" not in args:
        print("collected 129 items")
        print("==== 129 passed in 0.15s ====")
        print("collected 122 items")
        print("==== 122 passed in 0.10s ====")
        sys.exit(0)
    selectors = [a.replace("/src/vdp-test-overlay/", str({str(overlay_dir)!r}) + "/") for a in args[args.index("-rA") + 1:]]
    env = dict(os.environ)
    env["PYTHONPATH"] = {str(src_repo)!r}
    env["SYNTH_OVERLAY_VULN"] = Path({str(vuln_flag_file)!r}).read_text(encoding="utf-8").strip()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    proc = subprocess.run([sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-s", "-rA", *selectors], env=env, capture_output=True, text=True)
    fixed_lines = []
    for line in proc.stdout.splitlines():
        for kw in ("PASSED ", "FAILED ", "SKIPPED ", "ERROR "):
            if line.startswith(kw) and "test_synth_matrix.py::" in line:
                line = kw + "/src/vdp-test-overlay/test_synth_matrix.py::" + line.split("test_synth_matrix.py::", 1)[1]
                break
        fixed_lines.append(line)
    sys.stdout.write(chr(10).join(fixed_lines) + chr(10))
    sys.stderr.write(proc.stderr)
    sys.exit(proc.returncode)
sys.exit(2)
""",
        encoding="utf-8",
    )
    os.chmod(fake_docker, stat.S_IRWXU)

    db_path = tmp_path / "harness.db"
    vault_root = tmp_path / "vault"

    # Register overlay cleanly via register-vdp-overlay CLI!
    rc_reg = admin_main(
        [
            "register-vdp-overlay",
            "--vault-root",
            str(vault_root),
            "--overlay-dir",
            str(overlay_dir),
            "--profile-name",
            "synth-drf-profile",
            "--overlay-bundle",
            "synth-matrix-v1",
            "--image-ref",
            "synth-drf-scanner:1.0",
            "--image-digest",
            _SYNTH_DIGEST,
            "--source-commit",
            _SYNTH_COMMIT,
            "--docker-bin",
            str(fake_docker),
            "--apply",
            "--confirm-apply",
        ],
        env={"CTF_MCP_CURSOR_HMAC_KEY": "b" * 32, "CTF_MCP_ALLOW_DYNAMIC": "1"},
    )
    assert rc_reg == 0
    reg_out = json.loads(capsys.readouterr().out)
    selectors = list(reg_out["selector_roles"].keys())
    sel_pos = next(s for s in selectors if "test_positive_matrix_controls" in s)
    sel_def = next(s for s in selectors if "test_defense_matrix_boundaries" in s)
    sel_anom = next(s for s in selectors if "test_anomaly_matrix_repro" in s)

    storage = Storage(db_path)
    ctrl = create_default_controller(
        storage=storage,
        vault_root=vault_root,
        export_root=vault_root / "_exports",
        cursor_hmac_key=b"b" * 32,
        runtime_settings=RuntimeSettings(profile=RunMode.VDP),
        allow_dynamic=True,
        include_vdp_product_test=False,
        initialize=True,
    )
    reg_profiles = load_registered_vdp_profiles(vault_root)
    adapter = VdpProductTestAdapter(
        descriptor=create_vdp_product_test_descriptor(enabled=True),
        evidence_vault=ctrl.evidence_vault,
        runner=SubprocessRunner(),
        profiles=reg_profiles,
        vault_root=vault_root,
        docker_bin=str(fake_docker),
    )
    ctrl.register_adapter(adapter, tool_group="vdp.test", is_heavy_job=True)
    principal = PrincipalContext(
        principal_id="op-prb",
        auth_method="stdio_local",
        client_kind="OPERATOR_SELECTED",
        model_label="pr-b-test",
    )
    now = datetime.now(UTC)
    scope_payload = {
        "mode": "vdp",
        "task_id": "task-pr-b",
        "scope_revision": "scope-pr-b-1",
        "authorization_reference": "owned-synth-pr-b",
        "allowed_capabilities": ["vdp.test"],
        "allowed_execution_classes": ["static", "dynamic"],
        "expires_at": (now + timedelta(hours=2)).isoformat(),
        "network_enabled": False,
        "allowed_targets": [],
        "external_submission": False,
    }
    ctrl.create_run(
        principal=principal,
        run_id="run-pr-b-01",
        task_id="task-pr-b",
        mode=RunMode.VDP,
        scope=ScopePolicy(
            scope_revision="scope-pr-b-1",
            scope_sha256=canonical_digest(scope_payload),
            mode=RunMode.VDP,
            task_id="task-pr-b",
            authorization_reference="owned-synth-pr-b",
            allowed_execution_classes=(ExecutionClass.STATIC, ExecutionClass.DYNAMIC),
            allowed_capabilities=("vdp.test",),
            expires_at=now + timedelta(hours=2),
            network_enabled=False,
            allowed_targets=(),
            external_submission=False,
        ),
        budget=BudgetSpec(run_budget_seconds=300, max_tool_calls=20, max_evidence_bytes_per_run=10_000_000),
    )

    # 0. Smoke receipt first (required by VdpProductTestVerifier)
    snap0 = ctrl.runs.get_run_snapshot("run-pr-b-01")
    env_smoke = ctrl.execute_action(
        principal=principal,
        request=ActionRequest(
            run_id="run-pr-b-01",
            request_id="req-prb-smoke",
            expected_revision=snap0.revision,
            capability_name="vdp.test",
            operation="run_smoke",
            arguments={
                "target_profile": "synth-drf-profile",
                "source_commit": _SYNTH_COMMIT,
                "image_digest": _SYNTH_DIGEST,
            },
        ),
    )
    assert env_smoke.status == EnvelopeStatus.OK, (env_smoke.summary, env_smoke.error)
    smoke_eid = env_smoke.evidence[0].id

    # 1. Vulnerable mode: run positive + anomaly_repro -> anomaly_observed + auth_matrix_summary in evidence
    vuln_flag_file.write_text("1", encoding="utf-8")
    snap = ctrl.runs.get_run_snapshot("run-pr-b-01")
    env_anom = ctrl.execute_action(
        principal=principal,
        request=ActionRequest(
            run_id="run-pr-b-01",
            request_id="req-prb-vuln",
            expected_revision=snap.revision,
            capability_name="vdp.test",
            operation="run_pytest",
            arguments={
                "target_profile": "synth-drf-profile",
                "overlay_bundle": "synth-matrix-v1",
                "source_commit": _SYNTH_COMMIT,
                "image_digest": _SYNTH_DIGEST,
                "test_selectors": [sel_pos, sel_anom],
            },
        ),
    )
    assert env_anom.status == EnvelopeStatus.OK, (env_anom.summary, env_anom.error)
    eid_vuln = env_anom.evidence[0].id
    _, raw_vuln = ctrl.evidence_vault.read_view_bytes(run_id="run-pr-b-01", principal_id="op-prb", evidence_id=eid_vuln)
    parsed_vuln = json.loads(raw_vuln.decode("utf-8"))
    assert parsed_vuln["verdict"] == "anomaly_observed"
    matrix_sum_vuln = parsed_vuln["execution_context"]["auth_matrix_summary"]
    assert matrix_sum_vuln["status_policy"] == "investigation_candidate_only"
    assert matrix_sum_vuln["investigation_candidates"] == 1
    assert matrix_sum_vuln["positive_passed"] == 1

    ver_vuln = ctrl.verify_run(principal=principal, run_id="run-pr-b-01", verifier_id="vdp.product_test", evidence_ids=(smoke_eid, eid_vuln))
    assert ver_vuln.status == VerificationStatus.PASSED
    assert any("eligibility" in lim.lower() or "impact" in lim.lower() for lim in ver_vuln.limitations)

    # 2. Fixed mode: run positive + defense_check -> hypothesis_falsified, candidates == 0
    vuln_flag_file.write_text("0", encoding="utf-8")
    snap2 = ctrl.runs.get_run_snapshot("run-pr-b-01")
    env_fixed = ctrl.execute_action(
        principal=principal,
        request=ActionRequest(
            run_id="run-pr-b-01",
            request_id="req-prb-fixed",
            expected_revision=snap2.revision,
            capability_name="vdp.test",
            operation="run_pytest",
            arguments={
                "target_profile": "synth-drf-profile",
                "overlay_bundle": "synth-matrix-v1",
                "source_commit": _SYNTH_COMMIT,
                "image_digest": _SYNTH_DIGEST,
                "test_selectors": [sel_pos, sel_def],
            },
        ),
    )
    assert env_fixed.status == EnvelopeStatus.OK, (env_fixed.summary, env_fixed.error)
    eid_fixed = env_fixed.evidence[0].id
    _, raw_fixed = ctrl.evidence_vault.read_view_bytes(run_id="run-pr-b-01", principal_id="op-prb", evidence_id=eid_fixed)
    parsed_fixed = json.loads(raw_fixed.decode("utf-8"))
    assert parsed_fixed["verdict"] == "hypothesis_falsified"
    assert parsed_fixed["execution_context"]["auth_matrix_summary"]["investigation_candidates"] == 0
    assert parsed_fixed["execution_context"]["auth_matrix_summary"]["defense_held"] == 1

    ver_fixed = ctrl.verify_run(principal=principal, run_id="run-pr-b-01", verifier_id="vdp.product_test", evidence_ids=(smoke_eid, eid_fixed))
    assert ver_fixed.status == VerificationStatus.PASSED
