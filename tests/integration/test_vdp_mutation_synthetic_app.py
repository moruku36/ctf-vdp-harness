"""End-to-end integration tests for bounded differential/mutation testing on a synthetic app (PR-2B)."""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ctf_mcp.adapters.base import SubprocessOutcome, SubprocessResult
from ctf_mcp.adapters.vdp_product_test import (
    WEBLATE_2026_11_2_IMAGE_DIGEST,
    WEBLATE_2026_11_2_IMAGE_REF,
    WEBLATE_2026_11_2_SOURCE_COMMIT,
    VdpProductTestAdapter,
    VdpServiceSpec,
    VdpTargetProfile,
)
from ctf_mcp.cli import admin_main
from ctf_mcp.contracts import (
    ActionRequest,
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
from ctf_mcp.vdp_boundary_map import build_boundary_diff_map
from ctf_mcp.vdp_mutation import MutationPolicySpec


class _FakeDockerMutationRunner:
    """Runs overlay pytest files locally under --network=none simulation with env propagation."""

    @staticmethod
    def _ok(stdout: bytes, *, returncode: int = 0, wall_ms: int = 10) -> SubprocessResult:
        return SubprocessResult(
            outcome=SubprocessOutcome.COMPLETED,
            returncode=returncode,
            stdout=stdout,
            stderr=b"",
            wall_ms=wall_ms,
            output_bytes=len(stdout),
            bytes_observed=len(stdout),
            capture_complete=True,
            cleanup_confirmed=True,
        )

    def run(self, argv, *, timeout_seconds, max_output_bytes, env=None, cwd=None, cancel_event=None):
        del timeout_seconds, max_output_bytes, env, cwd, cancel_event
        if len(argv) >= 3 and argv[1] == "image" and argv[2] == "inspect":
            return self._ok((WEBLATE_2026_11_2_IMAGE_DIGEST + "\n").encode("utf-8"))
        if len(argv) >= 2 and argv[1] == "run":
            joined = " ".join(argv)
            if ".oss-scanner/smoke" in joined:
                out = (
                    "===== test session starts =====\n"
                    "collected 1 item\n"
                    "test_smoke.py::test_ok PASSED [100%]\n"
                    "==== 1 passed in 0.05s ====\n"
                    "ERROR: file or directory not found: /nonexistent-oss-scanner-test.py\n"
                ).encode("utf-8")
                return self._ok(out, wall_ms=5)

            overlay_dir = None
            env_vars: dict[str, str] = {}
            idx = 0
            while idx < len(argv):
                tok = argv[idx]
                if tok == "-e" and idx + 1 < len(argv):
                    k, _, v = argv[idx + 1].partition("=")
                    env_vars[k] = v
                    idx += 2
                    continue
                if tok.startswith("type=bind,source="):
                    for part in tok.split(","):
                        if part.startswith("source="):
                            overlay_dir = Path(part.split("=", 1)[1])
                idx += 1
            assert overlay_dir is not None

            selector_args = [
                str(overlay_dir / tok.split("/src/vdp-test-overlay/", 1)[1])
                if "/src/vdp-test-overlay/" in tok
                else tok
                for tok in argv
                if "::" in tok
            ]
            assert selector_args
            import subprocess

            proc_env = {
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": os.environ.get("PYTHONPATH")
                or str(Path(__file__).resolve().parents[2] / "src"),
                **env_vars,
            }
            res = subprocess.run(
                [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-v", "-s", "-rA", *selector_args],
                capture_output=True,
                text=True,
                env=proc_env,
                check=False,
            )
            fixed_lines: list[str] = []
            for line in res.stdout.splitlines():
                rewritten = line
                for kw in ("PASSED ", "FAILED ", "SKIPPED ", "ERROR "):
                    if line.startswith(kw) and "test_mutation_synth.py::" in line:
                        rewritten = kw + "/src/vdp-test-overlay/test_mutation_synth.py::" + line.split("test_mutation_synth.py::", 1)[1]
                        break
                fixed_lines.append(rewritten)
            combined = ("\n".join(fixed_lines) + "\n" + res.stderr).encode("utf-8")
            return self._ok(combined, returncode=res.returncode, wall_ms=25)
        return self._ok(b"")


def _write_synthetic_app_and_overlay(tmp_path: Path) -> tuple[Path, Path, Path]:
    src_dir = tmp_path / "synth_app"
    src_dir.mkdir(parents=True)
    (src_dir / "views.py").write_text(
        '''
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import permission_classes

@permission_classes([IsAuthenticated])
def api_update_repo(request):
    repo_url = validate_url(request.data.get("repo_url"))
    return update_repo(request.user.id, repo_url)

@permission_classes([AllowAny])
def webhook_update_repo(request):
    repo_url = request.data.get("repo_url")
    return trigger_sync(repo_url)
''',
        encoding="utf-8",
    )

    overlay_dir = tmp_path / "overlay_mutation"
    overlay_dir.mkdir(parents=True)
    flag_file = tmp_path / "app_mode.txt"
    flag_file.write_text("vulnerable", encoding="utf-8")

    overlay_test = overlay_dir / "test_mutation_synth.py"
    overlay_test.write_text(
        f'''
import json
import os
import socket
from pathlib import Path

from ctf_mcp.vdp_mutation import BoundedMutationRunner, EntrypointPair, MutationPolicySpec
from ctf_mcp.vdp_setting_diff import SettingDiffRecorder

MODE_FILE = Path({str(flag_file)!r})

def _api_handler(payload):
    val = str(payload.get("repo_url") or "")
    norm = val.split("#", 1)[0].strip()
    ok = norm.startswith("https://127.0.0.1/") and ".." not in norm and "%2e" not in norm.lower()
    return {{"accepted": ok, "normalized": norm}}

def _webhook_handler(payload):
    mode = MODE_FILE.read_text(encoding="utf-8").strip()
    if mode == "broken_baseline":
        return {{"accepted": False, "error": "500"}}
    if mode == "egress_attempt":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect(("93.184.216.34", 443))
        finally:
            s.close()
        return {{"accepted": True}}
    if mode == "fixed":
        return _api_handler(payload)
    val = str(payload.get("repo_url") or "")
    ok = val.startswith("https://127.0.0.1/") and ".." not in val
    return {{"accepted": ok, "normalized": val}}

def test_positive_control():
    assert _api_handler({{"repo_url": "https://127.0.0.1/org/repo.git"}})["accepted"] is True

def test_anomaly_differential_mutation():
    raw_pol = os.environ.get("CTF_VDP_MUTATION_POLICY_JSON")
    if raw_pol:
        policy = MutationPolicySpec.model_validate(json.loads(raw_pol))
    else:
        policy = MutationPolicySpec(
            seed=42,
            max_iterations=16,
            wall_time_cap_seconds=10,
            target_fields=("repo_url",),
            entrypoint_pair=EntrypointPair(baseline_entrypoint="api", candidate_entrypoint="webhook"),
        )
    rec = SettingDiffRecorder()
    rec.detect_from_settings({{"CELERY_TASK_ALWAYS_EAGER": True, "repo_url": "https://127.0.0.1/org/repo.git"}})
    rec.emit_marker()

    res = BoundedMutationRunner(policy).run(
        baseline_input={{"repo_url": "https://127.0.0.1/org/repo.git"}},
        baseline_fn=_api_handler,
        candidate_fn=_webhook_handler,
    )
    res.emit_marker()
    assert res.verdict in {{"hypothesis_falsified", "anomaly_observed", "baseline_failed", "environment_failure"}}
''',
        encoding="utf-8",
    )
    return src_dir, overlay_dir, flag_file


def test_mutation_e2e_with_boundary_map_overlay_assistant_setting_diff_and_verifier(tmp_path: Path, capsys) -> None:
    src_dir, overlay_dir, flag_file = _write_synthetic_app_and_overlay(tmp_path)

    # Feature 1: AST boundary diff map -> MutationPolicySpec handoff
    bmap = build_boundary_diff_map(
        feature="repo",
        source_dir=src_dir,
        baseline_kind="api",
    )
    assert bmap.total_investigation_candidates >= 1
    policy = MutationPolicySpec.from_boundary_map_candidate(
        bmap.cross_path_diffs[0] if bmap.cross_path_diffs else {
            "baseline_kind": "api",
            "compared_kind": "webhook",
            "finding_id": "BM-FALLBACK",
        },
        seed=42,
        target_fields=("repo_url",),
        max_iterations=16,
        wall_time_cap_seconds=10,
    )

    # Feature 2: register overlay via CLI dry-run then --apply --confirm-apply
    vault_root = tmp_path / "vault"
    storage = Storage(tmp_path / "harness.db")
    cli_env = {"CTF_MCP_CURSOR_HMAC_KEY": "m" * 32, "CTF_MCP_ALLOW_DYNAMIC": "1"}

    base_args = [
        "register-vdp-overlay",
        "--vault-root",
        str(vault_root),
        "--overlay-dir",
        str(overlay_dir),
        "--profile-name",
        "synth-mut-app",
        "--overlay-bundle",
        "synth-mut-v1",
        "--image-ref",
        WEBLATE_2026_11_2_IMAGE_REF,
        "--image-digest",
        WEBLATE_2026_11_2_IMAGE_DIGEST,
        "--source-commit",
        WEBLATE_2026_11_2_SOURCE_COMMIT,
        "--allow-unhealthy-env",
    ]
    assert admin_main(base_args, env=cli_env) == 0
    dry_out = json.loads(capsys.readouterr().out)
    assert dry_out["status"] == "dry_run_preview"

    assert admin_main([*base_args, "--apply", "--confirm-apply"], env=cli_env) == 0
    reg_out = json.loads(capsys.readouterr().out)
    assert reg_out["status"] == "registered"
    sel_pos = next(s for s in reg_out["selector_roles"] if "test_positive_control" in s)
    sel_mut = next(s for s in reg_out["selector_roles"] if "test_anomaly_differential_mutation" in s)

    ctrl = create_default_controller(
        storage=storage,
        vault_root=vault_root,
        cursor_hmac_key=b"m" * 32,
        allow_dynamic=True,
        include_vdp_product_test=False,
        enable_local_verifier=True,
        initialize=True,
    )
    adapter = VdpProductTestAdapter(
        evidence_vault=ctrl.evidence_vault,
        runner=_FakeDockerMutationRunner(),
        vault_root=vault_root,
        docker_bin="docker",
    )
    ctrl.register_adapter(adapter, tool_group="vdp.test", is_heavy_job=True)

    principal = PrincipalContext(
        principal_id="local-operator",
        auth_method="stdio_local",
        client_kind="OPERATOR_SELECTED",
        model_label="pr2b-e2e",
    )
    now = datetime.now(UTC)
    scope_payload = {
        "mode": "vdp",
        "task_id": "task-pr2b",
        "scope_revision": "scope-pr2b-v1",
        "authorization_reference": "owned-pr2b",
        "allowed_capabilities": ["analysis.query", "vdp.test"],
        "allowed_execution_classes": ["static", "dynamic"],
        "expires_at": (now + timedelta(hours=2)).isoformat(),
        "network_enabled": False,
        "allowed_targets": [],
        "external_submission": False,
    }
    scope = ScopePolicy(
        scope_revision="scope-pr2b-v1",
        scope_sha256=canonical_digest(scope_payload),
        mode=RunMode.VDP,
        task_id="task-pr2b",
        authorization_reference="owned-pr2b",
        allowed_execution_classes=(ExecutionClass.STATIC, ExecutionClass.DYNAMIC),
        allowed_capabilities=("analysis.query", "vdp.test"),
        expires_at=now + timedelta(hours=2),
        network_enabled=False,
        allowed_targets=(),
        external_submission=False,
    )
    ctrl.create_run(
        principal=principal,
        run_id="run-pr2b",
        task_id="task-pr2b",
        mode=RunMode.VDP,
        scope=scope,
        budget=BudgetSpec(run_budget_seconds=300, max_tool_calls=20, max_evidence_bytes_per_run=5_000_000),
    )

    def _run_vdp(req_id: str, op: str, extra: dict) -> object:
        snap = ctrl.runs.get_run_snapshot("run-pr2b")
        return ctrl.execute_action(
            principal=principal,
            request=ActionRequest(
                run_id="run-pr2b",
                request_id=req_id,
                expected_revision=snap.revision,
                capability_name="vdp.test",
                operation=op,
                arguments={
                    "target_profile": "synth-mut-app",
                    "source_commit": WEBLATE_2026_11_2_SOURCE_COMMIT,
                    "image_digest": WEBLATE_2026_11_2_IMAGE_DIGEST,
                    **extra,
                },
            ),
        )

    smoke = _run_vdp("req-smoke", "run_smoke", {})
    assert smoke.status == EnvelopeStatus.OK, (smoke.summary, smoke.error)

    pol_dict = policy.model_dump(mode="json")

    # 1. Vulnerable mode -> anomaly_observed + minimal_repro + setting diffs + bounded_mutation:verified
    flag_file.write_text("vulnerable", encoding="utf-8")
    ev_vuln = _run_vdp(
        "req-mut-vuln",
        "run_pytest",
        {
            "overlay_bundle": "synth-mut-v1",
            "test_selectors": [sel_pos, sel_mut],
            "mutation_policy": pol_dict,
        },
    )
    assert ev_vuln.status == EnvelopeStatus.OK, (ev_vuln.summary, ev_vuln.error)
    _, raw_vuln = ctrl.evidence_vault.read_view_bytes(
        run_id="run-pr2b",
        principal_id=principal.principal_id,
        evidence_id=ev_vuln.evidence[0].id,
    )
    parsed_vuln = json.loads(raw_vuln.decode("utf-8"))
    assert parsed_vuln["verdict"] == "anomaly_observed"
    assert parsed_vuln["network_mode"] == "none"
    ms_vuln = parsed_vuln["execution_context"]["mutation_summary"]
    assert ms_vuln["seed"] == 42
    assert len(ms_vuln["minimal_repro_cases"]) >= 1
    assert ms_vuln["finding_qualification"] == "separate_assessment_required_not_judged_from_pass_count"

    ver_vuln = ctrl.verify_run(
        principal=principal,
        run_id="run-pr2b",
        verifier_id="vdp.product_test",
        evidence_ids=(smoke.evidence[0].id, ev_vuln.evidence[0].id),
    )
    assert ver_vuln.status == VerificationStatus.PASSED
    assert "bounded_mutation:verified" in ver_vuln.checks_performed
    assert "setting_diff_audit:recorded" in ver_vuln.checks_performed
    assert "bounded_mutation_scope_not_exhaustive" in ver_vuln.limitations

    # 2. Fixed mode -> hypothesis_falsified
    flag_file.write_text("fixed", encoding="utf-8")
    ev_fixed = _run_vdp(
        "req-mut-fixed",
        "run_pytest",
        {
            "overlay_bundle": "synth-mut-v1",
            "test_selectors": [sel_pos, sel_mut],
            "mutation_policy": pol_dict,
        },
    )
    assert ev_fixed.status == EnvelopeStatus.OK
    _, raw_fixed = ctrl.evidence_vault.read_view_bytes(
        run_id="run-pr2b",
        principal_id=principal.principal_id,
        evidence_id=ev_fixed.evidence[0].id,
    )
    parsed_fixed = json.loads(raw_fixed.decode("utf-8"))
    assert parsed_fixed["verdict"] == "hypothesis_falsified"
    assert parsed_fixed["execution_context"]["mutation_summary"]["minimal_repro_cases"] == []

    ver_fixed = ctrl.verify_run(
        principal=principal,
        run_id="run-pr2b",
        verifier_id="vdp.product_test",
        evidence_ids=(smoke.evidence[0].id, ev_fixed.evidence[0].id),
    )
    assert ver_fixed.status == VerificationStatus.PASSED
    assert "outcome_state:hypothesis_falsified" in ver_fixed.checks_performed

    # 3. Broken positive control -> baseline_failed -> Verifier FAILED
    flag_file.write_text("broken_baseline", encoding="utf-8")
    ev_base = _run_vdp(
        "req-mut-basefail",
        "run_pytest",
        {
            "overlay_bundle": "synth-mut-v1",
            "test_selectors": [sel_pos, sel_mut],
            "mutation_policy": pol_dict,
        },
    )
    ver_base = ctrl.verify_run(
        principal=principal,
        run_id="run-pr2b",
        verifier_id="vdp.product_test",
        evidence_ids=(smoke.evidence[0].id, ev_base.evidence[0].id),
    )
    assert ver_base.status == VerificationStatus.FAILED
    assert "outcome_state:baseline_failed" in ver_base.checks_performed

    # 4. Egress guard violation inside container -> environment_failure -> Verifier FAILED
    flag_file.write_text("egress_attempt", encoding="utf-8")
    ev_egress = _run_vdp(
        "req-mut-egress",
        "run_pytest",
        {
            "overlay_bundle": "synth-mut-v1",
            "test_selectors": [sel_pos, sel_mut],
            "mutation_policy": pol_dict,
        },
    )
    assert ev_egress.status == EnvelopeStatus.TOOL_ERROR
    ver_egress = ctrl.verify_run(
        principal=principal,
        run_id="run-pr2b",
        verifier_id="vdp.product_test",
        evidence_ids=(smoke.evidence[0].id, ev_egress.evidence[0].id),
    )
    assert ver_egress.status == VerificationStatus.FAILED
    assert "network_isolation:violated" in ver_egress.checks_performed

    # 5. Oversized policy & non-'none' network_mode rejected preflight when mutation_policy is supplied
    bad_pol = {**pol_dict, "max_iterations": 999}
    with pytest.raises(ContractViolationError, match="256"):
        _run_vdp(
            "req-mut-badcap",
            "run_pytest",
            {
                "overlay_bundle": "synth-mut-v1",
                "test_selectors": [sel_pos, sel_mut],
                "mutation_policy": bad_pol,
            },
        )

    internal_profile = VdpTargetProfile(
        profile_name="synth-mut-internal",
        profile_revision="r1",
        image_ref=WEBLATE_2026_11_2_IMAGE_REF,
        expected_image_digest=WEBLATE_2026_11_2_IMAGE_DIGEST,
        expected_source_commit=WEBLATE_2026_11_2_SOURCE_COMMIT,
        network_mode="isolated_internal_services",
        runner_mode="direct_pytest",
        smoke_selectors=(sel_pos,),
        services=(
            VdpServiceSpec(
                name="db",
                service_kind="postgres",
                image_ref="postgres:16-alpine",
                expected_image_digest="sha256:" + ("d" * 64),
                internal_port=5432,
            ),
        ),
        allowed_test_selectors=(sel_pos, sel_mut),
        positive_selectors=(sel_pos,),
        negative_selectors=(sel_mut,),
        allowed_overlays=adapter.get_profiles()["synth-mut-app"].allowed_overlays,
    )
    adapter.register_profile(internal_profile)
    ev_non_none = _run_vdp(
        "req-mut-internal",
        "run_pytest",
        {
            "target_profile": "synth-mut-internal",
            "overlay_bundle": "synth-mut-v1",
            "test_selectors": [sel_pos, sel_mut],
            "mutation_policy": pol_dict,
        },
    )
    assert ev_non_none.status == EnvelopeStatus.DENIED
    assert ev_non_none.error is not None and ev_non_none.error.code == "network_mode_denied"
