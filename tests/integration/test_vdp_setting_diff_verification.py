"""Integration tests for PR-2A setting diff audit propagation & production parity guard."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ctf_mcp.adapters.base import SubprocessOutcome, SubprocessResult
from ctf_mcp.adapters.vdp_product_test import (
    WEBLATE_2026_11_2_IMAGE_DIGEST,
    WEBLATE_2026_11_2_IMAGE_REF,
    WEBLATE_2026_11_2_SOURCE_COMMIT,
    VdpOverlaySpec,
    VdpProductTestAdapter,
    VdpTargetProfile,
)
from ctf_mcp.contracts import (
    ActionRequest,
    BudgetSpec,
    ExecutionClass,
    PrincipalContext,
    RunMode,
    ScopePolicy,
    VerificationStatus,
    canonical_digest,
)
from ctf_mcp.controller import create_default_controller
from ctf_mcp.storage import Storage
from ctf_mcp.verification import VdpProductTestVerifier


class _FakeDockerWithSettingDiffRunner:
    """Simulated pinned Docker runner executing pytest inside an ephemeral synthetic overlay."""

    @staticmethod
    def _ok(stdout: bytes, *, returncode: int = 0, wall_ms: int = 5) -> SubprocessResult:
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
                return self._ok(out, wall_ms=10)

            overlay_dir = None
            for token in argv:
                if token.startswith("type=bind,source="):
                    for part in token.split(","):
                        if part.startswith("source="):
                            overlay_dir = Path(part.split("=", 1)[1])
            assert overlay_dir is not None
            import subprocess

            proc_env = {
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": os.environ.get("PYTHONPATH")
                or str(Path(__file__).resolve().parents[2] / "src"),
            }
            res = subprocess.run(
                [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-v", "-s", str(overlay_dir / "test_setting_diff.py")],
                capture_output=True,
                env=proc_env,
                check=False,
            )
            combined = res.stdout + res.stderr
            return self._ok(combined, returncode=res.returncode, wall_ms=25)
        return self._ok(b"", wall_ms=1)


def _setup_controller_with_overlay(tmp_path: Path, overlay_code: str):
    overlay_dir = tmp_path / "overlay"
    overlay_dir.mkdir(parents=True)
    test_file = overlay_dir / "test_setting_diff.py"
    test_file.write_text(overlay_code, encoding="utf-8")
    test_sha = hashlib.sha256(test_file.read_bytes()).hexdigest()

    profile = VdpTargetProfile(
        profile_name="synth-setting-diff",
        profile_revision="r1",
        image_ref=WEBLATE_2026_11_2_IMAGE_REF,
        expected_image_digest=WEBLATE_2026_11_2_IMAGE_DIGEST,
        expected_source_commit=WEBLATE_2026_11_2_SOURCE_COMMIT,
        allowed_test_selectors=(
            "test_setting_diff.py::test_positive_ok",
            "test_setting_diff.py::test_defense_ok",
        ),
        positive_selectors=("test_setting_diff.py::test_positive_ok",),
        negative_selectors=("test_setting_diff.py::test_defense_ok",),
        allowed_overlays={
            "bundle-sd": VdpOverlaySpec(
                bundle_name="bundle-sd",
                host_dir=overlay_dir,
                container_target="/src/vdp-test-overlay",
                allowed_files={"test_setting_diff.py": test_sha},
            )
        },
    )

    storage = Storage(tmp_path / "harness.db")
    vault_root = tmp_path / "vault"
    ctrl = create_default_controller(
        storage=storage,
        vault_root=vault_root,
        cursor_hmac_key=b"k" * 32,
        allow_dynamic=True,
        include_vdp_product_test=False,
        enable_local_verifier=True,
        initialize=True,
    )
    adapter = VdpProductTestAdapter(
        evidence_vault=ctrl.evidence_vault,
        runner=_FakeDockerWithSettingDiffRunner(),
        profiles={"synth-setting-diff": profile},
        vault_root=vault_root,
        docker_bin="docker",
    )
    ctrl.register_adapter(adapter, tool_group="vdp.test", is_heavy_job=True)

    principal = PrincipalContext(
        principal_id="local-operator",
        auth_method="stdio_local",
        client_kind="OPERATOR_SELECTED",
        model_label="pr2a-test",
    )
    now = datetime.now(UTC)
    scope_payload = {
        "mode": "vdp",
        "task_id": "task-pr2a",
        "scope_revision": "scope-pr2a-v1",
        "authorization_reference": "owned-pr2a",
        "allowed_capabilities": ["analysis.query", "vdp.test"],
        "allowed_execution_classes": ["static", "dynamic"],
        "expires_at": (now + timedelta(hours=2)).isoformat(),
        "network_enabled": False,
        "allowed_targets": [],
        "external_submission": False,
    }
    scope = ScopePolicy(
        scope_revision="scope-pr2a-v1",
        scope_sha256=canonical_digest(scope_payload),
        mode=RunMode.VDP,
        task_id="task-pr2a",
        authorization_reference="owned-pr2a",
        allowed_execution_classes=(ExecutionClass.STATIC, ExecutionClass.DYNAMIC),
        allowed_capabilities=("analysis.query", "vdp.test"),
        expires_at=now + timedelta(hours=2),
        network_enabled=False,
        allowed_targets=(),
        external_submission=False,
    )
    ctrl.create_run(
        principal=principal,
        run_id="run-pr2a",
        task_id="task-pr2a",
        mode=RunMode.VDP,
        scope=scope,
        budget=BudgetSpec(run_budget_seconds=300, max_tool_calls=20, max_evidence_bytes_per_run=5_000_000),
    )
    return ctrl, principal


def _exec_vdp(ctrl, *, principal: PrincipalContext, request_id: str, operation: str, arguments: dict):
    snap = ctrl.runs.get_run_snapshot("run-pr2a")
    return ctrl.execute_action(
        principal=principal,
        request=ActionRequest(
            run_id="run-pr2a",
            request_id=request_id,
            expected_revision=snap.revision,
            capability_name="vdp.test",
            operation=operation,
            arguments={
                "source_commit": WEBLATE_2026_11_2_SOURCE_COMMIT,
                "image_digest": WEBLATE_2026_11_2_IMAGE_DIGEST,
                **arguments,
            },
        ),
    )


def test_setting_diff_propagates_to_verifier_limitations_and_blocks_parity_claim(tmp_path: Path) -> None:
    overlay_code = """
from ctf_mcp.vdp_setting_diff import SettingDiffRecorder

def test_positive_ok():
    assert True

def test_defense_ok():
    rec = SettingDiffRecorder()
    rec.detect_from_settings(
        {
            "CELERY_TASK_ALWAYS_EAGER": True,
            "repo_url": "https://u:demo_url_pass_9999@127.0.0.1:9000/repo.git",
            "private_ip_allowlist": ["127.0.0.1/32"],
        },
        stage_verification={"update_scheduled": True, "sync_completed": True, "data_changed": False},
    )
    rec.emit_marker()
    assert True
"""
    ctrl, principal = _setup_controller_with_overlay(tmp_path, overlay_code)

    smoke_env = _exec_vdp(
        ctrl,
        principal=principal,
        request_id="req-smoke-1",
        operation="run_smoke",
        arguments={"target_profile": "synth-setting-diff"},
    )
    assert smoke_env.status.value == "ok", (smoke_env.summary, smoke_env.error)

    pytest_env = _exec_vdp(
        ctrl,
        principal=principal,
        request_id="req-pytest-1",
        operation="run_pytest",
        arguments={
            "target_profile": "synth-setting-diff",
            "overlay_bundle": "bundle-sd",
            "test_selectors": [
                "test_setting_diff.py::test_positive_ok",
                "test_setting_diff.py::test_defense_ok",
            ],
            "positive_selectors": ["test_setting_diff.py::test_positive_ok"],
            "negative_selectors": ["test_setting_diff.py::test_defense_ok"],
        },
    )
    assert pytest_env.status.value == "ok", (pytest_env.summary, pytest_env.error)
    _, raw_bytes = ctrl.evidence_vault.read_view_bytes(
        run_id="run-pr2a",
        principal_id=principal.principal_id,
        evidence_id=pytest_env.evidence[0].id,
    )
    payload = json.loads(raw_bytes.decode("utf-8"))
    assert len(payload["execution_context"]["setting_diffs"]) >= 3
    assert "loopback_fixture_vs_real_vcs_transport_unverified" in payload["conclusion_status"]["unverified_conditions"]
    assert "loopback_git_http_sync_confirmed" in payload["conclusion_status"]["confirmed_conditions"]
    assert "demo_url_pass_9999" not in raw_bytes.decode("utf-8")
    assert "***:***@" in raw_bytes.decode("utf-8")

    # Standard verification succeeds while propagating unverified setting diffs to limitations
    ver_ok = ctrl.verify_run(
        principal=principal,
        run_id="run-pr2a",
        verifier_id="vdp.product_test",
        evidence_ids=(smoke_env.evidence[0].id, pytest_env.evidence[0].id),
    )
    assert ver_ok.status == VerificationStatus.PASSED
    assert "setting_diff_audit:recorded" in ver_ok.checks_performed
    assert "loopback_fixture_vs_real_vcs_transport_unverified" in ver_ok.limitations
    assert "test_ca_or_private_allowlist_vs_prod_tls_policy_unverified" in ver_ok.limitations

    # Claiming production parity MUST fail closed when unverified diffs exist
    ver_parity = ctrl.verify_run(
        principal=principal,
        run_id="run-pr2a",
        verifier_id="vdp.product_test",
        evidence_ids=(smoke_env.evidence[0].id, pytest_env.evidence[0].id),
        claim="production_parity_confirmed",
    )
    assert ver_parity.status == VerificationStatus.FAILED
    assert "production_parity:unverified_setting_diff_present" in ver_parity.checks_performed


def test_confirmed_only_diffs_and_legacy_absence_handling(tmp_path: Path) -> None:
    overlay_confirmed = """
from ctf_mcp.vdp_setting_diff import SettingDiffRecorder

def test_positive_ok():
    assert True

def test_defense_ok():
    rec = SettingDiffRecorder()
    rec.detect_from_settings({"real_auth_middleware_exercised": True, "DEBUG": False})
    rec.emit_marker()
    assert True
"""
    ctrl, principal = _setup_controller_with_overlay(tmp_path / "conf", overlay_confirmed)
    smoke_env = _exec_vdp(
        ctrl,
        principal=principal,
        request_id="req-smoke-conf",
        operation="run_smoke",
        arguments={"target_profile": "synth-setting-diff"},
    )
    assert smoke_env.status.value == "ok", (smoke_env.summary, smoke_env.error)
    pytest_env = _exec_vdp(
        ctrl,
        principal=principal,
        request_id="req-pytest-conf",
        operation="run_pytest",
        arguments={
            "target_profile": "synth-setting-diff",
            "overlay_bundle": "bundle-sd",
            "test_selectors": [
                "test_setting_diff.py::test_positive_ok",
                "test_setting_diff.py::test_defense_ok",
            ],
            "positive_selectors": ["test_setting_diff.py::test_positive_ok"],
            "negative_selectors": ["test_setting_diff.py::test_defense_ok"],
        },
    )
    assert pytest_env.status.value == "ok", (pytest_env.summary, pytest_env.error)
    ver_conf = ctrl.verify_run(
        principal=principal,
        run_id="run-pr2a",
        verifier_id="vdp.product_test",
        evidence_ids=(smoke_env.evidence[0].id, pytest_env.evidence[0].id),
        claim="production_parity_confirmed",
    )
    assert ver_conf.status == VerificationStatus.PASSED
    assert "production_parity:all_audited_diffs_confirmed" in ver_conf.checks_performed

    # Legacy evidence without setting_diffs still passes normally with legacy_absent,
    # while production_parity_confirmed fails closed cleanly.
    overlay_legacy = """
def test_positive_ok():
    assert True

def test_defense_ok():
    assert True
"""
    ctrl_leg, prin_leg = _setup_controller_with_overlay(tmp_path / "leg", overlay_legacy)
    s_leg = _exec_vdp(
        ctrl_leg,
        principal=prin_leg,
        request_id="req-smoke-leg",
        operation="run_smoke",
        arguments={"target_profile": "synth-setting-diff"},
    )
    assert s_leg.status.value == "ok", (s_leg.summary, s_leg.error)
    p_leg = _exec_vdp(
        ctrl_leg,
        principal=prin_leg,
        request_id="req-pytest-leg",
        operation="run_pytest",
        arguments={
            "target_profile": "synth-setting-diff",
            "overlay_bundle": "bundle-sd",
            "test_selectors": [
                "test_setting_diff.py::test_positive_ok",
                "test_setting_diff.py::test_defense_ok",
            ],
            "positive_selectors": ["test_setting_diff.py::test_positive_ok"],
            "negative_selectors": ["test_setting_diff.py::test_defense_ok"],
        },
    )
    assert p_leg.status.value == "ok", (p_leg.summary, p_leg.error)
    ver_leg_ok = ctrl_leg.verify_run(
        principal=prin_leg,
        run_id="run-pr2a",
        verifier_id="vdp.product_test",
        evidence_ids=(s_leg.evidence[0].id, p_leg.evidence[0].id),
    )
    assert ver_leg_ok.status == VerificationStatus.PASSED
    assert "setting_diff_audit:legacy_absent" in ver_leg_ok.checks_performed

    ver_leg_parity = ctrl_leg.verify_run(
        principal=prin_leg,
        run_id="run-pr2a",
        verifier_id="vdp.product_test",
        evidence_ids=(s_leg.evidence[0].id, p_leg.evidence[0].id),
        claim="production_parity_confirmed",
    )
    assert ver_leg_parity.status == VerificationStatus.FAILED
    assert "production_parity:setting_diff_audit_missing" in ver_leg_parity.checks_performed
