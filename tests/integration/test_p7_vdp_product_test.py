"""Integration tests for bounded VDP product test execution (`vdp.test`) and verification."""

from __future__ import annotations

import json
import os
import secrets
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import anyio
import pytest
from fastmcp import Client

from ctf_mcp.adapters.runner import SubprocessRunner
from ctf_mcp.adapters.vdp_product_test import (
    WEBLATE_2026_11_2_IMAGE_DIGEST,
    WEBLATE_2026_11_2_PROFILE_NAME,
    WEBLATE_2026_11_2_PROFILE_REVISION,
    WEBLATE_2026_11_2_SOURCE_COMMIT,
    WEBLATE_W01_OVERLAY_BUNDLE,
    WEBLATE_W02_OVERLAY_BUNDLE,
    VdpOverlaySpec,
    VdpProductTestAdapter,
    VdpTargetProfile,
    _WEBLATE_W02_OVERLAY_SCOPE,
    _WEBLATE_W02_UPSTREAM_COMPACTED,
    _WEBLATE_W02_UPSTREAM_NEG,
    build_default_weblate_profile,
    create_vdp_product_test_descriptor,
    load_registered_vdp_profiles,
)
from ctf_mcp.cli import admin_main
from ctf_mcp.contracts import (
    ActionRequest,
    BudgetSpec,
    CapabilityLimits,
    ContractViolationError,
    EnvelopeStatus,
    ExecutionClass,
    GuestBlockedError,
    PrincipalContext,
    RunMode,
    ScopeDeniedError,
    ScopePolicy,
    VerificationStatus,
    canonical_digest,
    sha256_bytes,
)
from ctf_mcp.controller import create_default_controller
from ctf_mcp.server import build_server_from_env
from ctf_mcp.storage import Storage

FAKE_COMMIT = WEBLATE_2026_11_2_SOURCE_COMMIT
FAKE_IMAGE_REF = "weblate-oss-scanner:2026.11.2"
FAKE_IMAGE_DIGEST = WEBLATE_2026_11_2_IMAGE_DIGEST

POS_SEL = "weblate/trans/tests/test_search.py::BulkEditTest::test_replacement_processes_each_selected_translation_once"
NEG_SEL = "weblate/trans/tests/test_search.py::BulkEditTest::test_bulk_edit_requires_bulk_permission_per_unit"
EDIT_NEG_SEL = "weblate/trans/tests/test_edit.py::EditPropagateTest::test_edit_skips_restricted_propagated_component"
OVERLAY_POS_SEL = "/src/vdp-test-overlay/test_w01.py::TestBulkPropagationPermission::test_positive_control_with_peer_permission"
OVERLAY_NEG_SEL = "/src/vdp-test-overlay/test_w01.py::TestBulkPropagationPermission::test_restricted_peer_is_not_changed"


def _make_principal(pid: str = "local-operator") -> PrincipalContext:
    return PrincipalContext(
        principal_id=pid,
        auth_method="stdio_local",
        client_kind="OPERATOR_SELECTED",
        model_label="codex-p7-test",
    )


def _make_scope(
    *,
    mode: RunMode = RunMode.VDP,
    task_id: str = "task-p7-vdp",
    scope_revision: str = "scope-p7-v1",
    allowed_capabilities: tuple[str, ...] = (
        "analysis.query",
        "artifact.inspect",
        "net.probe",
        "vdp.test",
    ),
    allowed_execution_classes: tuple[ExecutionClass, ...] = (
        ExecutionClass.STATIC,
        ExecutionClass.DYNAMIC,
        ExecutionClass.NETWORK,
    ),
    network_enabled: bool = False,
    allowed_targets: tuple[str, ...] = (),
) -> ScopePolicy:
    now = datetime.now(UTC)
    payload = {
        "mode": mode.value,
        "task_id": task_id,
        "scope_revision": scope_revision,
        "authorization_reference": "owned-p7-scope",
        "allowed_capabilities": list(allowed_capabilities),
        "allowed_execution_classes": [c.value for c in allowed_execution_classes],
        "expires_at": (now + timedelta(hours=2)).isoformat(),
        "network_enabled": network_enabled,
        "allowed_targets": list(allowed_targets),
        "external_submission": False,
    }
    return ScopePolicy(
        scope_revision=scope_revision,
        scope_sha256=canonical_digest(payload),
        mode=mode,
        task_id=task_id,
        authorization_reference="owned-p7-scope",
        allowed_execution_classes=allowed_execution_classes,
        allowed_capabilities=allowed_capabilities,
        expires_at=now + timedelta(hours=2),
        network_enabled=network_enabled,
        allowed_targets=allowed_targets,
        external_submission=False,
    )


def _setup_overlay(tmp_path: Path, *, symlink_target: Path | None = None) -> tuple[Path, str]:
    overlay_dir = tmp_path / "overlay" / WEBLATE_W01_OVERLAY_BUNDLE
    overlay_dir.mkdir(parents=True, exist_ok=True)
    test_file = overlay_dir / "test_w01.py"
    if symlink_target is not None:
        test_file.symlink_to(symlink_target)
        return overlay_dir, sha256_bytes(symlink_target.read_bytes())
    content = b"def test_stub():\n    assert True\n"
    test_file.write_bytes(content)
    return overlay_dir, sha256_bytes(content)


def _write_fake_docker(tmp_path: Path, state: dict[str, Any]) -> tuple[Path, Path, Path]:
    """Create a POSIX executable fake docker CLI driven by a sibling state JSON."""
    script_path = tmp_path / "fake-docker"
    state_path = tmp_path / "fake-docker.state.json"
    log_path = tmp_path / "fake-docker.invocations.jsonl"
    state_path.write_text(json.dumps(state), encoding="utf-8")

    script_body = f"""#!{sys.executable}
import json
import sys
import time
from pathlib import Path

STATE_PATH = Path({str(state_path)!r})
LOG_PATH = Path({str(log_path)!r})

state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
args = sys.argv[1:]
with LOG_PATH.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(args) + "\\n")

if args[:2] == ["image", "inspect"]:
    if state.get("inspect_fail"):
        sys.stderr.write("Error: No such image\\n")
        sys.exit(1)
    sys.stdout.write(state.get("inspect_digest", {FAKE_IMAGE_DIGEST!r}) + "\\n")
    sys.exit(0)

if args[:1] == ["ps"]:
    cname = ""
    for item in args:
        if item.startswith("name="):
            cname = item.split("=", 1)[1].lstrip("^/").rstrip("$")
    running = state.get("leaked_containers", [])
    if cname and cname in running:
        sys.stdout.write("deadbeef1234\\n")
    sys.exit(0)

if args[:1] == ["rm"]:
    cname = args[-1]
    if state.get("rm_fail"):
        sys.stderr.write("Error: failed to remove container\\n")
        sys.exit(1)
    leaked = [c for c in state.get("leaked_containers", []) if c != cname]
    state["leaked_containers"] = leaked
    STATE_PATH.write_text(json.dumps(state), encoding="utf-8")
    sys.exit(0)

if args[:1] == ["run"]:
    cname = None
    if "--name" in args:
        idx = args.index("--name")
        if idx + 1 < len(args):
            cname = args[idx + 1]
    if state.get("leak_on_run") and cname:
        leaked = list(state.get("leaked_containers", []))
        leaked.append(cname)
        state["leaked_containers"] = leaked
        STATE_PATH.write_text(json.dumps(state), encoding="utf-8")

    delay = float(state.get("sleep_seconds", 0.0))
    if delay > 0:
        time.sleep(delay)

    mode = state.get("mode", "hypothesis_falsified")
    if mode == "smoke_passed":
        sys.stdout.write("collected 129 items\\n")
        sys.stdout.write("==== 129 passed in 2.10s ====\\n")
        sys.stdout.write("collected 122 items\\n")
        sys.stdout.write("==== 122 passed in 1.20s ====\\n")
        sys.stdout.write("ERROR: file or directory not found: /nonexistent-oss-scanner-test.py\\n")
        sys.exit(0)
    if mode == "baseline_failed":
        sys.stdout.write("collected 2 items\\n")
        sys.stdout.write(f"FAILED {POS_SEL}\\n")
        sys.stdout.write(f"PASSED {NEG_SEL}\\n")
        sys.stdout.write("==== 1 failed, 1 passed in 1.50s ====\\n")
        sys.exit(1)
    if mode == "deviation_reproduced":
        sys.stdout.write("collected 2 items\\n")
        sys.stdout.write(f"PASSED {POS_SEL}\\n")
        sys.stdout.write(f"FAILED {NEG_SEL}\\n")
        sys.stdout.write("==== 1 failed, 1 passed in 1.50s ====\\n")
        sys.exit(1)
    if mode == "hypothesis_falsified":
        selectors = []
        if "-rA" in args:
            selectors = args[args.index("-rA") + 1 :]
        sys.stdout.write(f"collected {{len(selectors)}} items\\n")
        for sel in selectors:
            sys.stdout.write(f"PASSED {{sel}}\\n")
        count = len(selectors)
        sys.stdout.write(f"==== {{count}} passed in 1.10s ====\\n")
        sys.exit(0)
    if mode == "not_executed":
        sys.stdout.write("collected 0 items\\n")
        sys.stdout.write("==== no tests ran in 0.12s ====\\n")
        sys.exit(5)
    if mode == "skipped":
        sys.stdout.write("collected 1 item\\n")
        sys.stdout.write(f"SKIPPED {POS_SEL}\\n")
        sys.stdout.write("==== 1 skipped in 0.25s ====\\n")
        sys.exit(0)
    if mode == "environment_failure":
        sys.stderr.write("docker: Error response from daemon: OCI runtime failed.\\n")
        sys.exit(125)
    if mode == "huge_output":
        selectors = args[args.index("-rA") + 1 :] if "-rA" in args else [POS_SEL, NEG_SEL]
        sys.stdout.write(f"collected {{len(selectors)}} items\\n")
        sys.stdout.write("X" * 16000 + "\\n")
        for sel in selectors:
            sys.stdout.write(f"PASSED {{sel}}\\n")
        sys.stdout.write(f"==== {{len(selectors)}} passed in 1.00s ====\\n")
        sys.exit(0)

sys.stderr.write(f"unsupported fake docker args: {{args!r}}\\n")
sys.exit(2)
"""
    script_path.write_text(script_body, encoding="utf-8")
    os.chmod(script_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)
    return script_path, state_path, log_path


def _build_profile(overlay_dir: Path, overlay_hash: str) -> VdpTargetProfile:
    return VdpTargetProfile(
        profile_name=WEBLATE_2026_11_2_PROFILE_NAME,
        image_ref=FAKE_IMAGE_REF,
        expected_image_digest=FAKE_IMAGE_DIGEST,
        expected_source_commit=FAKE_COMMIT,
        checkout_dir=None,
        allowed_test_selectors=(POS_SEL, NEG_SEL, EDIT_NEG_SEL, OVERLAY_POS_SEL, OVERLAY_NEG_SEL),
        positive_selectors=(POS_SEL, OVERLAY_POS_SEL),
        negative_selectors=(NEG_SEL, EDIT_NEG_SEL, OVERLAY_NEG_SEL),
        allowed_overlays={
            WEBLATE_W01_OVERLAY_BUNDLE: VdpOverlaySpec(
                bundle_name=WEBLATE_W01_OVERLAY_BUNDLE,
                host_dir=overlay_dir,
                container_target="/src/vdp-test-overlay",
                allowed_files={"test_w01.py": overlay_hash},
            )
        },
        max_cpus=2,
        max_memory_mb=6144,
        max_timeout_seconds=120,
    )


def _create_controller_with_fake_docker(
    tmp_path: Path,
    *,
    docker_state: dict[str, Any],
    max_output_bytes: int = 262_144,
    timeout_seconds: int = 30,
    overlay_dir: Path | None = None,
    overlay_hash: str | None = None,
):
    db_path = tmp_path / "harness.db"
    vault_root = tmp_path / "vault"
    storage = Storage(db_path)
    storage.initialize()
    controller = create_default_controller(
        storage=storage,
        vault_root=vault_root,
        cursor_hmac_key=secrets.token_bytes(32),
        allow_dynamic=True,
        include_scoped_http_probe=True,
        include_vdp_product_test=False,
        initialize=True,
    )

    if overlay_dir is None or overlay_hash is None:
        overlay_dir, overlay_hash = _setup_overlay(tmp_path)
    docker_bin, state_path, log_path = _write_fake_docker(tmp_path, docker_state)
    profile = _build_profile(overlay_dir, overlay_hash)
    desc = create_vdp_product_test_descriptor(
        enabled=True,
        limits=CapabilityLimits(
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            max_decode_bytes=65_536,
        ),
    )
    adapter = VdpProductTestAdapter(
        descriptor=desc,
        evidence_vault=controller.evidence_vault,
        runner=SubprocessRunner(),
        profiles={profile.profile_name: profile},
        docker_bin=str(docker_bin),
    )
    controller.register_adapter(adapter, tool_group="vdp.test", is_heavy_job=True)
    return controller, storage, state_path, log_path


def _base_vdp_args(**overrides: Any) -> dict[str, Any]:
    args: dict[str, Any] = {
        "target_profile": WEBLATE_2026_11_2_PROFILE_NAME,
        "source_commit": FAKE_COMMIT,
        "image_digest": FAKE_IMAGE_DIGEST,
        "test_selectors": [POS_SEL, NEG_SEL],
    }
    args.update(overrides)
    return args


def test_vdp_product_test_authorization_and_target_pinning(tmp_path: Path) -> None:
    controller, _, _, log_path = _create_controller_with_fake_docker(
        tmp_path,
        docker_state={"mode": "hypothesis_falsified"},
    )
    alice = _make_principal("alice")
    bob = _make_principal("bob")

    # 1. Offline CTF run cannot run vdp.test
    controller.create_run(
        principal=alice,
        task_id="t-off",
        run_id="run-off",
        mode=RunMode.OFFLINE_CTF,
        scope=_make_scope(
            mode=RunMode.OFFLINE_CTF,
            task_id="t-off",
            allowed_capabilities=("analysis.query", "vdp.test"),
            allowed_execution_classes=(ExecutionClass.STATIC, ExecutionClass.DYNAMIC),
        ),
        budget=BudgetSpec(max_tool_calls=10),
    )
    env_off = controller.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id="run-off",
            request_id="r-off",
            expected_revision=1,
            capability_name="vdp.test",
            operation="run_smoke",
            arguments={"target_profile": WEBLATE_2026_11_2_PROFILE_NAME, "source_commit": FAKE_COMMIT, "image_digest": FAKE_IMAGE_DIGEST},
        ),
    )
    assert env_off.status == EnvelopeStatus.DENIED
    assert env_off.error is not None
    assert env_off.error.code == "capability_denied"

    # 2. Scoped CTF run cannot run vdp.test
    controller.create_run(
        principal=alice,
        task_id="t-scoped",
        run_id="run-scoped",
        mode=RunMode.SCOPED_CTF,
        scope=_make_scope(
            mode=RunMode.SCOPED_CTF,
            task_id="t-scoped",
            allowed_capabilities=("analysis.query", "vdp.test"),
            allowed_execution_classes=(ExecutionClass.STATIC, ExecutionClass.DYNAMIC),
        ),
        budget=BudgetSpec(max_tool_calls=10),
    )
    env_scoped = controller.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id="run-scoped",
            request_id="r-scoped",
            expected_revision=1,
            capability_name="vdp.test",
            operation="run_smoke",
            arguments={"target_profile": WEBLATE_2026_11_2_PROFILE_NAME, "source_commit": FAKE_COMMIT, "image_digest": FAKE_IMAGE_DIGEST},
        ),
    )
    assert env_scoped.status == EnvelopeStatus.DENIED
    assert env_scoped.error is not None
    assert env_scoped.error.code == "capability_denied"

    # 3. VDP run without vdp.test in scope is denied & hidden in visible_capabilities
    controller.create_run(
        principal=alice,
        task_id="t-no-cap",
        run_id="run-no-cap",
        mode=RunMode.VDP,
        scope=_make_scope(mode=RunMode.VDP, task_id="t-no-cap", allowed_capabilities=("analysis.query", "net.probe")),
        budget=BudgetSpec(max_tool_calls=10),
    )
    desc_no_cap = controller.describe_run(principal=alice, run_id="run-no-cap")
    assert "vdp.test" not in desc_no_cap["visible_capabilities"]
    assert "net.probe" in desc_no_cap["visible_capabilities"]
    env_no_cap = controller.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id="run-no-cap",
            request_id="r-no-cap",
            expected_revision=1,
            capability_name="vdp.test",
            operation="run_smoke",
            arguments={"target_profile": WEBLATE_2026_11_2_PROFILE_NAME, "source_commit": FAKE_COMMIT, "image_digest": FAKE_IMAGE_DIGEST},
        ),
    )
    assert env_no_cap.status == EnvelopeStatus.DENIED
    assert env_no_cap.error is not None
    assert env_no_cap.error.code == "scope_denied"

    # 4. Authorized VDP run + cross-principal + pinning/allowlist rejections
    controller.create_run(
        principal=alice,
        task_id="t-vdp",
        run_id="run-vdp-auth",
        mode=RunMode.VDP,
        scope=_make_scope(mode=RunMode.VDP, task_id="t-vdp"),
        budget=BudgetSpec(max_tool_calls=30),
    )
    with pytest.raises(ScopeDeniedError):
        controller.execute_action(
            principal=bob,
            request=ActionRequest(
                run_id="run-vdp-auth",
                request_id="r-bob",
                expected_revision=1,
                capability_name="vdp.test",
                operation="run_smoke",
                arguments={"target_profile": WEBLATE_2026_11_2_PROFILE_NAME, "source_commit": FAKE_COMMIT, "image_digest": FAKE_IMAGE_DIGEST},
            ),
        )

    # Source commit mismatch
    rev = controller.runs.get_run_snapshot("run-vdp-auth").revision
    env_commit = controller.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id="run-vdp-auth",
            request_id="r-bad-commit",
            expected_revision=rev,
            capability_name="vdp.test",
            operation="run_smoke",
            arguments={"target_profile": WEBLATE_2026_11_2_PROFILE_NAME, "source_commit": "a" * 40, "image_digest": FAKE_IMAGE_DIGEST},
        ),
    )
    assert env_commit.status == EnvelopeStatus.DENIED
    assert env_commit.error is not None
    assert env_commit.error.code == "source_commit_mismatch"

    # Image digest mismatch in args
    rev = controller.runs.get_run_snapshot("run-vdp-auth").revision
    env_digest = controller.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id="run-vdp-auth",
            request_id="r-bad-digest",
            expected_revision=rev,
            capability_name="vdp.test",
            operation="run_smoke",
            arguments={"target_profile": WEBLATE_2026_11_2_PROFILE_NAME, "source_commit": FAKE_COMMIT, "image_digest": "sha256:" + "0" * 64},
        ),
    )
    assert env_digest.status == EnvelopeStatus.DENIED
    assert env_digest.error is not None
    assert env_digest.error.code == "image_digest_mismatch"

    # Non-"none" network_mode denied
    rev = controller.runs.get_run_snapshot("run-vdp-auth").revision
    env_net = controller.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id="run-vdp-auth",
            request_id="r-bad-net",
            expected_revision=rev,
            capability_name="vdp.test",
            operation="run_smoke",
            arguments={
                "target_profile": WEBLATE_2026_11_2_PROFILE_NAME,
                "source_commit": FAKE_COMMIT,
                "image_digest": FAKE_IMAGE_DIGEST,
                "network_mode": "bridge",
            },
        ),
    )
    assert env_net.status == EnvelopeStatus.DENIED
    assert env_net.error is not None
    assert env_net.error.code == "network_mode_denied"

    # Unallowlisted test_selector denied
    rev = controller.runs.get_run_snapshot("run-vdp-auth").revision
    env_sel = controller.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id="run-vdp-auth",
            request_id="r-bad-sel",
            expected_revision=rev,
            capability_name="vdp.test",
            operation="run_pytest",
            arguments=_base_vdp_args(test_selectors=["weblate/accounts/tests/test_other.py::Other::test_x"]),
        ),
    )
    assert env_sel.status == EnvelopeStatus.DENIED
    assert env_sel.error is not None
    assert env_sel.error.code == "selector_not_allowlisted"

    # Shell metacharacters / pytest flag-like selector rejected at schema validation
    rev = controller.runs.get_run_snapshot("run-vdp-auth").revision
    with pytest.raises(ContractViolationError):
        controller.execute_action(
            principal=alice,
            request=ActionRequest(
                run_id="run-vdp-auth",
                request_id="r-flag-sel",
                expected_revision=rev,
                capability_name="vdp.test",
                operation="run_pytest",
                arguments=_base_vdp_args(test_selectors=["-k;id"]),
            ),
        )

    # Unallowlisted overlay bundle rejected
    rev = controller.runs.get_run_snapshot("run-vdp-auth").revision
    env_ov = controller.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id="run-vdp-auth",
            request_id="r-bad-ov",
            expected_revision=rev,
            capability_name="vdp.test",
            operation="run_pytest",
            arguments=_base_vdp_args(overlay_bundle="rogue-bundle"),
        ),
    )
    assert env_ov.status == EnvelopeStatus.DENIED
    assert env_ov.error is not None
    assert env_ov.error.code == "overlay_not_allowlisted"

    # Docker CLI must never have been invoked for any rejected call
    assert not log_path.exists() or log_path.read_text(encoding="utf-8") == ""


def test_vdp_product_test_overlay_integrity_and_live_digest_mismatch(tmp_path: Path) -> None:
    overlay_dir, _ = _setup_overlay(tmp_path)
    initial_hash = sha256_bytes((overlay_dir / "test_w01.py").read_bytes())
    controller, _, state_path, _ = _create_controller_with_fake_docker(
        tmp_path,
        docker_state={"mode": "hypothesis_falsified"},
        overlay_dir=overlay_dir,
        overlay_hash=initial_hash,
    )
    alice = _make_principal("alice")
    controller.create_run(
        principal=alice,
        task_id="t-ov",
        run_id="run-ov",
        mode=RunMode.VDP,
        scope=_make_scope(mode=RunMode.VDP, task_id="t-ov"),
        budget=BudgetSpec(max_tool_calls=20),
    )

    # Overwrite overlay file -> SHA-256 mismatch
    (overlay_dir / "test_w01.py").write_bytes(b"def test_stub():\n    assert False\n")
    env_tamper = controller.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id="run-ov",
            request_id="r-tamper",
            expected_revision=1,
            capability_name="vdp.test",
            operation="run_pytest",
            arguments=_base_vdp_args(
                overlay_bundle=WEBLATE_W01_OVERLAY_BUNDLE,
                test_selectors=[OVERLAY_POS_SEL, OVERLAY_NEG_SEL],
            ),
        ),
    )
    assert env_tamper.status == EnvelopeStatus.DENIED
    assert env_tamper.error is not None
    assert env_tamper.error.code == "overlay_integrity_failed"

    # Symlinked overlay file -> rejected
    outside = tmp_path / "outside.py"
    outside.write_bytes(b"def test_stub():\n    assert True\n")
    (overlay_dir / "test_w01.py").unlink()
    (overlay_dir / "test_w01.py").symlink_to(outside)
    rev = controller.runs.get_run_snapshot("run-ov").revision
    env_sym = controller.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id="run-ov",
            request_id="r-sym",
            expected_revision=rev,
            capability_name="vdp.test",
            operation="run_pytest",
            arguments=_base_vdp_args(
                overlay_bundle=WEBLATE_W01_OVERLAY_BUNDLE,
                test_selectors=[OVERLAY_POS_SEL, OVERLAY_NEG_SEL],
            ),
        ),
    )
    assert env_sym.status == EnvelopeStatus.DENIED
    assert env_sym.error is not None
    assert env_sym.error.code == "overlay_integrity_failed"

    # Live docker image inspect returning wrong digest -> DENIED image_digest_mismatch
    state_path.write_text(
        json.dumps({"mode": "hypothesis_falsified", "inspect_digest": "sha256:" + "9" * 64}),
        encoding="utf-8",
    )
    rev = controller.runs.get_run_snapshot("run-ov").revision
    env_live = controller.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id="run-ov",
            request_id="r-live-mismatch",
            expected_revision=rev,
            capability_name="vdp.test",
            operation="run_pytest",
            arguments=_base_vdp_args(),
        ),
    )
    assert env_live.status == EnvelopeStatus.DENIED
    assert env_live.error is not None
    assert env_live.error.code == "image_digest_mismatch"


def test_vdp_product_test_verdicts_and_verifier_gates(tmp_path: Path) -> None:
    controller, _, state_path, log_path = _create_controller_with_fake_docker(
        tmp_path,
        docker_state={"mode": "smoke_passed"},
        timeout_seconds=1,
    )
    alice = _make_principal("alice")
    controller.create_run(
        principal=alice,
        task_id="t-verdicts",
        run_id="run-verdicts",
        mode=RunMode.VDP,
        scope=_make_scope(mode=RunMode.VDP, task_id="t-verdicts"),
        budget=BudgetSpec(max_tool_calls=50, action_timeout_seconds=5, run_budget_seconds=600),
    )

    def _run_case(req_id: str, mode_name: str, op: str = "run_pytest", extra_args: dict[str, Any] | None = None):
        if mode_name == "timeout":
            state_path.write_text(
                json.dumps({"mode": "hypothesis_falsified", "sleep_seconds": 3.0, "leak_on_run": True}),
                encoding="utf-8",
            )
        else:
            state_path.write_text(json.dumps({"mode": mode_name}), encoding="utf-8")
        rev = controller.runs.get_run_snapshot("run-verdicts").revision
        args = (
            {"target_profile": WEBLATE_2026_11_2_PROFILE_NAME, "source_commit": FAKE_COMMIT, "image_digest": FAKE_IMAGE_DIGEST}
            if op == "run_smoke"
            else _base_vdp_args(**(extra_args or {}))
        )
        return controller.execute_action(
            principal=alice,
            request=ActionRequest(
                run_id="run-verdicts",
                request_id=req_id,
                expected_revision=rev,
                capability_name="vdp.test",
                operation=op,
                arguments=args,
            ),
        )

    # 1. Smoke passed
    env_smoke = _run_case("r-smoke", "smoke_passed", op="run_smoke")
    assert env_smoke.status == EnvelopeStatus.OK
    assert "smoke_passed" in env_smoke.summary
    smoke_eid = env_smoke.evidence[0].id

    # 2. Positive fails while negative passes -> MUST be baseline_failed, NEVER hypothesis_falsified
    env_base_fail = _run_case("r-base-fail", "baseline_failed")
    assert env_base_fail.status == EnvelopeStatus.OK
    assert "baseline_failed" in env_base_fail.summary
    assert "hypothesis_falsified" not in env_base_fail.summary
    base_fail_eid = env_base_fail.evidence[0].id

    ver_base_fail = controller.verify_run(
        principal=alice,
        run_id="run-verdicts",
        verifier_id="vdp.product_test",
        evidence_ids=(smoke_eid, base_fail_eid),
        claim="hypothesis_falsified",
    )
    assert ver_base_fail.status == VerificationStatus.FAILED
    assert "outcome_state:baseline_failed" in ver_base_fail.checks_performed

    # 3. Distinct inconclusive states: not_executed, skipped, timeout, environment_failure
    env_not_exec = _run_case("r-0coll", "not_executed")
    assert "not_executed" in env_not_exec.summary
    ver_not_exec = controller.verify_run(
        principal=alice,
        run_id="run-verdicts",
        verifier_id="vdp.product_test",
        evidence_ids=(smoke_eid, env_not_exec.evidence[0].id),
    )
    assert ver_not_exec.status == VerificationStatus.INCONCLUSIVE
    assert "outcome_state:not_executed" in ver_not_exec.checks_performed

    env_skip = _run_case("r-skip", "skipped")
    assert "skipped" in env_skip.summary
    ver_skip = controller.verify_run(
        principal=alice,
        run_id="run-verdicts",
        verifier_id="vdp.product_test",
        evidence_ids=(smoke_eid, env_skip.evidence[0].id),
    )
    assert ver_skip.status == VerificationStatus.INCONCLUSIVE
    assert "outcome_state:skipped" in ver_skip.checks_performed

    env_to = _run_case("r-to", "timeout", extra_args={"timeout_seconds": 5})
    assert env_to.status == EnvelopeStatus.TIMEOUT
    assert '["rm", "-f"' in log_path.read_text(encoding="utf-8")
    ver_to = controller.verify_run(
        principal=alice,
        run_id="run-verdicts",
        verifier_id="vdp.product_test",
        evidence_ids=(smoke_eid, env_to.evidence[0].id),
    )
    assert ver_to.status == VerificationStatus.INCONCLUSIVE
    assert "outcome_state:timeout" in ver_to.checks_performed

    env_env = _run_case("r-env", "environment_failure")
    assert env_env.status == EnvelopeStatus.TOOL_ERROR
    ver_env = controller.verify_run(
        principal=alice,
        run_id="run-verdicts",
        verifier_id="vdp.product_test",
        evidence_ids=(smoke_eid, env_env.evidence[0].id),
    )
    assert ver_env.status == VerificationStatus.INCONCLUSIVE
    assert "outcome_state:environment_failure" in ver_env.checks_performed

    # 4. Hypothesis falsified without smoke fails verifier; WITH smoke passes verifier
    env_hyp = _run_case("r-hyp", "hypothesis_falsified")
    assert "hypothesis_falsified" in env_hyp.summary
    hyp_eid = env_hyp.evidence[0].id

    ver_no_smoke = controller.verify_run(
        principal=alice,
        run_id="run-verdicts",
        verifier_id="vdp.product_test",
        evidence_ids=(hyp_eid,),
        claim="hypothesis_falsified",
    )
    assert ver_no_smoke.status == VerificationStatus.FAILED
    assert "smoke_receipt:missing" in ver_no_smoke.checks_performed

    ver_ok = controller.verify_run(
        principal=alice,
        run_id="run-verdicts",
        verifier_id="vdp.product_test",
        evidence_ids=(smoke_eid, hyp_eid),
        claim="hypothesis_falsified",
    )
    assert ver_ok.status == VerificationStatus.PASSED
    assert "outcome_state:hypothesis_falsified" in ver_ok.checks_performed

    # 5. Deviation reproduced + verifier PASSED
    env_repro = _run_case("r-repro", "deviation_reproduced")
    assert "deviation_reproduced" in env_repro.summary
    repro_eid = env_repro.evidence[0].id
    ver_repro = controller.verify_run(
        principal=alice,
        run_id="run-verdicts",
        verifier_id="vdp.product_test",
        evidence_ids=(smoke_eid, repro_eid),
        claim="deviation_reproduced",
    )
    assert ver_repro.status == VerificationStatus.PASSED
    assert "outcome_state:deviation_reproduced" in ver_repro.checks_performed

    # 6. Non-product-test JSON evidence (simulating net.probe HTTP 200) MUST NOT pass vdp.product_test
    probe_manifest = controller.evidence_vault.store_raw(
        run_id="run-verdicts",
        owner_principal_id="alice",
        action_id=env_smoke.action_id,
        data=json.dumps({"url": "http://127.0.0.1:8000/", "status_code": 200}).encode("utf-8"),
        media_type="application/json; charset=utf-8",
        capture_complete=True,
        omission_reason=None,
        source_artifact_hashes=(),
        adapter_revision="probe-test",
        sanitized_args_sha256="0" * 64,
    )
    ver_http200 = controller.verify_run(
        principal=alice,
        run_id="run-verdicts",
        verifier_id="vdp.product_test",
        evidence_ids=(probe_manifest.evidence_id,),
    )
    assert ver_http200.status == VerificationStatus.FAILED
    assert "http_200_rejected_as_product_verification" in ver_http200.checks_performed


def test_vdp_product_test_retry_truncation_and_close_integrity(tmp_path: Path) -> None:
    controller, _, state_path, log_path = _create_controller_with_fake_docker(
        tmp_path,
        docker_state={"mode": "hypothesis_falsified"},
        max_output_bytes=4096,
    )
    alice = _make_principal("alice")
    controller.create_run(
        principal=alice,
        task_id="t-lifecycle",
        run_id="run-lifecycle",
        mode=RunMode.VDP,
        scope=_make_scope(mode=RunMode.VDP, task_id="t-lifecycle"),
        budget=BudgetSpec(max_tool_calls=20),
    )

    # 1. Idempotent retry on same request_id
    env1 = controller.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id="run-lifecycle",
            request_id="req-idem",
            expected_revision=1,
            capability_name="vdp.test",
            operation="run_pytest",
            arguments=_base_vdp_args(),
        ),
    )
    run_calls_before = sum(1 for line in log_path.read_text(encoding="utf-8").splitlines() if '["run"' in line)
    calls_left_1 = controller.describe_run(principal=alice, run_id="run-lifecycle")["budget"]["remaining_calls"]

    env2 = controller.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id="run-lifecycle",
            request_id="req-idem",
            expected_revision=1,
            capability_name="vdp.test",
            operation="run_pytest",
            arguments=_base_vdp_args(),
        ),
    )
    assert env2.action_id == env1.action_id
    assert env2.evidence == env1.evidence
    run_calls_after = sum(1 for line in log_path.read_text(encoding="utf-8").splitlines() if '["run"' in line)
    assert run_calls_after == run_calls_before
    assert controller.describe_run(principal=alice, run_id="run-lifecycle")["budget"]["remaining_calls"] == calls_left_1

    # 2. Log truncation preserves valid JSON + marks capture_complete=False
    state_path.write_text(json.dumps({"mode": "huge_output"}), encoding="utf-8")
    rev = controller.runs.get_run_snapshot("run-lifecycle").revision
    env_huge = controller.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id="run-lifecycle",
            request_id="req-huge",
            expected_revision=rev,
            capability_name="vdp.test",
            operation="run_pytest",
            arguments=_base_vdp_args(),
        ),
    )
    assert env_huge.truncated is True
    page = controller.read_evidence(
        principal=alice,
        run_id="run-lifecycle",
        evidence_id=env_huge.evidence[0].id,
    )
    assert page.capture_complete is False
    assert page.omission_reason is not None
    chunks = [page.content]
    while page.next_cursor is not None:
        page = controller.read_evidence(
            principal=alice,
            run_id="run-lifecycle",
            evidence_id=env_huge.evidence[0].id,
            cursor=page.next_cursor,
        )
        chunks.append(page.content)
    parsed_trunc = json.loads("".join(chunks))
    assert parsed_trunc["log_truncated"] is True

    # Verifier rejects incomplete capture
    ver_incomplete = controller.verify_run(
        principal=alice,
        run_id="run-lifecycle",
        verifier_id="vdp.product_test",
        evidence_ids=(env_huge.evidence[0].id,),
    )
    assert ver_incomplete.status == VerificationStatus.FAILED
    assert "capture_completeness:incomplete" in ver_incomplete.checks_performed

    # 3. Unconfirmed container cleanup blocks close_run until recover_guest_ready
    state_path.write_text(
        json.dumps({"mode": "hypothesis_falsified", "leak_on_run": True, "rm_fail": True}),
        encoding="utf-8",
    )
    rev = controller.runs.get_run_snapshot("run-lifecycle").revision
    env_uncleaned = controller.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id="run-lifecycle",
            request_id="req-uncleaned",
            expected_revision=rev,
            capability_name="vdp.test",
            operation="run_pytest",
            arguments=_base_vdp_args(),
        ),
    )
    assert env_uncleaned.error is not None
    assert env_uncleaned.error.code == "cleanup_unconfirmed"
    desc_uncleaned = controller.describe_run(principal=alice, run_id="run-lifecycle")
    assert desc_uncleaned["guest_health"] == "cleanup_unconfirmed"

    with pytest.raises(GuestBlockedError):
        controller.close_run(principal=alice, run_id="run-lifecycle")

    # Recover guest once operator verifies cleanup, then close_run succeeds
    controller.recover_guest_ready(
        run_id="run-lifecycle",
        cleanup_verified=True,
        note="Operator removed container",
    )
    closed_ok = controller.close_run(principal=alice, run_id="run-lifecycle")
    assert closed_ok.integrity_report.close_allowed is True
    assert closed_ok.integrity_report.cleanup_confirmed is True
    assert controller.runs.get_run_snapshot("run-lifecycle").manifest.closed_at is not None


def test_update_scope_cli_and_mcp_vdp_test_visibility(tmp_path: Path) -> None:
    db_path = tmp_path / "cli.db"
    vault_root = tmp_path / "vault"
    cfg_path = tmp_path / "config.vdp.json"
    hmac_hex = secrets.token_hex(32)
    cfg = {
        "schema_version": "1",
        "executable": True,
        "profile": "vdp",
        "description": "VDP CLI + update-scope test.",
        "client": {
            "kind": "OPERATOR_SELECTED",
            "model_label": "codex-p7-cli",
            "instruction_revision": "inst-p7-v1",
        },
        "scope": {
            "task_id": "task-p7-cli",
            "revision": "scope-p7-v1",
            "authorization_reference": "owned-p7-cli",
            "expires_at": None,
        },
        "network": {
            "enabled": True,
            "allowed_targets": ["http://127.0.0.1:8000"],
            "external_submission": False,
        },
        "execution": {
            "adapters_enabled": [
                "ctf-static-inspector",
                "ctf-scoped-http-probe",
                "ctf-vdp-product-test",
            ],
            "arbitrary_shell": False,
            "dynamic_execution": True,
            "heavy_job_concurrency": 1,
            "interactive_session_limit": 2,
            "action_timeout_seconds": 30,
            "session_idle_seconds": 900,
            "run_budget_seconds": 600,
            "max_tool_calls": 40,
            "max_output_chars_per_page": 4000,
            "max_evidence_bytes_per_run": 1048576,
        },
        "evidence": {
            "storage": "private_vault",
            "cross_run_access": False,
            "automatic_git_export": False,
            "retention_policy_reference": "local-retention-p7-v1",
            "audit_raw_output": False,
        },
        "acceptance": {
            "require_pinned_revisions": True,
            "require_scope_validation": True,
            "require_registered_verifier": True,
        },
    }
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")

    # Create VDP run initially without vdp.test
    rc_create = admin_main(
        [
            "create-run",
            "--db-path",
            str(db_path),
            "--vault-root",
            str(vault_root),
            "--config",
            str(cfg_path),
            "--run-id",
            "run-vdp-cli",
            "--mode",
            "vdp",
            "--allowed-capabilities",
            "analysis.query,net.probe",
            "--allowed-execution-classes",
            "static,dynamic,network",
            "--network-enabled",
            "--allowed-target",
            "http://127.0.0.1:8000",
        ],
        env={"CTF_MCP_CURSOR_HMAC_KEY": hmac_hex},
    )
    assert rc_create == 0

    srv1 = build_server_from_env(
        {
            "CTF_MCP_DB_PATH": str(db_path),
            "CTF_MCP_VAULT_ROOT": str(vault_root),
            "CTF_MCP_CURSOR_HMAC_KEY": hmac_hex,
            "CTF_MCP_ALLOW_DYNAMIC": "1",
        },
        config_path=cfg_path,
    )
    srv1.set_active_run("run-vdp-cli")
    rev_before = srv1.controller.runs.get_run_snapshot("run-vdp-cli").revision

    async def _list_tools_before() -> set[str]:
        async with Client(srv1.mcp) as client:
            return {t.name for t in await client.list_tools()}

    tools_before = anyio.run(_list_tools_before)
    assert "net.probe" in tools_before
    assert "vdp.test" not in tools_before

    # Update scope via CLI without incrementing revision
    rc_up = admin_main(
        [
            "update-scope",
            "--db-path",
            str(db_path),
            "--vault-root",
            str(vault_root),
            "--run-id",
            "run-vdp-cli",
            "--scope-revision",
            "scope-p7-v2",
            "--add-capability",
            "vdp.test",
        ],
        env={"CTF_MCP_CURSOR_HMAC_KEY": hmac_hex},
    )
    assert rc_up == 0
    assert srv1.controller.runs.get_run_snapshot("run-vdp-cli").revision == rev_before

    srv2 = build_server_from_env(
        {
            "CTF_MCP_DB_PATH": str(db_path),
            "CTF_MCP_VAULT_ROOT": str(vault_root),
            "CTF_MCP_CURSOR_HMAC_KEY": hmac_hex,
            "CTF_MCP_ALLOW_DYNAMIC": "1",
        },
        config_path=cfg_path,
    )
    srv2.set_active_run("run-vdp-cli")

    async def _list_tools_after() -> set[str]:
        async with Client(srv2.mcp) as client:
            return {t.name for t in await client.list_tools()}

    tools_after = anyio.run(_list_tools_after)
    assert "net.probe" in tools_after
    assert "vdp.test" in tools_after
    assert "analysis.query" in tools_after


def test_p8_describe_profile_and_run_describe_omit_host_paths(tmp_path: Path) -> None:
    controller, _, _, log_path = _create_controller_with_fake_docker(
        tmp_path,
        docker_state={"mode": "hypothesis_falsified"},
    )
    alice = _make_principal("alice")
    controller.create_run(
        principal=alice,
        task_id="t-p8-desc",
        run_id="run-p8-desc",
        mode=RunMode.VDP,
        scope=_make_scope(mode=RunMode.VDP, task_id="t-p8-desc"),
        budget=BudgetSpec(max_tool_calls=10),
    )

    desc = controller.describe_run(principal=alice, run_id="run-p8-desc")
    assert "vdp_profiles" in desc
    profiles = desc["vdp_profiles"]
    assert len(profiles) == 1
    p_meta = profiles[0]
    assert p_meta["profile_name"] == WEBLATE_2026_11_2_PROFILE_NAME
    assert p_meta["profile_revision"] == WEBLATE_2026_11_2_PROFILE_REVISION
    assert p_meta["expected_source_commit"] == FAKE_COMMIT
    assert p_meta["expected_image_digest"] == FAKE_IMAGE_DIGEST
    assert p_meta["network_mode"] == "none"
    assert "host_dir" not in json.dumps(p_meta)
    assert "checkout_dir" not in json.dumps(p_meta)

    env = controller.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id="run-p8-desc",
            request_id="req-desc-prof",
            expected_revision=1,
            capability_name="vdp.test",
            operation="describe_profile",
            arguments={"target_profile": WEBLATE_2026_11_2_PROFILE_NAME},
        ),
    )
    assert env.status == EnvelopeStatus.OK
    assert env.truncated is False
    assert not log_path.exists()
    ev_page = controller.read_evidence(
        principal=alice,
        run_id="run-p8-desc",
        evidence_id=env.evidence[0].id,
    )
    parsed = json.loads(ev_page.content)
    assert parsed["schema"] == "vdp-profile-description/1"
    assert parsed["profile_name"] == WEBLATE_2026_11_2_PROFILE_NAME
    assert parsed["network_mode"] == "none"
    assert WEBLATE_W01_OVERLAY_BUNDLE in parsed["allowed_overlays"]
    assert "host_dir" not in parsed
    assert "checkout_dir" not in parsed

    # Non-VDP runs must not expose vdp_profiles in describe_run
    controller.create_run(
        principal=alice,
        task_id="t-p8-ctf",
        run_id="run-p8-ctf",
        mode=RunMode.OFFLINE_CTF,
        scope=_make_scope(
            mode=RunMode.OFFLINE_CTF,
            task_id="t-p8-ctf",
            allowed_capabilities=("analysis.query",),
            allowed_execution_classes=(ExecutionClass.STATIC,),
        ),
        budget=BudgetSpec(max_tool_calls=5),
    )
    assert "vdp_profiles" not in controller.describe_run(principal=alice, run_id="run-p8-ctf")


def test_p8_register_vdp_profile_cli_and_wildcard_rejection(tmp_path: Path) -> None:
    vault_root = tmp_path / "vault"
    db_path = tmp_path / "harness.db"
    overlay_dir = tmp_path / "ov" / WEBLATE_W02_OVERLAY_BUNDLE
    overlay_dir.mkdir(parents=True, exist_ok=True)
    w02_bytes = b"def test_w02_stub():\n    assert True\n"
    (overlay_dir / "test_w02.py").write_bytes(w02_bytes)
    w02_sha = sha256_bytes(w02_bytes)

    rc = admin_main(
        [
            "register-vdp-profile",
            "--vault-root",
            str(vault_root),
            "--profile-name",
            WEBLATE_2026_11_2_PROFILE_NAME,
            "--profile-revision",
            "weblate-2026.11.2-r9",
            "--overlay-bundle",
            WEBLATE_W02_OVERLAY_BUNDLE,
            "--overlay-host-dir",
            str(overlay_dir),
            "--overlay-file-sha256",
            f"test_w02.py={w02_sha}",
            "--expires-at",
            "2027-02-01T00:00:00Z",
        ]
    )
    assert rc == 0

    loaded = load_registered_vdp_profiles(vault_root)
    assert WEBLATE_2026_11_2_PROFILE_NAME in loaded
    prof = loaded[WEBLATE_2026_11_2_PROFILE_NAME]
    assert prof.profile_revision == "weblate-2026.11.2-r9"
    assert _WEBLATE_W02_UPSTREAM_NEG in prof.allowed_test_selectors
    assert _WEBLATE_W02_UPSTREAM_COMPACTED in prof.allowed_test_selectors
    assert _WEBLATE_W02_OVERLAY_SCOPE in prof.allowed_test_selectors
    assert prof.allowed_overlays[WEBLATE_W02_OVERLAY_BUNDLE].allowed_files["test_w02.py"] == w02_sha

    # Controller built against vault_root picks up registered profile automatically.
    controller = create_default_controller(
        storage=Storage(db_path),
        vault_root=vault_root,
        cursor_hmac_key=secrets.token_bytes(32),
        allow_dynamic=True,
        include_vdp_product_test=True,
        initialize=True,
    )
    alice = _make_principal("alice")
    controller.create_run(
        principal=alice,
        task_id="t-p8-reg",
        run_id="run-p8-reg",
        mode=RunMode.VDP,
        scope=_make_scope(mode=RunMode.VDP, task_id="t-p8-reg"),
        budget=BudgetSpec(max_tool_calls=5),
    )
    desc = controller.describe_run(principal=alice, run_id="run-p8-reg")
    assert desc["vdp_profiles"][0]["profile_revision"] == "weblate-2026.11.2-r9"

    # Wildcard / flag / whole-directory / bad digest inputs must be rejected fail-closed.
    for bad_sel in ("weblate/*.py::TestA", "-k test_foo", "weblate/api"):
        assert (
            admin_main(
                [
                    "register-vdp-profile",
                    "--vault-root",
                    str(vault_root),
                    "--profile-name",
                    "custom-bad",
                    "--image-ref",
                    FAKE_IMAGE_REF,
                    "--image-digest",
                    FAKE_IMAGE_DIGEST,
                    "--source-commit",
                    FAKE_COMMIT,
                    "--allow-selector",
                    bad_sel,
                ]
            )
            == 2
        )
    assert (
        admin_main(
            [
                "register-vdp-profile",
                "--vault-root",
                str(vault_root),
                "--profile-name",
                "custom-bad-sha",
                "--image-ref",
                FAKE_IMAGE_REF,
                "--image-digest",
                FAKE_IMAGE_DIGEST,
                "--source-commit",
                FAKE_COMMIT,
                "--allow-selector",
                POS_SEL,
                "--overlay-bundle",
                "w02-bad",
                "--overlay-host-dir",
                str(overlay_dir),
                "--overlay-file-sha256",
                "test_w02.py=not-a-sha256",
            ]
        )
        == 2
    )


def test_p8_w02_overlay_blocked_env_and_provenance_enforcement(tmp_path: Path) -> None:
    # 1. Missing Docker -> BLOCKED_ENV and INCONCLUSIVE verification
    db_path = tmp_path / "blocked.db"
    vault_root = tmp_path / "blocked_vault"
    storage = Storage(db_path)
    storage.initialize()
    controller = create_default_controller(
        storage=storage,
        vault_root=vault_root,
        cursor_hmac_key=secrets.token_bytes(32),
        allow_dynamic=True,
        include_vdp_product_test=False,
        initialize=True,
    )
    overlay_dir = tmp_path / "ov_w02" / WEBLATE_W02_OVERLAY_BUNDLE
    overlay_dir.mkdir(parents=True, exist_ok=True)
    w02_bytes = b"def test_w02():\n    assert True\n"
    (overlay_dir / "test_w02.py").write_bytes(w02_bytes)
    w02_sha = sha256_bytes(w02_bytes)
    default_prof = build_default_weblate_profile()
    prof = default_prof.model_copy(
        update={
            "allowed_overlays": {
                WEBLATE_W02_OVERLAY_BUNDLE: VdpOverlaySpec(
                    bundle_name=WEBLATE_W02_OVERLAY_BUNDLE,
                    host_dir=overlay_dir,
                    container_target="/src/vdp-test-overlay",
                    allowed_files={"test_w02.py": w02_sha},
                )
            }
        }
    )
    adapter_nodocker = VdpProductTestAdapter(
        descriptor=create_vdp_product_test_descriptor(enabled=True),
        evidence_vault=controller.evidence_vault,
        runner=SubprocessRunner(),
        profiles={prof.profile_name: prof},
        docker_bin="/nonexistent/docker-missing",
    )
    controller.register_adapter(adapter_nodocker, tool_group="vdp.test", is_heavy_job=True)
    alice = _make_principal("alice")
    controller.create_run(
        principal=alice,
        task_id="t-p8-blk",
        run_id="run-p8-blk",
        mode=RunMode.VDP,
        scope=_make_scope(mode=RunMode.VDP, task_id="t-p8-blk"),
        budget=BudgetSpec(max_tool_calls=10),
    )
    env_blk = controller.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id="run-p8-blk",
            request_id="req-blk",
            expected_revision=1,
            capability_name="vdp.test",
            operation="run_smoke",
            arguments={
                "target_profile": WEBLATE_2026_11_2_PROFILE_NAME,
                "source_commit": FAKE_COMMIT,
                "image_digest": FAKE_IMAGE_DIGEST,
            },
        ),
    )
    assert env_blk.status == EnvelopeStatus.TOOL_ERROR
    assert env_blk.error is not None
    assert env_blk.error.code == "BLOCKED_ENV"
    ver_blk = controller.verify_run(
        principal=alice,
        run_id="run-p8-blk",
        verifier_id="vdp.product_test",
        evidence_ids=(env_blk.evidence[0].id,),
    )
    assert ver_blk.status == VerificationStatus.INCONCLUSIVE
    assert "outcome_state:environment_failure" in ver_blk.checks_performed

    # 2. Fake docker: self-contained W-02 positive+negative selector -> hypothesis_falsified + provenance
    w02_work = tmp_path / "w02_ok"
    w02_work.mkdir()
    ctrl2, _, state_path2, _ = _create_controller_with_fake_docker(
        w02_work,
        docker_state={"mode": "smoke_passed"},
        overlay_dir=overlay_dir,
        overlay_hash=w02_sha,
    )
    docker_bin2 = str(w02_work / "fake-docker")
    adapter2 = VdpProductTestAdapter(
        descriptor=create_vdp_product_test_descriptor(enabled=True),
        evidence_vault=ctrl2.evidence_vault,
        runner=SubprocessRunner(),
        profiles={prof.profile_name: prof},
        docker_bin=docker_bin2,
    )
    ctrl2.register_adapter(adapter2, tool_group="vdp.test", is_heavy_job=True)
    ctrl2.create_run(
        principal=alice,
        task_id="t-p8-w02",
        run_id="run-p8-w02",
        mode=RunMode.VDP,
        scope=_make_scope(mode=RunMode.VDP, task_id="t-p8-w02"),
        budget=BudgetSpec(max_tool_calls=10),
    )
    smoke_env = ctrl2.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id="run-p8-w02",
            request_id="req-smoke-w02",
            expected_revision=1,
            capability_name="vdp.test",
            operation="run_smoke",
            arguments={
                "target_profile": WEBLATE_2026_11_2_PROFILE_NAME,
                "source_commit": FAKE_COMMIT,
                "image_digest": FAKE_IMAGE_DIGEST,
            },
        ),
    )
    assert smoke_env.status == EnvelopeStatus.OK
    state_path2.write_text(json.dumps({"mode": "hypothesis_falsified"}), encoding="utf-8")
    w02_env = ctrl2.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id="run-p8-w02",
            request_id="req-pytest-w02",
            expected_revision=2,
            capability_name="vdp.test",
            operation="run_pytest",
            arguments={
                "target_profile": WEBLATE_2026_11_2_PROFILE_NAME,
                "source_commit": FAKE_COMMIT,
                "image_digest": FAKE_IMAGE_DIGEST,
                "test_selectors": [_WEBLATE_W02_OVERLAY_SCOPE],
                "overlay_bundle": WEBLATE_W02_OVERLAY_BUNDLE,
            },
        ),
    )
    assert w02_env.status == EnvelopeStatus.OK
    w02_payload = json.loads(
        ctrl2.read_evidence(principal=alice, run_id="run-p8-w02", evidence_id=w02_env.evidence[0].id).content
    )
    assert w02_payload["profile_revision"] == WEBLATE_2026_11_2_PROFILE_REVISION
    assert w02_payload["execution_provenance"] == "harness_docker_isolated"
    assert w02_payload["verdict"] == "hypothesis_falsified"
    ver_w02 = ctrl2.verify_run(
        principal=alice,
        run_id="run-p8-w02",
        verifier_id="vdp.product_test",
        evidence_ids=(smoke_env.evidence[0].id, w02_env.evidence[0].id),
    )
    assert ver_w02.status == VerificationStatus.PASSED

    # 3. Tampered W-02 overlay file must fail SHA-256 verification before container launch
    (overlay_dir / "test_w02.py").write_bytes(b"def test_tampered():\n    assert False\n")
    tampered_env = ctrl2.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id="run-p8-w02",
            request_id="req-w02-tamper",
            expected_revision=3,
            capability_name="vdp.test",
            operation="run_pytest",
            arguments={
                "target_profile": WEBLATE_2026_11_2_PROFILE_NAME,
                "source_commit": FAKE_COMMIT,
                "image_digest": FAKE_IMAGE_DIGEST,
                "test_selectors": [_WEBLATE_W02_OVERLAY_SCOPE],
                "overlay_bundle": WEBLATE_W02_OVERLAY_BUNDLE,
            },
        ),
    )
    assert tampered_env.status == EnvelopeStatus.DENIED
    assert tampered_env.error is not None

    # 4. External/manual execution provenance must be rejected by VdpProductTestVerifier
    valid_aid = ctrl2.actions.list_actions("run-p8-w02")[0].action_id
    spoofed_man = ctrl2.evidence_vault.store_raw(
        run_id="run-p8-w02",
        owner_principal_id=alice.principal_id,
        action_id=valid_aid,
        data=json.dumps(
            {
                **w02_payload,
                "execution_provenance": "manual_host_script",
            }
        ).encode("utf-8"),
        media_type="application/json",
        capture_complete=True,
        omission_reason=None,
        source_artifact_hashes=(),
        adapter_revision="manual",
        sanitized_args_sha256="0" * 64,
    )
    ver_spoof = ctrl2.verify_run(
        principal=alice,
        run_id="run-p8-w02",
        verifier_id="vdp.product_test",
        evidence_ids=(smoke_env.evidence[0].id, spoofed_man.evidence_id),
    )
    assert ver_spoof.status == VerificationStatus.FAILED
    assert "execution_provenance:unverified_external" in ver_spoof.checks_performed
