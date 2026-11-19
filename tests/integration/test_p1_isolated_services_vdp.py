"""Integration tests for bounded offline internal-service VDP product tests (`isolated_internal_services`)."""

from __future__ import annotations

import json
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from ctf_mcp.adapters.runner import SubprocessRunner
from ctf_mcp.adapters.vdp_product_test import (
    WEBLATE_2026_11_2_IMAGE_DIGEST,
    WEBLATE_2026_11_2_SOURCE_COMMIT,
    VdpOverlaySpec,
    VdpProductTestAdapter,
    VdpServiceSpec,
    VdpTargetProfile,
    create_vdp_product_test_descriptor,
    validate_vdp_profile_registration,
)
from ctf_mcp.contracts import (
    ActionRequest,
    BudgetSpec,
    CapabilityLimits,
    ContractViolationError,
    EnvelopeStatus,
    ExecutionClass,
    PrincipalContext,
    RunMode,
    ScopePolicy,
    VerificationStatus,
    canonical_digest,
    sha256_bytes,
)
from ctf_mcp.controller import create_default_controller
from ctf_mcp.storage import Storage
from ctf_mcp.verification.vdp_product_test import VdpProductTestVerifier

PINNED_IMG = "weblate-oss-scanner:2026.11.2"
PINNED_DIGEST = WEBLATE_2026_11_2_IMAGE_DIGEST
PINNED_COMMIT = WEBLATE_2026_11_2_SOURCE_COMMIT
SVC_IMAGE = "postgres-isolated:18"
SVC_DIGEST = "sha256:" + ("a" * 64)

SMOKE_SEL = "/src/vdp-test-overlay/test_g01_pg.py::test_pg_connectivity"
POS_SEL = "/src/vdp-test-overlay/test_g01_pg.py::test_public_child_positive_control"
DEF_SEL = "/src/vdp-test-overlay/test_g01_pg.py::test_external_egress_blocked"
ANOM_SEL = "/src/vdp-test-overlay/test_g01_pg.py::test_public_child_git_301_leaks_private_parent_slug"


def _make_principal() -> PrincipalContext:
    return PrincipalContext(
        principal_id="local-operator",
        auth_method="stdio_local",
        client_kind="OPERATOR_SELECTED",
        model_label="p1-svc-test",
    )


def _make_scope() -> ScopePolicy:
    now = datetime.now(UTC)
    payload = {
        "mode": "vdp",
        "task_id": "task-p1-svc",
        "scope_revision": "scope-p1-svc-v1",
        "authorization_reference": "owned-p1-svc",
        "allowed_capabilities": ["vdp.test"],
        "allowed_execution_classes": ["static", "dynamic"],
        "expires_at": (now + timedelta(hours=2)).isoformat(),
        "network_enabled": False,
        "allowed_targets": [],
        "external_submission": False,
    }
    return ScopePolicy(
        scope_revision="scope-p1-svc-v1",
        scope_sha256=canonical_digest(payload),
        mode=RunMode.VDP,
        task_id="task-p1-svc",
        authorization_reference="owned-p1-svc",
        allowed_execution_classes=(ExecutionClass.STATIC, ExecutionClass.DYNAMIC),
        allowed_capabilities=("vdp.test",),
        expires_at=now + timedelta(hours=2),
        network_enabled=False,
        allowed_targets=(),
        external_submission=False,
    )


def _make_overlay(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    overlay_dir = tmp_path / "overlays" / "g01_pg_bundle"
    overlay_dir.mkdir(parents=True, exist_ok=True)
    test_file = overlay_dir / "test_g01_pg.py"
    raw = b"def test_pg_connectivity(): assert True\n"
    test_file.write_bytes(raw)
    return overlay_dir, {"test_g01_pg.py": sha256_bytes(raw)}


def _make_service_profile(tmp_path: Path) -> VdpTargetProfile:
    overlay_dir, hashes = _make_overlay(tmp_path)
    return VdpTargetProfile(
        profile_name="weblate-2026.11.2-pg-synthetic",
        profile_revision="vdp-pg-test/1",
        image_ref=PINNED_IMG,
        expected_image_digest=PINNED_DIGEST,
        expected_source_commit=PINNED_COMMIT,
        network_mode="isolated_internal_services",
        runner_mode="direct_pytest",
        pytest_executable="/opt/oss-scanner/venv/bin/pytest",
        smoke_selectors=(SMOKE_SEL,),
        services=(
            VdpServiceSpec(
                name="db",
                service_kind="postgres",
                image_ref=SVC_IMAGE,
                expected_image_digest=SVC_DIGEST,
                internal_port=5432,
                publish_ports=False,
                env={"POSTGRES_DB": "weblate_synth"},
                client_env={"PGHOST": "db", "PGPORT": "5432"},
                readiness_command=("pg_isready", "-h", "127.0.0.1"),
                readiness_timeout_seconds=10,
                cpus=1,
                memory_mb=512,
            ),
        ),
        allowed_overlays={
            "g01_pg_bundle": VdpOverlaySpec(
                bundle_name="g01_pg_bundle",
                host_dir=overlay_dir,
                allowed_files=hashes,
            )
        },
        positive_selectors=(POS_SEL,),
        negative_selectors=(DEF_SEL,),
        anomaly_repro_selectors=(ANOM_SEL,),
        allowed_test_selectors=(SMOKE_SEL, POS_SEL, DEF_SEL, ANOM_SEL),
        selector_roles={
            SMOKE_SEL: "env_check",
            POS_SEL: "positive_control",
            DEF_SEL: "defense_check",
            ANOM_SEL: "anomaly_repro",
        },
        max_cpus=2,
        max_memory_mb=2048,
        max_timeout_seconds=60,
    )


def _write_fake_service_docker(tmp_path: Path, state: dict[str, Any]) -> tuple[Path, Path, Path]:
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
    img = args[-1]
    if img == {SVC_IMAGE!r}:
        sys.stdout.write({SVC_DIGEST!r} + "\\n")
    else:
        sys.stdout.write({PINNED_DIGEST!r} + "\\n")
    sys.exit(0)

if args[:2] == ["network", "create"]:
    net_name = args[-1]
    nets = list(state.get("networks", []))
    nets.append(net_name)
    state["networks"] = nets
    STATE_PATH.write_text(json.dumps(state), encoding="utf-8")
    sys.stdout.write(net_name + "\\n")
    sys.exit(0)

if args[:2] == ["network", "inspect"]:
    flag = "false" if state.get("internal_false") else "true"
    sys.stdout.write(flag + "\\n")
    sys.exit(0)

if args[:2] == ["network", "ls"]:
    target = ""
    for item in args:
        if item.startswith("name="):
            target = item.split("=", 1)[1].lstrip("^").rstrip("$")
    for n in state.get("networks", []):
        if n == target or not target:
            sys.stdout.write(n + "\\n")
    sys.exit(0)

if args[:2] == ["network", "rm"]:
    target = args[-1]
    state["networks"] = [n for n in state.get("networks", []) if n != target]
    STATE_PATH.write_text(json.dumps(state), encoding="utf-8")
    sys.exit(0)

if args[:1] == ["inspect"]:
    if "PortBindings" in " ".join(args):
        ports = {{"5432/tcp": [{{"HostPort": "5432"}}]}} if state.get("leak_host_port") else {{}}
        sys.stdout.write(json.dumps(ports) + "\\n")
    elif "State.Running" in " ".join(args):
        sys.stdout.write("true\\n")
    sys.exit(0)

if args[:1] == ["exec"]:
    if state.get("readiness_fail"):
        sys.stderr.write("not ready\\n")
        sys.exit(1)
    sys.stdout.write("accepting connections\\n")
    sys.exit(0)

if args[:1] == ["ps"]:
    cname = ""
    for item in args:
        if item.startswith("name="):
            cname = item.split("=", 1)[1].lstrip("^/").rstrip("$")
    for c in state.get("containers", []):
        if c == cname or not cname:
            sys.stdout.write("cid-" + c + "\\n")
    sys.exit(0)

if args[:1] == ["rm"]:
    cname = args[-1]
    if state.get("fail_rm_prefix") and cname.startswith(state["fail_rm_prefix"]):
        sys.stderr.write("rm failed\\n")
        sys.exit(1)
    state["containers"] = [c for c in state.get("containers", []) if c != cname]
    STATE_PATH.write_text(json.dumps(state), encoding="utf-8")
    sys.exit(0)

if args[:1] == ["run"]:
    cname = None
    if "--name" in args:
        cname = args[args.index("--name") + 1]
    if "-d" in args:
        if cname:
            containers = list(state.get("containers", []))
            containers.append(cname)
            state["containers"] = containers
            STATE_PATH.write_text(json.dumps(state), encoding="utf-8")
        sys.stdout.write("svc-container-id\\n")
        sys.exit(0)

    delay = float(state.get("sleep_seconds", 0.0))
    if delay > 0:
        time.sleep(delay)

    if state.get("run_mode") == "smoke":
        sys.stdout.write("collected 1 item\\n")
        sys.stdout.write(f"PASSED {SMOKE_SEL}\\n")
        sys.stdout.write("==== 1 passed in 0.20s ====\\n")
        sys.exit(0)

    sys.stdout.write("collected 3 items\\n")
    sys.stdout.write(f"PASSED {POS_SEL}\\n")
    sys.stdout.write(f"PASSED {DEF_SEL}\\n")
    sys.stdout.write(f"PASSED {ANOM_SEL}\\n")
    sys.stdout.write("==== 3 passed in 0.40s ====\\n")
    sys.exit(0)

sys.exit(0)
"""
    script_path.write_text(script_body, encoding="utf-8")
    script_path.chmod(script_path.stat().st_mode | stat.S_IXUSR | stat.S_IRUSR)
    return script_path, state_path, log_path


def test_profile_validation_rejects_unsafe_network_and_resource_caps(tmp_path: Path) -> None:
    valid = _make_service_profile(tmp_path)
    validated = validate_vdp_profile_registration(valid)
    assert validated.network_mode == "isolated_internal_services"
    assert len(validated.services) == 1

    with pytest.raises(ValueError, match="publish_ports"):
        VdpServiceSpec(
            name="db",
            service_kind="postgres",
            image_ref=SVC_IMAGE,
            expected_image_digest=SVC_DIGEST,
            internal_port=5432,
            publish_ports=True,
        )

    bad_none_with_svc = valid.model_copy(update={"network_mode": "none"})
    with pytest.raises(ContractViolationError, match="cannot declare dependency services"):
        validate_vdp_profile_registration(bad_none_with_svc)

    bad_iso_without_svc = valid.model_copy(update={"services": ()})
    with pytest.raises(ContractViolationError, match="requires at least one pinned service"):
        validate_vdp_profile_registration(bad_iso_without_svc)

    bad_cpu_sum = valid.model_copy(update={"max_cpus": 4})  # 4 + 1 service CPU = 5 > 4
    with pytest.raises(ContractViolationError):
        validate_vdp_profile_registration(bad_cpu_sum)


def test_isolated_internal_services_execution_and_verifier_pass(tmp_path: Path) -> None:
    profile = _make_service_profile(tmp_path)
    fake_docker, state_path, log_path = _write_fake_service_docker(tmp_path, {"run_mode": "smoke"})
    storage = Storage(tmp_path / "harness.db")
    vault_root = tmp_path / "vault"

    ctrl = create_default_controller(
        storage=storage,
        vault_root=vault_root,
        export_root=vault_root / "_exports",
        cursor_hmac_key=b"p" * 32,
        allow_dynamic=True,
        include_vdp_product_test=False,
        initialize=True,
        enable_local_verifier=True,
    )
    desc = create_vdp_product_test_descriptor(
        enabled=True,
        limits=CapabilityLimits(timeout_seconds=30, max_output_bytes=500_000, max_decode_bytes=65_536),
    )
    adapter = VdpProductTestAdapter(
        descriptor=desc,
        evidence_vault=ctrl.evidence_vault,
        profiles={profile.profile_name: profile},
        runner=SubprocessRunner(),
        docker_bin=str(fake_docker),
    )
    ctrl.register_adapter(adapter, tool_group="vdp.test", is_heavy_job=True)

    principal = _make_principal()
    run_id = "run-p1-iso-01"
    ctrl.create_run(
        principal=principal,
        run_id=run_id,
        task_id="task-p1-svc",
        mode=RunMode.VDP,
        scope=_make_scope(),
        budget=BudgetSpec(run_budget_seconds=300, max_tool_calls=20, max_evidence_bytes_per_run=20_000_000),
    )

    # 1. Smoke run against internal PG service
    smoke_env = ctrl.execute_action(
        request=ActionRequest(
            run_id=run_id,
            request_id="req-smoke-01",
            expected_revision=1,
            capability_name="vdp.test",
            operation="run_smoke",
            arguments={
                "target_profile": profile.profile_name,
                "source_commit": PINNED_COMMIT,
                "image_digest": PINNED_DIGEST,
                "network_mode": "isolated_internal_services",
                "overlay_bundle": "g01_pg_bundle",
            },
        ),
        principal=principal,
    )
    assert smoke_env.status == EnvelopeStatus.OK, smoke_env.error
    smoke_ev = smoke_env.evidence[0].id

    # 2. G-01 equivalent synthetic pytest run (positive control + egress check + anomaly repro)
    state_path.write_text(json.dumps({"run_mode": "pytest"}), encoding="utf-8")
    snap = ctrl.runs.get_run_snapshot(run_id)
    pytest_env = ctrl.execute_action(
        request=ActionRequest(
            run_id=run_id,
            request_id="req-g01-01",
            expected_revision=snap.revision,
            capability_name="vdp.test",
            operation="run_pytest",
            arguments={
                "target_profile": profile.profile_name,
                "source_commit": PINNED_COMMIT,
                "image_digest": PINNED_DIGEST,
                "network_mode": "isolated_internal_services",
                "overlay_bundle": "g01_pg_bundle",
                "test_selectors": [POS_SEL, DEF_SEL, ANOM_SEL],
                "positive_selectors": [POS_SEL],
                "negative_selectors": [DEF_SEL],
                "anomaly_repro_selectors": [ANOM_SEL],
                "baseline_evidence_ref": smoke_ev,
            },
        ),
        principal=principal,
    )
    assert pytest_env.status == EnvelopeStatus.OK, pytest_env.error
    pytest_ev = pytest_env.evidence[0].id

    _, pytest_raw = ctrl.evidence_vault.read_view_bytes(
        run_id=run_id,
        principal_id=principal.principal_id,
        evidence_id=pytest_ev,
    )
    pytest_payload = json.loads(pytest_raw.decode("utf-8"))
    assert pytest_payload["verdict"] == "anomaly_observed"
    assert pytest_payload["network_mode"] == "isolated_internal_services"
    assert pytest_payload["network_isolation"]["internal_flag_verified"] is True
    assert pytest_payload["network_isolation"]["published_ports_verified_none"] is True
    assert pytest_payload["service_cleanup_confirmed"] is True
    assert pytest_payload["network_cleanup_confirmed"] is True

    # Confirm fake docker was invoked with --internal and zero remaining networks/containers.
    invocations = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert any(cmd[:2] == ["network", "create"] and "--internal" in cmd for cmd in invocations)
    final_state = json.loads(state_path.read_text(encoding="utf-8"))
    assert final_state.get("containers", []) == []
    assert final_state.get("networks", []) == []

    # 3. Verifier passes on smoke + pytest evidence
    ver = ctrl.verify_run(
        principal=principal,
        run_id=run_id,
        verifier_id="vdp.product_test",
        evidence_ids=(smoke_ev, pytest_ev),
        claim="anomaly_observed",
    )
    assert ver.status == VerificationStatus.PASSED
    assert "network_isolation:internal_services_verified" in ver.checks_performed
    assert "published_ports:none_verified" in ver.checks_performed
    assert "service_image_pins:verified" in ver.checks_performed
    assert "service_and_network_cleanup:confirmed" in ver.checks_performed


def test_timeout_and_isolation_failure_cleanup_and_verifier_fail_closed(tmp_path: Path) -> None:
    profile = _make_service_profile(tmp_path)
    fake_docker, state_path, _ = _write_fake_service_docker(
        tmp_path,
        {"run_mode": "pytest", "sleep_seconds": 6.5},
    )
    storage = Storage(tmp_path / "harness.db")
    vault_root = tmp_path / "vault"

    ctrl = create_default_controller(
        storage=storage,
        vault_root=vault_root,
        export_root=vault_root / "_exports",
        cursor_hmac_key=b"p" * 32,
        allow_dynamic=True,
        include_vdp_product_test=False,
        initialize=True,
        enable_local_verifier=True,
    )
    desc = create_vdp_product_test_descriptor(
        enabled=True,
        limits=CapabilityLimits(timeout_seconds=5, max_output_bytes=500_000, max_decode_bytes=65_536),
    )
    adapter = VdpProductTestAdapter(
        descriptor=desc,
        evidence_vault=ctrl.evidence_vault,
        profiles={profile.profile_name: profile},
        runner=SubprocessRunner(),
        docker_bin=str(fake_docker),
    )
    ctrl.register_adapter(adapter, tool_group="vdp.test", is_heavy_job=True)

    principal = _make_principal()
    run_id = "run-p1-iso-timeout"
    ctrl.create_run(
        principal=principal,
        run_id=run_id,
        task_id="task-p1-svc",
        mode=RunMode.VDP,
        scope=_make_scope(),
        budget=BudgetSpec(run_budget_seconds=300, max_tool_calls=20, max_evidence_bytes_per_run=20_000_000),
    )

    res = ctrl.execute_action(
        request=ActionRequest(
            run_id=run_id,
            request_id="req-timeout-01",
            expected_revision=1,
            capability_name="vdp.test",
            operation="run_pytest",
            arguments={
                "target_profile": profile.profile_name,
                "source_commit": PINNED_COMMIT,
                "image_digest": PINNED_DIGEST,
                "network_mode": "isolated_internal_services",
                "overlay_bundle": "g01_pg_bundle",
                "test_selectors": [POS_SEL],
                "positive_selectors": [POS_SEL],
                "timeout_seconds": 5,
            },
        ),
        principal=principal,
    )
    assert res.status == EnvelopeStatus.TIMEOUT
    final_state = json.loads(state_path.read_text(encoding="utf-8"))
    assert final_state.get("containers", []) == []
    assert final_state.get("networks", []) == []

    # Verifier must reject forged/broken internal isolation evidence (published port > 0)
    ev_id = res.evidence[0].id
    _, raw = ctrl.evidence_vault.read_view_bytes(
        run_id=run_id,
        principal_id=principal.principal_id,
        evidence_id=ev_id,
    )
    timeout_payload = json.loads(raw.decode("utf-8"))
    assert timeout_payload["verdict"] == "timeout"
    assert timeout_payload["service_cleanup_confirmed"] is True
    assert timeout_payload["network_cleanup_confirmed"] is True

    ver_timeout = ctrl.verify_run(
        principal=principal,
        run_id=run_id,
        verifier_id="vdp.product_test",
        evidence_ids=(ev_id,),
    )
    assert ver_timeout.status == VerificationStatus.INCONCLUSIVE
    assert "outcome_state:timeout" in ver_timeout.checks_performed

    # If Internal!=true, adapter aborts before starting test container and cleans up network
    state_path.write_text(json.dumps({"internal_false": True}), encoding="utf-8")
    snap = ctrl.runs.get_run_snapshot(run_id)
    bad_net_res = ctrl.execute_action(
        request=ActionRequest(
            run_id=run_id,
            request_id="req-badnet-01",
            expected_revision=snap.revision,
            capability_name="vdp.test",
            operation="run_smoke",
            arguments={
                "target_profile": profile.profile_name,
                "source_commit": PINNED_COMMIT,
                "image_digest": PINNED_DIGEST,
                "network_mode": "isolated_internal_services",
                "overlay_bundle": "g01_pg_bundle",
            },
        ),
        principal=principal,
    )
    assert bad_net_res.status == EnvelopeStatus.TOOL_ERROR
    final_state_2 = json.loads(state_path.read_text(encoding="utf-8"))
    assert final_state_2.get("networks", []) == []


def test_verifier_rejects_broken_isolation_or_unexpected_services(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "harness.db")
    vault_root = tmp_path / "vault"
    ctrl = create_default_controller(
        storage=storage,
        vault_root=vault_root,
        export_root=vault_root / "_exports",
        cursor_hmac_key=b"v" * 32,
        allow_dynamic=True,
        initialize=True,
        enable_local_verifier=True,
    )
    principal = _make_principal()
    run_id = "run-p1-ver-neg"
    ctrl.create_run(
        principal=principal,
        run_id=run_id,
        task_id="task-p1-svc",
        mode=RunMode.VDP,
        scope=_make_scope(),
        budget=BudgetSpec(run_budget_seconds=300, max_tool_calls=20, max_evidence_bytes_per_run=10_000_000),
    )

    def _import_payload(idx: int, payload: dict[str, Any]) -> str:
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        ctrl.staging_root.mkdir(parents=True, exist_ok=True)
        rel = f"neg/{idx}.json"
        (ctrl.staging_root / "neg").mkdir(parents=True, exist_ok=True)
        (ctrl.staging_root / rel).write_bytes(raw)
        act_id = f"act-neg-{idx}"
        with ctrl.storage.transaction() as conn:
            conn.execute(
                """
                INSERT INTO actions (
                    action_id, principal_id, run_id, request_id, expected_revision,
                    capability_name, operation, adapter_revision, canonical_args_sha256,
                    sanitized_args_json, scope_revision, repeat_of, state,
                    reserved_ms, reserved_bytes, used_ms, used_bytes,
                    fencing_token, supervisor_instance_id, process_start_id,
                    envelope_json, error_code, error_message, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 1, 'vdp.test', 'run_smoke', 'v1', ?, '{}', 'scope-p1-svc-v1', NULL, 'COMPLETED', 0, 0, 1, ?, NULL, NULL, NULL, NULL, NULL, NULL, '2026-11-19T00:00:00Z', '2026-11-19T00:00:00Z')
                """,
                (act_id, principal.principal_id, run_id, f"req-neg-{idx}", sha256_bytes(raw), len(raw)),
            )
            rec = ctrl.bounded_importer.import_object(
                run_id=run_id,
                owner_principal_id=principal.principal_id,
                action_id=act_id,
                object_id=f"obj-neg-{idx}",
                expected_sha256=sha256_bytes(raw),
                media_type="application/json; charset=utf-8",
                capture_complete=True,
                omission_reason=None,
                source_artifact_hashes=(),
                adapter_revision="v1",
                sanitized_args_sha256=sha256_bytes(raw),
                expected_size_bytes=len(raw),
                staging_relpath=rel,
                conn=conn,
            )
        return rec.evidence_id

    verifier = VdpProductTestVerifier(storage=storage, vault_root=vault_root)
    base_iso = {
        "schema": "vdp-product-test-evidence/1",
        "execution_provenance": "harness_docker_isolated",
        "operation": "run_smoke",
        "source_commit": PINNED_COMMIT,
        "image_digest": PINNED_DIGEST,
        "network_mode": "isolated_internal_services",
        "network_isolation": {
            "mode": "isolated_internal_services",
            "network_name": "ctf-vdp-net-abc",
            "internal_flag_verified": True,
            "external_egress_blocked": True,
            "published_ports_count": 0,
            "published_ports_verified_none": True,
        },
        "services_executed": [
            {
                "service_name": "db",
                "image_digest": SVC_DIGEST,
                "published_ports_verified_none": True,
                "ready_verified": True,
                "container_cleanup_confirmed": True,
                "cpus": 1,
                "memory_mb": 512,
            }
        ],
        "container_cleanup_confirmed": True,
        "process_cleanup_confirmed": True,
        "service_cleanup_confirmed": True,
        "network_cleanup_confirmed": True,
        "verdict": "smoke_passed",
    }

    bad_ports = dict(base_iso)
    bad_ports["network_isolation"] = {**base_iso["network_isolation"], "published_ports_count": 1, "published_ports_verified_none": False}
    assert verifier.verify(run_id=run_id, evidence_ids=(_import_payload(1, bad_ports),)).status == VerificationStatus.FAILED

    bad_net_clean = {**base_iso, "network_cleanup_confirmed": False}
    assert verifier.verify(run_id=run_id, evidence_ids=(_import_payload(2, bad_net_clean),)).status == VerificationStatus.FAILED

    bad_none_svcs = {
        **base_iso,
        "network_mode": "none",
        "network_isolation": {"mode": "none"},
    }
    assert verifier.verify(run_id=run_id, evidence_ids=(_import_payload(3, bad_none_svcs),)).status == VerificationStatus.FAILED
