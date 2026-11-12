"""Contract & invariant tests for MVP P3 Wave P3-A.

Verifies:
(a) Real OS resource telemetry (peak_rss_bytes, cpu_ms, os_pid, process_start_id)
    across UsageMetrics -> SubprocessResult -> BaseAdapter -> ResultEnvelope, and
    real OS process liveness + creation-time matching via is_os_process_alive().
(b) RecoveryManager.resolve_reconciled_action_in_tx retains conservative budget
    reservations (no refund) when usage is unknown (has_tool_receipt=False / usage=None
    or cleanup_confirmed=False), and settles exact differences when usage is known.
(c) LeaseManager.expire_reserved_actions_in_tx and RecoveryManager maintain
    accurate active_heavy_jobs / active_sessions concurrency slots without corrupting
    held heavy or interactive slots.
(d) RunReportExporter aggregates peak_rss_bytes (max) and cpu_ms (sum) into
    Outcome and cost (JA/EN) or outputs "N/A" when unrecorded, and prepares/writes cleanly.
(e) Layer 2 package isolation (no horizontal imports) and AST safety checks.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ctf_mcp.adapters import (
    BaseAdapter,
    SubprocessOutcome,
    SubprocessRunner,
    build_signed_descriptor,
    get_os_process_start_id,
    is_os_process_alive,
)
from ctf_mcp.contracts import (
    ActionLifecycleState,
    ActionRecord,
    ActionRequest,
    BudgetSpec,
    CapabilityDescriptor,
    CapabilityLimits,
    ContractViolationError,
    EnvelopeStatus,
    ExecutionClass,
    GuestBlockedError,
    GuestHealthState,
    InvalidStateTransitionError,
    RunManifest,
    RunMode,
    UsageMetrics,
)
from ctf_mcp.evidence import (
    EvidenceVault,
    ReportMetadata,
    RunReportExporter,
)
from ctf_mcp.runs import (
    ActionManager,
    LeaseManager,
    RecoveryManager,
    RunManifestManager,
)
from ctf_mcp.storage import Storage


def _init_storage(tmp_path: Path) -> Storage:
    storage = Storage(tmp_path / "harness.db")
    storage.initialize()
    return storage


def _make_manifest(
    run_id: str = "run-p3a",
    *,
    owner: str = "alice",
    task_id: str = "task-p3a",
    budget: BudgetSpec | None = None,
) -> RunManifest:
    return RunManifest(
        run_id=run_id,
        owner_principal_id=owner,
        task_id=task_id,
        mode=RunMode.OFFLINE_CTF,
        scope_revision="scope-1",
        scope_sha256="a" * 64,
        scope_expires_at=None,
        artifact_hashes={"art-1": "b" * 64},
        adapter_revisions={"p3-adapter": "0123456789abcdef"},
        client_label="P3A-Test-Client",
        instruction_revision="instr-p3a",
        budget_spec=budget or BudgetSpec(),
        created_at=datetime(2026, 11, 13, 0, 0, 0, tzinfo=UTC),
    )


def _make_capability(
    name: str = "artifact.inspect",
    *,
    exec_classes: tuple[ExecutionClass, ...] = (ExecutionClass.STATIC,),
    timeout_seconds: int = 60,
    max_output_bytes: int = 16_384,
) -> CapabilityDescriptor:
    return CapabilityDescriptor(
        name=name,
        adapter_id="p3-adapter",
        adapter_commit="0123456789abcdef",
        dependency_lock_sha256="c" * 64,
        descriptor_sha256="d" * 64,
        operations=("inspect", "run"),
        arg_schema={"type": "object", "required": ["artifact_id"]},
        execution_classes=exec_classes,
        required_scope={"mode": "offline_ctf"},
        limits=CapabilityLimits(
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            max_decode_bytes=4096,
        ),
    )


def _create_run(
    storage: Storage,
    run_id: str = "run-p3a",
    *,
    owner: str = "alice",
    budget: BudgetSpec | None = None,
) -> RunManifest:
    manifests = RunManifestManager(storage)
    manifest = _make_manifest(run_id, owner=owner, budget=budget)
    manifests.create_run(manifest)
    return manifest


class _EchoTelemetryAdapter(BaseAdapter):
    """Concrete BaseAdapter subclass invoking a bounded Python child for telemetry checks."""

    def _build_invocation(
        self,
        action: ActionRecord,
        *,
        artifact_paths: dict[str, Path] | None = None,
    ) -> tuple[list[str], dict[str, str] | None, Path | None]:
        del action, artifact_paths
        script = (
            "buf = bytearray(2 * 1024 * 1024); "
            "_ = sum(range(100_000)); "
            "print('telemetry-ok')"
        )
        return [sys.executable, "-c", script], None, None


# ---------------------------------------------------------------------------
# (a) Real OS resource telemetry & process_start_id liveness verification
# ---------------------------------------------------------------------------


def test_usage_metrics_backward_compat_and_subprocess_telemetry(tmp_path: Path) -> None:
    legacy = UsageMetrics(wall_ms=12, output_bytes=34)
    assert legacy.peak_rss_bytes is None
    assert legacy.cpu_ms is None

    rich = UsageMetrics(wall_ms=12, output_bytes=34, peak_rss_bytes=1_048_576, cpu_ms=8)
    assert rich.peak_rss_bytes == 1_048_576
    assert rich.cpu_ms == 8

    runner = SubprocessRunner(default_timeout_seconds=15.0)
    res = runner.run(
        [
            sys.executable,
            "-c",
            "buf = bytearray(2 * 1024 * 1024); _ = sum(range(150_000)); print('done')",
        ],
        cwd=tmp_path,
    )
    assert res.outcome == SubprocessOutcome.COMPLETED
    assert res.cleanup_confirmed is True
    assert res.os_pid is not None and res.os_pid >= 1
    assert res.process_start_id is not None and res.process_start_id.startswith(f"pid:{res.os_pid}:")
    assert res.peak_rss_bytes is not None and res.peak_rss_bytes > 0
    assert res.cpu_ms is not None and res.cpu_ms >= 0
    assert is_os_process_alive(res.process_start_id) is False


def test_is_os_process_alive_real_process_and_anti_pid_reuse() -> None:
    assert is_os_process_alive(None) is False
    assert is_os_process_alive("") is False
    assert is_os_process_alive("malformed-id") is False
    assert is_os_process_alive("pid:0:win:123") is False
    assert is_os_process_alive("pid:999999999:win:123") is False

    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=False,
    )
    try:
        start_id = get_os_process_start_id(proc.pid)
        assert start_id is not None
        assert is_os_process_alive(start_id) is True

        # Simulated PID reuse: same PID, mismatched creation timestamp -> False.
        parts = start_id.split(":", 3)
        spoofed_token = (
            str(int(parts[3]) + 1)
            if parts[3].isdigit()
            else f"{parts[3]}-mismatch"
        )
        spoofed_id = f"{parts[0]}:{parts[1]}:{parts[2]}:{spoofed_token}"
        assert is_os_process_alive(spoofed_id) is False

        # Wrong platform kind -> False.
        foreign_kind = "proc" if parts[2] == "win" else "win"
        assert is_os_process_alive(f"{parts[0]}:{parts[1]}:{foreign_kind}:{parts[3]}") is False
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    assert is_os_process_alive(start_id) is False
    assert get_os_process_start_id(proc.pid) is None


def test_base_adapter_propagates_resource_telemetry_to_envelope(tmp_path: Path) -> None:
    descriptor = build_signed_descriptor(
        name="artifact.telemetry",
        adapter_id="telemetry-adapter",
        adapter_commit="0123456789abcdef",
        dependency_lock_sha256="e" * 64,
        operations=("run",),
        arg_schema={"type": "object"},
        execution_classes=(ExecutionClass.STATIC,),
        required_scope={"mode": "offline_ctf"},
        limits=CapabilityLimits(
            timeout_seconds=20,
            max_output_bytes=16_384,
            max_decode_bytes=4096,
        ),
    )
    storage = _init_storage(tmp_path)
    _create_run(storage, "run-p3a")
    actions = ActionManager(storage)
    sub = actions.submit_action(
        run_id="run-p3a",
        principal_id="alice",
        request=ActionRequest(
            run_id="run-p3a",
            request_id="req-telemetry",
            expected_revision=1,
            capability_name="artifact.telemetry",
            operation="run",
            arguments={},
        ),
        capability=descriptor,
        scope_revision="scope-1",
    )
    running = actions.start_action(
        action_id=sub.action.action_id,
        supervisor_key="sup-tel",
        supervisor_instance_id="inst-tel",
        process_start_id="pid:9001:win:1",
    )
    vault = EvidenceVault(
        storage=storage,
        vault_root=tmp_path / "vault",
        cursor_hmac_key=b"p3a-test-hmac-key-0123456789abcdef",
    )
    adapter = _EchoTelemetryAdapter(
        descriptor,
        evidence_vault=vault,
        runner=SubprocessRunner(default_timeout_seconds=20.0),
    )
    outcome = adapter.execute_with_capture(running)
    assert outcome.envelope.status == EnvelopeStatus.OK
    assert outcome.envelope.usage.peak_rss_bytes is not None
    assert outcome.envelope.usage.peak_rss_bytes > 0
    assert outcome.envelope.usage.cpu_ms is not None
    assert outcome.envelope.usage.cpu_ms >= 0


# ---------------------------------------------------------------------------
# (b) RecoveryManager usage_unknown & cleanup_confirmed budget invariants
# ---------------------------------------------------------------------------


def test_recovery_unknown_usage_retains_reservation_while_known_usage_refunds_delta(
    tmp_path: Path,
) -> None:
    storage = _init_storage(tmp_path)
    budget = BudgetSpec(
        run_budget_seconds=120,
        action_timeout_seconds=30,
        max_tool_calls=5,
        max_evidence_bytes_per_run=100_000,
        heavy_job_concurrency=1,
    )
    _create_run(storage, "run-unknown", budget=budget)
    actions = ActionManager(storage)
    recovery = RecoveryManager(storage)
    manifests = RunManifestManager(storage)
    cap = _make_capability(timeout_seconds=30, max_output_bytes=20_000)

    sub = actions.submit_action(
        run_id="run-unknown",
        principal_id="alice",
        request=ActionRequest(
            run_id="run-unknown",
            request_id="req-1",
            expected_revision=1,
            capability_name="artifact.inspect",
            operation="inspect",
            arguments={"artifact_id": "art-1"},
        ),
        capability=cap,
        scope_revision="scope-1",
    )
    actions.start_action(
        action_id=sub.action.action_id,
        supervisor_key="sup-1",
        supervisor_instance_id="inst-1",
        process_start_id="pid:1001:win:999",
    )
    recovery.reconcile_inflight_actions(
        run_id="run-unknown",
        is_process_alive=lambda _a: False,
        supervisor_key="sup-1",
    )
    before = manifests.get_run_snapshot("run-unknown")
    assert before.remaining_ms == 90_000
    assert before.remaining_bytes == 80_000
    assert before.usage.active_heavy_jobs == 1

    # Resolve with has_tool_receipt=False & usage=None -> NO refund of reserved_ms/bytes.
    with storage.transaction() as conn:
        resolved = recovery.resolve_reconciled_action_in_tx(
            conn,
            action_id=sub.action.action_id,
            target_state=ActionLifecycleState.FAILED,
            usage=None,
            has_tool_receipt=False,
            summary="Process died before receipt could be confirmed.",
        )
    assert resolved.action.state == ActionLifecycleState.FAILED
    assert resolved.envelope is not None
    assert resolved.envelope.status == EnvelopeStatus.TOOL_ERROR

    after = manifests.get_run_snapshot("run-unknown")
    assert after.remaining_ms == 90_000
    assert after.remaining_bytes == 80_000
    assert after.usage.active_heavy_jobs == 0

    # Known measured usage DOES settle exact difference.
    sub2 = actions.submit_action(
        run_id="run-unknown",
        principal_id="alice",
        request=ActionRequest(
            run_id="run-unknown",
            request_id="req-2",
            expected_revision=after.revision,
            capability_name="artifact.inspect",
            operation="inspect",
            arguments={"artifact_id": "art-1"},
        ),
        capability=cap,
        scope_revision="scope-1",
    )
    actions.start_action(
        action_id=sub2.action.action_id,
        supervisor_key="sup-1",
        supervisor_instance_id="inst-1",
        process_start_id="pid:1002:win:999",
    )
    recovery.reconcile_inflight_actions(
        run_id="run-unknown",
        is_process_alive=lambda _a: False,
        supervisor_key="sup-1",
    )
    with storage.transaction() as conn:
        resolved2 = recovery.resolve_reconciled_action_in_tx(
            conn,
            action_id=sub2.action.action_id,
            target_state=ActionLifecycleState.FAILED,
            usage=UsageMetrics(wall_ms=5_000, output_bytes=2_500),
            has_tool_receipt=True,
            summary="Observed bounded partial telemetry prior to crash.",
        )
    assert resolved2.action.state == ActionLifecycleState.FAILED
    after2 = manifests.get_run_snapshot("run-unknown")
    # Subtracted (30_000 reserved) then refunded (30_000 - 5_000 = 25_000) -> 90_000 - 5_000 = 85_000
    assert after2.remaining_ms == 85_000
    assert after2.remaining_bytes == 77_500
    assert after2.usage.active_heavy_jobs == 0


def test_unconfirmed_cleanup_retains_all_budget_and_recovers_only_when_verified(
    tmp_path: Path,
) -> None:
    storage = _init_storage(tmp_path)
    budget = BudgetSpec(
        run_budget_seconds=100,
        action_timeout_seconds=25,
        max_tool_calls=4,
        max_evidence_bytes_per_run=40_000,
        heavy_job_concurrency=1,
    )
    _create_run(storage, "run-dirty", budget=budget)
    actions = ActionManager(storage)
    recovery = RecoveryManager(storage)
    manifests = RunManifestManager(storage)
    cap = _make_capability(timeout_seconds=25, max_output_bytes=10_000)

    sub = actions.submit_action(
        run_id="run-dirty",
        principal_id="alice",
        request=ActionRequest(
            run_id="run-dirty",
            request_id="req-dirty",
            expected_revision=1,
            capability_name="artifact.inspect",
            operation="inspect",
            arguments={"artifact_id": "art-1"},
        ),
        capability=cap,
        scope_revision="scope-1",
    )
    running = actions.start_action(
        action_id=sub.action.action_id,
        supervisor_key="sup-d",
        supervisor_instance_id="inst-d",
        process_start_id="pid:2001:win:888",
    )

    with storage.transaction() as conn:
        actions.settle_action_in_tx(
            conn,
            action_id=running.action_id,
            target_state=ActionLifecycleState.TIMEOUT,
            usage=UsageMetrics(wall_ms=25_000, output_bytes=0),
            fencing_token=running.fencing_token,
            has_tool_receipt=False,
            usage_unknown=True,
            cleanup_confirmed=False,
            summary="Timed out with lingering descendant PID.",
        )

    snap_dirty = manifests.get_run_snapshot("run-dirty")
    assert snap_dirty.guest_health == GuestHealthState.CLEANUP_UNCONFIRMED
    assert snap_dirty.remaining_ms == 75_000
    assert snap_dirty.remaining_bytes == 30_000
    assert snap_dirty.usage.active_heavy_jobs == 1

    with storage.transaction() as conn:
        with pytest.raises(GuestBlockedError):
            recovery.mark_guest_rolled_back_in_tx(conn, "run-dirty")

        with pytest.raises(ContractViolationError, match="cleanup_verified"):
            recovery.recover_guest_ready_in_tx(
                conn, "run-dirty", cleanup_verified=False, note="attempted"
            )
        with pytest.raises(ContractViolationError, match="note"):
            recovery.recover_guest_ready_in_tx(
                conn, "run-dirty", cleanup_verified=True, note="   "
            )

        recovered_state = recovery.recover_guest_ready_in_tx(
            conn,
            "run-dirty",
            cleanup_verified=True,
            note="VM snapshot restored and lingering PIDs verified gone.",
        )
        assert recovered_state == GuestHealthState.READY

    snap_recovered = manifests.get_run_snapshot("run-dirty")
    assert snap_recovered.guest_health == GuestHealthState.READY
    # Slots cleared so run can be exported/reused, while conservative time/byte hold persists.
    assert snap_recovered.usage.active_heavy_jobs == 0
    assert snap_recovered.usage.active_sessions == 0
    assert snap_recovered.remaining_ms == 75_000
    assert snap_recovered.remaining_bytes == 30_000

    # Rolled-back run cannot revert to ready.
    with storage.transaction() as conn:
        recovery.mark_guest_rolled_back_in_tx(conn, "run-dirty")
        with pytest.raises(InvalidStateTransitionError):
            recovery.recover_guest_ready_in_tx(
                conn, "run-dirty", cleanup_verified=True, note="too late"
            )


# ---------------------------------------------------------------------------
# (c) LeaseManager & RecoveryManager slot accounting fidelity
# ---------------------------------------------------------------------------


def test_lease_expiry_and_recovery_preserve_independent_heavy_and_session_slots(
    tmp_path: Path,
) -> None:
    storage = _init_storage(tmp_path)
    budget = BudgetSpec(
        run_budget_seconds=120,
        action_timeout_seconds=20,
        max_tool_calls=6,
        max_evidence_bytes_per_run=100_000,
        heavy_job_concurrency=1,
        interactive_session_limit=1,
    )
    _create_run(storage, "run-slots", budget=budget)
    actions = ActionManager(storage)
    leases = LeaseManager(storage)
    recovery = RecoveryManager(storage)
    manifests = RunManifestManager(storage)

    static_cap = _make_capability("artifact.inspect", timeout_seconds=20, max_output_bytes=10_000)
    dyn_cap = _make_capability(
        "debug.session",
        exec_classes=(ExecutionClass.DYNAMIC,),
        timeout_seconds=20,
        max_output_bytes=10_000,
    )

    t0 = datetime(2026, 11, 13, 1, 0, 0, tzinfo=UTC)

    # 1. Start a live heavy job (holds heavy_job_slot=True).
    heavy_sub = actions.submit_action(
        run_id="run-slots",
        principal_id="alice",
        request=ActionRequest(
            run_id="run-slots",
            request_id="req-heavy",
            expected_revision=1,
            capability_name="artifact.inspect",
            operation="inspect",
            arguments={"artifact_id": "art-1"},
        ),
        capability=static_cap,
        scope_revision="scope-1",
        heavy_job_slot=True,
        interactive_session_slot=False,
        now=t0,
    )
    actions.start_action(
        action_id=heavy_sub.action.action_id,
        supervisor_key="sup-s",
        supervisor_instance_id="inst-s",
        process_start_id="pid:3001:win:777",
        now=t0,
    )

    # 2. Reserve a stale lightweight non-heavy action (heavy_job_slot=False).
    light_sub = actions.submit_action(
        run_id="run-slots",
        principal_id="alice",
        request=ActionRequest(
            run_id="run-slots",
            request_id="req-light",
            expected_revision=2,
            capability_name="artifact.inspect",
            operation="inspect",
            arguments={"artifact_id": "art-1"},
        ),
        capability=static_cap,
        scope_revision="scope-1",
        heavy_job_slot=False,
        interactive_session_slot=False,
        now=t0,
    )

    # 3. Reserve a stale interactive session action (interactive_session_slot=True, heavy=False).
    sess_sub = actions.submit_action(
        run_id="run-slots",
        principal_id="alice",
        request=ActionRequest(
            run_id="run-slots",
            request_id="req-sess",
            expected_revision=3,
            capability_name="debug.session",
            operation="run",
            arguments={"artifact_id": "art-1"},
        ),
        capability=dyn_cap,
        scope_revision="scope-1",
        heavy_job_slot=False,
        interactive_session_slot=True,
        now=t0,
    )

    mid = manifests.get_run_snapshot("run-slots")
    assert mid.usage.active_heavy_jobs == 1
    assert mid.usage.active_sessions == 1
    assert mid.remaining_ms == 60_000
    assert mid.remaining_bytes == 70_000

    # Expire only the two reserved actions after 120s without touching the running heavy job's slot!
    expired = leases.expire_reserved_actions(
        run_id="run-slots",
        max_age_seconds=60,
        now=t0 + timedelta(seconds=120),
    )
    assert {s.action.action_id for s in expired} == {
        light_sub.action.action_id,
        sess_sub.action.action_id,
    }

    after_exp = manifests.get_run_snapshot("run-slots")
    # Running heavy slot MUST remain 1; interactive session slot MUST return to 0.
    assert after_exp.usage.active_heavy_jobs == 1
    assert after_exp.usage.active_sessions == 0
    # Reserved time/bytes for both pre-launch expired actions are refunded.
    assert after_exp.remaining_ms == 100_000
    assert after_exp.remaining_bytes == 90_000

    # Verify RecoveryManager also leaves active_heavy_jobs=1 intact if settling a non-heavy action.
    light2 = actions.submit_action(
        run_id="run-slots",
        principal_id="alice",
        request=ActionRequest(
            run_id="run-slots",
            request_id="req-light2",
            expected_revision=after_exp.revision,
            capability_name="artifact.inspect",
            operation="inspect",
            arguments={"artifact_id": "art-1"},
        ),
        capability=static_cap,
        scope_revision="scope-1",
        heavy_job_slot=False,
        interactive_session_slot=False,
        now=t0 + timedelta(seconds=125),
    )
    actions.start_action(
        action_id=light2.action.action_id,
        supervisor_key="sup-s",
        supervisor_instance_id="inst-s",
        process_start_id="pid:3002:win:777",
        now=t0 + timedelta(seconds=125),
    )
    recovery.reconcile_inflight_actions(
        run_id="run-slots",
        is_process_alive=lambda act: act.action_id == heavy_sub.action.action_id,
        supervisor_key="sup-s",
        mark_sessions_lost=False,
        now=t0 + timedelta(seconds=130),
    )
    with storage.transaction() as conn:
        recovery.resolve_reconciled_action_in_tx(
            conn,
            action_id=light2.action.action_id,
            target_state=ActionLifecycleState.FAILED,
            usage=UsageMetrics(wall_ms=1_000, output_bytes=500),
            has_tool_receipt=True,
            summary="Light worker failed cleanly.",
        )
    final_snap = manifests.get_run_snapshot("run-slots")
    assert final_snap.usage.active_heavy_jobs == 1


# ---------------------------------------------------------------------------
# (d) RunReportExporter resource peak aggregation & prepare/write staging
# ---------------------------------------------------------------------------


def test_exporter_aggregates_peak_rss_max_and_cpu_ms_sum_and_supports_na(
    tmp_path: Path,
) -> None:
    storage = _init_storage(tmp_path)
    _create_run(storage, "run-export-metrics")
    actions = ActionManager(storage)
    recovery = RecoveryManager(storage)
    exporter = RunReportExporter(
        storage=storage,
        export_root=tmp_path / "exports",
    )
    cap = _make_capability()

    a1 = actions.submit_action(
        run_id="run-export-metrics",
        principal_id="alice",
        request=ActionRequest(
            run_id="run-export-metrics",
            request_id="req-m1",
            expected_revision=1,
            capability_name="artifact.inspect",
            operation="inspect",
            arguments={"artifact_id": "art-1"},
        ),
        capability=cap,
        scope_revision="scope-1",
    )
    a1_run = actions.start_action(
        action_id=a1.action.action_id,
        supervisor_key="sup-e1",
        supervisor_instance_id="inst-e1",
        process_start_id="pid:4001:win:1",
    )
    actions.settle_action_with_envelope(
        action_id=a1_run.action_id,
        target_state=ActionLifecycleState.COMPLETED,
        usage=UsageMetrics(
            wall_ms=100,
            output_bytes=64,
            peak_rss_bytes=2_000_000,
            cpu_ms=40,
        ),
        fencing_token=a1_run.fencing_token,
        has_tool_receipt=True,
        summary="first action",
    )

    a2 = actions.submit_action(
        run_id="run-export-metrics",
        principal_id="alice",
        request=ActionRequest(
            run_id="run-export-metrics",
            request_id="req-m2",
            expected_revision=2,
            capability_name="artifact.inspect",
            operation="inspect",
            arguments={"artifact_id": "art-1"},
        ),
        capability=cap,
        scope_revision="scope-1",
    )
    a2_run = actions.start_action(
        action_id=a2.action.action_id,
        supervisor_key="sup-e1",
        supervisor_instance_id="inst-e1",
        process_start_id="pid:4002:win:1",
    )
    actions.settle_action_with_envelope(
        action_id=a2_run.action_id,
        target_state=ActionLifecycleState.COMPLETED,
        usage=UsageMetrics(
            wall_ms=250,
            output_bytes=128,
            peak_rss_bytes=5_500_000,
            cpu_ms=110,
        ),
        fencing_token=a2_run.fencing_token,
        has_tool_receipt=True,
        summary="second action",
    )

    # Prepare report in memory prior to disk write; verify both JA and EN render resource peaks.
    staged_ja = exporter.prepare_run_report(
        run_id="run-export-metrics",
        principal_id="alice",
        language="ja",
        metadata=ReportMetadata(outcome_summary="verified-metrics"),
    )
    assert staged_ja.output_path is None
    assert "`wall_ms=350`" in staged_ja.markdown
    assert "`peak_rss_bytes=5500000`" in staged_ja.markdown
    assert "`cpu_ms=150`" in staged_ja.markdown

    # Complete rollback and commit staged report to export_root.
    with storage.transaction() as conn:
        recovery.mark_guest_rolled_back_in_tx(conn, "run-export-metrics")

    en_written = exporter.export_run_report(
        run_id="run-export-metrics",
        principal_id="alice",
        language="en",
        require_rolled_back=True,
        output_relpath="reports/run-export-metrics.md",
    )
    assert en_written.output_path is not None
    assert Path(en_written.output_path).exists()
    assert "`wall_ms=350`" in en_written.markdown
    assert "`peak_rss_bytes=5500000`" in en_written.markdown
    assert "`cpu_ms=150`" in en_written.markdown

    # Also verify write_verified_report works standalone on a prepared result.
    ja_written = exporter.write_verified_report(
        staged_ja,
        output_relpath="reports/run-export-metrics.ja.md",
    )
    assert ja_written.output_path is not None
    assert Path(ja_written.output_path).read_text(encoding="utf-8") == staged_ja.markdown

    # Unrecorded resource telemetry -> "N/A".
    _create_run(storage, "run-export-na")
    a_na = actions.submit_action(
        run_id="run-export-na",
        principal_id="alice",
        request=ActionRequest(
            run_id="run-export-na",
            request_id="req-na",
            expected_revision=1,
            capability_name="artifact.inspect",
            operation="inspect",
            arguments={"artifact_id": "art-1"},
        ),
        capability=cap,
        scope_revision="scope-1",
    )
    a_na_run = actions.start_action(
        action_id=a_na.action.action_id,
        supervisor_key="sup-e2",
        supervisor_instance_id="inst-e2",
        process_start_id="pid:4003:win:1",
    )
    actions.settle_action_with_envelope(
        action_id=a_na_run.action_id,
        target_state=ActionLifecycleState.COMPLETED,
        usage=UsageMetrics(wall_ms=50, output_bytes=10),
        fencing_token=a_na_run.fencing_token,
        has_tool_receipt=True,
        summary="no resource counters",
    )
    na_res = exporter.prepare_run_report(
        run_id="run-export-na",
        principal_id="alice",
        language="en",
    )
    assert "`peak_rss_bytes=N/A`" in na_res.markdown
    assert "`cpu_ms=N/A`" in na_res.markdown


# ---------------------------------------------------------------------------
# (e) Layer-2 horizontal import isolation & AST safety checks
# ---------------------------------------------------------------------------


def test_p3a_modified_packages_preserve_layer2_isolation_and_ast_safety() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    src_root = repo_root / "src" / "ctf_mcp"
    layer2_packages = {"gateway", "runs", "evidence", "verification", "adapters"}

    for pkg in ("adapters", "runs", "evidence"):
        own_pkg = pkg
        forbidden_siblings = layer2_packages - {own_pkg}
        for py_file in (src_root / pkg).rglob("*.py"):
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        parts = alias.name.split(".")
                        if len(parts) >= 2 and parts[0] == "ctf_mcp" and parts[1] in forbidden_siblings:
                            raise AssertionError(
                                f"Horizontal Layer 2 import {alias.name!r} in {py_file}"
                            )
                elif isinstance(node, ast.ImportFrom) and node.module:
                    parts = node.module.split(".")
                    if len(parts) >= 2 and parts[0] == "ctf_mcp" and parts[1] in forbidden_siblings:
                        raise AssertionError(
                            f"Horizontal Layer 2 import {node.module!r} in {py_file}"
                        )
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                        raise AssertionError(f"Forbidden call {node.func.id} in {py_file}")
                    if (
                        isinstance(node.func, ast.Attribute)
                        and node.func.attr == "system"
                        and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "os"
                    ):
                        raise AssertionError(f"Forbidden os.system call in {py_file}")
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            raise AssertionError(f"Forbidden shell=True in {py_file}")
