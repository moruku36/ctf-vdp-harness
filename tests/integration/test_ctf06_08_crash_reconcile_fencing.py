"""Integration tests for CTF-06, CTF-07 guest blocking, CTF-08 fencing/session loss, and leases."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ctf_mcp.contracts import (
    ActionLifecycleState,
    ActionRequest,
    BudgetExceededError,
    BudgetSpec,
    CapabilityDescriptor,
    CapabilityLimits,
    EnvelopeStatus,
    ExecutionClass,
    FencingError,
    GuestBlockedError,
    GuestHealthState,
    InvalidStateTransitionError,
    RunManifest,
    RunMode,
    UsageMetrics,
)
from ctf_mcp.runs import (
    ActionManager,
    LeaseManager,
    RecoveryManager,
    RunManifestManager,
    SessionLeaseState,
)
from ctf_mcp.storage import Storage


def _make_manifest(run_id: str = "run-rec-1", *, budget: BudgetSpec | None = None) -> RunManifest:
    return RunManifest(
        run_id=run_id,
        owner_principal_id="alice",
        task_id="task-crash-1",
        mode=RunMode.OFFLINE_CTF,
        scope_revision="scope-1",
        scope_sha256="a" * 64,
        artifact_hashes={"art-1": "b" * 64},
        adapter_revisions={"static-core": "deadbeef1234"},
        client_label="Codex-CLI-Test",
        instruction_revision="instr-v1",
        budget_spec=budget or BudgetSpec(),
        created_at=datetime(2026, 11, 13, 0, 0, 0, tzinfo=UTC),
    )


def _make_capability(
    name: str = "analysis.query",
    *,
    execution_classes: tuple[ExecutionClass, ...] = (ExecutionClass.STATIC,),
) -> CapabilityDescriptor:
    return CapabilityDescriptor(
        name=name,
        adapter_id="static-core",
        adapter_commit="deadbeef1234",
        dependency_lock_sha256="c" * 64,
        descriptor_sha256="d" * 64,
        operations=("functions", "strings"),
        arg_schema={"type": "object", "required": ["artifact_id"]},
        execution_classes=execution_classes,
        required_scope={"mode": "offline_ctf"},
        limits=CapabilityLimits(timeout_seconds=60, max_output_bytes=16_384, max_decode_bytes=4096),
    )


def _setup_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "state" / "harness.db"
    storage = Storage(db_path)
    storage.initialize()
    return db_path


# ---------------------------------------------------------------------------
# CTF-06: Crash at Reserve / Launch / Result Boundaries -> Reconciliation
# ---------------------------------------------------------------------------


def test_ctf06_crash_reconciliation_across_restart_prevents_duplicates(tmp_path: Path) -> None:
    db_path = _setup_db(tmp_path)
    s1 = Storage(db_path)
    manifests1 = RunManifestManager(s1)
    actions1 = ActionManager(s1)

    budget = BudgetSpec(
        run_budget_seconds=120,
        max_evidence_bytes_per_run=50_000,
        max_tool_calls=5,
        heavy_job_concurrency=2,
    )
    manifests1.create_run(_make_manifest("run-crash", budget=budget))
    cap = _make_capability()

    # Action A: reserved and started (crashes while running)
    req_running = ActionRequest(
        run_id="run-crash",
        request_id="req-running",
        expected_revision=1,
        capability_name="analysis.query",
        operation="functions",
        arguments={"artifact_id": "art-1"},
    )
    sub_a = actions1.submit_action(
        run_id="run-crash",
        principal_id="alice",
        request=req_running,
        capability=cap,
        scope_revision="scope-1",
    )
    running_a = actions1.start_action(
        action_id=sub_a.action.action_id,
        supervisor_key="guest-1",
        supervisor_instance_id="sup-old",
        process_start_id="pid-101",
    )
    assert running_a.fencing_token == 1

    # Action B: reserved only (crashes between reserve and launch)
    req_reserved = ActionRequest(
        run_id="run-crash",
        request_id="req-reserved",
        expected_revision=2,
        capability_name="analysis.query",
        operation="strings",
        arguments={"artifact_id": "art-1"},
    )
    sub_b = actions1.submit_action(
        run_id="run-crash",
        principal_id="alice",
        request=req_reserved,
        capability=cap,
        scope_revision="scope-1",
    )
    assert sub_b.action.state == ActionLifecycleState.RESERVED

    # Simulate restart with fresh Storage / Managers reading the same SQLite DB
    s2 = Storage(db_path)
    recovery2 = RecoveryManager(s2)
    actions2 = ActionManager(s2)
    manifests2 = RunManifestManager(s2)

    report = recovery2.reconcile_inflight_actions(
        run_id="run-crash",
        is_process_alive=lambda _act: False,
        supervisor_key="guest-1",
    )
    assert [a.action_id for a in report.reconciled_to_required] == [running_a.action_id]
    assert [a.action_id for a in report.expired_reserved] == [sub_b.action.action_id]
    assert report.new_supervisor_token == 2

    # Action A is reconciliation_required (no successful result) and retains its conservative reservation
    reloaded_a = actions2.get_action_with_envelope(running_a.action_id)
    assert reloaded_a.action.state == ActionLifecycleState.RECONCILIATION_REQUIRED
    assert reloaded_a.envelope is None

    # Action B is expired before launch -> ResultEnvelope is denied (never ok), slot released
    reloaded_b = actions2.get_action_with_envelope(sub_b.action.action_id)
    assert reloaded_b.action.state == ActionLifecycleState.EXPIRED
    assert reloaded_b.envelope is not None
    assert reloaded_b.envelope.status == EnvelopeStatus.DENIED

    # Conservative reservation from running_a stays locked (active_heavy_jobs == 1, remaining_ms == 60_000)
    snap = manifests2.get_run_snapshot("run-crash")
    assert snap.usage.active_heavy_jobs == 1
    assert snap.remaining_ms == 60_000

    # Retrying original requests after crash returns reconciled records without creating duplicates
    replay_a = actions2.submit_action(
        run_id="run-crash",
        principal_id="alice",
        request=req_running,
        capability=cap,
        scope_revision="scope-1",
    )
    assert replay_a.replayed is True
    assert replay_a.action.action_id == running_a.action_id
    assert replay_a.action.state == ActionLifecycleState.RECONCILIATION_REQUIRED

    # Registry explicitly resolves reconciliation_required -> FAILED (releases conservative reservation)
    resolved = recovery2.resolve_reconciled_action(
        action_id=running_a.action_id,
        target_state=ActionLifecycleState.FAILED,
        usage=UsageMetrics(wall_ms=10_000, output_bytes=0),
        summary="Process crashed during restart reconciliation.",
    )
    assert resolved.action.state == ActionLifecycleState.FAILED
    assert resolved.envelope is not None
    assert resolved.envelope.status == EnvelopeStatus.TOOL_ERROR

    snap_resolved = manifests2.get_run_snapshot("run-crash")
    assert snap_resolved.usage.active_heavy_jobs == 0
    assert snap_resolved.remaining_ms == 110_000


# ---------------------------------------------------------------------------
# CTF-08: Supervisor Restart -> Stale Fencing Rejected & Session Marked Lost
# ---------------------------------------------------------------------------


def test_ctf08_stale_fencing_token_rejected_and_session_marked_lost(tmp_path: Path) -> None:
    db_path = _setup_db(tmp_path)
    s1 = Storage(db_path)
    manifests1 = RunManifestManager(s1)
    actions1 = ActionManager(s1)
    leases1 = LeaseManager(s1)

    manifests1.create_run(_make_manifest("run-fence"))
    cap = _make_capability()

    # Open an active dynamic session lease and start an action on sup-1
    lease = leases1.acquire_lease(
        run_id="run-fence",
        principal_id="alice",
        capability_name="session.control",
        adapter_revision="dbg-rev-1",
        artifact_id="art-1",
        supervisor_instance_id="sup-1",
        idle_seconds=900,
    )
    assert lease.state == SessionLeaseState.ACTIVE

    sub = actions1.submit_action(
        run_id="run-fence",
        principal_id="alice",
        request=ActionRequest(
            run_id="run-fence",
            request_id="req-f1",
            expected_revision=2,  # lease acquisition bumped revision 1 -> 2
            capability_name="analysis.query",
            operation="functions",
            arguments={"artifact_id": "art-1"},
        ),
        capability=cap,
        scope_revision="scope-1",
    )
    running = actions1.start_action(
        action_id=sub.action.action_id,
        supervisor_key="guest-1",
        supervisor_instance_id="sup-1",
        process_start_id="pid-old",
    )
    old_token = running.fencing_token
    assert old_token == 1

    # Supervisor restarts -> reconciliation fences out old epoch and marks dynamic sessions lost
    s2 = Storage(db_path)
    recovery2 = RecoveryManager(s2)
    leases2 = LeaseManager(s2)
    manifests2 = RunManifestManager(s2)

    report = recovery2.reconcile_inflight_actions(
        run_id="run-fence",
        is_process_alive=lambda _act: False,
        supervisor_key="guest-1",
    )
    assert lease.session_id in report.lost_session_ids
    assert report.new_supervisor_token == 2

    reloaded_lease = leases2.get_lease(lease.session_id)
    assert reloaded_lease.state == SessionLeaseState.LOST
    assert manifests2.get_run_snapshot("run-fence").usage.active_sessions == 0

    # Old worker wakes up and attempts completion with old fencing_token=1 -> rejected
    with pytest.raises(FencingError):
        recovery2.commit_worker_result(
            action_id=running.action_id,
            fencing_token=old_token,
            target_state=ActionLifecycleState.COMPLETED,
            usage=UsageMetrics(wall_ms=100, output_bytes=100),
            summary="Late stale completion",
            supervisor_key="guest-1",
        )

    # Also test resume -> new worker gets fencing_token=3, old token=1 still rejected, token=3 accepted
    resumed = recovery2.resolve_reconciled_action(
        action_id=running.action_id,
        target_state=ActionLifecycleState.RUNNING,
        supervisor_key="guest-1",
        supervisor_instance_id="sup-2",
        process_start_id="pid-new",
    )
    new_token = resumed.action.fencing_token
    assert new_token == 3

    with pytest.raises(FencingError):
        recovery2.commit_worker_result(
            action_id=running.action_id,
            fencing_token=old_token,
            target_state=ActionLifecycleState.COMPLETED,
            usage=UsageMetrics(wall_ms=100, output_bytes=100),
            summary="Late stale completion after resume",
            supervisor_key="guest-1",
        )

    committed = recovery2.commit_worker_result(
        action_id=running.action_id,
        fencing_token=new_token,
        target_state=ActionLifecycleState.COMPLETED,
        usage=UsageMetrics(wall_ms=120, output_bytes=256),
        summary="Replacement worker succeeded.",
        supervisor_key="guest-1",
    )
    assert committed.action.state == ActionLifecycleState.COMPLETED
    assert committed.envelope is not None
    assert committed.envelope.status == EnvelopeStatus.OK


# ---------------------------------------------------------------------------
# CTF-07 (Guest Blocking) & Session Lease / Reserved Expiry Contracts
# ---------------------------------------------------------------------------


def test_ctf07_cleanup_unconfirmed_blocks_new_actions_and_leases(tmp_path: Path) -> None:
    db_path = _setup_db(tmp_path)
    storage = Storage(db_path)
    manifests = RunManifestManager(storage)
    actions = ActionManager(storage)
    recovery = RecoveryManager(storage)
    leases = LeaseManager(storage)

    manifests.create_run(_make_manifest("run-unconfirmed"))
    cap = _make_capability()

    sub = actions.submit_action(
        run_id="run-unconfirmed",
        principal_id="alice",
        request=ActionRequest(
            run_id="run-unconfirmed",
            request_id="req-1",
            expected_revision=1,
            capability_name="analysis.query",
            operation="functions",
            arguments={"artifact_id": "art-1"},
        ),
        capability=cap,
        scope_revision="scope-1",
    )
    running = actions.start_action(
        action_id=sub.action.action_id,
        supervisor_key="guest-1",
        supervisor_instance_id="sup-1",
        process_start_id="pid-hung",
    )
    # Timeout with unconfirmed cleanup retains conservative reservation and blocks guest
    actions.settle_action_with_envelope(
        action_id=running.action_id,
        target_state=ActionLifecycleState.TIMEOUT,
        usage=UsageMetrics(wall_ms=60_000, output_bytes=0),
        fencing_token=running.fencing_token,
        summary="Timed out; descendant cleanup pending verification.",
        retain_reservation=True,
    )
    health = recovery.mark_cleanup_unconfirmed(
        "run-unconfirmed",
        "Descendant process still alive after kill.",
        action_id=running.action_id,
    )
    assert health == GuestHealthState.CLEANUP_UNCONFIRMED

    snap = manifests.get_run_snapshot("run-unconfirmed")
    assert snap.guest_health == GuestHealthState.CLEANUP_UNCONFIRMED
    assert snap.usage.active_heavy_jobs == 1

    with pytest.raises(GuestBlockedError):
        actions.submit_action(
            run_id="run-unconfirmed",
            principal_id="alice",
            request=ActionRequest(
                run_id="run-unconfirmed",
                request_id="req-2",
                expected_revision=snap.revision,
                capability_name="analysis.query",
                operation="strings",
                arguments={"artifact_id": "art-1"},
            ),
            capability=cap,
            scope_revision="scope-1",
        )

    with pytest.raises(GuestBlockedError):
        leases.acquire_lease(
            run_id="run-unconfirmed",
            principal_id="alice",
            capability_name="session.control",
            adapter_revision="dbg-rev-1",
        )


def test_session_lease_idle_expiry_and_reserved_action_expiry(tmp_path: Path) -> None:
    db_path = _setup_db(tmp_path)
    storage = Storage(db_path)
    manifests = RunManifestManager(storage)
    actions = ActionManager(storage)
    leases = LeaseManager(storage)

    t0 = datetime(2026, 11, 13, 1, 0, 0, tzinfo=UTC)
    budget = BudgetSpec(interactive_session_limit=1, session_idle_seconds=900)
    manifests.create_run(_make_manifest("run-lease", budget=budget))
    cap = _make_capability()

    lease = leases.acquire_lease(
        run_id="run-lease",
        principal_id="alice",
        capability_name="session.control",
        adapter_revision="dbg-rev-1",
        now=t0,
    )
    assert lease.expires_at == t0 + timedelta(seconds=900)

    # Concurrency limit = 1 blocks second session
    with pytest.raises(BudgetExceededError):
        leases.acquire_lease(
            run_id="run-lease",
            principal_id="alice",
            capability_name="session.control",
            adapter_revision="dbg-rev-1",
            now=t0 + timedelta(seconds=10),
        )

    # Touch extends idle expiry
    touched = leases.touch_lease(
        lease.session_id,
        run_id="run-lease",
        principal_id="alice",
        now=t0 + timedelta(seconds=300),
    )
    assert touched.expires_at == t0 + timedelta(seconds=1200)

    # Touch past idle expiry transitions lease to EXPIRED and raises InvalidStateTransitionError
    with pytest.raises(InvalidStateTransitionError):
        leases.touch_lease(
            lease.session_id,
            run_id="run-lease",
            principal_id="alice",
            now=t0 + timedelta(seconds=1201),
        )
    assert leases.get_lease(lease.session_id).state == SessionLeaseState.EXPIRED
    assert manifests.get_run_snapshot("run-lease").usage.active_sessions == 0

    # Pre-launch reserved action expiry transitions reserved -> expired -> denied
    sub = actions.submit_action(
        run_id="run-lease",
        principal_id="alice",
        request=ActionRequest(
            run_id="run-lease",
            request_id="req-stale",
            expected_revision=2,
            capability_name="analysis.query",
            operation="functions",
            arguments={"artifact_id": "art-1"},
        ),
        capability=cap,
        scope_revision="scope-1",
        now=t0,
    )
    expired = leases.expire_reserved_actions(
        run_id="run-lease",
        max_age_seconds=60,
        expiry_reason="reservation_ttl_elapsed",
        now=t0 + timedelta(seconds=61),
    )
    assert len(expired) == 1
    assert expired[0].action.action_id == sub.action.action_id
    assert expired[0].action.state == ActionLifecycleState.EXPIRED
    assert expired[0].envelope is not None
    assert expired[0].envelope.status == EnvelopeStatus.DENIED
    assert expired[0].envelope.error is not None
    assert expired[0].envelope.error.message == "reservation_ttl_elapsed"
