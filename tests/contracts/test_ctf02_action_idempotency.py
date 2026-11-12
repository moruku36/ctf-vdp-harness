"""Contract tests for runs subsystem: manifest guards, CTF-02 idempotency, CTF-11 invariants, hypotheses."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from ctf_mcp.contracts import (
    ActionConflictError,
    ActionLifecycleState,
    ActionRequest,
    BudgetExceededError,
    BudgetManagerPort,
    BudgetSpec,
    CapabilityDescriptor,
    CapabilityLimits,
    ContractViolationError,
    EnvelopeStatus,
    ErrorDetail,
    EvidenceAccessDeniedError,
    EvidenceRef,
    ExecutionClass,
    HypothesisState,
    InvalidStateTransitionError,
    RunManifest,
    RunMode,
    ScopeDeniedError,
    UsageMetrics,
    sha256_bytes,
)
from ctf_mcp.runs import (
    ActionManager,
    HypothesisManager,
    RunManifestManager,
    build_result_envelope,
)
from ctf_mcp.storage import Storage


def _make_manifest(
    run_id: str = "run-1",
    *,
    owner: str = "alice",
    task_id: str = "task-local-1",
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
        adapter_revisions={"static-core": "deadbeef1234"},
        client_label="Codex-CLI-Test",
        instruction_revision="instr-v1",
        budget_spec=budget or BudgetSpec(),
        created_at=datetime(2026, 11, 13, 0, 0, 0, tzinfo=UTC),
    )


def _make_capability(
    name: str = "artifact.inspect",
    *,
    timeout_seconds: int = 60,
    max_output_bytes: int = 16384,
) -> CapabilityDescriptor:
    return CapabilityDescriptor(
        name=name,
        adapter_id="static-core",
        adapter_commit="deadbeef1234",
        dependency_lock_sha256="c" * 64,
        descriptor_sha256="d" * 64,
        operations=("header", "strings"),
        arg_schema={"type": "object", "required": ["artifact_id"]},
        execution_classes=(ExecutionClass.STATIC,),
        required_scope={"mode": "offline_ctf"},
        limits=CapabilityLimits(
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            max_decode_bytes=4096,
        ),
    )


def _init_storage(tmp_path: Path) -> Storage:
    storage = Storage(tmp_path / "harness.db")
    storage.initialize()
    return storage


# ---------------------------------------------------------------------------
# 1. RunManifest Persistence & Secret/Flag Guards
# ---------------------------------------------------------------------------


def test_run_manifest_lifecycle_and_secret_rejection(tmp_path: Path) -> None:
    storage = _init_storage(tmp_path)
    manifests = RunManifestManager(storage)

    budget = BudgetSpec(run_budget_seconds=120, max_evidence_bytes_per_run=50_000, max_tool_calls=5)
    m = _make_manifest("run-m1", budget=budget)
    created = manifests.create_run(m)
    assert created.run_id == "run-m1"

    snap = manifests.get_run_snapshot("run-m1", principal_id="alice")
    assert snap.remaining_ms == 120_000
    assert snap.remaining_bytes == 50_000
    assert snap.remaining_calls == 5
    assert snap.revision == 1

    with pytest.raises(ScopeDeniedError):
        manifests.get_run_snapshot("run-m1", principal_id="bob")

    # Duplicate run_id rejected
    with pytest.raises(ActionConflictError):
        manifests.create_run(m)

    # Secrets, tokens, synthetic markers, and flags are forbidden in RunManifest
    for bad_task in (
        "flag{never_put_flags_in_manifest}",
        "SYNTHETIC_SECRET_ABC123",
        "CTF_SENSITIVE_MARKER_99",
        "Bearer abcdefghijklmnop",
        "sk-1234567890abcdef1234",
    ):
        with pytest.raises(ContractViolationError):
            manifests.create_run(_make_manifest(f"run-bad-{hash(bad_task)}", task_id=bad_task))

    closed = manifests.close_run("run-m1", expected_revision=1)
    assert closed.closed_at is not None

    # Re-closing is forbidden
    with pytest.raises(InvalidStateTransitionError):
        manifests.close_run("run-m1")


# ---------------------------------------------------------------------------
# 2. CTF-02: Action Idempotency, Conflicts, repeat_of, Optimistic Locking
# ---------------------------------------------------------------------------


def test_ctf02_idempotent_replay_conflict_and_no_double_charge(tmp_path: Path) -> None:
    storage = _init_storage(tmp_path)
    manifests = RunManifestManager(storage)
    actions = ActionManager(storage)

    assert isinstance(actions, BudgetManagerPort)

    budget = BudgetSpec(run_budget_seconds=120, max_evidence_bytes_per_run=100_000, max_tool_calls=5)
    manifests.create_run(_make_manifest("run-1", budget=budget))
    cap = _make_capability(timeout_seconds=30, max_output_bytes=10_000)

    req1 = ActionRequest(
        run_id="run-1",
        request_id="req-1",
        expected_revision=1,
        capability_name="artifact.inspect",
        operation="strings",
        arguments={"artifact_id": "art-1", "opts": {"min_len": 4, "limit": 50}},
    )
    first = actions.submit_action(
        run_id="run-1",
        principal_id="alice",
        request=req1,
        capability=cap,
        scope_revision="scope-1",
    )
    assert first.replayed is False
    assert first.action.state == ActionLifecycleState.RESERVED
    assert first.action.reserved_ms == 30_000
    assert first.action.reserved_bytes == 10_000

    snap_after_first = manifests.get_run_snapshot("run-1")
    assert snap_after_first.remaining_calls == 4
    assert snap_after_first.remaining_ms == 90_000
    assert snap_after_first.remaining_bytes == 90_000
    assert snap_after_first.revision == 2

    # Replay with equivalent canonical args (key order differs) returns existing action, zero double-charge
    req1_reordered = ActionRequest(
        run_id="run-1",
        request_id="req-1",
        expected_revision=1,
        capability_name="artifact.inspect",
        operation="strings",
        arguments={"opts": {"limit": 50, "min_len": 4}, "artifact_id": "art-1"},
    )
    replay = actions.submit_action(
        run_id="run-1",
        principal_id="alice",
        request=req1_reordered,
        capability=cap,
        scope_revision="scope-1",
    )
    assert replay.replayed is True
    assert replay.action.action_id == first.action.action_id

    snap_after_replay = manifests.get_run_snapshot("run-1")
    assert snap_after_replay.remaining_calls == 4
    assert snap_after_replay.remaining_ms == 90_000
    assert snap_after_replay.revision == 2

    # Same (principal, run_id, request_id) with altered arguments raises ActionConflictError
    req1_changed_args = ActionRequest(
        run_id="run-1",
        request_id="req-1",
        expected_revision=1,
        capability_name="artifact.inspect",
        operation="strings",
        arguments={"artifact_id": "art-1", "opts": {"min_len": 8, "limit": 50}},
    )
    with pytest.raises(ActionConflictError):
        actions.submit_action(
            run_id="run-1",
            principal_id="alice",
            request=req1_changed_args,
            capability=cap,
            scope_revision="scope-1",
        )

    # Same request_id under a DIFFERENT principal is an independent idempotency key
    manifests.create_run(_make_manifest("run-bob", owner="bob", budget=budget))
    bob_action = actions.submit_action(
        run_id="run-bob",
        principal_id="bob",
        request=ActionRequest(
            run_id="run-bob",
            request_id="req-1",
            expected_revision=1,
            capability_name="artifact.inspect",
            operation="strings",
            arguments={"artifact_id": "art-1"},
        ),
        capability=cap,
        scope_revision="scope-1",
    )
    assert bob_action.action.action_id != first.action.action_id


def test_ctf02_repeat_of_expected_revision_and_budget_clamping(tmp_path: Path) -> None:
    storage = _init_storage(tmp_path)
    manifests = RunManifestManager(storage)
    actions = ActionManager(storage)

    # Short total run budget: 45s total vs 60s capability timeout
    budget = BudgetSpec(
        run_budget_seconds=45,
        action_timeout_seconds=60,
        max_evidence_bytes_per_run=5_000,
        max_tool_calls=2,
        heavy_job_concurrency=1,
    )
    manifests.create_run(_make_manifest("run-2", budget=budget))
    cap = _make_capability(timeout_seconds=60, max_output_bytes=3_000)

    # Wrong expected_revision fails
    with pytest.raises(ActionConflictError):
        actions.submit_action(
            run_id="run-2",
            principal_id="alice",
            request=ActionRequest(
                run_id="run-2",
                request_id="req-bad-rev",
                expected_revision=99,
                capability_name="artifact.inspect",
                operation="header",
                arguments={"artifact_id": "art-1"},
            ),
            capability=cap,
            scope_revision="scope-1",
        )

    # First action reserves min(60s, 45s) = 45_000 ms, then settles using 40_000 ms and 2_000 bytes
    sub1 = actions.submit_action(
        run_id="run-2",
        principal_id="alice",
        request=ActionRequest(
            run_id="run-2",
            request_id="req-1",
            expected_revision=1,
            capability_name="artifact.inspect",
            operation="header",
            arguments={"artifact_id": "art-1"},
        ),
        capability=cap,
        scope_revision="scope-1",
    )
    assert sub1.action.reserved_ms == 45_000
    assert sub1.action.reserved_bytes == 3_000

    # Concurrent second action blocked while heavy job slot is busy
    with pytest.raises(BudgetExceededError):
        actions.submit_action(
            run_id="run-2",
            principal_id="alice",
            request=ActionRequest(
                run_id="run-2",
                request_id="req-concurrent",
                expected_revision=2,
                capability_name="artifact.inspect",
                operation="header",
                arguments={"artifact_id": "art-1"},
            ),
            capability=cap,
            scope_revision="scope-1",
        )

    running = actions.start_action(
        action_id=sub1.action.action_id,
        supervisor_key="guest-1",
        supervisor_instance_id="sup-1",
        process_start_id="pid-10",
    )
    settled1 = actions.settle_action_with_envelope(
        action_id=running.action_id,
        target_state=ActionLifecycleState.COMPLETED,
        usage=UsageMetrics(wall_ms=40_000, output_bytes=2_000),
        fencing_token=running.fencing_token,
        summary="Header parsed.",
        evidence=(EvidenceRef(id="ev-1", sha256=sha256_bytes(b"hdr"), kind="tool_output"),),
    )
    assert settled1.envelope is not None
    assert settled1.envelope.status == EnvelopeStatus.OK

    # Replay after completion returns saved ResultEnvelope too
    replay1 = actions.submit_action(
        run_id="run-2",
        principal_id="alice",
        request=ActionRequest(
            run_id="run-2",
            request_id="req-1",
            expected_revision=1,
            capability_name="artifact.inspect",
            operation="header",
            arguments={"artifact_id": "art-1"},
        ),
        capability=cap,
        scope_revision="scope-1",
    )
    assert replay1.replayed is True
    assert replay1.envelope is not None
    assert replay1.envelope.status == EnvelopeStatus.OK

    # Deliberate repeat_of with new request_id clamps remaining 5_000 ms and 3_000 bytes
    sub2 = actions.submit_action(
        run_id="run-2",
        principal_id="alice",
        request=ActionRequest(
            run_id="run-2",
            request_id="req-2",
            expected_revision=2,
            capability_name="artifact.inspect",
            operation="header",
            arguments={"artifact_id": "art-1"},
            repeat_of=sub1.action.action_id,
        ),
        capability=cap,
        scope_revision="scope-1",
    )
    assert sub2.action.repeat_of == sub1.action.action_id
    assert sub2.action.reserved_ms == 5_000
    assert sub2.action.reserved_bytes == 3_000

    # Unknown repeat_of rejected
    with pytest.raises(ContractViolationError):
        actions.submit_action(
            run_id="run-2",
            principal_id="alice",
            request=ActionRequest(
                run_id="run-2",
                request_id="req-bad-repeat",
                expected_revision=3,
                capability_name="artifact.inspect",
                operation="header",
                arguments={"artifact_id": "art-1"},
                repeat_of="act-does-not-exist",
            ),
            capability=cap,
            scope_revision="scope-1",
        )


# ---------------------------------------------------------------------------
# 3. CTF-11 & Lifecycle Envelope Invariants
# ---------------------------------------------------------------------------


def test_ctf11_failed_analyzer_maps_to_tool_error_and_blocks_fake_ok(tmp_path: Path) -> None:
    storage = _init_storage(tmp_path)
    manifests = RunManifestManager(storage)
    actions = ActionManager(storage)
    manifests.create_run(_make_manifest("run-err"))
    cap = _make_capability()

    sub = actions.submit_action(
        run_id="run-err",
        principal_id="alice",
        request=ActionRequest(
            run_id="run-err",
            request_id="req-fail",
            expected_revision=1,
            capability_name="artifact.inspect",
            operation="strings",
            arguments={"artifact_id": "art-1"},
        ),
        capability=cap,
        scope_revision="scope-1",
    )
    running = actions.start_action(
        action_id=sub.action.action_id,
        supervisor_key="guest-1",
        supervisor_instance_id="sup-1",
        process_start_id="pid-99",
    )

    # COMPLETED without tool receipt cannot become OK
    with pytest.raises(ContractViolationError):
        build_result_envelope(
            action=running,
            target_state=ActionLifecycleState.COMPLETED,
            usage=UsageMetrics(wall_ms=10, output_bytes=0),
            has_tool_receipt=False,
        )

    # FAILED with empty output always produces tool_error with explicit ErrorDetail
    settled = actions.settle_action_with_envelope(
        action_id=running.action_id,
        target_state=ActionLifecycleState.FAILED,
        usage=UsageMetrics(wall_ms=50, output_bytes=0),
        fencing_token=running.fencing_token,
        summary="",
        evidence=(),
    )
    assert settled.envelope is not None
    assert settled.envelope.status == EnvelopeStatus.TOOL_ERROR
    assert settled.envelope.error is not None
    assert settled.envelope.error.code == "tool_error"
    assert settled.envelope.evidence == ()


# ---------------------------------------------------------------------------
# 4. Hypothesis Ledger CRUD & Optimistic Locking
# ---------------------------------------------------------------------------


def test_hypothesis_crud_optimistic_locking_and_cross_run_isolation(tmp_path: Path) -> None:
    storage = _init_storage(tmp_path)
    manifests = RunManifestManager(storage)
    hyp = HypothesisManager(storage)

    manifests.create_run(_make_manifest("run-h1"))
    manifests.create_run(_make_manifest("run-h2"))

    created = hyp.create_hypothesis(
        run_id="run-h1",
        claim="XOR key is single-byte 0x42",
        next_observation="Decode payload and inspect magic bytes.",
        supporting_evidence_ids=("ev-1", "ev-1"),
    )
    assert created.revision == 1
    assert created.state == HypothesisState.UNKNOWN
    assert created.supporting_evidence_ids == ("ev-1",)

    # Overlapping supporting & contradicting evidence rejected
    with pytest.raises(ContractViolationError):
        hyp.update_hypothesis(
            hypothesis_id=created.hypothesis_id,
            run_id="run-h1",
            expected_revision=1,
            add_contradicting_evidence_ids=("ev-1",),
        )

    updated = hyp.update_hypothesis(
        hypothesis_id=created.hypothesis_id,
        run_id="run-h1",
        expected_revision=1,
        state=HypothesisState.SUPPORTED,
        add_supporting_evidence_ids=("ev-2",),
        next_observation="Verify recovered plaintext against local verifier.",
    )
    assert updated.revision == 2
    assert updated.state == HypothesisState.SUPPORTED
    assert updated.supporting_evidence_ids == ("ev-1", "ev-2")

    # Stale expected_revision raises ActionConflictError
    with pytest.raises(ActionConflictError):
        hyp.update_hypothesis(
            hypothesis_id=created.hypothesis_id,
            run_id="run-h1",
            expected_revision=1,
            state=HypothesisState.REFUTED,
        )

    # Cross-run access denied
    with pytest.raises(EvidenceAccessDeniedError):
        hyp.get_hypothesis(created.hypothesis_id, run_id="run-h2")
    with pytest.raises(EvidenceAccessDeniedError):
        hyp.update_hypothesis(
            hypothesis_id=created.hypothesis_id,
            run_id="run-h2",
            expected_revision=2,
            state=HypothesisState.REFUTED,
        )
