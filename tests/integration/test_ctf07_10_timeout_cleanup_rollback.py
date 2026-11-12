"""Integration and contract tests for verification and adapters (CTF-05, CTF-07, CTF-10, CTF-11, CTF-12)."""

from __future__ import annotations

import asyncio
import ctypes
import os
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from ctf_mcp.adapters import (
    BaseAdapter,
    ProcessTreeGuard,
    SubprocessOutcome,
    SubprocessRunner,
    SyntheticAdapter,
    compute_descriptor_sha256,
    create_synthetic_descriptor,
)
from ctf_mcp.adapters.runner import _default_tree_guard_factory
from ctf_mcp.contracts import (
    ActionLifecycleState,
    ActionRecord,
    AdapterPort,
    CapabilityDeniedError,
    CapabilityDescriptor,
    CapabilityLimits,
    ContractViolationError,
    EnvelopeStatus,
    ExecutionClass,
    GuestBlockedError,
    GuestHealthState,
    PathSecurityError,
    RunMode,
    VerificationStatus,
    VerifierPort,
    canonical_digest,
    sha256_bytes,
)
from ctf_mcp.fs_guard import safe_write_atomic
from ctf_mcp.storage import Storage
from ctf_mcp.verification import (
    CloseIntegrityChecker,
    ExpectedChallengeSpec,
    LocalCtfVerifier,
    VerifierRegistry,
    assert_close_ready,
    evaluate_close_integrity,
    load_verifications_for_run,
    save_verification_record,
)


def _now() -> datetime:
    return datetime(2026, 11, 13, 12, 0, 0, tzinfo=UTC)


def _is_os_pid_alive(pid: int) -> bool:
    """Check directly at the OS layer whether ``pid`` is still running."""
    if sys.platform == "win32":
        from ctypes import wintypes

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = k32.OpenProcess(0x1000, False, pid)
        if not handle:
            err = ctypes.get_last_error()
            if err == 87:  # ERROR_INVALID_PARAMETER (process gone)
                return False
            # Handle inaccessible -> conservative True for safety check
            return True
        try:
            exit_code = wintypes.DWORD()
            if not k32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return True
            return int(exit_code.value) == 259  # STILL_ACTIVE
        finally:
            k32.CloseHandle(handle)

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_pid_dead(pid: int, timeout: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _is_os_pid_alive(pid):
            return True
        time.sleep(0.02)
    return not _is_os_pid_alive(pid)


def _seed_run(
    storage: Storage,
    *,
    run_id: str = "run-1",
    task_id: str = "task-1",
    guest_health: GuestHealthState = GuestHealthState.READY,
    active_heavy_jobs: int = 0,
    active_sessions: int = 0,
) -> None:
    with storage.transaction() as conn:
        conn.execute(
            """
            INSERT INTO runs (
                run_id, owner_principal_id, task_id, mode, scope_revision,
                manifest_json, budget_spec_json, remaining_ms, remaining_bytes,
                remaining_calls, active_heavy_jobs, active_sessions, guest_health,
                revision, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                "alice",
                task_id,
                RunMode.OFFLINE_CTF.value,
                "scope-v1",
                "{}",
                "{}",
                60_000,
                10_485_760,
                40,
                active_heavy_jobs,
                active_sessions,
                guest_health.value,
                1,
                _now().isoformat(),
            ),
        )


def _seed_action(
    storage: Storage,
    *,
    action_id: str,
    run_id: str = "run-1",
    request_id: str | None = None,
    state: ActionLifecycleState = ActionLifecycleState.COMPLETED,
) -> None:
    req_id = request_id or f"req-{action_id}"
    with storage.transaction() as conn:
        conn.execute(
            """
            INSERT INTO actions (
                action_id, principal_id, run_id, request_id, expected_revision,
                capability_name, operation, adapter_revision, canonical_args_sha256,
                sanitized_args_json, scope_revision, state, reserved_ms, reserved_bytes,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                action_id,
                "alice",
                run_id,
                req_id,
                1,
                "synthetic.probe",
                "observe",
                "p1-synthetic-adapter-v1",
                "a" * 64,
                "{}",
                "scope-v1",
                state.value,
                1000,
                4096,
                _now().isoformat(),
                _now().isoformat(),
            ),
        )


def _seed_evidence(
    storage: Storage,
    vault_root: Path,
    *,
    evidence_id: str,
    run_id: str = "run-1",
    action_id: str = "act-1",
    payload: bytes = b"sample-evidence",
    capture_complete: bool = True,
    omission_reason: str | None = None,
    revoked_at: str | None = None,
) -> str:
    digest = sha256_bytes(payload)
    relpath = f"blobs/{digest[:2]}/{digest}"
    safe_write_atomic(vault_root, relpath, payload, overwrite=True)

    with storage.transaction() as conn:
        conn.execute(
            """
            INSERT INTO evidence_objects (
                evidence_id, run_id, owner_principal_id, action_id, raw_sha256,
                byte_length, media_type, capture_complete, omission_reason,
                role, parent_evidence_ids_json, manifest_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence_id,
                run_id,
                "alice",
                action_id,
                digest,
                len(payload),
                "text/plain; charset=utf-8",
                1 if capture_complete else 0,
                omission_reason,
                "raw",
                "[]",
                "{}",
                _now().isoformat(),
            ),
        )
        conn.execute(
            """
            INSERT INTO evidence_views (
                evidence_id, view_revision, run_id, owner_principal_id, view_sha256,
                view_bytes, encoding, capture_complete, omission_reason,
                storage_relpath, redaction_policy_rev, revoked_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence_id,
                "raw-v1",
                run_id,
                "alice",
                digest,
                len(payload),
                "utf-8",
                1 if capture_complete else 0,
                omission_reason,
                relpath,
                None,
                revoked_at,
                _now().isoformat(),
            ),
        )
    return digest


def _make_action(
    *,
    operation: str,
    args: dict[str, Any] | None = None,
    capability_name: str = "synthetic.probe",
    adapter_revision: str = "p1-synthetic-adapter-v1",
    state: ActionLifecycleState = ActionLifecycleState.RUNNING,
    reserved_ms: int = 10_000,
    reserved_bytes: int = 65_536,
) -> ActionRecord:
    sanitized = dict(args or {})
    return ActionRecord(
        run_id="run-1",
        action_id="act-1",
        request_id="req-1",
        principal_id="alice",
        expected_revision=1,
        capability_name=capability_name,
        operation=operation,
        adapter_revision=adapter_revision,
        canonical_args_sha256=canonical_digest(sanitized),
        sanitized_args=sanitized,
        scope_revision="scope-v1",
        state=state,
        reserved_ms=reserved_ms,
        reserved_bytes=reserved_bytes,
        fencing_token=1,
        supervisor_instance_id="sup-1",
        process_start_id="proc-1",
        created_at=_now(),
        updated_at=_now(),
    )


# ---------------------------------------------------------------------------
# 1. VerifierRegistry & LocalCtfVerifier (CTF local deterministic verification)
# ---------------------------------------------------------------------------


def test_verifier_registry_and_local_ctf_verifier_omits_plaintext_flag(
    tmp_path: Path,
) -> None:
    storage = Storage(tmp_path / "state" / "harness.db")
    storage.initialize()
    vault_root = tmp_path / "vault"
    vault_root.mkdir()

    _seed_run(storage, run_id="run-1", task_id="task-flag")
    _seed_run(storage, run_id="run-2", task_id="task-other")
    _seed_action(storage, action_id="act-1", run_id="run-1")
    _seed_action(storage, action_id="act-2", run_id="run-2", request_id="req-2")

    secret_flag = "flag{deterministic_local_secret_value_991}"
    flag_sha = sha256_bytes(secret_flag.encode("utf-8"))
    evidence_payload = f"solver_header=ok\n{secret_flag}\n".encode("utf-8")
    ev_sha = _seed_evidence(
        storage,
        vault_root,
        evidence_id="ev-1",
        run_id="run-1",
        action_id="act-1",
        payload=evidence_payload,
    )
    _seed_evidence(
        storage,
        vault_root,
        evidence_id="ev-other",
        run_id="run-2",
        action_id="act-2",
        payload=b"other-run-data",
    )

    verifier = LocalCtfVerifier(
        storage=storage,
        vault_root=vault_root,
        expected_by_task={
            "task-flag": ExpectedChallengeSpec(
                expected_flag_sha256=flag_sha,
                expected_evidence_sha256=ev_sha,
            )
        },
        clock=_now,
    )
    assert isinstance(verifier, VerifierPort)

    registry = VerifierRegistry()
    with pytest.raises(CapabilityDeniedError):
        registry.get("ctf.local_digest")
    with pytest.raises(CapabilityDeniedError):
        registry.verify("unregistered.verifier", run_id="run-1")

    registry.register(verifier)
    with pytest.raises(ContractViolationError):
        registry.register(verifier, replace=False)

    assert len(registry.list_verifiers()) == 1

    # Passing match via stored evidence (and wrong/descriptive claim) + persisted to DB
    rec_pass = registry.verify(
        "ctf.local_digest",
        run_id="run-1",
        evidence_ids=("ev-1",),
        claim="Solver output stored in ev-1",
    )
    assert rec_pass.status == VerificationStatus.PASSED
    save_verification_record(storage, rec_pass)
    loaded = load_verifications_for_run(storage, "run-1")
    assert len(loaded) == 1
    assert loaded[0].verification_id == rec_pass.verification_id

    # Plaintext flag must never appear in checks, limitations, or DB serialized record
    serialized = loaded[0].model_dump_json()
    assert secret_flag not in serialized
    assert "deterministic_local_secret_value" not in serialized

    # Failing match via wrong claim without evidence
    rec_fail = registry.verify(
        "ctf.local_digest",
        run_id="run-1",
        evidence_ids=(),
        claim="flag{wrong_candidate_value}",
    )
    assert rec_fail.status == VerificationStatus.FAILED
    assert "flag{wrong_candidate_value}" not in rec_fail.model_dump_json()

    # Cross-run evidence must fail ownership check
    rec_cross = registry.verify(
        "ctf.local_digest",
        run_id="run-1",
        evidence_ids=("ev-other",),
    )
    assert rec_cross.status == VerificationStatus.FAILED
    assert "evidence_run_ownership:failed" in rec_cross.checks_performed

    # Run without configured expectation returns INCONCLUSIVE
    rec_inc = registry.verify("ctf.local_digest", run_id="run-2", evidence_ids=("ev-other",))
    assert rec_inc.status == VerificationStatus.INCONCLUSIVE


# ---------------------------------------------------------------------------
# 2. AdapterPort Contract Enforcement & Self-Verification
# ---------------------------------------------------------------------------


def test_adapter_descriptor_self_verification_and_input_rejection(tmp_path: Path) -> None:
    # Production default for SyntheticAdapter is disabled/non-public
    disabled_adapter = SyntheticAdapter()
    assert isinstance(disabled_adapter, AdapterPort)
    assert disabled_adapter.descriptor().enabled is False
    with pytest.raises(CapabilityDeniedError):
        disabled_adapter.execute(_make_action(operation="observe"))

    # Tampered descriptor_sha256 must be rejected
    good_desc = create_synthetic_descriptor(enabled=True)
    assert compute_descriptor_sha256(good_desc) == good_desc.descriptor_sha256
    tampered_desc = good_desc.model_copy(
        update={
            "limits": CapabilityLimits(
                timeout_seconds=999,
                max_output_bytes=65_536,
                max_decode_bytes=4096,
            )
        }
    )
    with pytest.raises(ContractViolationError, match="descriptor_sha256"):
        SyntheticAdapter(descriptor_override=tampered_desc)

    # Placeholder adapter_commit must be rejected
    placeholder_desc = CapabilityDescriptor(
        name="synthetic.probe",
        adapter_id="synthetic",
        adapter_commit="COMMIT_PLACEHOLDER",
        dependency_lock_sha256="a" * 64,
        descriptor_sha256="b" * 64,
        operations=("observe",),
        arg_schema={"type": "object"},
        execution_classes=(ExecutionClass.STATIC,),
        required_scope={},
        limits=CapabilityLimits(timeout_seconds=10, max_output_bytes=1024, max_decode_bytes=512),
    )
    with pytest.raises(ContractViolationError, match="adapter_commit"):
        SyntheticAdapter(descriptor_override=placeholder_desc)

    adapter = SyntheticAdapter(enabled=True)

    # Disallowed operation enum
    with pytest.raises(CapabilityDeniedError):
        adapter.execute(_make_action(operation="arbitrary_shell"))

    # Raw command or client path keys rejected even if wrapped in nested args
    for bad_args in (
        {"command": "whoami"},
        {"shell_command": "ls"},
        {"path": "/etc/passwd"},
        {"file_path": "C:\\secret.txt"},
        {"nested": {"guest_path": "/tmp/x"}},
    ):
        with pytest.raises(ContractViolationError):
            adapter.execute(_make_action(operation="observe", args=bad_args))

    # Path traversal in opaque artifact_id rejected
    with pytest.raises(PathSecurityError):
        adapter.execute(_make_action(operation="observe", args={"artifact_id": "../escape"}))

    # Schema mismatch (additionalProperties=False) rejected
    with pytest.raises(ContractViolationError):
        adapter.execute(_make_action(operation="observe", args={"unexpected_param": 123}))

    # Symlink / missing artifact_paths rejected before launch
    missing_file = tmp_path / "does_not_exist.bin"
    with pytest.raises(PathSecurityError):
        adapter.execute(
            _make_action(operation="observe"),
            artifact_paths={"art-1": missing_file},
        )


# ---------------------------------------------------------------------------
# 3. CTF-05: Pre-Buffering Bounded Capture & Minimal Environment
# ---------------------------------------------------------------------------


def test_ctf05_runner_bounded_capture_and_minimal_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Host secrets must never leak into subprocess environment
    monkeypatch.setenv("CTF_MCP_AUTH_TOKEN", "host-secret-token-should-not-leak")
    monkeypatch.setenv("CTF_MCP_CURSOR_HMAC_KEY", "0123456789abcdef0123456789abcdef")

    runner = SubprocessRunner(default_timeout_seconds=10.0, default_max_output_bytes=1024)

    env_res = runner.run(
        [
            sys.executable,
            "-c",
            "import os, json; print(json.dumps(sorted(os.environ.keys())))",
        ]
    )
    assert env_res.outcome == SubprocessOutcome.COMPLETED
    assert env_res.capture_complete is True
    assert env_res.cleanup_confirmed is True
    child_env_keys = env_res.stdout.decode("utf-8")
    assert "CTF_MCP_AUTH_TOKEN" not in child_env_keys
    assert "CTF_MCP_CURSOR_HMAC_KEY" not in child_env_keys

    # String argv (raw command) must be refused
    with pytest.raises(ContractViolationError):
        runner.run("echo hi")  # type: ignore[arg-type]

    # Output flood via SyntheticAdapter exceeds max_output_bytes -> stopped immediately
    adapter = SyntheticAdapter(enabled=True, max_output_bytes=2048)
    outcome = adapter.execute_with_capture(
        _make_action(
            operation="output_flood",
            args={"bytes_to_emit": 2_097_152},
            reserved_bytes=2048,
        )
    )
    assert outcome.envelope.status == EnvelopeStatus.PARTIAL
    assert outcome.envelope.truncated is True
    assert outcome.capture_complete is False
    assert outcome.omission_reason is not None and "output_bytes_limit_exceeded" in outcome.omission_reason
    assert len(outcome.captured_bytes) <= 2048
    assert outcome.envelope.usage.output_bytes <= 2048
    assert outcome.cleanup_confirmed is True


# ---------------------------------------------------------------------------
# 4. CTF-07: Real Descendant Process Tree Termination & Unconfirmed Detection
# ---------------------------------------------------------------------------


def test_ctf07_timeout_and_cancel_kill_real_descendant_tree() -> None:
    import ctf_mcp.adapters.synthetic as synthetic_mod

    synthetic_script = str(Path(synthetic_mod.__file__).resolve())

    # A) Wall-clock timeout with real parent + grandchild Python processes
    adapter = SyntheticAdapter(enabled=True, timeout_seconds=10)
    timeout_outcome = adapter.execute_with_capture(
        _make_action(
            operation="spawn_timeout",
            args={"sleep_seconds": 15.0, "child_sleep_seconds": 15.0},
            reserved_ms=1500,  # lowered budget clamps timeout to 1.5s
        )
    )
    sub_res = timeout_outcome.subprocess_result
    assert sub_res.outcome == SubprocessOutcome.TIMEOUT
    assert timeout_outcome.envelope.status == EnvelopeStatus.TIMEOUT
    assert sub_res.cleanup_confirmed is True
    assert sub_res.capture_complete is False
    assert sub_res.omission_reason is not None

    stdout_text = sub_res.stdout.decode("utf-8", errors="replace")
    ready_lines = [ln for ln in stdout_text.splitlines() if ln.startswith("READY:")]
    assert len(ready_lines) == 1, f"Expected READY:<child_pid> in stdout, got {stdout_text!r}"
    child_pid = int(ready_lines[0].split(":", 1)[1].strip())

    # Confirm at OS level that BOTH root, observed PIDs, and grandchild PID are dead
    assert sub_res.root_pid is not None
    assert _wait_pid_dead(sub_res.root_pid)
    assert _wait_pid_dead(child_pid)
    for pid in sub_res.observed_pids:
        assert _wait_pid_dead(pid), f"Descendant PID {pid} survived timeout cleanup!"

    # B) Explicit cancellation triggered as soon as child reports READY:<grandchild_pid>
    cancel_ev = threading.Event()
    captured_child_pids: list[int] = []

    def _on_chunk(stream_name: str, chunk: bytes) -> None:
        if stream_name == "stdout" and b"READY:" in chunk:
            text = chunk.decode("utf-8", errors="replace")
            for ln in text.splitlines():
                if ln.startswith("READY:"):
                    captured_child_pids.append(int(ln.split(":", 1)[1].strip()))
            cancel_ev.set()

    runner = SubprocessRunner(default_timeout_seconds=15.0, default_max_output_bytes=65_536)
    cancel_res = runner.run(
        [
            sys.executable,
            synthetic_script,
            "--mode",
            "spawn_timeout",
            "--sleep-seconds",
            "15.0",
            "--child-sleep-seconds",
            "15.0",
        ],
        cancel_event=cancel_ev,
        on_output_chunk=_on_chunk,
    )
    assert cancel_res.outcome == SubprocessOutcome.CANCELLED
    assert cancel_res.cleanup_confirmed is True
    assert len(captured_child_pids) == 1
    assert cancel_res.root_pid is not None
    assert _wait_pid_dead(cancel_res.root_pid)
    assert _wait_pid_dead(captured_child_pids[0])
    for pid in cancel_res.observed_pids:
        assert _wait_pid_dead(pid)

    # C) Asyncio task cancellation also terminates the descendant tree
    async def _run_and_cancel_async() -> None:
        async_runner = SubprocessRunner(default_timeout_seconds=15.0)
        ready_async = asyncio.Event()
        loop = asyncio.get_running_loop()
        pids_seen: list[int] = []

        def _on_async_chunk(stream_name: str, chunk: bytes) -> None:
            if stream_name == "stdout" and b"READY:" in chunk:
                for ln in chunk.decode("utf-8", errors="replace").splitlines():
                    if ln.startswith("READY:"):
                        pids_seen.append(int(ln.split(":", 1)[1].strip()))
                loop.call_soon_threadsafe(ready_async.set)

        task = asyncio.create_task(
            async_runner.run_async(
                [
                    sys.executable,
                    synthetic_script,
                    "--mode",
                    "spawn_timeout",
                    "--sleep-seconds",
                    "15.0",
                    "--child-sleep-seconds",
                    "15.0",
                ],
                on_output_chunk=_on_async_chunk,
            )
        )
        await asyncio.wait_for(ready_async.wait(), timeout=5.0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert len(pids_seen) == 1
        assert _wait_pid_dead(pids_seen[0])

    asyncio.run(_run_and_cancel_async())


def test_ctf07_unconfirmed_cleanup_returns_false_and_blocks_close(tmp_path: Path) -> None:
    class _UnconfirmedGuardWrapper:
        """Wraps the real OS guard to simulate failed termination confirmation without leaking."""

        def __init__(self) -> None:
            self._inner: ProcessTreeGuard = _default_tree_guard_factory()

        def popen_kwargs(self) -> dict[str, Any]:
            return self._inner.popen_kwargs()

        def attach(self, proc: Any) -> bool:
            return self._inner.attach(proc)

        def collect_pids(self, root_pid: int) -> tuple[int, ...]:
            return self._inner.collect_pids(root_pid)

        def active_descendants_remain(self, root_pid: int) -> bool:
            return True

        def terminate_tree(self) -> bool:
            # Simulate kill failure on first attempt; close() / finally kills safely
            return False

        def confirm_terminated(
            self,
            proc: Any,
            observed_pids: tuple[int, ...],
            *,
            timeout_seconds: float,
        ) -> tuple[bool, tuple[int, ...], str | None]:
            try:
                return False, (proc.pid, *observed_pids), "simulated_unconfirmed_descendant"
            finally:
                self._inner.terminate_tree()
                self._inner.confirm_terminated(proc, observed_pids, timeout_seconds=2.0)

        def close(self) -> None:
            self._inner.close()

    unconfirmed_runner = SubprocessRunner(
        default_timeout_seconds=10.0,
        cleanup_confirm_timeout_seconds=1.0,
        tree_guard_factory=_UnconfirmedGuardWrapper,
    )
    adapter = SyntheticAdapter(enabled=True, runner=unconfirmed_runner)
    outcome = adapter.execute_with_capture(
        _make_action(operation="observe", args={"message": "hello"})
    )

    assert outcome.cleanup_confirmed is False
    assert outcome.subprocess_result.cleanup_confirmed is False
    assert outcome.subprocess_result.unconfirmed_pids
    # Unconfirmed cleanup must NEVER return EnvelopeStatus.OK
    assert outcome.envelope.status == EnvelopeStatus.TOOL_ERROR
    assert outcome.envelope.error is not None
    assert outcome.envelope.error.code == "cleanup_unconfirmed"

    # Close integrity check must block when cleanup_unconfirmed or unconfirmed PIDs exist
    storage = Storage(tmp_path / "state" / "harness.db")
    storage.initialize()
    _seed_run(
        storage,
        run_id="run-1",
        guest_health=GuestHealthState.CLEANUP_UNCONFIRMED,
    )
    _seed_action(storage, action_id="act-1", state=ActionLifecycleState.TIMEOUT)

    report = evaluate_close_integrity(
        storage,
        run_id="run-1",
        child_processes_confirmed_stopped=False,
        unconfirmed_process_ids=outcome.subprocess_result.unconfirmed_pids,
    )
    assert report.close_allowed is False
    assert report.cleanup_confirmed is False
    assert "guest_cleanup_unconfirmed" in report.blocking_reasons
    assert "child_processes_unconfirmed" in report.blocking_reasons

    with pytest.raises(GuestBlockedError):
        assert_close_ready(
            storage,
            run_id="run-1",
            child_processes_confirmed_stopped=False,
            unconfirmed_process_ids=outcome.subprocess_result.unconfirmed_pids,
        )


# ---------------------------------------------------------------------------
# 5. CTF-10: Close Integrity (Import Failure Before VM Rollback & Non-Terminal Actions)
# ---------------------------------------------------------------------------


def test_ctf10_import_failure_before_vm_rollback_blocks_export_and_preserves_evidence(
    tmp_path: Path,
) -> None:
    storage = Storage(tmp_path / "state" / "harness.db")
    storage.initialize()
    vault_root = tmp_path / "vault"
    vault_root.mkdir()

    _seed_run(storage, run_id="run-1", guest_health=GuestHealthState.ROLLED_BACK)
    _seed_action(storage, action_id="act-1", state=ActionLifecycleState.COMPLETED)

    payload = b"captured-evidence-that-must-survive-failed-export"
    expected_sha = _seed_evidence(
        storage,
        vault_root,
        evidence_id="ev-1",
        run_id="run-1",
        action_id="act-1",
        payload=payload,
    )

    checker = CloseIntegrityChecker(storage, vault_root=vault_root, clock=_now)

    # Host import fails immediately before VM rollback, and VM rollback succeeds:
    # export MUST NOT be marked successful and remaining evidence MUST stay intact.
    report = checker.evaluate(
        run_id="run-1",
        import_completed=False,
        import_errors=("host_importer_hash_verification_failed",),
        expected_evidence_ids=("ev-1", "ev-missing"),
        vm_rollback_succeeded=True,
    )
    assert report.vm_rollback_succeeded is True
    assert report.import_verified is False
    assert report.export_succeeded is False
    assert report.close_allowed is False
    assert "host_import_incomplete" in report.blocking_reasons
    assert "missing_expected_evidence" in report.blocking_reasons
    assert report.missing_evidence_ids == ("ev-missing",)
    assert report.preserved_evidence_ids == ("ev-1",)
    assert any("vm_rollback_succeeded_does_not_imply_export_success" in w for w in report.warnings)

    # Confirm remaining evidence blob on disk was untouched and matches hash
    blob_path = vault_root / "blobs" / expected_sha[:2] / expected_sha
    assert blob_path.read_bytes() == payload

    with pytest.raises(ContractViolationError):
        checker.assert_ready(
            run_id="run-1",
            import_completed=False,
            import_errors=("host_importer_failed",),
            vm_rollback_succeeded=True,
        )

    # Non-terminal actions also block close
    _seed_action(
        storage,
        action_id="act-2",
        request_id="req-2",
        state=ActionLifecycleState.RUNNING,
    )
    non_term_report = checker.evaluate(
        run_id="run-1",
        import_completed=True,
        expected_evidence_ids=("ev-1",),
        vm_rollback_succeeded=True,
    )
    assert non_term_report.close_allowed is False
    assert non_term_report.export_succeeded is False
    assert non_term_report.non_terminal_action_ids == ("act-2",)
    assert "non_terminal_actions_remaining" in non_term_report.blocking_reasons

    # Once non-terminal action completes and import is verified, close succeeds
    with storage.transaction() as conn:
        conn.execute(
            "UPDATE actions SET state = ? WHERE action_id = ?",
            (ActionLifecycleState.COMPLETED.value, "act-2"),
        )
    ok_report = checker.assert_ready(
        run_id="run-1",
        import_completed=True,
        expected_evidence_ids=("ev-1",),
        vm_rollback_succeeded=True,
    )
    assert ok_report.close_allowed is True
    assert ok_report.import_verified is True
    assert ok_report.export_succeeded is True
    assert ok_report.preserved_evidence_ids == ("ev-1",)


# ---------------------------------------------------------------------------
# 6. CTF-11 & CTF-12: Synthetic Forced Empty Error & Prompt Injection Marker
# ---------------------------------------------------------------------------


def test_ctf11_forced_error_empty_output_returns_tool_error() -> None:
    adapter = SyntheticAdapter(enabled=True)
    outcome = adapter.execute_with_capture(
        _make_action(operation="force_error_empty", args={"exit_code": 2})
    )
    assert outcome.captured_bytes == b""
    assert outcome.capture_complete is True
    assert outcome.cleanup_confirmed is True
    assert outcome.envelope.status == EnvelopeStatus.TOOL_ERROR
    assert outcome.envelope.error is not None
    assert outcome.envelope.error.code == "tool_execution_failed"
    assert outcome.envelope.usage.output_bytes == 0


def test_ctf12_prompt_injection_and_secret_marker_stay_out_of_summary(
    tmp_path: Path,
) -> None:
    artifact_file = tmp_path / "sample.bin"
    artifact_file.write_bytes(b"ELF-fixture")

    adapter = SyntheticAdapter(enabled=True)
    before_desc = adapter.descriptor()

    # Normal observation with resolved artifact_paths
    obs = adapter.execute_with_capture(
        _make_action(
            operation="observe",
            args={"artifact_id": "art-1", "message": "check"},
        ),
        artifact_paths={"art-1": artifact_file},
    )
    assert obs.envelope.status == EnvelopeStatus.OK
    assert b"artifact_bytes=11" in obs.captured_bytes

    # Prompt injection + synthetic secret marker stays in raw captured output,
    # never leaks into summary, and cannot alter adapter descriptor/authority.
    inj = adapter.execute_with_capture(
        _make_action(
            operation="prompt_injection_marker",
            args={"include_flag_marker": True},
        )
    )
    assert inj.envelope.status == EnvelopeStatus.OK
    raw_text = inj.captured_bytes.decode("utf-8")
    assert "IGNORE PREVIOUS INSTRUCTIONS" in raw_text
    assert "SYNTHETIC_SECRET_TEST_MARKER_DO_NOT_EXPORT_v1" in raw_text
    assert "flag{synthetic_fixture_marker_never_export}" in raw_text

    assert "SYNTHETIC_SECRET" not in inj.envelope.summary
    assert "CTF_SENSITIVE_MARKER" not in inj.envelope.summary
    assert "flag{" not in inj.envelope.summary
    assert adapter.descriptor() == before_desc


def test_runner_missing_executable_and_layer2_import_isolation(tmp_path: Path) -> None:
    import ast

    runner = SubprocessRunner(default_timeout_seconds=5.0)
    missing_exe = str(tmp_path / "nonexistent_tool_binary.exe")
    res = runner.run([missing_exe, "--version"])
    assert res.outcome == SubprocessOutcome.FAILED
    assert res.returncode is None
    assert res.cleanup_confirmed is True
    assert res.cleanup_detail is not None and "spawn_failed" in res.cleanup_detail

    # Verify Layer 2 isolation: verification/ and adapters/ never import gateway/runs/evidence
    src_root = Path(__file__).resolve().parents[2] / "src" / "ctf_mcp"
    forbidden_peers = {"gateway", "runs", "evidence"}
    for subpkg in ("verification", "adapters"):
        for py_file in (src_root / subpkg).rglob("*.py"):
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        parts = alias.name.split(".")
                        if len(parts) >= 2 and parts[0] == "ctf_mcp" and parts[1] in forbidden_peers:
                            raise AssertionError(f"Cross-layer import {alias.name} in {py_file}")
                elif isinstance(node, ast.ImportFrom) and node.module:
                    parts = node.module.split(".")
                    if len(parts) >= 2 and parts[0] == "ctf_mcp" and parts[1] in forbidden_peers:
                        raise AssertionError(f"Cross-layer import {node.module} in {py_file}")
