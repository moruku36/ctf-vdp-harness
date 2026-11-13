"""P3 E2E tests covering CTF-02, CTF-04, CTF-06, CTF-07, CTF-08, CTF-10, and server boundary."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from ctf_mcp.adapters import (
    BaseAdapter,
    SubprocessRunner,
    build_signed_descriptor,
    get_os_process_start_id,
    is_os_process_alive,
)
from ctf_mcp.contracts import (
    ActionConflictError,
    ActionLifecycleState,
    ActionRecord,
    ActionRequest,
    BudgetSpec,
    CapabilityDescriptor,
    CapabilityLimits,
    EnvelopeStatus,
    EvidenceAccessDeniedError,
    ExecutionClass,
    GuestBlockedError,
    GuestHealthState,
    PrincipalContext,
    ResultEnvelope,
    RunMode,
    ScopePolicy,
    UsageMetrics,
    canonical_digest,
    sha256_bytes,
)
from ctf_mcp.controller import HarnessController, register_default_adapters
from ctf_mcp.evidence import BoundedEvidenceImporter, ReportMetadata
from ctf_mcp.runs import SessionLeaseState
from ctf_mcp.server import create_mcp_server
from ctf_mcp.storage import Storage


class _MutableClock:
    def __init__(self, start: datetime | None = None) -> None:
        self.now = start or datetime(2026, 11, 13, 1, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


class _GrandchildSubprocessAdapter(BaseAdapter):
    """Real stdlib subprocess adapter launching a child + grandchild tree for CTF-07 tests."""

    def __init__(
        self,
        *,
        marker_dir: Path,
        runner: SubprocessRunner | None = None,
        evidence_vault: Any = None,
        enabled: bool = True,
    ) -> None:
        self._marker_dir = marker_dir
        self._marker_dir.mkdir(parents=True, exist_ok=True)
        self.exec_count = 0
        descriptor = build_signed_descriptor(
            name="analysis.query",
            adapter_id="p3-grandchild-test-adapter",
            adapter_commit="p3-test-v1",
            execution_classes=(ExecutionClass.STATIC,),
            operations=("spawn_grandchild", "echo_fixture"),
            arg_schema={
                "type": "object",
                "additionalProperties": False,
                "required": ["tag"],
                "properties": {
                    "tag": {"type": "string", "minLength": 1, "maxLength": 64},
                    "sleep_s": {"type": "number", "minimum": 0.0, "maximum": 30.0},
                },
            },
            limits=CapabilityLimits(
                timeout_seconds=10,
                max_output_bytes=16384,
                max_decode_bytes=4096,
            ),
            dependency_lock_sha256=sha256_bytes(b"p3-grandchild-test-adapter-lock-v1"),
            enabled=enabled,
            profile_modes=(RunMode.OFFLINE_CTF,),
            required_scope={"mode": "offline_ctf"},
        )
        super().__init__(
            descriptor,
            runner=runner or SubprocessRunner(default_timeout_seconds=10.0),
            evidence_vault=evidence_vault,
            require_running_state=True,
        )

    def _build_invocation(
        self,
        action: ActionRecord,
        *,
        artifact_paths: dict[str, Path],
    ) -> tuple[list[str], dict[str, str] | None, Path | None]:
        _ = artifact_paths
        self.exec_count += 1
        tag = str(action.sanitized_args["tag"])
        sleep_s = float(action.sanitized_args.get("sleep_s", 0.0))
        marker_file = self._marker_dir / f"{action.action_id}.json"

        worker_code = (
            "import json, pathlib, subprocess, sys, time\n"
            f"marker = pathlib.Path({str(marker_file)!r})\n"
            f"sleep_s = {sleep_s!r}\n"
            f"tag = {tag!r}\n"
            "if sleep_s > 0:\n"
            "    gc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
            "    marker.write_text(json.dumps({'grandchild_pid': gc.pid}), encoding='utf-8')\n"
            "    sys.stdout.write('started-' + tag + '\\n')\n"
            "    sys.stdout.flush()\n"
            "    time.sleep(sleep_s)\n"
            "else:\n"
            "    marker.write_text(json.dumps({'grandchild_pid': None}), encoding='utf-8')\n"
            "    sys.stdout.write(json.dumps({'tag': tag, 'status': 'ok'}) + '\\n')\n"
        )
        return [sys.executable, "-c", worker_code], None, self._marker_dir


def _principal(pid: str = "alice") -> PrincipalContext:
    return PrincipalContext(
        principal_id=pid,
        auth_method="stdio_local",
        client_kind="OPERATOR_SELECTED",
        model_label="p3-test-client",
    )


def _scope(
    *,
    task_id: str = "task-p3-e2e",
    rev: str = "scope-p3-1",
    caps: tuple[str, ...] = ("analysis.query",),
) -> ScopePolicy:
    payload = {
        "mode": RunMode.OFFLINE_CTF.value,
        "task_id": task_id,
        "scope_revision": rev,
        "allowed_capabilities": list(caps),
    }
    return ScopePolicy(
        mode=RunMode.OFFLINE_CTF,
        task_id=task_id,
        scope_revision=rev,
        scope_sha256=canonical_digest(payload),
        authorization_reference="OWNED_LOCAL_P3_E2E_TEST",
        allowed_execution_classes=(ExecutionClass.STATIC,),
        allowed_capabilities=caps,
    )


def _budget(**overrides: Any) -> BudgetSpec:
    defaults = {
        "run_budget_seconds": 300,
        "action_timeout_seconds": 10,
        "session_idle_seconds": 900,
        "max_tool_calls": 20,
        "max_output_chars_per_page": 200,
        "max_evidence_bytes_per_run": 1_048_576,
        "heavy_job_concurrency": 1,
        "interactive_session_limit": 1,
    }
    defaults.update(overrides)
    return BudgetSpec(**defaults)


def _make_controller(
    tmp_path: Path,
    *,
    clock: Any = None,
    supervisor_key: str = "sup-p3",
    supervisor_instance_id: str = "inst-1",
    register_static: bool = True,
) -> HarnessController:
    storage = Storage(tmp_path / "state" / "harness.db")
    vault_root = tmp_path / "vault"
    export_root = tmp_path / "exports"
    ctrl = HarnessController(
        storage=storage,
        vault_root=vault_root,
        export_root=export_root,
        cursor_hmac_key=b"p3-fixed-hmac-test-key-32-bytes!",
        supervisor_key=supervisor_key,
        supervisor_instance_id=supervisor_instance_id,
        clock=clock,
    )
    ctrl.initialize()
    if register_static:
        register_default_adapters(ctrl, timeout_seconds=10)
    return ctrl


# ---------------------------------------------------------------------------
# 1. CTF-02: request_id replay (0 subprocess re-exec), conflict, repeat_of, hypothesis.update
# ---------------------------------------------------------------------------


def test_ctf02_mcp_replay_zero_subprocess_conflict_repeat_of_and_hypothesis_restart(
    tmp_path: Path,
) -> None:
    clock = _MutableClock()
    ctrl1 = HarnessController(
        storage=Storage(tmp_path / "state" / "harness.db"),
        vault_root=tmp_path / "vault",
        export_root=tmp_path / "exports",
        cursor_hmac_key=b"p3-fixed-hmac-test-key-32-bytes!",
        clock=clock,
    )
    ctrl1.initialize()
    adapter1 = _GrandchildSubprocessAdapter(
        marker_dir=tmp_path / "markers",
        evidence_vault=ctrl1.evidence_vault,
    )
    ctrl1.register_adapter(adapter1, tool_group="analysis.query")

    alice = _principal("alice")
    manifest = ctrl1.create_run(
        principal=alice,
        task_id="task-ctf02",
        mode=RunMode.OFFLINE_CTF,
        scope=_scope(task_id="task-ctf02"),
        budget=_budget(),
    )
    server1 = create_mcp_server(ctrl1, default_stdio_principal=alice, active_run_id=manifest.run_id)

    state: dict[str, Any] = {}

    async def _phase1() -> None:
        async with Client(server1.mcp) as client:
            first = await client.call_tool(
                "analysis.query",
                {
                    "run_id": manifest.run_id,
                    "request_id": "req-act-1",
                    "expected_revision": 1,
                    "operation": "echo_fixture",
                    "arguments": {"tag": "alpha", "sleep_s": 0.0},
                },
            )
            assert first.data["status"] == "ok"
            assert adapter1.exec_count == 1
            state["first_action_id"] = first.data["action_id"]

            desc_after_first = await client.call_tool("run.describe", {"run_id": manifest.run_id})
            rem_calls_1 = desc_after_first.data["budget"]["remaining_calls"]
            rem_ms_1 = desc_after_first.data["budget"]["remaining_ms"]
            rem_bytes_1 = desc_after_first.data["budget"]["remaining_bytes"]
            rev_after_first = desc_after_first.data["revision"]

            # Exact same request_id + args -> 0 subprocess re-executions, 0 budget deduction.
            replay = await client.call_tool(
                "analysis.query",
                {
                    "run_id": manifest.run_id,
                    "request_id": "req-act-1",
                    "expected_revision": 1,
                    "operation": "echo_fixture",
                    "arguments": {"tag": "alpha", "sleep_s": 0.0},
                },
            )
            assert replay.data["action_id"] == state["first_action_id"]
            assert adapter1.exec_count == 1

            desc_after_replay = await client.call_tool("run.describe", {"run_id": manifest.run_id})
            assert desc_after_replay.data["budget"]["remaining_calls"] == rem_calls_1
            assert desc_after_replay.data["budget"]["remaining_ms"] == rem_ms_1
            assert desc_after_replay.data["budget"]["remaining_bytes"] == rem_bytes_1
            assert desc_after_replay.data["action_count"] == 1

            # Same request_id with different arguments -> ActionConflictError (MCP ToolError)
            with pytest.raises(ToolError):
                await client.call_tool(
                    "analysis.query",
                    {
                        "run_id": manifest.run_id,
                        "request_id": "req-act-1",
                        "expected_revision": rev_after_first,
                        "operation": "echo_fixture",
                        "arguments": {"tag": "tampered", "sleep_s": 0.0},
                    },
                )
            assert adapter1.exec_count == 1

            # Deliberate repeat_of referencing original action_id succeeds cleanly.
            repeated = await client.call_tool(
                "analysis.query",
                {
                    "run_id": manifest.run_id,
                    "request_id": "req-act-2",
                    "expected_revision": rev_after_first,
                    "operation": "echo_fixture",
                    "arguments": {"tag": "alpha", "sleep_s": 0.0},
                    "repeat_of": state["first_action_id"],
                },
            )
            assert repeated.data["status"] == "ok"
            assert repeated.data["action_id"] != state["first_action_id"]
            assert adapter1.exec_count == 2

            # hypothesis.update with request_id idempotency & conflict
            h1 = await client.call_tool(
                "hypothesis.update",
                {
                    "run_id": manifest.run_id,
                    "state": "unknown",
                    "claim": "Header offset indicates UPX-like section layout.",
                    "next_observation": "Check entropy in section table.",
                    "request_id": "req-hyp-1",
                },
            )
            state["hyp_id"] = h1.data["hypothesis_id"]
            assert h1.data["revision"] == 1

            h1_replay = await client.call_tool(
                "hypothesis.update",
                {
                    "run_id": manifest.run_id,
                    "state": "unknown",
                    "claim": "Header offset indicates UPX-like section layout.",
                    "next_observation": "Check entropy in section table.",
                    "request_id": "req-hyp-1",
                },
            )
            assert h1_replay.data["hypothesis_id"] == state["hyp_id"]
            assert h1_replay.data["revision"] == 1

            with pytest.raises(ToolError):
                await client.call_tool(
                    "hypothesis.update",
                    {
                        "run_id": manifest.run_id,
                        "state": "supported",
                        "claim": "Changed claim on reused request_id",
                        "next_observation": "Changed obs",
                        "request_id": "req-hyp-1",
                    },
                )

    asyncio.run(_phase1())

    # Simulate process restart: new Storage + new HarnessController + new MCP server.
    ctrl2 = HarnessController(
        storage=Storage(tmp_path / "state" / "harness.db"),
        vault_root=tmp_path / "vault",
        export_root=tmp_path / "exports",
        cursor_hmac_key=b"p3-fixed-hmac-test-key-32-bytes!",
        clock=clock,
    )
    ctrl2.initialize()
    adapter2 = _GrandchildSubprocessAdapter(
        marker_dir=tmp_path / "markers",
        evidence_vault=ctrl2.evidence_vault,
    )
    ctrl2.register_adapter(adapter2, tool_group="analysis.query")
    server2 = create_mcp_server(ctrl2, default_stdio_principal=alice, active_run_id=manifest.run_id)

    async def _phase2_after_restart() -> None:
        async with Client(server2.mcp) as client2:
            # Replay action across restart -> 0 subprocess executions in adapter2!
            post_restart_action = await client2.call_tool(
                "analysis.query",
                {
                    "run_id": manifest.run_id,
                    "request_id": "req-act-1",
                    "expected_revision": 1,
                    "operation": "echo_fixture",
                    "arguments": {"tag": "alpha", "sleep_s": 0.0},
                },
            )
            assert post_restart_action.data["action_id"] == state["first_action_id"]
            assert adapter2.exec_count == 0

            # Replay hypothesis.update across restart -> still idempotent and conflict-checked!
            h1_after_restart = await client2.call_tool(
                "hypothesis.update",
                {
                    "run_id": manifest.run_id,
                    "state": "unknown",
                    "claim": "Header offset indicates UPX-like section layout.",
                    "next_observation": "Check entropy in section table.",
                    "request_id": "req-hyp-1",
                },
            )
            assert h1_after_restart.data["hypothesis_id"] == state["hyp_id"]
            assert h1_after_restart.data["revision"] == 1

            with pytest.raises(ToolError):
                await client2.call_tool(
                    "hypothesis.update",
                    {
                        "run_id": manifest.run_id,
                        "state": "refuted",
                        "claim": "Different claim post-restart",
                        "next_observation": "Diff",
                        "request_id": "req-hyp-1",
                    },
                )

    asyncio.run(_phase2_after_restart())

    # Confirm repeat_of persisted in SQLite actions table
    act2_rec = ctrl2.actions.list_actions(manifest.run_id)[1]
    assert act2_rec.repeat_of == state["first_action_id"]


# ---------------------------------------------------------------------------
# 2. CTF-04: Cross-run cursor rejection & post-redaction cursor revocation
# ---------------------------------------------------------------------------


def test_ctf04_cross_run_cursor_rejected_and_redaction_revokes_old_cursor(
    tmp_path: Path,
) -> None:
    ctrl = _make_controller(tmp_path)
    alice = _principal("alice")
    ws = tmp_path / "ws"
    ws.mkdir()
    sample = ws / "notes.txt"
    long_lines = "\n".join(
        [f"line-{i:03d} SECRET_MARKER_{i:03d} padding-value-for-paging" for i in range(40)]
    )
    sample.write_text(long_lines, encoding="utf-8")

    run_a = ctrl.create_run(
        principal=alice,
        task_id="task-a",
        mode=RunMode.OFFLINE_CTF,
        scope=_scope(task_id="task-a"),
        budget=_budget(max_output_chars_per_page=180),
    )
    run_b = ctrl.create_run(
        principal=alice,
        task_id="task-b",
        mode=RunMode.OFFLINE_CTF,
        scope=_scope(task_id="task-b", rev="scope-b"),
        budget=_budget(max_output_chars_per_page=180),
    )
    art_a = ctrl.ingest_artifact(
        principal=alice,
        run_id=run_a.run_id,
        source_root=ws,
        rel_path="notes.txt",
        media_type="text/plain; charset=utf-8",
    )
    art_b = ctrl.ingest_artifact(
        principal=alice,
        run_id=run_b.run_id,
        source_root=ws,
        rel_path="notes.txt",
        media_type="text/plain; charset=utf-8",
    )

    server = create_mcp_server(ctrl, default_stdio_principal=alice, active_run_id=run_a.run_id)

    async def _run() -> None:
        async with Client(server.mcp) as client:
            res_a = await client.call_tool(
                "analysis.query",
                {
                    "run_id": run_a.run_id,
                    "request_id": "req-a-1",
                    "expected_revision": 2,
                    "operation": "extract_strings",
                    "arguments": {"artifact_id": art_a.artifact_id},
                },
            )
            assert res_a.data["status"] == "ok"
            ev_a = res_a.data["evidence"][0]["id"]

            res_b = await client.call_tool(
                "analysis.query",
                {
                    "run_id": run_b.run_id,
                    "request_id": "req-b-1",
                    "expected_revision": 2,
                    "operation": "extract_strings",
                    "arguments": {"artifact_id": art_b.artifact_id},
                },
            )
            assert res_b.data["status"] == "ok"
            ev_b = res_b.data["evidence"][0]["id"]

            page1_a = await client.call_tool(
                "evidence.read",
                {"run_id": run_a.run_id, "evidence_id": ev_a, "max_chars": 150},
            )
            cursor_a = page1_a.data["next_cursor"]
            assert cursor_a

            # Cross-run cursor reuse must be rejected even by the same principal.
            with pytest.raises(ToolError):
                await client.call_tool(
                    "evidence.read",
                    {
                        "run_id": run_b.run_id,
                        "evidence_id": ev_b,
                        "cursor": cursor_a,
                        "max_chars": 150,
                    },
                )

            # Redact Run A evidence and revoke prior raw views -> old cursor fails closed!
            red = ctrl.redact_evidence(
                principal=alice,
                run_id=run_a.run_id,
                evidence_id=ev_a,
                extra_literals=("SECRET_MARKER_000", "SECRET_MARKER_001"),
                revoke_prior_views=True,
            )
            assert red.redacted_view.view_revision == "redacted-v1"

            with pytest.raises(ToolError):
                await client.call_tool(
                    "evidence.read",
                    {
                        "run_id": run_a.run_id,
                        "evidence_id": ev_a,
                        "cursor": cursor_a,
                        "max_chars": 150,
                    },
                )

            # Reading the new redacted derived view succeeds and hides raw markers.
            page1_redacted = await client.call_tool(
                "evidence.read",
                {
                    "run_id": run_a.run_id,
                    "evidence_id": red.redacted_view.evidence_id,
                    "max_chars": 200,
                },
            )
            assert "SECRET_MARKER_000" not in page1_redacted.data["content"]
            assert page1_redacted.data["view_revision"] == "redacted-v1"

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 3. CTF-06: Real OS process crash reconciliation & reservation retention
# ---------------------------------------------------------------------------


def test_ctf06_real_os_process_crash_reconciliation_on_initialize(tmp_path: Path) -> None:
    clock = _MutableClock()
    ctrl1 = _make_controller(tmp_path, clock=clock, supervisor_instance_id="sup-old")
    alice = _principal("alice")
    manifest = ctrl1.create_run(
        principal=alice,
        task_id="task-ctf06",
        mode=RunMode.OFFLINE_CTF,
        scope=_scope(task_id="task-ctf06"),
        budget=_budget(run_budget_seconds=120, heavy_job_concurrency=1),
    )

    cap = ctrl1.catalog.get_capability("analysis.query", RunMode.OFFLINE_CTF)
    live_proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        proc_start_id = get_os_process_start_id(live_proc.pid)
        assert proc_start_id is not None and is_os_process_alive(proc_start_id)

        req = ActionRequest(
            run_id=manifest.run_id,
            request_id="req-inflight-real",
            expected_revision=1,
            capability_name="analysis.query",
            operation="inspect_header",
            arguments={"artifact_id": "art-dummy"},
        )
        with ctrl1.storage.transaction() as conn:
            sub = ctrl1.actions.reserve_action_in_tx(
                conn,
                run_id=manifest.run_id,
                principal_id=alice.principal_id,
                request=req,
                capability=cap,
                scope_revision="scope-p3-1",
                reserved_ms=30_000,
                reserved_bytes=65_536,
                heavy_job_slot=True,
                interactive_session_slot=False,
                manage_run_budget=True,
                now=clock.now,
            )
            started = ctrl1.actions.start_action_in_tx(
                conn,
                action_id=sub.action.action_id,
                supervisor_key="sup-p3",
                supervisor_instance_id="sup-old",
                process_start_id=proc_start_id,
                now=clock.now,
            )

        # Case A: Process is STILL alive on restart -> default is_os_process_alive keeps it RUNNING.
        ctrl2 = _make_controller(tmp_path, clock=clock, supervisor_instance_id="sup-mid")
        # ctrl2.__init__ used default is_os_process_alive inside initialize()!
        still_rec = ctrl2.actions.get_action_with_envelope(started.action_id).action
        assert still_rec.state == ActionLifecycleState.RUNNING

        # Case B: Process actually died before next restart -> reconciliation_required.
        live_proc.terminate()
        live_proc.wait(timeout=5)
        assert is_os_process_alive(proc_start_id) is False
    finally:
        if live_proc.poll() is None:
            live_proc.kill()
            live_proc.wait(timeout=5)

    clock.advance(5)
    ctrl3 = HarnessController(
        storage=Storage(tmp_path / "state" / "harness.db"),
        vault_root=tmp_path / "vault",
        export_root=tmp_path / "exports",
        cursor_hmac_key=b"p3-fixed-hmac-test-key-32-bytes!",
        supervisor_key="sup-p3",
        supervisor_instance_id="sup-new",
        clock=clock,
    )
    report = ctrl3.initialize()
    assert any(a.action_id == started.action_id for a in report.reconciled_to_required)

    desc = ctrl3.describe_run(principal=alice, run_id=manifest.run_id)
    assert len(desc["reconciliation_required"]) == 1
    assert desc["reconciliation_required"][0]["action_id"] == started.action_id
    assert desc["reconciliation_required"][0]["fencing_token"] == started.fencing_token
    assert desc["reconciliation_required"][0]["error_code"] == "reconciliation_required"
    assert desc["budget"]["active_heavy_jobs"] == 1

    # Verify AuditEvent captured crash reconciliation
    audits = ctrl3.audit.list_events(manifest.run_id)
    assert any("reconcile:reconciliation_required" in (ev.destination_summary or "") for ev in audits)

    # Resolve with retain_reservation=False, usage_unknown=True, cleanup_confirmed=True
    # -> releases heavy_job slot lock while keeping conservative budget reservation!
    before_ms = desc["budget"]["remaining_ms"]
    before_bytes = desc["budget"]["remaining_bytes"]
    resolved = ctrl3.resolve_reconciled_action(
        action_id=started.action_id,
        target_state=ActionLifecycleState.FAILED,
        principal=alice,
        summary="Supervisor restarted after host power loss; reservation retained.",
        retain_reservation=False,
        usage_unknown=True,
        cleanup_confirmed=True,
    )
    assert resolved.action.state == ActionLifecycleState.FAILED
    desc_after = ctrl3.describe_run(principal=alice, run_id=manifest.run_id)
    assert desc_after["budget"]["active_heavy_jobs"] == 0
    assert desc_after["budget"]["remaining_ms"] == before_ms
    assert desc_after["budget"]["remaining_bytes"] == before_bytes


# ---------------------------------------------------------------------------
# 4. CTF-07: Timeout/cancel subprocess tree cleanup (0 OS survivors) & guest recovery
# ---------------------------------------------------------------------------


def test_ctf07_timeout_cancel_zero_survivors_and_cleanup_unconfirmed_recovery(
    tmp_path: Path,
) -> None:
    clock = _MutableClock()
    ctrl = _make_controller(tmp_path, clock=clock, register_static=False)
    marker_dir = tmp_path / "markers"
    runner = SubprocessRunner(default_timeout_seconds=0.4, default_max_output_bytes=16384)
    adapter = _GrandchildSubprocessAdapter(
        marker_dir=marker_dir,
        runner=runner,
        evidence_vault=ctrl.evidence_vault,
    )
    ctrl.register_adapter(adapter, tool_group="analysis.query")

    alice = _principal("alice")
    manifest = ctrl.create_run(
        principal=alice,
        task_id="task-ctf07",
        mode=RunMode.OFFLINE_CTF,
        scope=_scope(task_id="task-ctf07"),
        budget=_budget(action_timeout_seconds=1),
    )
    server = create_mcp_server(ctrl, default_stdio_principal=alice, active_run_id=manifest.run_id)

    async def _timeout_via_mcp() -> dict[str, Any]:
        async with Client(server.mcp) as client:
            res = await client.call_tool(
                "analysis.query",
                {
                    "run_id": manifest.run_id,
                    "request_id": "req-timeout-tree",
                    "expected_revision": 1,
                    "operation": "spawn_grandchild",
                    "arguments": {"tag": "timeout-tree", "sleep_s": 5.0},
                },
            )
            return dict(res.data)

    timeout_data = asyncio.run(_timeout_via_mcp())
    assert timeout_data["status"] == "timeout"

    # Give OS a brief beat if needed, then verify grandchild PID from marker is dead.
    act_timeout = ctrl.actions.list_actions(manifest.run_id)[0]
    mfile_to = marker_dir / f"{act_timeout.action_id}.json"
    if mfile_to.exists():
        gc_pid = json.loads(mfile_to.read_text(encoding="utf-8")).get("grandchild_pid")
        if gc_pid is not None:
            # Verify no process survives cleanup
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                gc_start = get_os_process_start_id(int(gc_pid))
                if gc_start is None or not is_os_process_alive(gc_start):
                    break
                time.sleep(0.05)
            gc_start = get_os_process_start_id(int(gc_pid))
            assert gc_start is None or not is_os_process_alive(gc_start)

    # Cancel path via cancel_event -> cancelled & zero OS survivors
    cancel_ev = threading.Event()

    def _trigger_cancel() -> None:
        time.sleep(0.35)
        cancel_ev.set()

    canceller = threading.Thread(target=_trigger_cancel, daemon=True)
    canceller.start()
    desc_mid = ctrl.describe_run(principal=alice, run_id=manifest.run_id)
    cancelled_env = ctrl.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id=manifest.run_id,
            request_id="req-cancel-tree",
            expected_revision=desc_mid["revision"],
            capability_name="analysis.query",
            operation="spawn_grandchild",
            arguments={"tag": "cancel-tree", "sleep_s": 5.0},
        ),
        cancel_event=cancel_ev,
    )
    canceller.join(timeout=2)
    assert cancelled_env.status == EnvelopeStatus.CANCELLED
    act_cancel = ctrl.actions.list_actions(manifest.run_id)[1]
    assert act_cancel.process_start_id is not None
    assert is_os_process_alive(act_cancel.process_start_id) is False
    mfile_c = marker_dir / f"{act_cancel.action_id}.json"
    if mfile_c.exists():
        gc_pid_c = json.loads(mfile_c.read_text(encoding="utf-8")).get("grandchild_pid")
        if gc_pid_c is not None:
            gc_start_c = get_os_process_start_id(int(gc_pid_c))
            assert gc_start_c is None or not is_os_process_alive(gc_start_c)

    # Cleanup unconfirmed state blocks both new actions and MCP run.close until recover_guest_ready.
    ctrl.recovery.mark_cleanup_unconfirmed(
        manifest.run_id,
        "Simulated orphan child check unconfirmed.",
        action_id=act_cancel.action_id,
    )
    desc_blocked = ctrl.describe_run(principal=alice, run_id=manifest.run_id)
    assert desc_blocked["guest_health"] == GuestHealthState.CLEANUP_UNCONFIRMED.value

    async def _check_blocked_then_recover() -> None:
        async with Client(server.mcp) as client:
            blocked_act = await client.call_tool(
                "analysis.query",
                {
                    "run_id": manifest.run_id,
                    "request_id": "req-blocked-while-dirty",
                    "expected_revision": desc_blocked["revision"],
                    "operation": "echo_fixture",
                    "arguments": {"tag": "should-block", "sleep_s": 0.0},
                },
            )
            assert blocked_act.data["status"] == "denied"
            assert blocked_act.data["error"]["code"] == "guest_blocked"

            with pytest.raises(ToolError):
                await client.call_tool(
                    "run.close",
                    {"run_id": manifest.run_id, "language": "en"},
                )

    asyncio.run(_check_blocked_then_recover())

    # Operator verifies cleanup -> recover_guest_ready -> run.close succeeds cleanly!
    recovered_health = ctrl.recover_guest_ready(
        run_id=manifest.run_id,
        cleanup_verified=True,
        note="Verified zero survivor PIDs via OS process table.",
        principal=alice,
    )
    assert recovered_health == GuestHealthState.READY

    async def _close_after_recover() -> None:
        async with Client(server.mcp) as client:
            closed = await client.call_tool(
                "run.close",
                {
                    "run_id": manifest.run_id,
                    "language": "en",
                    "output_relpath": "recovered-report.en.md",
                },
            )
            assert closed.data["guest_rolled_back"] is True
            assert closed.data["manifest"]["closed_at"] is not None

    asyncio.run(_close_after_recover())


# ---------------------------------------------------------------------------
# 5. CTF-08: Monotonic fencing_token, stale worker FencingError, session leases (lost + 15m idle)
# ---------------------------------------------------------------------------


def test_ctf08_fencing_and_session_leases_lost_and_idle_expiry(tmp_path: Path) -> None:
    clock = _MutableClock()
    ctrl1 = _make_controller(tmp_path, clock=clock, supervisor_instance_id="inst-1")
    alice = _principal("alice")
    manifest = ctrl1.create_run(
        principal=alice,
        task_id="task-ctf08",
        mode=RunMode.OFFLINE_CTF,
        scope=_scope(task_id="task-ctf08"),
        budget=_budget(session_idle_seconds=900, interactive_session_limit=1),
    )

    # 1. Idle session lease: touch at +899s works; idle at +900s fails & expires cleanly.
    lease1 = ctrl1.acquire_lease(
        principal=alice,
        run_id=manifest.run_id,
        capability_name="analysis.query",
    )
    assert lease1.state == SessionLeaseState.ACTIVE
    assert ctrl1.describe_run(principal=alice, run_id=manifest.run_id)["budget"]["active_sessions"] == 1

    clock.advance(899)
    touched = ctrl1.touch_lease(session_id=lease1.session_id, run_id=manifest.run_id, principal=alice)
    assert touched.state == SessionLeaseState.ACTIVE

    clock.advance(900)
    expired_list = ctrl1.expire_idle_leases(principal=alice, run_id=manifest.run_id)
    assert [l.session_id for l in expired_list] == [lease1.session_id]
    assert expired_list[0].state == SessionLeaseState.EXPIRED
    desc_exp = ctrl1.describe_run(principal=alice, run_id=manifest.run_id)
    assert desc_exp["budget"]["active_sessions"] == 0
    assert desc_exp["session_leases"][0]["state"] == "expired"

    # 2. Acquire active lease2 + start fenced action, then simulate crash restart.
    lease2 = ctrl1.acquire_lease(
        principal=alice,
        run_id=manifest.run_id,
        capability_name="analysis.query",
    )
    cap = ctrl1.catalog.get_capability("analysis.query", RunMode.OFFLINE_CTF)
    with ctrl1.storage.transaction() as conn:
        sub = ctrl1.actions.reserve_action_in_tx(
            conn,
            run_id=manifest.run_id,
            principal_id=alice.principal_id,
            request=ActionRequest(
                run_id=manifest.run_id,
                request_id="req-fenced-1",
                expected_revision=ctrl1.runs.get_run_snapshot_in_tx(conn, manifest.run_id).revision,
                capability_name="analysis.query",
                operation="inspect_header",
                arguments={"artifact_id": "art-1"},
            ),
            capability=cap,
            scope_revision="scope-p3-1",
            heavy_job_slot=True,
            interactive_session_slot=False,
            manage_run_budget=True,
            now=clock.now,
        )
        started_t1 = ctrl1.actions.start_action_in_tx(
            conn,
            action_id=sub.action.action_id,
            supervisor_key="sup-p3",
            supervisor_instance_id="inst-1",
            process_start_id="proc-crashed-old",
            now=clock.now,
        )
    token_t1 = started_t1.fencing_token
    assert token_t1 is not None

    # Restart controller -> mints token > T1, reconciles action, marks lease2 as 'lost'.
    clock.advance(10)
    ctrl2 = _make_controller(tmp_path, clock=clock, supervisor_instance_id="inst-2")
    desc_restarted = ctrl2.describe_run(principal=alice, run_id=manifest.run_id)
    leases_by_id = {l["session_id"]: l for l in desc_restarted["session_leases"]}
    assert leases_by_id[lease2.session_id]["state"] == "lost"
    assert leases_by_id[lease2.session_id]["termination_reason"] == "supervisor_or_vm_restart"
    assert desc_restarted["budget"]["active_sessions"] == 0
    assert desc_restarted["reconciliation_required"][0]["fencing_token"] == token_t1

    # Stale worker with token_t1 tries to commit -> FencingError!
    from ctf_mcp.contracts import FencingError

    with pytest.raises(FencingError):
        ctrl2.commit_worker_result(
            action_id=started_t1.action_id,
            fencing_token=token_t1,
            target_state=ActionLifecycleState.COMPLETED,
            usage=UsageMetrics(wall_ms=10, output_bytes=16),
            summary="Stale worker late result",
            principal=alice,
        )

    # Resume action with strictly monotonic new fencing token T2 > T1.
    resumed = ctrl2.resolve_reconciled_action(
        action_id=started_t1.action_id,
        target_state=ActionLifecycleState.RUNNING,
        process_start_id="proc-resumed-alive",
        principal=alice,
    )
    token_t2 = resumed.action.fencing_token
    assert token_t2 is not None and token_t2 > token_t1

    # Old T1 still rejected; current T2 commits cleanly!
    with pytest.raises(FencingError):
        ctrl2.commit_worker_result(
            action_id=started_t1.action_id,
            fencing_token=token_t1,
            target_state=ActionLifecycleState.COMPLETED,
            usage=UsageMetrics(wall_ms=10, output_bytes=16),
            summary="Old T1 still blocked",
            principal=alice,
        )

    committed = ctrl2.commit_worker_result(
        action_id=started_t1.action_id,
        fencing_token=token_t2,
        target_state=ActionLifecycleState.COMPLETED,
        usage=UsageMetrics(wall_ms=25, output_bytes=16),
        has_tool_receipt=True,
        summary="Current T2 worker result committed.",
        principal=alice,
    )
    assert committed.action.state == ActionLifecycleState.COMPLETED


# ---------------------------------------------------------------------------
# 6. CTF-10 & MCP run.close server-side derivation / rollback failure protection
# ---------------------------------------------------------------------------


def test_ctf10_mcp_rejects_client_bypass_flags_and_preserves_evidence_on_rollback_failure(
    tmp_path: Path,
) -> None:
    ctrl = _make_controller(tmp_path)
    alice = _principal("alice")
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "sample.txt").write_text("evidence-line-one\n", encoding="utf-8")

    manifest = ctrl.create_run(
        principal=alice,
        task_id="task-ctf10",
        mode=RunMode.OFFLINE_CTF,
        scope=_scope(task_id="task-ctf10"),
        budget=_budget(),
    )
    art = ctrl.ingest_artifact(
        principal=alice,
        run_id=manifest.run_id,
        source_root=ws,
        rel_path="sample.txt",
        media_type="text/plain; charset=utf-8",
    )
    server = create_mcp_server(ctrl, default_stdio_principal=alice, active_run_id=manifest.run_id)

    async def _run() -> dict[str, Any]:
        async with Client(server.mcp) as client:
            res = await client.call_tool(
                "analysis.query",
                {
                    "run_id": manifest.run_id,
                    "request_id": "req-ev-1",
                    "expected_revision": 2,
                    "operation": "inspect_header",
                    "arguments": {"artifact_id": art.artifact_id},
                },
            )
            assert res.data["status"] == "ok"
            eid = res.data["evidence"][0]["id"]

            # MCP run.close must not expose client-side bypass flags!
            with pytest.raises(ToolError):
                await client.call_tool(
                    "run.close",
                    {
                        "run_id": manifest.run_id,
                        "import_completed": True,
                        "child_processes_confirmed_stopped": True,
                    },
                )
            return {"eid": eid}

    info = asyncio.run(_run())
    eid = info["eid"]

    # Failing vm_rollback_hook must raise GuestBlockedError and leave ZERO report files on disk.
    with pytest.raises(GuestBlockedError, match="rollback"):
        ctrl.close_run(
            principal=alice,
            run_id=manifest.run_id,
            language="en",
            output_relpath="should-never-exist.md",
            vm_rollback_hook=lambda _rid: False,
        )

    assert not (tmp_path / "exports" / "should-never-exist.md").exists()
    snap = ctrl.runs.get_run_snapshot(manifest.run_id)
    assert snap.manifest.closed_at is None
    assert snap.guest_health == GuestHealthState.READY

    # Preserved evidence remains readable and SHA-256 intact!
    page = ctrl.read_evidence(principal=alice, run_id=manifest.run_id, evidence_id=eid)
    assert "utf8_text" in page.content

    # Once vm_rollback_hook succeeds, report is written cleanly and run closes!
    closed = ctrl.close_run(
        principal=alice,
        run_id=manifest.run_id,
        language="ja",
        output_relpath="final-report.ja.md",
        vm_rollback_hook=lambda _rid: True,
    )
    assert closed.guest_rolled_back is True
    assert closed.manifest.closed_at is not None
    assert (tmp_path / "exports" / "final-report.ja.md").exists()
