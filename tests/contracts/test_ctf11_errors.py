"""CTF-11 error handling, expiry, reconciliation, and security contract tests across Layer 3 & Layer 4."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client

from ctf_mcp.adapters import (
    PRODUCTION_DEFAULT_ENABLED,
    SyntheticAdapter,
    build_signed_descriptor,
)
from ctf_mcp.adapters.synthetic import (
    SYNTHETIC_ARG_SCHEMA,
    SYNTHETIC_ADAPTER_COMMIT,
    SYNTHETIC_ADAPTER_ID,
    SYNTHETIC_DEPENDENCY_LOCK_SHA256,
    SYNTHETIC_OPERATIONS,
)
from ctf_mcp.contracts import (
    ActionLifecycleState,
    ActionRecord,
    ActionRequest,
    BudgetSpec,
    CapabilityDeniedError,
    CapabilityDescriptor,
    CapabilityLimits,
    EnvelopeStatus,
    ExecutionClass,
    GuestBlockedError,
    GuestHealthState,
    InvalidStateTransitionError,
    ProvenanceInfo,
    ResultEnvelope,
    RunMode,
    ScopePolicy,
    UsageMetrics,
    canonical_digest,
)
from ctf_mcp.controller import HarnessController
from ctf_mcp.server import create_mcp_server
from ctf_mcp.storage import Storage


def _make_scope(
    *,
    task_id: str = "task-ctf11",
    scope_revision: str = "scope-v1",
    allowed_capabilities: tuple[str, ...] = ("artifact.inspect", "analysis.query"),
    expires_at: datetime | None = None,
) -> ScopePolicy:
    now = datetime.now(UTC)
    exp = expires_at if expires_at is not None else (now + timedelta(hours=1))
    payload = {
        "mode": RunMode.OFFLINE_CTF.value,
        "task_id": task_id,
        "scope_revision": scope_revision,
        "allowed_capabilities": list(allowed_capabilities),
        "expires_at": exp.isoformat(),
    }
    return ScopePolicy(
        scope_revision=scope_revision,
        scope_sha256=canonical_digest(payload),
        mode=RunMode.OFFLINE_CTF,
        task_id=task_id,
        authorization_reference="local-ctf11-fixture",
        allowed_execution_classes=(ExecutionClass.STATIC,),
        allowed_capabilities=allowed_capabilities,
        expires_at=exp,
        network_enabled=False,
        allowed_targets=(),
        external_submission=False,
    )


def _make_budget(*, max_calls: int = 10) -> BudgetSpec:
    return BudgetSpec(
        run_budget_seconds=120,
        action_timeout_seconds=15,
        session_idle_seconds=60,
        max_tool_calls=max_calls,
        max_output_chars_per_page=1000,
        max_evidence_bytes_per_run=512_000,
        heavy_job_concurrency=1,
        interactive_session_limit=1,
    )


def _signed_synthetic_descriptor(name: str = "artifact.inspect") -> CapabilityDescriptor:
    return build_signed_descriptor(
        name=name,
        adapter_id=SYNTHETIC_ADAPTER_ID,
        adapter_commit=SYNTHETIC_ADAPTER_COMMIT,
        dependency_lock_sha256=SYNTHETIC_DEPENDENCY_LOCK_SHA256,
        operations=SYNTHETIC_OPERATIONS,
        arg_schema=dict(SYNTHETIC_ARG_SCHEMA),
        execution_classes=(ExecutionClass.STATIC,),
        required_scope={"modes": ["offline_ctf", "scoped_ctf", "vdp"]},
        limits=CapabilityLimits(
            timeout_seconds=15,
            max_output_bytes=32_768,
            max_decode_bytes=4096,
        ),
        enabled=True,
        profile_modes=(RunMode.OFFLINE_CTF, RunMode.SCOPED_CTF, RunMode.VDP),
    )


def _make_controller(
    tmp_path: Path,
    *,
    allow_synthetic_adapters: bool = True,
    is_process_alive: Any = None,
    clock: Any = None,
) -> HarnessController:
    storage = Storage(tmp_path / "state" / "harness.db")
    ctrl = HarnessController(
        storage=storage,
        vault_root=tmp_path / "vault",
        export_root=tmp_path / "exports",
        allow_ephemeral_cursor_key=True,
        allow_synthetic_adapters=allow_synthetic_adapters,
        is_process_alive=is_process_alive,
        clock=clock,
    )
    ctrl.initialize()
    return ctrl


def test_production_default_disables_synthetic_adapter(tmp_path: Path) -> None:
    assert PRODUCTION_DEFAULT_ENABLED is False
    ctrl = _make_controller(tmp_path, allow_synthetic_adapters=False)
    adapter = SyntheticAdapter(
        enabled=True,
        descriptor_override=_signed_synthetic_descriptor("artifact.inspect"),
    )
    with pytest.raises(CapabilityDeniedError, match="disabled"):
        ctrl.register_adapter(adapter)


def test_ctf11_failed_and_empty_analyzer_outputs_always_map_to_tool_error(
    tmp_path: Path,
) -> None:
    ctrl = _make_controller(tmp_path, allow_synthetic_adapters=True)
    principal = ctrl.authenticator.authenticate_stdio(principal_id="alice")
    adapter = SyntheticAdapter(
        enabled=True,
        evidence_vault=ctrl.evidence_vault,
        descriptor_override=_signed_synthetic_descriptor("artifact.inspect"),
    )
    ctrl.register_adapter(adapter, tool_group="artifact.inspect")

    # Fake adapter claiming OK with zero bytes / zero evidence must be coerced to tool_error.
    class FakeSilentOkAdapter:
        def __init__(self, desc: CapabilityDescriptor) -> None:
            self._desc = desc

        def descriptor(self) -> CapabilityDescriptor:
            return self._desc

        def execute(self, action: ActionRecord) -> ResultEnvelope:
            return ResultEnvelope(
                run_id=action.run_id,
                action_id=action.action_id,
                status=EnvelopeStatus.OK,
                summary="no vulnerabilities found",
                evidence=(),
                truncated=False,
                next_cursor=None,
                error=None,
                usage=UsageMetrics(wall_ms=5, output_bytes=0),
                provenance=ProvenanceInfo(
                    adapter_revision=self._desc.adapter_commit,
                    scope_revision=action.scope_revision,
                ),
            )

    analysis_desc = build_signed_descriptor(
        name="analysis.query",
        adapter_id="fake.silent",
        adapter_commit="fake-1",
        dependency_lock_sha256="b" * 64,
        operations=("scan",),
        arg_schema={"type": "object", "properties": {}, "additionalProperties": False},
        execution_classes=(ExecutionClass.STATIC,),
        required_scope={"modes": ["offline_ctf"]},
        limits=CapabilityLimits(timeout_seconds=10, max_output_bytes=4096, max_decode_bytes=4096),
        enabled=True,
        profile_modes=(RunMode.OFFLINE_CTF,),
    )
    ctrl.register_adapter(FakeSilentOkAdapter(analysis_desc), tool_group="analysis.query")

    scope = _make_scope()
    manifest = ctrl.create_run(
        principal=principal,
        task_id="task-ctf11",
        mode=RunMode.OFFLINE_CTF,
        scope=scope,
        budget=_make_budget(max_calls=10),
    )

    server = create_mcp_server(
        ctrl,
        default_stdio_principal=principal,
        active_run_id=manifest.run_id,
    )

    async def _run() -> None:
        async with Client(server.mcp) as client:
            tools = {t.name for t in await client.list_tools()}
            assert {"artifact.inspect", "analysis.query"}.issubset(tools)

            # 1) Synthetic forced error + empty capture -> status="tool_error", never "ok".
            fail_res = await client.call_tool(
                "artifact.inspect",
                {
                    "run_id": manifest.run_id,
                    "request_id": "req-fail-1",
                    "expected_revision": 1,
                    "operation": "force_error_empty",
                    "arguments": {"exit_code": 2},
                },
            )
            assert fail_res.data["status"] == "tool_error"
            assert fail_res.data["error"]["code"] == "tool_execution_failed"
            assert fail_res.data["usage"]["output_bytes"] == 0

            # 2) Fake empty OK -> coerced to status="tool_error" with code="empty_tool_output".
            silent_res = await client.call_tool(
                "analysis.query",
                {
                    "run_id": manifest.run_id,
                    "request_id": "req-silent-2",
                    "expected_revision": 2,
                    "operation": "scan",
                    "arguments": {},
                },
            )
            assert silent_res.data["status"] == "tool_error"
            assert silent_res.data["error"]["code"] == "empty_tool_output"

            # 3) #29 idempotent replay check BEFORE expected_revision check:
            #    Re-sending req-fail-1 with old expected_revision=1 when current revision is 3
            #    must return cached envelope WITHOUT consuming budget.
            desc_before = await client.call_tool("run.describe", {"run_id": manifest.run_id})
            calls_before = desc_before.data["budget"]["remaining_calls"]
            rev_before = desc_before.data["revision"]
            assert rev_before == 3

            replay_res = await client.call_tool(
                "artifact.inspect",
                {
                    "run_id": manifest.run_id,
                    "request_id": "req-fail-1",
                    "expected_revision": 1,
                    "operation": "force_error_empty",
                    "arguments": {"exit_code": 2},
                },
            )
            assert replay_res.data == fail_res.data

            desc_after = await client.call_tool("run.describe", {"run_id": manifest.run_id})
            assert desc_after.data["budget"]["remaining_calls"] == calls_before
            assert desc_after.data["revision"] == rev_before

            # 4) Reusing req-fail-1 with modified arguments must raise conflict error.
            conflict_res = await client.call_tool(
                "artifact.inspect",
                {
                    "run_id": manifest.run_id,
                    "request_id": "req-fail-1",
                    "expected_revision": 3,
                    "operation": "force_error_empty",
                    "arguments": {"exit_code": 3},
                },
                raise_on_error=False,
            )
            assert conflict_res.is_error is True
            assert conflict_res.structured_content["status"] == "tool_error"
            assert conflict_res.structured_content["error"]["code"] == "action_conflict"

    asyncio.run(_run())


def test_ctf11_prelaunch_expired_and_scope_expired_return_denied_with_reason(
    tmp_path: Path,
) -> None:
    ctrl = _make_controller(tmp_path, allow_synthetic_adapters=True)
    principal = ctrl.authenticator.authenticate_stdio(principal_id="alice")
    adapter = SyntheticAdapter(
        enabled=True,
        evidence_vault=ctrl.evidence_vault,
        descriptor_override=_signed_synthetic_descriptor("artifact.inspect"),
    )
    ctrl.register_adapter(adapter, tool_group="artifact.inspect")

    active_scope = _make_scope(scope_revision="scope-active")
    run_active = ctrl.create_run(
        principal=principal,
        task_id="task-ctf11",
        mode=RunMode.OFFLINE_CTF,
        scope=active_scope,
        budget=_make_budget(max_calls=5),
    )

    # Case A: Pre-launch reservation expiration (reserved -> expired -> denied with reason).
    prelaunch_env = ctrl.execute_action(
        principal=principal,
        request=ActionRequest(
            run_id=run_active.run_id,
            request_id="req-expired-prelaunch",
            expected_revision=1,
            capability_name="artifact.inspect",
            operation="observe",
            arguments={"message": "should expire prelaunch"},
        ),
        pre_launch_expired_reason="prelaunch deadline reached before guest launch",
    )
    assert prelaunch_env.status == EnvelopeStatus.DENIED
    assert prelaunch_env.error is not None
    assert prelaunch_env.error.code == "action_expired"
    assert "prelaunch deadline" in prelaunch_env.error.message
    stored_action = ctrl.actions.get_action_with_envelope(prelaunch_env.action_id).action
    assert stored_action.state == ActionLifecycleState.EXPIRED

    # Unused ms/bytes/slots are refunded on prelaunch expiry; call counter decrements once.
    desc_active = ctrl.describe_run(principal=principal, run_id=run_active.run_id)
    assert desc_active["budget"]["remaining_ms"] == 120_000
    assert desc_active["budget"]["remaining_bytes"] == 512_000
    assert desc_active["budget"]["active_heavy_jobs"] == 0
    assert desc_active["budget"]["active_sessions"] == 0
    assert desc_active["budget"]["remaining_calls"] == 4

    # Case B: Expired scope via controller & FastMCP server -> denied with expiry reason.
    expired_scope = _make_scope(
        scope_revision="scope-expired",
        expires_at=datetime.now(UTC) - timedelta(seconds=30),
    )
    run_expired = ctrl.create_run(
        principal=principal,
        task_id="task-ctf11",
        mode=RunMode.OFFLINE_CTF,
        scope=expired_scope,
        budget=_make_budget(max_calls=5),
    )
    ctrl_denied = ctrl.execute_action(
        principal=principal,
        request=ActionRequest(
            run_id=run_expired.run_id,
            request_id="req-scope-exp",
            expected_revision=0,
            capability_name="artifact.inspect",
            operation="observe",
            arguments={"message": "after expiry"},
        ),
    )
    assert ctrl_denied.status == EnvelopeStatus.DENIED
    assert ctrl_denied.error is not None
    assert ctrl_denied.error.code == "scope_expired"
    assert "expired" in ctrl_denied.error.message.lower()

    server = create_mcp_server(
        ctrl,
        default_stdio_principal=principal,
        active_run_id=run_expired.run_id,
    )

    async def _run() -> None:
        async with Client(server.mcp) as client:
            tools = {t.name for t in await client.list_tools()}
            assert "artifact.inspect" not in tools
            denied_mcp = await client.call_tool(
                "artifact.inspect",
                {
                    "run_id": run_expired.run_id,
                    "request_id": "req-mcp-exp",
                    "expected_revision": 0,
                    "operation": "observe",
                    "arguments": {},
                },
                raise_on_error=False,
            )
            assert denied_mcp.is_error is True
            assert denied_mcp.structured_content["status"] == "denied"
            assert denied_mcp.structured_content["error"]["code"] == "scope_expired"
            assert "expired" in denied_mcp.structured_content["error"]["message"].lower()

    asyncio.run(_run())


def test_ctf11_reconciliation_required_and_unexpected_crash_blocks_ok_and_close(
    tmp_path: Path,
) -> None:
    ctrl = _make_controller(tmp_path, allow_synthetic_adapters=True)
    principal = ctrl.authenticator.authenticate_stdio(principal_id="alice")
    adapter = SyntheticAdapter(
        enabled=True,
        evidence_vault=ctrl.evidence_vault,
        descriptor_override=_signed_synthetic_descriptor("artifact.inspect"),
    )
    ctrl.register_adapter(adapter, tool_group="artifact.inspect")

    manifest = ctrl.create_run(
        principal=principal,
        task_id="task-ctf11",
        mode=RunMode.OFFLINE_CTF,
        scope=_make_scope(),
        budget=_make_budget(max_calls=10),
    )

    # Simulate an in-flight action interrupted by supervisor crash before TX2.
    req = ActionRequest(
        run_id=manifest.run_id,
        request_id="req-inflight-crash",
        expected_revision=1,
        capability_name="artifact.inspect",
        operation="observe",
        arguments={"message": "crash test"},
    )
    with ctrl.storage.transaction() as conn:
        cap = ctrl.catalog.get_capability("artifact.inspect", RunMode.OFFLINE_CTF)
        sub = ctrl.actions.reserve_action_in_tx(
            conn,
            run_id=manifest.run_id,
            principal_id=principal.principal_id,
            request=req,
            capability=cap,
            scope_revision="scope-v1",
        )
        ctrl.actions.start_action_in_tx(
            conn,
            action_id=sub.action.action_id,
            supervisor_key="harness-supervisor",
            supervisor_instance_id="dead-sup",
            process_start_id="dead-proc",
        )

    # Restart controller -> recovery marks unknown in-flight action as reconciliation_required.
    restarted_ctrl = _make_controller(
        tmp_path,
        allow_synthetic_adapters=True,
        is_process_alive=lambda _a: False,
    )
    restarted_ctrl.register_adapter(adapter, tool_group="artifact.inspect")
    # Run initialize again on same DB triggers reconciliation.
    rec_report = restarted_ctrl.initialize()
    # Note first _make_controller call already ran initialize() once; verify state is reconciliation_required.
    reconciled_action = restarted_ctrl.actions.get_action_with_envelope(sub.action.action_id).action
    assert reconciled_action.state == ActionLifecycleState.RECONCILIATION_REQUIRED
    assert rec_report is not None

    # Controller replay of reconciliation_required must NEVER return 'ok'.
    with pytest.raises(InvalidStateTransitionError, match="reconciliation_required"):
        restarted_ctrl.execute_action(principal=principal, request=req)

    # Server layer must fail closed with tool_error / is_error=True on both replay and run.close.
    server = create_mcp_server(
        restarted_ctrl,
        default_stdio_principal=principal,
        active_run_id=manifest.run_id,
    )

    async def _run() -> None:
        async with Client(server.mcp) as client:
            replay_err = await client.call_tool(
                "artifact.inspect",
                {
                    "run_id": manifest.run_id,
                    "request_id": req.request_id,
                    "expected_revision": 1,
                    "operation": req.operation,
                    "arguments": req.arguments,
                },
                raise_on_error=False,
            )
            assert replay_err.is_error is True
            assert replay_err.structured_content["status"] == "tool_error"
            assert replay_err.structured_content["error"]["code"] == "invalid_state_transition"

            close_err = await client.call_tool(
                "run.close",
                {"run_id": manifest.run_id},
                raise_on_error=False,
            )
            assert close_err.is_error is True
            assert close_err.structured_content["status"] == "tool_error"
            assert "non_terminal_actions_remaining" in close_err.structured_content["error"]["message"]

    asyncio.run(_run())

    # Resolving reconciliation_required explicitly as FAILED produces tool_error cleanly.
    with restarted_ctrl.storage.transaction() as conn:
        resolved = restarted_ctrl.recovery.resolve_reconciled_action_in_tx(
            conn,
            action_id=sub.action.action_id,
            target_state=ActionLifecycleState.FAILED,
            has_tool_receipt=False,
            summary="Supervisor crashed prior to receipt confirmation.",
        )
    assert resolved.envelope is not None
    assert resolved.envelope.status == EnvelopeStatus.TOOL_ERROR


def test_readonly_hint_never_bypasses_ownership_or_crashing_adapter_cleanup(
    tmp_path: Path,
) -> None:
    ctrl = _make_controller(tmp_path, allow_synthetic_adapters=True)
    alice = ctrl.authenticator.authenticate_stdio(principal_id="alice")
    bob = ctrl.authenticator.authenticate_stdio(principal_id="bob")

    class CrashingAdapter:
        def __init__(self, desc: CapabilityDescriptor) -> None:
            self._desc = desc

        def descriptor(self) -> CapabilityDescriptor:
            return self._desc

        def execute_with_capture(self, action: ActionRecord, **_kwargs: Any) -> Any:
            raise RuntimeError("simulated unconfirmed adapter crash")

    crash_desc = _signed_synthetic_descriptor("artifact.inspect")
    ctrl.register_adapter(CrashingAdapter(crash_desc), tool_group="artifact.inspect")

    manifest = ctrl.create_run(
        principal=alice,
        task_id="task-ctf11",
        mode=RunMode.OFFLINE_CTF,
        scope=_make_scope(),
        budget=_make_budget(max_calls=5),
    )

    # Bob cannot read Alice's run even though run.describe carries readOnlyHint=True.
    bob_server = create_mcp_server(ctrl, default_stdio_principal=bob)

    async def _run_bob() -> None:
        async with Client(bob_server.mcp) as client:
            tools = {t.name: t for t in await client.list_tools()}
            assert tools["run.describe"].annotations.read_only_hint is True
            res = await client.call_tool(
                "run.describe", {"run_id": manifest.run_id}, raise_on_error=False
            )
            assert res.is_error is True
            assert res.structured_content["status"] == "denied"

    asyncio.run(_run_bob())

    # Unexpected adapter exception inside execute_action settles to TOOL_ERROR and blocks guest!
    env = ctrl.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id=manifest.run_id,
            request_id="req-crash-outside-tx",
            expected_revision=1,
            capability_name="artifact.inspect",
            operation="observe",
            arguments={},
        ),
    )
    assert env.status == EnvelopeStatus.TOOL_ERROR
    desc = ctrl.describe_run(principal=alice, run_id=manifest.run_id)
    assert desc["guest_health"] == GuestHealthState.CLEANUP_UNCONFIRMED.value
    with pytest.raises(GuestBlockedError):
        ctrl.close_run(principal=alice, run_id=manifest.run_id)
