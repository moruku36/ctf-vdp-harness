"""End-to-End offline vertical slice integration tests through Layer 3 & Layer 4 FastMCP."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx2
import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

from ctf_mcp.adapters import (
    PRODUCTION_DEFAULT_ENABLED,
    SYNTHETIC_FLAG_MARKER,
    SYNTHETIC_SECRET_MARKER,
    SYNTHETIC_SENSITIVE_MARKER,
    SyntheticAdapter,
    build_signed_descriptor,
)
from ctf_mcp.adapters.synthetic import (
    SYNTHETIC_ADAPTER_COMMIT,
    SYNTHETIC_ADAPTER_ID,
    SYNTHETIC_ARG_SCHEMA,
    SYNTHETIC_DEPENDENCY_LOCK_SHA256,
    SYNTHETIC_OPERATIONS,
)
from ctf_mcp.config import load_runtime_settings
from ctf_mcp.contracts import (
    ActionRequest,
    BudgetSpec,
    CapabilityDescriptor,
    CapabilityLimits,
    ConfigurationError,
    EnvelopeStatus,
    ExecutionClass,
    HypothesisState,
    PrincipalContext,
    RunMode,
    ScopePolicy,
    TransportMode,
    VerificationStatus,
    canonical_digest,
    sha256_bytes,
)
from ctf_mcp.controller import HarnessController
from ctf_mcp.evidence import REDACTED_PLACEHOLDER, ReportMetadata, validate_evidence_page_schema
from ctf_mcp.server import create_mcp_server
from ctf_mcp.storage import Storage
from ctf_mcp.verification import ExpectedChallengeSpec, LocalCtfVerifier

REPO_ROOT = Path(__file__).resolve().parents[2]
JA_TEMPLATE_PATH = REPO_ROOT / "templates" / "run-report.ja.md"


def _make_scope(
    *,
    task_id: str = "task-e2e-01",
    scope_revision: str = "scope-e2e-v1",
    allowed_capabilities: tuple[str, ...] = ("artifact.inspect",),
) -> ScopePolicy:
    exp = datetime.now(UTC) + timedelta(hours=2)
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
        authorization_reference="offline-pilot-e2e-auth",
        allowed_execution_classes=(ExecutionClass.STATIC,),
        allowed_capabilities=allowed_capabilities,
        expires_at=exp,
        network_enabled=False,
        allowed_targets=(),
        external_submission=False,
    )


def _make_budget() -> BudgetSpec:
    return BudgetSpec(
        run_budget_seconds=180,
        action_timeout_seconds=15,
        session_idle_seconds=60,
        max_tool_calls=20,
        max_output_chars_per_page=500,
        max_evidence_bytes_per_run=1_048_576,
        heavy_job_concurrency=1,
        interactive_session_limit=1,
    )


def _signed_descriptor(
    name: str,
    *,
    execution_classes: tuple[ExecutionClass, ...] = (ExecutionClass.STATIC,),
    profile_modes: tuple[RunMode, ...] = (RunMode.OFFLINE_CTF, RunMode.SCOPED_CTF, RunMode.VDP),
    enabled: bool = True,
) -> CapabilityDescriptor:
    return build_signed_descriptor(
        name=name,
        adapter_id=SYNTHETIC_ADAPTER_ID,
        adapter_commit=SYNTHETIC_ADAPTER_COMMIT,
        dependency_lock_sha256=SYNTHETIC_DEPENDENCY_LOCK_SHA256,
        operations=SYNTHETIC_OPERATIONS,
        arg_schema=dict(SYNTHETIC_ARG_SCHEMA),
        execution_classes=execution_classes,
        required_scope={"modes": [m.value for m in profile_modes]},
        limits=CapabilityLimits(
            timeout_seconds=15,
            max_output_bytes=32_768,
            max_decode_bytes=4096,
        ),
        enabled=enabled,
        profile_modes=profile_modes,
    )


def test_e2e_offline_vertical_slice_via_fastmcp(tmp_path: Path) -> None:
    """Full P1 offline vertical slice through Layer 4 FastMCP Client and Layer 3 controller."""
    assert PRODUCTION_DEFAULT_ENABLED is False

    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    challenge_file = workspace / "challenge.bin"
    challenge_bytes = b"\x7fELF-offline-challenge-fixture-v1\nentry=0x401000\n"
    challenge_file.write_bytes(challenge_bytes)

    db_path = tmp_path / "state" / "harness.db"
    storage = Storage(db_path)
    controller = HarnessController(
        storage=storage,
        vault_root=tmp_path / "vault",
        export_root=tmp_path / "exports",
        allow_ephemeral_cursor_key=True,
        allow_synthetic_adapters=True,
    )
    reconcile_report = controller.initialize()
    assert reconcile_report.reconciled_to_required == ()
    assert reconcile_report.expired_reserved == ()

    alice = controller.authenticator.authenticate_stdio(principal_id="alice")
    bob = controller.authenticator.authenticate_stdio(principal_id="bob")

    # Register unaccepted / dynamic / network descriptors in catalog before enabling static P1 tool.
    controller.register_catalog_descriptor(
        _signed_descriptor(
            "session.control",
            execution_classes=(ExecutionClass.DYNAMIC,),
            profile_modes=(RunMode.SCOPED_CTF,),
            enabled=False,
        )
    )
    controller.register_catalog_descriptor(
        _signed_descriptor(
            "net.probe",
            execution_classes=(ExecutionClass.NETWORK,),
            profile_modes=(RunMode.SCOPED_CTF, RunMode.VDP),
            enabled=True,
        )
    )
    controller.register_catalog_descriptor(
        _signed_descriptor("analysis.query", enabled=False)
    )

    server = create_mcp_server(controller, default_stdio_principal=alice)

    # 1. CTF-01 / N1: Initial P1 state hides unaccepted analysis.query, helper.transform,
    #    session.control, net.probe, and never exposes exec_shell; direct call is denied.
    async def _phase1_initial_visibility() -> None:
        async with Client(server.mcp) as client:
            listed = {t.name for t in await client.list_tools()}
            assert listed == {
                "run.describe",
                "evidence.read",
                "hypothesis.update",
                "run.verify",
                "run.close",
            }
            for hidden in (
                "exec_shell",
                "session.control",
                "net.probe",
                "analysis.query",
                "artifact.inspect",
                "helper.transform",
            ):
                denied = await client.call_tool(hidden, {}, raise_on_error=False)
                assert denied.is_error is True
                assert denied.structured_content["status"] == "denied"

    asyncio.run(_phase1_initial_visibility())

    # 2. Register accepted offline SyntheticAdapter under artifact.inspect + LocalCtfVerifier.
    artifact_adapter = SyntheticAdapter(
        enabled=True,
        evidence_vault=controller.evidence_vault,
        descriptor_override=_signed_descriptor("artifact.inspect", enabled=True),
    )
    controller.register_adapter(artifact_adapter, tool_group="artifact.inspect")

    expected_flag_sha = sha256_bytes(SYNTHETIC_FLAG_MARKER.encode("utf-8"))
    verifier = LocalCtfVerifier(
        storage=storage,
        vault_root=controller.vault_root,
        expected_by_task={
            "task-e2e-01": ExpectedChallengeSpec(
                expected_flag_sha256=expected_flag_sha,
                normalize_whitespace=True,
                description="Offline synthetic E2E digest check",
            )
        },
    )
    controller.register_verifier(verifier)

    manifest = controller.create_run(
        principal=alice,
        task_id="task-e2e-01",
        mode=RunMode.OFFLINE_CTF,
        scope=_make_scope(),
        budget=_make_budget(),
    )
    server.set_active_run(manifest.run_id)

    ingested = controller.ingest_artifact(
        principal=alice,
        run_id=manifest.run_id,
        source_root=workspace,
        rel_path="challenge.bin",
        media_type="application/octet-stream",
    )
    assert ingested.sha256 == sha256_bytes(challenge_bytes)

    # 3. Full E2E vertical slice via FastMCP Client.
    captured_state: dict[str, Any] = {}

    async def _phase2_full_slice() -> None:
        async with Client(server.mcp) as client:
            # Dynamic tools/list now includes artifact.inspect, while forbidden/unaccepted remain hidden.
            listed = {t.name for t in await client.list_tools()}
            assert "artifact.inspect" in listed
            assert "exec_shell" not in listed
            assert "session.control" not in listed
            assert "analysis.query" not in listed
            assert "helper.transform" not in listed

            # run.describe shows ingested artifact, budget, and updated revision=2 after intake provenance.
            desc = await client.call_tool("run.describe", {"run_id": manifest.run_id})
            assert desc.data["revision"] == 2
            assert len(desc.data["artifacts"]) == 1
            assert desc.data["artifacts"][0]["sha256"] == ingested.sha256

            # Observe ingested artifact via SyntheticAdapter.
            obs = await client.call_tool(
                "artifact.inspect",
                {
                    "run_id": manifest.run_id,
                    "request_id": "req-e2e-observe-1",
                    "expected_revision": 2,
                    "operation": "observe",
                    "arguments": {
                        "artifact_id": ingested.artifact_id,
                        "message": "inspect offline ELF header",
                    },
                },
            )
            assert obs.data["status"] == "ok"
            obs_ev_id = obs.data["evidence"][0]["id"]
            captured_state["obs_ev_id"] = obs_ev_id

            # Emit long multi-page UTF-8 output (> 500 chars) and reassemble all pages (CTF-03).
            stream = await client.call_tool(
                "artifact.inspect",
                {
                    "run_id": manifest.run_id,
                    "request_id": "req-e2e-stream-2",
                    "expected_revision": 3,
                    "operation": "output_flood",
                    "arguments": {"bytes_to_emit": 2400},
                },
            )
            assert stream.data["status"] == "ok"
            stream_ev_id = stream.data["evidence"][0]["id"]
            captured_state["stream_ev_id"] = stream_ev_id

            chunks: list[str] = []
            cursor: str | None = None
            page_count = 0
            raw_sha = ""
            while True:
                page_res = await client.call_tool(
                    "evidence.read",
                    {
                        "run_id": manifest.run_id,
                        "evidence_id": stream_ev_id,
                        "cursor": cursor,
                        "max_chars": 500,
                    },
                )
                page_dict = page_res.data
                validate_evidence_page_schema(page_dict)
                assert len(page_dict["content"]) <= 500
                chunks.append(page_dict["content"])
                raw_sha = page_dict["view_sha256"]
                page_count += 1
                cursor = page_dict["next_cursor"]
                if cursor is None:
                    break

            assert page_count >= 4
            reassembled = "".join(chunks).encode("utf-8")
            assert len(reassembled) == 2400
            assert sha256_bytes(reassembled) == raw_sha

            # Emit prompt injection + synthetic secret/flag markers into raw evidence (CTF-12).
            inj = await client.call_tool(
                "artifact.inspect",
                {
                    "run_id": manifest.run_id,
                    "request_id": "req-e2e-inj-3",
                    "expected_revision": 4,
                    "operation": "prompt_injection_marker",
                    "arguments": {"include_flag_marker": True},
                },
            )
            assert inj.data["status"] == "ok"
            assert SYNTHETIC_FLAG_MARKER not in inj.data["summary"]
            assert SYNTHETIC_SECRET_MARKER not in inj.data["summary"]
            assert SYNTHETIC_SENSITIVE_MARKER not in inj.data["summary"]
            assert "flag{" not in inj.data["summary"]
            inj_ev_id = inj.data["evidence"][0]["id"]
            captured_state["inj_ev_id"] = inj_ev_id

            # Grab an initial cursor BEFORE redaction to test cursor revocation below (CTF-04).
            first_inj_page = await client.call_tool(
                "evidence.read",
                {
                    "run_id": manifest.run_id,
                    "evidence_id": inj_ev_id,
                    "max_chars": 40,
                },
            )
            captured_state["pre_redact_cursor"] = first_inj_page.data["next_cursor"]
            assert captured_state["pre_redact_cursor"] is not None

            # Create hypothesis, then update with optimistic locking and test conflict.
            hyp_create = await client.call_tool(
                "hypothesis.update",
                {
                    "run_id": manifest.run_id,
                    "state": HypothesisState.UNKNOWN.value,
                    "claim": "Offline challenge binary exposes deterministic check path.",
                    "next_observation": "Correlate multi-page trace with verification digest.",
                    "supporting_evidence_ids": [obs_ev_id],
                },
            )
            assert hyp_create.data["revision"] == 1

            hyp_upd = await client.call_tool(
                "hypothesis.update",
                {
                    "run_id": manifest.run_id,
                    "hypothesis_id": hyp_create.data["hypothesis_id"],
                    "expected_revision": 1,
                    "state": HypothesisState.SUPPORTED.value,
                    "add_supporting_evidence_ids": [stream_ev_id],
                },
            )
            assert hyp_upd.data["revision"] == 2
            assert hyp_upd.data["state"] == HypothesisState.SUPPORTED.value

            stale_hyp = await client.call_tool(
                "hypothesis.update",
                {
                    "run_id": manifest.run_id,
                    "hypothesis_id": hyp_create.data["hypothesis_id"],
                    "expected_revision": 1,
                    "state": HypothesisState.REFUTED.value,
                },
                raise_on_error=False,
            )
            assert stale_hyp.is_error is True
            assert stale_hyp.structured_content["error"]["code"] == "action_conflict"

            # Verify BEFORE revoking raw view (#29 ordering):
            # 1) Store an evidence item containing the exact flag line and confirm run.verify
            #    WITHOUT plaintext claim passes while raw-v1 is unrevoked, then auto-redacts.
            raw_flag_manifest = controller.evidence_vault.store_raw(
                run_id=manifest.run_id,
                owner_principal_id=alice.principal_id,
                action_id=inj.data["action_id"],
                data=f"header\n{SYNTHETIC_FLAG_MARKER}\n".encode("utf-8"),
                media_type="text/plain; charset=utf-8",
                capture_complete=True,
                omission_reason=None,
                source_artifact_hashes=(ingested.sha256,),
                adapter_revision="synthetic-1",
                sanitized_args_sha256="0" * 64,
            )
            flag_ev_id = raw_flag_manifest.evidence_id
            captured_state["flag_ev_id"] = flag_ev_id

            verify_res = await client.call_tool(
                "run.verify",
                {
                    "run_id": manifest.run_id,
                    "verifier_id": "ctf.local_digest",
                    "evidence_ids": [flag_ev_id],
                    "auto_redact_after_verify": True,
                },
            )
            assert verify_res.data["status"] == VerificationStatus.PASSED.value
            verify_serialized = json.dumps(verify_res.data)
            assert SYNTHETIC_FLAG_MARKER not in verify_serialized
            assert "flag{" not in verify_serialized

            # Re-verifying solely from evidence AFTER redaction must fail because raw-v1
            # was revoked and redacted-v1 no longer contains the plaintext flag.
            post_redact_verify = await client.call_tool(
                "run.verify",
                {
                    "run_id": manifest.run_id,
                    "verifier_id": "ctf.local_digest",
                    "evidence_ids": [flag_ev_id],
                },
            )
            assert post_redact_verify.data["status"] == VerificationStatus.FAILED.value

            # Also verify inj_ev_id with claim + auto-redaction revoking pre_redact_cursor.
            inj_verify_res = await client.call_tool(
                "run.verify",
                {
                    "run_id": manifest.run_id,
                    "verifier_id": "ctf.local_digest",
                    "evidence_ids": [inj_ev_id],
                    "claim": SYNTHETIC_FLAG_MARKER,
                    "auto_redact_after_verify": True,
                },
            )
            assert inj_verify_res.data["status"] == VerificationStatus.PASSED.value

            # CTF-04 / CTF-12: Old cursor referencing revoked raw-v1 must be denied!
            stale_cursor_res = await client.call_tool(
                "evidence.read",
                {
                    "run_id": manifest.run_id,
                    "evidence_id": inj_ev_id,
                    "cursor": captured_state["pre_redact_cursor"],
                    "max_chars": 500,
                },
                raise_on_error=False,
            )
            assert stale_cursor_res.is_error is True
            assert stale_cursor_res.structured_content["status"] == "denied"

            # Reading redacted view returns REDACTED_PLACEHOLDER with no secrets/flags.
            redacted_res = await client.call_tool(
                "evidence.read",
                {
                    "run_id": manifest.run_id,
                    "evidence_id": inj_ev_id,
                    "max_chars": 500,
                },
            )
            assert redacted_res.data["view_revision"] == "redacted-v1"
            assert REDACTED_PLACEHOLDER in redacted_res.data["content"]
            assert SYNTHETIC_FLAG_MARKER not in redacted_res.data["content"]
            assert SYNTHETIC_SECRET_MARKER not in redacted_res.data["content"]
            assert SYNTHETIC_SENSITIVE_MARKER not in redacted_res.data["content"]
            assert "flag{" not in redacted_res.data["content"]

            # Close run cleanly -> close integrity, Japanese report export, guest rollback.
            close_res = await client.call_tool(
                "run.close",
                {
                    "run_id": manifest.run_id,
                    "language": "ja",
                    "output_relpath": "run-report.ja.md",
                    "require_verification": True,
                    "expected_evidence_ids": [obs_ev_id, stream_ev_id, inj_ev_id],
                    "forbidden_literals": [SYNTHETIC_FLAG_MARKER],
                    "metadata": ReportMetadata(
                        experiment_arm="offline-e2e-slice",
                        outcome_summary="Offline synthetic check verified without secret leak.",
                    ).model_dump(mode="json"),
                },
            )
            assert close_res.data["guest_rolled_back"] is True
            assert close_res.data["manifest"]["closed_at"] is not None
            assert close_res.data["integrity_report"]["close_allowed"] is True
            assert close_res.data["integrity_report"]["cleanup_confirmed"] is True
            assert close_res.data["integrity_report"]["import_verified"] is True
            captured_state["report_path"] = close_res.data["export_result"]["output_path"]

    asyncio.run(_phase2_full_slice())

    # Cross-principal read denial (CTF-04): bob cannot read Alice's evidence or run.
    bob_server = create_mcp_server(controller, default_stdio_principal=bob)

    async def _phase3_bob_denied() -> None:
        async with Client(bob_server.mcp) as bob_client:
            denied_ev = await bob_client.call_tool(
                "evidence.read",
                {
                    "run_id": manifest.run_id,
                    "evidence_id": captured_state["stream_ev_id"],
                },
                raise_on_error=False,
            )
            assert denied_ev.is_error is True
            assert denied_ev.structured_content["status"] == "denied"

    asyncio.run(_phase3_bob_denied())

    # Verify exported Japanese report matches templates/run-report.ja.md structure and contains zero leaks.
    report_path = Path(captured_state["report_path"])
    assert report_path.exists()
    report_text = report_path.read_text(encoding="utf-8")
    template_headings = [
        line.strip()
        for line in JA_TEMPLATE_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("#")
    ]
    for heading in template_headings:
        # Top-level title or numbered section heading must be preserved in generated JA report.
        section_prefix = heading.split("{", 1)[0].strip()
        assert section_prefix in report_text

    for forbidden in (
        SYNTHETIC_FLAG_MARKER,
        SYNTHETIC_SECRET_MARKER,
        SYNTHETIC_SENSITIVE_MARKER,
        "flag{",
    ):
        assert forbidden not in report_text

    # Verify SQLite audit_events and manifests contain zero markers/flags.
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT destination_summary FROM audit_events WHERE run_id = ?",
            (manifest.run_id,),
        ).fetchall()
        audit_blob = "\n".join(str(r[0]) for r in rows if r[0])
        for forbidden in (
            SYNTHETIC_FLAG_MARKER,
            SYNTHETIC_SECRET_MARKER,
            SYNTHETIC_SENSITIVE_MARKER,
            "flag{",
        ):
            assert forbidden not in audit_blob
    finally:
        conn.close()

    # Post-close actions must be rejected (run_closed -> denied).
    closed_retry = controller.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id=manifest.run_id,
            request_id="req-after-close",
            expected_revision=5,
            capability_name="artifact.inspect",
            operation="observe",
            arguments={"message": "should be denied after close"},
        ),
    )
    assert closed_retry.status == EnvelopeStatus.DENIED
    assert closed_retry.error is not None and closed_retry.error.code == "run_closed"


def test_streamable_http_auth_fail_closed_and_principal_isolation(
    tmp_path: Path,
) -> None:
    """HTTP transport enforces CTF_MCP_AUTH_TOKEN and isolates principals end-to-end."""
    with pytest.raises(ConfigurationError):
        load_runtime_settings({"CTF_MCP_TRANSPORT": "streamable-http"})

    alice_token = "alice-real-http-token-123456"
    bob_token = "bob-real-http-token-654321"
    settings = load_runtime_settings(
        {
            "CTF_MCP_TRANSPORT": "streamable-http",
            "CTF_MCP_AUTH_TOKEN": alice_token,
            "CTF_MCP_PROFILE": "offline_ctf",
        }
    )

    storage = Storage(tmp_path / "state" / "http_harness.db")
    controller = HarnessController(
        storage=storage,
        vault_root=tmp_path / "vault",
        export_root=tmp_path / "exports",
        runtime_settings=settings,
        allow_ephemeral_cursor_key=True,
        allow_synthetic_adapters=False,
    )
    controller.initialize()
    controller.authenticator.register_token(
        bob_token,
        PrincipalContext(
            principal_id="bob",
            auth_method="bearer_token",
            client_kind="OPERATOR_SELECTED",
            model_label="offline-test",
        ),
    )

    alice = controller.authenticator.authenticate(
        TransportMode.STREAMABLE_HTTP, token=alice_token
    )
    manifest = controller.create_run(
        principal=alice,
        task_id="task-http-01",
        mode=RunMode.OFFLINE_CTF,
        scope=_make_scope(task_id="task-http-01"),
        budget=_make_budget(),
    )

    server = create_mcp_server(controller, runtime_settings=settings)
    app = server.http_app(path="/mcp")

    async def _run_http() -> None:
        async with app.router.lifespan_context(app):
            def make_client(**kwargs: Any) -> httpx2.AsyncClient:
                return httpx2.AsyncClient(
                    transport=httpx2.ASGITransport(app=app),
                    **kwargs,
                )

            # 1) Unauthenticated client rejected.
            unauth = StreamableHttpTransport("http://test/mcp", httpx_client_factory=make_client)
            with pytest.raises(Exception):
                async with Client(unauth) as client:
                    await client.list_tools()

            # 2) Invalid token rejected.
            bad_auth = StreamableHttpTransport(
                "http://test/mcp",
                headers={"Authorization": "Bearer wrong-token-value-123456"},
                httpx_client_factory=make_client,
            )
            with pytest.raises(Exception):
                async with Client(bad_auth) as client:
                    await client.list_tools()

            # 3) Valid Alice bearer token accesses her run cleanly.
            alice_transport = StreamableHttpTransport(
                "http://test/mcp",
                headers={
                    "Authorization": f"Bearer {alice_token}",
                    "X-CTF-Run-Id": manifest.run_id,
                },
                httpx_client_factory=make_client,
            )
            async with Client(alice_transport) as alice_client:
                desc = await alice_client.call_tool(
                    "run.describe", {"run_id": manifest.run_id}
                )
                assert desc.data["run_id"] == manifest.run_id

            # 4) Valid Bob bearer token is denied access to Alice's run.
            bob_transport = StreamableHttpTransport(
                "http://test/mcp",
                headers={"Authorization": f"Bearer {bob_token}"},
                httpx_client_factory=make_client,
            )
            async with Client(bob_transport) as bob_client:
                denied = await bob_client.call_tool(
                    "run.describe",
                    {"run_id": manifest.run_id},
                    raise_on_error=False,
                )
                assert denied.is_error is True
                assert denied.structured_content["status"] == "denied"

    asyncio.run(_run_http())
