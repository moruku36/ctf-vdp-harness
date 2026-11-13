"""P4 integration tests for DeterministicTransformAdapter (`helper.transform`) and
InteractiveDebugSessionAdapter (`session.control`) including LeaseManager lifecycle,
15-minute idle expiry, crash/restart `lost` handling, OS process cleanup, and
dynamic profile isolation.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import struct
import sys
import threading
import time
import urllib.parse
import zlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client

from ctf_mcp.adapters import (
    InteractiveDebugSessionAdapter,
    SubprocessRunner,
    create_interactive_session_descriptor,
    is_os_process_alive,
)
from ctf_mcp.contracts import (
    ActionRequest,
    BudgetSpec,
    CapabilityDeniedError,
    CapabilityLimits,
    ContractViolationError,
    EnvelopeStatus,
    ExecutionClass,
    PrincipalContext,
    RunMode,
    ScopePolicy,
    canonical_digest,
)
from ctf_mcp.controller import (
    HarnessController,
    create_default_controller,
    register_default_adapters,
)
from ctf_mcp.runs import SessionLeaseState
from ctf_mcp.server import create_mcp_server
from ctf_mcp.storage import Storage

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"


class _MutableClock:
    def __init__(self, start: datetime | None = None) -> None:
        self.now = start or datetime(2026, 11, 13, 3, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


def _principal(pid: str = "alice") -> PrincipalContext:
    return PrincipalContext(
        principal_id=pid,
        auth_method="stdio_local",
        client_kind="Codex",
        model_label="p4-test-model",
    )


def _scope(
    *,
    mode: RunMode = RunMode.OFFLINE_CTF,
    task_id: str = "task-p4",
    rev: str = "scope-p4-v1",
    caps: tuple[str, ...] = ("artifact.inspect", "analysis.query", "helper.transform"),
    exec_classes: tuple[ExecutionClass, ...] = (ExecutionClass.STATIC,),
    expires_hours: int = 2,
    clock: _MutableClock | None = None,
) -> ScopePolicy:
    base_time = clock() if clock is not None else datetime.now(UTC)
    exp = base_time + timedelta(hours=expires_hours)
    payload = {
        "mode": mode.value,
        "task_id": task_id,
        "scope_revision": rev,
        "allowed_capabilities": list(caps),
        "allowed_execution_classes": [ec.value for ec in exec_classes],
        "expires_at": exp.isoformat(),
    }
    return ScopePolicy(
        scope_revision=rev,
        scope_sha256=canonical_digest(payload),
        mode=mode,
        task_id=task_id,
        authorization_reference="OWNED_LOCAL_P4_TEST",
        allowed_execution_classes=exec_classes,
        allowed_capabilities=caps,
        expires_at=exp,
        network_enabled=False,
        allowed_targets=(),
        external_submission=False,
    )


def _budget(**overrides: Any) -> BudgetSpec:
    defaults = {
        "run_budget_seconds": 300,
        "action_timeout_seconds": 10,
        "session_idle_seconds": 900,
        "max_tool_calls": 40,
        "max_output_chars_per_page": 200,
        "max_evidence_bytes_per_run": 1_048_576,
        "heavy_job_concurrency": 1,
        "interactive_session_limit": 1,
    }
    defaults.update(overrides)
    return BudgetSpec(**defaults)


def _build_minimal_elf64() -> bytes:
    """Construct a valid minimal 64-bit little-endian ELF binary with .text and .rodata."""
    text_data = b"\x48\xc7\xc0\x2a\x00\x00\x00\xc3" * 8  # mov rax, 42; ret repeated
    rodata_data = b"CTF_ELF_BANNER_VALUE\x00SECOND_STRING\x00"
    shstrtab = b"\x00.text\x00.rodata\x00.shstrtab\x00"

    ehdr_size = 64
    text_off = ehdr_size
    rodata_off = text_off + len(text_data)
    shstrtab_off = rodata_off + len(rodata_data)
    raw_end = shstrtab_off + len(shstrtab)
    pad = (8 - (raw_end % 8)) % 8
    sh_off = raw_end + pad

    e_ident = struct.pack(
        "<4sBBBBB7s",
        b"\x7fELF",
        2,  # ELFCLASS64
        1,  # ELFDATA2LSB
        1,  # EV_CURRENT
        0,  # ELFOSABI_NONE
        0,
        b"\x00" * 7,
    )
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,  # ET_EXEC
        62,  # EM_X86_64
        1,  # EV_CURRENT
        0x401000,  # e_entry
        0,
        sh_off,
        0,
        64,
        0,
        0,
        64,
        4,
        3,
    )

    def _shdr64(
        sh_name: int,
        sh_type: int,
        sh_flags: int,
        sh_addr: int,
        sh_offset: int,
        sh_size: int,
    ) -> bytes:
        return struct.pack(
            "<IIQQQQIIQQ",
            sh_name,
            sh_type,
            sh_flags,
            sh_addr,
            sh_offset,
            sh_size,
            0,
            0,
            1,
            0,
        )

    shdrs = b"".join(
        [
            _shdr64(0, 0, 0, 0, 0, 0),
            _shdr64(1, 1, 6, 0x401000, text_off, len(text_data)),
            _shdr64(7, 1, 2, 0x402000, rodata_off, len(rodata_data)),
            _shdr64(15, 3, 0, 0, shstrtab_off, len(shstrtab)),
        ]
    )
    return ehdr + text_data + rodata_data + shstrtab + (b"\x00" * pad) + shdrs


def _tool_payload(res: Any) -> dict[str, Any]:
    if getattr(res, "structured_content", None) is not None:
        return dict(res.structured_content)
    if getattr(res, "data", None) is not None:
        return dict(res.data)
    return json.loads(res.content[0].text)


def _read_all_evidence_json(
    ctrl: HarnessController,
    *,
    principal: PrincipalContext,
    run_id: str,
    evidence_id: str,
    max_chars: int = 200,
) -> dict[str, Any]:
    chunks: list[str] = []
    cursor: str | None = None
    while True:
        page = ctrl.read_evidence(
            principal=principal,
            run_id=run_id,
            evidence_id=evidence_id,
            cursor=cursor,
            max_chars=max_chars,
        )
        chunks.append(page.content)
        if page.next_cursor is None:
            break
        cursor = page.next_cursor
    return json.loads("".join(chunks))


def _sync_rev(ctrl: HarnessController, run_id: str) -> int:
    return ctrl.runs.get_run_snapshot(run_id).revision


# ---------------------------------------------------------------------------
# 1. DeterministicTransformAdapter (`helper.transform`) E2E + bounds + bomb guard
# ---------------------------------------------------------------------------


def test_helper_transform_all_operations_paging_bounds_and_telemetry(
    tmp_path: Path,
) -> None:
    clock = _MutableClock()
    ctrl = create_default_controller(
        storage=Storage(tmp_path / "state" / "harness.db"),
        vault_root=tmp_path / "vault",
        export_root=tmp_path / "exports",
        cursor_hmac_key=b"p4-transform-fixed-hmac-32bytes!",
        allow_dynamic=False,
        include_transform_helper=True,
        clock=clock,
    )
    alice = _principal("alice")
    manifest = ctrl.create_run(
        principal=alice,
        task_id="task-p4-transform",
        mode=RunMode.OFFLINE_CTF,
        scope=_scope(
            task_id="task-p4-transform",
            caps=("analysis.query", "helper.transform"),
            clock=clock,
        ),
        budget=_budget(max_output_chars_per_page=180, max_tool_calls=60),
    )

    ws = tmp_path / "workspace"
    ws.mkdir()
    sample_payload = b"AlphaBetaGamma:0123456789!"
    (ws / "blob.bin").write_bytes(b"\x00\x01\x02\x03" + sample_payload + b"\xff\xfe")
    ing = ctrl.ingest_artifact(
        principal=alice,
        run_id=manifest.run_id,
        source_root=ws,
        rel_path="blob.bin",
        media_type="application/octet-stream",
    )

    server = create_mcp_server(ctrl, default_stdio_principal=alice, active_run_id=manifest.run_id)

    async def _run() -> None:
        async with Client(server.mcp) as client:
            listed = {t.name for t in await client.list_tools()}
            assert "helper.transform" in listed
            assert "session.control" not in listed
            assert "net.probe" not in listed

            # Run all 8 deterministic operations via MCP helper.transform
            zlib_compressed = zlib.compress(b"decompressed-stream-payload-12345")
            gzip_comp = zlib.compressobj(wbits=31)
            gzip_compressed = gzip_comp.compress(b"gzip-stream-hello") + gzip_comp.flush()

            cases: list[tuple[str, dict[str, Any], dict[str, Any]]] = [
                ("base64_encode", {"data_text": "hello-p4"}, {"output_utf8": "aGVsbG8tcDQ="}),
                ("base64_decode", {"data_text": "aGVsbG8tcDQ="}, {"output_utf8": "hello-p4"}),
                (
                    "base64_decode",
                    {"data_text": base64.urlsafe_b64encode(b"\xfb\xff~p4").decode("ascii"), "urlsafe": True},
                    {"output_hex": "fbff7e7034"},
                ),
                ("hex_encode", {"data_text": "AB"}, {"output_utf8": "4142"}),
                ("hex_decode", {"data_text": "41 42 43"}, {"output_utf8": "ABC"}),
                ("xor_bytes", {"data_text": "ABCD", "key_byte": 0x20}, {"output_utf8": "abcd"}),
                (
                    "xor_bytes",
                    {"data_hex": "00010203", "key_hex": "ff00"},
                    {"output_hex": "ff01fd03"},
                ),
                ("rot_caesar", {"data_text": "Uryyb, Jbeyq!", "shift": 13}, {"output_utf8": "Hello, World!"}),
                (
                    "url_decode",
                    {"data_text": "a+b%2F%3D%31%32%33", "plus_as_space": True},
                    {"output_utf8": "a b/=123"},
                ),
                (
                    "zlib_decompress",
                    {"data_base64": base64.b64encode(zlib_compressed).decode("ascii")},
                    {"output_utf8": "decompressed-stream-payload-12345"},
                ),
                (
                    "zlib_decompress",
                    {"data_base64": base64.b64encode(gzip_compressed).decode("ascii"), "wbits": 31},
                    {"output_utf8": "gzip-stream-hello"},
                ),
                (
                    "hex_encode",
                    {
                        "artifact_id": ing.artifact_id,
                        "offset": 4,
                        "length": len(sample_payload),
                    },
                    {"output_utf8": sample_payload.hex()},
                ),
            ]

            for idx, (op, args, expected_subset) in enumerate(cases):
                rev = _sync_rev(ctrl, manifest.run_id)
                res = await client.call_tool(
                    "helper.transform",
                    {
                        "run_id": manifest.run_id,
                        "request_id": f"req-tx-{idx}",
                        "expected_revision": rev,
                        "operation": op,
                        "arguments": args,
                    },
                )
                env = _tool_payload(res)
                assert env["status"] == "ok", f"{op} failed: {env}"
                assert env["usage"]["wall_ms"] >= 0
                assert env["usage"]["output_bytes"] > 0
                assert env["usage"]["peak_rss_bytes"] is not None
                assert env["usage"]["peak_rss_bytes"] > 0
                assert env["usage"]["cpu_ms"] is not None
                assert env["usage"]["cpu_ms"] >= 0
                ev_id = env["evidence"][0]["id"]
                parsed = _read_all_evidence_json(
                    ctrl, principal=alice, run_id=manifest.run_id, evidence_id=ev_id, max_chars=250
                )
                for key, val in expected_subset.items():
                    assert parsed[key] == val

            # Multi-page output paging verification via MCP evidence.read
            long_plain = ("P4TransformChunk_" * 60).encode("ascii")
            rev = _sync_rev(ctrl, manifest.run_id)
            long_res = await client.call_tool(
                "helper.transform",
                {
                    "run_id": manifest.run_id,
                    "request_id": "req-tx-long-page",
                    "expected_revision": rev,
                    "operation": "base64_decode",
                    "arguments": {"data_text": base64.b64encode(long_plain).decode("ascii")},
                },
            )
            long_env = _tool_payload(long_res)
            assert long_env["status"] == "ok"
            long_ev_id = long_env["evidence"][0]["id"]

            page_parts: list[str] = []
            cursor: str | None = None
            pages_fetched = 0
            while True:
                p_res = await client.call_tool(
                    "evidence.read",
                    {
                        "run_id": manifest.run_id,
                        "evidence_id": long_ev_id,
                        "cursor": cursor,
                        "max_chars": 160,
                    },
                )
                p_data = _tool_payload(p_res)
                assert len(p_data["content"]) <= 160
                page_parts.append(p_data["content"])
                pages_fetched += 1
                cursor = p_data["next_cursor"]
                if cursor is None:
                    break
            assert pages_fetched >= 4
            reassembled = json.loads("".join(page_parts))
            assert reassembled["output_utf8"] == long_plain.decode("ascii")

            # Zlib bomb protection (256 KiB compressed into small stream -> rejected by worker)
            bomb_compressed = zlib.compress(b"A" * (256 * 1024), level=9)
            assert len(bomb_compressed) < 4096
            rev = _sync_rev(ctrl, manifest.run_id)
            bomb_res = await client.call_tool(
                "helper.transform",
                {
                    "run_id": manifest.run_id,
                    "request_id": "req-tx-bomb",
                    "expected_revision": rev,
                    "operation": "zlib_decompress",
                    "arguments": {"data_base64": base64.b64encode(bomb_compressed).decode("ascii")},
                },
            )
            bomb_env = _tool_payload(bomb_res)
            assert bomb_env["status"] == "tool_error"

            # Input > 64 KiB raw decoded bytes rejected cleanly
            oversized_b64 = base64.b64encode(b"B" * (65 * 1024)).decode("ascii")
            rev = _sync_rev(ctrl, manifest.run_id)
            big_res = await client.call_tool(
                "helper.transform",
                {
                    "run_id": manifest.run_id,
                    "request_id": "req-tx-oversized",
                    "expected_revision": rev,
                    "operation": "base64_decode",
                    "arguments": {"data_text": oversized_b64},
                },
            )
            big_env = _tool_payload(big_res)
            assert big_env["status"] == "tool_error"

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 2. InteractiveDebugSessionAdapter (`session.control`) dynamic profile isolation
# ---------------------------------------------------------------------------


def test_session_control_profile_isolation_hidden_and_denied_by_default(
    tmp_path: Path,
) -> None:
    clock = _MutableClock()
    # Even if include_interactive_session=True in SCOPED_CTF, default allow_dynamic is False!
    ctrl = create_default_controller(
        storage=Storage(tmp_path / "state" / "harness.db"),
        vault_root=tmp_path / "vault",
        export_root=tmp_path / "exports",
        cursor_hmac_key=b"p4-dyn-iso-fixed-hmac-32bytes!!!",
        include_interactive_session=True,
        clock=clock,
    )
    alice = _principal("alice")
    manifest_off = ctrl.create_run(
        principal=alice,
        task_id="task-dyn-off",
        mode=RunMode.OFFLINE_CTF,
        scope=_scope(
            mode=RunMode.OFFLINE_CTF,
            task_id="task-dyn-off",
            caps=("analysis.query", "session.control"),
            exec_classes=(ExecutionClass.STATIC, ExecutionClass.DYNAMIC),
            clock=clock,
        ),
        budget=_budget(),
    )
    server = create_mcp_server(ctrl, default_stdio_principal=alice, active_run_id=manifest_off.run_id)

    async def _run() -> None:
        async with Client(server.mcp) as client:
            listed = {t.name for t in await client.list_tools()}
            assert "session.control" not in listed

            denied = await client.call_tool("session.control", {}, raise_on_error=False)
            assert denied.is_error is True
            dpayload = _tool_payload(denied)
            assert dpayload["status"] == "denied"
            assert dpayload["error"]["code"] == "tool_denied"

    asyncio.run(_run())

    # Direct controller invocation also denies DYNAMIC under allow_dynamic=False
    direct_env = ctrl.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id=manifest_off.run_id,
            request_id="req-direct-dyn-denied",
            expected_revision=_sync_rev(ctrl, manifest_off.run_id),
            capability_name="session.control",
            operation="open",
            arguments={},
        ),
    )
    assert direct_env.status == EnvelopeStatus.DENIED


# ---------------------------------------------------------------------------
# 3. `session.control` lifecycle, concurrency limit=1, 15m idle expiry, crash/restart `lost`,
#    and raw command/eval/exec rejection
# ---------------------------------------------------------------------------


def test_session_control_lifecycle_limit_expiry_restart_and_injection_rejection(
    tmp_path: Path,
) -> None:
    clock = _MutableClock()
    db_path = tmp_path / "state" / "harness.db"
    vault_root = tmp_path / "vault"
    export_root = tmp_path / "exports"

    ctrl = create_default_controller(
        storage=Storage(db_path),
        vault_root=vault_root,
        export_root=export_root,
        cursor_hmac_key=b"p4-sess-life-fixed-hmac-32bytes!",
        allow_dynamic=True,
        include_interactive_session=True,
        clock=clock,
    )
    alice = _principal("alice")
    manifest = ctrl.create_run(
        principal=alice,
        task_id="task-p4-sess",
        mode=RunMode.OFFLINE_CTF,
        scope=_scope(
            mode=RunMode.OFFLINE_CTF,
            task_id="task-p4-sess",
            caps=("analysis.query", "session.control"),
            exec_classes=(ExecutionClass.STATIC, ExecutionClass.DYNAMIC),
            expires_hours=4,
            clock=clock,
        ),
        budget=_budget(session_idle_seconds=900, interactive_session_limit=1),
    )

    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "prog.elf").write_bytes(_build_minimal_elf64())
    ing = ctrl.ingest_artifact(
        principal=alice,
        run_id=manifest.run_id,
        source_root=ws,
        rel_path="prog.elf",
        media_type="application/octet-stream",
    )

    server = create_mcp_server(ctrl, default_stdio_principal=alice, active_run_id=manifest.run_id)

    async def _run_lifecycle() -> str:
        async with Client(server.mcp) as client:
            listed = {t.name for t in await client.list_tools()}
            assert "session.control" in listed

            # 1) open -> active lease (active_sessions = 1)
            open_res = await client.call_tool(
                "session.control",
                {
                    "run_id": manifest.run_id,
                    "request_id": "req-sess-open-1",
                    "expected_revision": _sync_rev(ctrl, manifest.run_id),
                    "operation": "open",
                    "arguments": {"artifact_id": ing.artifact_id},
                },
            )
            open_env = _tool_payload(open_res)
            assert open_env["status"] == "ok"
            open_json = _read_all_evidence_json(
                ctrl,
                principal=alice,
                run_id=manifest.run_id,
                evidence_id=open_env["evidence"][0]["id"],
            )
            sid1 = open_json["session_id"]
            assert sid1.startswith("sess-")
            assert open_json["format"] == "ELF64"

            desc_active = _tool_payload(
                await client.call_tool("run.describe", {"run_id": manifest.run_id})
            )
            assert desc_active["budget"]["active_sessions"] == 1

            # 2) Second concurrent open -> denied due to interactive_session_limit=1
            dup_open = await client.call_tool(
                "session.control",
                {
                    "run_id": manifest.run_id,
                    "request_id": "req-sess-open-dup",
                    "expected_revision": _sync_rev(ctrl, manifest.run_id),
                    "operation": "open",
                    "arguments": {"artifact_id": ing.artifact_id},
                },
                raise_on_error=False,
            )
            assert dup_open.is_error is True
            dup_payload = _tool_payload(dup_open)
            assert dup_payload["status"] == "tool_error"
            assert dup_payload["error"]["code"] == "budget_exceeded"

            # 3) Typed inspect views + step
            reg_before = _tool_payload(
                await client.call_tool(
                    "session.control",
                    {
                        "run_id": manifest.run_id,
                        "request_id": "req-sess-insp-regs-1",
                        "expected_revision": _sync_rev(ctrl, manifest.run_id),
                        "operation": "inspect",
                        "arguments": {"session_id": sid1, "view": "registers"},
                    },
                )
            )
            assert reg_before["status"] == "ok"
            regs1 = _read_all_evidence_json(
                ctrl,
                principal=alice,
                run_id=manifest.run_id,
                evidence_id=reg_before["evidence"][0]["id"],
            )
            ip_before = int(regs1["registers"]["pc"], 16)

            mem_res = _tool_payload(
                await client.call_tool(
                    "session.control",
                    {
                        "run_id": manifest.run_id,
                        "request_id": "req-sess-insp-mem-1",
                        "expected_revision": _sync_rev(ctrl, manifest.run_id),
                        "operation": "inspect",
                        "arguments": {
                            "session_id": sid1,
                            "view": "memory",
                            "section_name": ".rodata",
                            "offset": 0,
                            "length": 24,
                        },
                    },
                )
            )
            mem_json = _read_all_evidence_json(
                ctrl,
                principal=alice,
                run_id=manifest.run_id,
                evidence_id=mem_res["evidence"][0]["id"],
            )
            assert b"CTF_ELF_BANNER_VALUE" in bytes.fromhex(mem_json["bytes_hex"])

            step_res = _tool_payload(
                await client.call_tool(
                    "session.control",
                    {
                        "run_id": manifest.run_id,
                        "request_id": "req-sess-step-1",
                        "expected_revision": _sync_rev(ctrl, manifest.run_id),
                        "operation": "step",
                        "arguments": {"session_id": sid1, "step_count": 4},
                    },
                )
            )
            assert step_res["status"] == "ok"
            step_json = _read_all_evidence_json(
                ctrl,
                principal=alice,
                run_id=manifest.run_id,
                evidence_id=step_res["evidence"][0]["id"],
            )
            assert step_json["step_index"] == 4
            assert len(step_json["steps"]) >= 4

            reg_after = _tool_payload(
                await client.call_tool(
                    "session.control",
                    {
                        "run_id": manifest.run_id,
                        "request_id": "req-sess-insp-regs-2",
                        "expected_revision": _sync_rev(ctrl, manifest.run_id),
                        "operation": "inspect",
                        "arguments": {"session_id": sid1, "view": "registers"},
                    },
                )
            )
            regs2 = _read_all_evidence_json(
                ctrl,
                principal=alice,
                run_id=manifest.run_id,
                evidence_id=reg_after["evidence"][0]["id"],
            )
            assert int(regs2["registers"]["pc"], 16) > ip_before

            # 4) Reject raw commands, python eval/exec, shell flags, and invalid ops
            for bad_idx, (bad_op, bad_args, ctrl_exc) in enumerate(
                [
                    ("inspect", {"session_id": sid1, "command": "id"}, ContractViolationError),
                    (
                        "inspect",
                        {"session_id": sid1, "eval": "__import__('os').system('id')"},
                        ContractViolationError,
                    ),
                    ("step", {"session_id": sid1, "exec": "print(1)"}, ContractViolationError),
                    ("open", {"artifact_id": "../../etc/passwd"}, ContractViolationError),
                ]
            ):
                bad_mcp = await client.call_tool(
                    "session.control",
                    {
                        "run_id": manifest.run_id,
                        "request_id": f"req-sess-bad-mcp-{bad_idx}",
                        "expected_revision": _sync_rev(ctrl, manifest.run_id),
                        "operation": bad_op,
                        "arguments": bad_args,
                    },
                    raise_on_error=False,
                )
                assert bad_mcp.is_error is True
                with pytest.raises(ctrl_exc):
                    ctrl.execute_action(
                        principal=alice,
                        request=ActionRequest(
                            run_id=manifest.run_id,
                            request_id=f"req-sess-bad-{bad_idx}",
                            expected_revision=_sync_rev(ctrl, manifest.run_id),
                            capability_name="session.control",
                            operation=bad_op,
                            arguments=bad_args,
                        ),
                    )

            bad_op_mcp = _tool_payload(
                await client.call_tool(
                    "session.control",
                    {
                        "run_id": manifest.run_id,
                        "request_id": "req-sess-bad-op-mcp",
                        "expected_revision": _sync_rev(ctrl, manifest.run_id),
                        "operation": "exec_shell",
                        "arguments": {"cmd": "whoami"},
                    },
                )
            )
            assert bad_op_mcp["status"] == "denied"
            assert bad_op_mcp["error"]["code"] == "scope_denied"

            # 5) Explicit close -> slot released + checkpoint file cleaned up
            close_res = _tool_payload(
                await client.call_tool(
                    "session.control",
                    {
                        "run_id": manifest.run_id,
                        "request_id": "req-sess-close-1",
                        "expected_revision": _sync_rev(ctrl, manifest.run_id),
                        "operation": "close",
                        "arguments": {"session_id": sid1},
                    },
                )
            )
            assert close_res["status"] == "ok"
            assert not (vault_root / "_sessions" / manifest.run_id / f"{sid1}.json").exists()
            desc_closed = _tool_payload(
                await client.call_tool("run.describe", {"run_id": manifest.run_id})
            )
            assert desc_closed["budget"]["active_sessions"] == 0

            # Using closed session denied
            use_closed = _tool_payload(
                await client.call_tool(
                    "session.control",
                    {
                        "run_id": manifest.run_id,
                        "request_id": "req-sess-after-close",
                        "expected_revision": _sync_rev(ctrl, manifest.run_id),
                        "operation": "inspect",
                        "arguments": {"session_id": sid1, "view": "summary"},
                    },
                )
            )
            assert use_closed["status"] == "denied"
            assert use_closed["error"]["code"] == "session_closed"

            # 6) Open 2nd session, advance clock past 900s idle limit -> auto-expired
            open2 = _tool_payload(
                await client.call_tool(
                    "session.control",
                    {
                        "run_id": manifest.run_id,
                        "request_id": "req-sess-open-2",
                        "expected_revision": _sync_rev(ctrl, manifest.run_id),
                        "operation": "open",
                        "arguments": {"artifact_id": ing.artifact_id},
                    },
                )
            )
            sid2 = _read_all_evidence_json(
                ctrl,
                principal=alice,
                run_id=manifest.run_id,
                evidence_id=open2["evidence"][0]["id"],
            )["session_id"]
            assert (vault_root / "_sessions" / manifest.run_id / f"{sid2}.json").exists()

            clock.advance(901)
            after_idle = _tool_payload(
                await client.call_tool(
                    "session.control",
                    {
                        "run_id": manifest.run_id,
                        "request_id": "req-sess-after-idle",
                        "expected_revision": _sync_rev(ctrl, manifest.run_id),
                        "operation": "inspect",
                        "arguments": {"session_id": sid2, "view": "summary"},
                    },
                )
            )
            assert after_idle["status"] == "denied"
            assert after_idle["error"]["code"] == "session_expired"
            assert not (vault_root / "_sessions" / manifest.run_id / f"{sid2}.json").exists()
            lease2 = ctrl.leases.get_lease(sid2, run_id=manifest.run_id)
            assert lease2.state == SessionLeaseState.EXPIRED

            # After expiry, opening a fresh 3rd session succeeds immediately!
            open3 = _tool_payload(
                await client.call_tool(
                    "session.control",
                    {
                        "run_id": manifest.run_id,
                        "request_id": "req-sess-open-3",
                        "expected_revision": _sync_rev(ctrl, manifest.run_id),
                        "operation": "open",
                        "arguments": {"artifact_id": ing.artifact_id},
                    },
                )
            )
            assert open3["status"] == "ok"
            sid3 = _read_all_evidence_json(
                ctrl,
                principal=alice,
                run_id=manifest.run_id,
                evidence_id=open3["evidence"][0]["id"],
            )["session_id"]
            return sid3

    sid3 = asyncio.run(_run_lifecycle())

    # 7) Supervisor restart marks active session `lost`, deletes checkpoint, blocks reuse
    clock.advance(10)
    ctrl_restarted = create_default_controller(
        storage=Storage(db_path),
        vault_root=vault_root,
        export_root=export_root,
        cursor_hmac_key=b"p4-sess-life-fixed-hmac-32bytes!",
        allow_dynamic=True,
        include_interactive_session=True,
        supervisor_instance_id="sup-restarted",
        clock=clock,
    )
    lease3 = ctrl_restarted.leases.get_lease(sid3, run_id=manifest.run_id)
    assert lease3.state == SessionLeaseState.LOST
    assert not (vault_root / "_sessions" / manifest.run_id / f"{sid3}.json").exists()

    snap_restarted = ctrl_restarted.describe_run(principal=alice, run_id=manifest.run_id)
    assert snap_restarted["budget"]["active_sessions"] == 0

    reuse_lost = ctrl_restarted.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id=manifest.run_id,
            request_id="req-sess-after-restart",
            expected_revision=_sync_rev(ctrl_restarted, manifest.run_id),
            capability_name="session.control",
            operation="inspect",
            arguments={"session_id": sid3, "view": "summary"},
        ),
    )
    assert reuse_lost.status == EnvelopeStatus.DENIED
    assert reuse_lost.error is not None and reuse_lost.error.code == "session_lost"


# ---------------------------------------------------------------------------
# 4. Timeout and cancel kill real OS worker + grandchild (`is_os_process_alive == False`)
# ---------------------------------------------------------------------------


def test_session_control_timeout_and_cancel_kill_os_process_tree(tmp_path: Path) -> None:
    clock = _MutableClock()
    marker_file = tmp_path / "hanging_pids.json"
    slow_worker = tmp_path / "slow_session_worker.py"
    slow_worker.write_text(
        "\n".join(
            [
                "import argparse, json, os, subprocess, sys, time",
                f"sys.path.insert(0, {str(SRC_ROOT)!r})",
                "from ctf_mcp.adapters.runner import get_os_process_start_id",
                "parser = argparse.ArgumentParser()",
                "parser.add_argument('--request-file', required=True)",
                "args = parser.parse_args()",
                "_ = open(args.request_file, 'rb').read()",
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])",
                "payload = {",
                "    'parent_pid': os.getpid(),",
                "    'parent_start_id': get_os_process_start_id(os.getpid()),",
                "    'grandchild_pid': child.pid,",
                "    'grandchild_start_id': get_os_process_start_id(child.pid),",
                "}",
                f"with open({str(marker_file)!r}, 'w', encoding='utf-8') as f:",
                "    json.dump(payload, f)",
                "    f.flush()",
                "while True:",
                "    time.sleep(0.2)",
            ]
        ),
        encoding="utf-8",
    )

    ctrl = HarnessController(
        storage=Storage(tmp_path / "state" / "harness.db"),
        vault_root=tmp_path / "vault",
        export_root=tmp_path / "exports",
        cursor_hmac_key=b"p4-timeout-fixed-hmac-32bytes!!!",
        allow_dynamic=True,
        clock=clock,
    )
    ctrl.initialize()
    register_default_adapters(ctrl)
    adapter = InteractiveDebugSessionAdapter(
        descriptor=create_interactive_session_descriptor(
            limits=CapabilityLimits(timeout_seconds=2, max_output_bytes=65_536, max_decode_bytes=16_384)
        ),
        runner=SubprocessRunner(default_timeout_seconds=1.5, default_max_output_bytes=65_536),
        evidence_vault=ctrl.evidence_vault,
        session_root=tmp_path / "vault" / "_sessions",
        worker_script=slow_worker,
    )
    ctrl.register_adapter(adapter, tool_group="session.control", is_interactive_session=True)

    alice = _principal("alice")
    manifest = ctrl.create_run(
        principal=alice,
        task_id="task-p4-kill",
        mode=RunMode.OFFLINE_CTF,
        scope=_scope(
            mode=RunMode.OFFLINE_CTF,
            task_id="task-p4-kill",
            caps=("analysis.query", "session.control"),
            exec_classes=(ExecutionClass.STATIC, ExecutionClass.DYNAMIC),
            clock=clock,
        ),
        budget=_budget(action_timeout_seconds=2, interactive_session_limit=1),
    )

    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "prog.elf").write_bytes(_build_minimal_elf64())
    ing = ctrl.ingest_artifact(
        principal=alice,
        run_id=manifest.run_id,
        source_root=ws,
        rel_path="prog.elf",
        media_type="application/octet-stream",
    )

    def _assert_marker_dead() -> None:
        assert marker_file.exists()
        info = json.loads(marker_file.read_text(encoding="utf-8"))
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if not is_os_process_alive(info["parent_start_id"]) and not is_os_process_alive(
                info["grandchild_start_id"]
            ):
                break
            time.sleep(0.05)
        assert not is_os_process_alive(info["parent_start_id"])
        assert not is_os_process_alive(info["grandchild_start_id"])

    # 1) Timeout kills worker + grandchild and releases session slot back to 0
    to_env = ctrl.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id=manifest.run_id,
            request_id="req-sess-timeout",
            expected_revision=_sync_rev(ctrl, manifest.run_id),
            capability_name="session.control",
            operation="open",
            arguments={"artifact_id": ing.artifact_id},
        ),
    )
    assert to_env.status == EnvelopeStatus.TIMEOUT
    _assert_marker_dead()
    assert ctrl.describe_run(principal=alice, run_id=manifest.run_id)["budget"]["active_sessions"] == 0

    # 2) Cancel kills worker + grandchild and releases session slot back to 0
    # Re-register adapter and use a run with generous timeout so cancel cleanly fires before timeout
    adapter_cancel = InteractiveDebugSessionAdapter(
        descriptor=create_interactive_session_descriptor(
            limits=CapabilityLimits(timeout_seconds=10, max_output_bytes=65_536, max_decode_bytes=16_384)
        ),
        runner=SubprocessRunner(default_timeout_seconds=10.0, default_max_output_bytes=65_536),
        evidence_vault=ctrl.evidence_vault,
        session_root=tmp_path / "vault" / "_sessions",
        worker_script=slow_worker,
    )
    ctrl.register_adapter(adapter_cancel, tool_group="session.control", is_interactive_session=True)

    manifest_cancel = ctrl.create_run(
        principal=alice,
        task_id="task-p4-kill-cancel",
        mode=RunMode.OFFLINE_CTF,
        scope=_scope(
            mode=RunMode.OFFLINE_CTF,
            task_id="task-p4-kill-cancel",
            caps=("analysis.query", "session.control"),
            exec_classes=(ExecutionClass.STATIC, ExecutionClass.DYNAMIC),
            clock=clock,
        ),
        budget=_budget(action_timeout_seconds=10, interactive_session_limit=1),
    )
    ing_cancel = ctrl.ingest_artifact(
        principal=alice,
        run_id=manifest_cancel.run_id,
        source_root=ws,
        rel_path="prog.elf",
        media_type="application/octet-stream",
    )

    marker_file.unlink()
    cancel_ev = threading.Event()

    def _wait_and_cancel() -> None:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if marker_file.exists():
                time.sleep(0.08)
                cancel_ev.set()
                return
            time.sleep(0.02)
        cancel_ev.set()

    canceller = threading.Thread(target=_wait_and_cancel, daemon=True)
    canceller.start()
    cancel_env = ctrl.execute_action(
        principal=alice,
        request=ActionRequest(
            run_id=manifest_cancel.run_id,
            request_id="req-sess-cancel",
            expected_revision=_sync_rev(ctrl, manifest_cancel.run_id),
            capability_name="session.control",
            operation="open",
            arguments={"artifact_id": ing_cancel.artifact_id},
        ),
        cancel_event=cancel_ev,
    )
    canceller.join(timeout=2.0)
    assert cancel_env.status == EnvelopeStatus.CANCELLED
    _assert_marker_dead()
    assert (
        ctrl.describe_run(principal=alice, run_id=manifest_cancel.run_id)["budget"]["active_sessions"]
        == 0
    )
