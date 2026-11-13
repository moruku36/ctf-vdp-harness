"""Integration tests for P6 config/CLI/env adapter autowiring and POSIX ELF inspection.

Verifies:
1. ``create_default_controller`` autowires ``helper.transform``, ``session.control``,
   and ``net.probe`` from ``HarnessConfig.execution.adapters_enabled`` while preserving
   default-disabled boundaries when ``config=None`` or adapters are omitted.
2. ``build_server_from_env`` and ``server_main`` support ``CTF_MCP_ALLOW_DYNAMIC=1|true``,
   ``--allow-dynamic``, ``--enable-transform-helper``, and ``--enable-interactive-session``
   strictly when configured or explicitly requested (fail-closed otherwise).
3. ``admin_main`` creates runs and scopes with ``helper.transform`` / ``session.control`` /
   ``net.probe`` under ``--config`` and ``--allowed-capabilities``.
4. ``interactive_session`` POSIX GDB/binutils metadata helper uses fixed read-only
   ``shell=False`` commands, rejects raw gdb commands, and preserves deterministic fallback
   when ``gdb`` is absent.
"""

from __future__ import annotations

import json
import secrets
import shutil
import struct
import subprocess
import sys
import threading
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import anyio
import pytest
from fastmcp import Client

from ctf_mcp.adapters import interactive_session as isess
from ctf_mcp.cli import admin_main, build_server_parser, server_main
from ctf_mcp.config import HarnessConfig, load_config_file
from ctf_mcp.contracts import (
    ActionRequest,
    BudgetExceededError,
    BudgetSpec,
    ConfigurationError,
    ContractViolationError,
    ExecutionClass,
    PrincipalContext,
    RunMode,
    ScopePolicy,
    canonical_digest,
)
from ctf_mcp.controller import create_default_controller
from ctf_mcp.server import build_server_from_env
from ctf_mcp.storage import Storage


def _write_harness_config(
    path: Path,
    *,
    profile: str = "offline_ctf",
    adapters_enabled: Sequence[str] = ("analysis.query",),
    network_enabled: bool = False,
    allowed_targets: Sequence[str] = (),
    external_submission: bool = False,
    dynamic_execution: bool = False,
    max_tool_calls: int = 40,
    expires_at: str | None = None,
    task_id: str = "task-p6-autowire",
) -> Path:
    cfg = {
        "schema_version": "1",
        "executable": True,
        "profile": profile,
        "description": "P6 config adapter autowire integration test.",
        "client": {
            "kind": "OPERATOR_SELECTED",
            "model_label": "codex-p6-test",
            "instruction_revision": "inst-p6-v1",
        },
        "scope": {
            "task_id": task_id,
            "revision": "scope-p6-1",
            "authorization_reference": "owned-p6-test-scope",
            "expires_at": expires_at,
        },
        "network": {
            "enabled": network_enabled,
            "allowed_targets": list(allowed_targets),
            "external_submission": external_submission,
        },
        "execution": {
            "adapters_enabled": list(adapters_enabled),
            "arbitrary_shell": False,
            "dynamic_execution": dynamic_execution,
            "heavy_job_concurrency": 1,
            "interactive_session_limit": 2,
            "action_timeout_seconds": 30,
            "session_idle_seconds": 900,
            "run_budget_seconds": 600,
            "max_tool_calls": max_tool_calls,
            "max_output_chars_per_page": 4000,
            "max_evidence_bytes_per_run": 10_485_760,
        },
        "evidence": {
            "storage": "private_vault",
            "cross_run_access": False,
            "automatic_git_export": False,
            "retention_policy_reference": "local-retention-p6-v1",
            "audit_raw_output": False,
        },
        "acceptance": {
            "require_pinned_revisions": True,
            "require_scope_validation": True,
            "require_registered_verifier": True,
        },
    }
    path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return path


def _build_minimal_elf64() -> bytes:
    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2  # ELF64
    ehdr[5] = 1  # little-endian
    ehdr[6] = 1  # version
    text_off = 64
    text_bytes = b"\xf3\x0f\x1e\xfa\x48\x31\xc0\xc3"
    shstrtab_off = text_off + len(text_bytes)
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    shoff = shstrtab_off + len(shstrtab)
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        ehdr,
        16,
        2,          # ET_EXEC
        0x3E,       # EM_X86_64
        1,
        0x401000,   # e_entry
        0,
        shoff,
        0,
        64,
        56,
        0,
        64,
        3,
        2,
    )

    def _shdr(name_off: int, sh_type: int, addr: int, offset: int, size: int) -> bytes:
        return struct.pack(
            "<IIQQQQIIQQ",
            name_off,
            sh_type,
            0,
            addr,
            offset,
            size,
            0,
            0,
            1,
            0,
        )

    sh_null = _shdr(0, 0, 0, 0, 0)
    sh_text = _shdr(1, 1, 0x401000, text_off, len(text_bytes))
    sh_shstr = _shdr(7, 3, 0, shstrtab_off, len(shstrtab))
    return bytes(ehdr) + text_bytes + shstrtab + sh_null + sh_text + sh_shstr


def _scope(
    *,
    mode: RunMode,
    task_id: str,
    caps: tuple[str, ...],
    exec_classes: tuple[ExecutionClass, ...],
    network_enabled: bool = False,
    allowed_targets: tuple[str, ...] = (),
) -> ScopePolicy:
    expires = datetime.now(UTC) + timedelta(hours=2)
    payload = {
        "mode": mode.value,
        "task_id": task_id,
        "scope_revision": "scope-p6-v1",
        "authorization_reference": "owned-p6-scope",
        "allowed_capabilities": list(caps),
        "allowed_execution_classes": [c.value for c in exec_classes],
        "expires_at": expires.isoformat(),
        "network_enabled": network_enabled,
        "allowed_targets": list(allowed_targets),
        "external_submission": False,
    }
    return ScopePolicy(
        scope_revision="scope-p6-v1",
        scope_sha256=canonical_digest(payload),
        mode=mode,
        task_id=task_id,
        authorization_reference="owned-p6-scope",
        allowed_execution_classes=exec_classes,
        allowed_capabilities=caps,
        expires_at=expires,
        network_enabled=network_enabled,
        allowed_targets=allowed_targets,
        external_submission=False,
    )


def _registered_tools(controller: Any) -> set[str]:
    return {desc.name for desc in controller.catalog.verify_all_descriptors()}


def test_create_default_controller_autowire_and_default_disabled_boundaries(
    tmp_path: Path,
) -> None:
    hmac_bytes = secrets.token_bytes(32)

    # 1) config=None preserves legacy default-disabled behavior
    ctrl_none = create_default_controller(
        storage=Storage(tmp_path / "none.db"),
        vault_root=tmp_path / "vault-none",
        cursor_hmac_key=hmac_bytes,
    )
    assert ctrl_none.allow_dynamic is False
    assert _registered_tools(ctrl_none) == {"analysis.query"}

    # 2) helper.transform by capability name or adapter id enables ONLY transform helper
    cfg_tf_path = _write_harness_config(
        tmp_path / "cfg-tf.json",
        adapters_enabled=("ctf-static-inspector", "helper.transform"),
    )
    cfg_tf = load_config_file(cfg_tf_path)
    ctrl_tf = create_default_controller(
        storage=Storage(tmp_path / "tf.db"),
        vault_root=tmp_path / "vault-tf",
        cursor_hmac_key=hmac_bytes,
        config=cfg_tf,
    )
    assert ctrl_tf.allow_dynamic is False
    assert _registered_tools(ctrl_tf) == {"analysis.query", "helper.transform"}

    cfg_tf_id = load_config_file(
        _write_harness_config(
            tmp_path / "cfg-tf-id.json",
            adapters_enabled=("ctf-helper-transform",),
        )
    )
    ctrl_tf_id = create_default_controller(
        storage=Storage(tmp_path / "tf-id.db"),
        vault_root=tmp_path / "vault-tf-id",
        cursor_hmac_key=hmac_bytes,
        config=cfg_tf_id,
    )
    assert ctrl_tf_id.allow_dynamic is False
    assert _registered_tools(ctrl_tf_id) == {"helper.transform"}

    # 3) session.control / ctf-interactive-session autowires adapter + allow_dynamic when None
    cfg_sess = load_config_file(
        _write_harness_config(
            tmp_path / "cfg-sess.json",
            adapters_enabled=(
                "ctf-static-inspector",
                "ctf-helper-transform",
                "ctf-interactive-session",
            ),
        )
    )
    ctrl_sess = create_default_controller(
        storage=Storage(tmp_path / "sess.db"),
        vault_root=tmp_path / "vault-sess",
        cursor_hmac_key=hmac_bytes,
        config=cfg_sess,
    )
    assert ctrl_sess.allow_dynamic is True
    assert _registered_tools(ctrl_sess) == {
        "analysis.query",
        "helper.transform",
        "session.control",
    }

    # Explicit allow_dynamic=False still overrides config fail-closed
    ctrl_sess_denied = create_default_controller(
        storage=Storage(tmp_path / "sess-denied.db"),
        vault_root=tmp_path / "vault-sess-denied",
        cursor_hmac_key=hmac_bytes,
        config=cfg_sess,
        allow_dynamic=False,
    )
    assert ctrl_sess_denied.allow_dynamic is False
    assert "session.control" in _registered_tools(ctrl_sess_denied)
    # Catalog filters out DYNAMIC capabilities when allow_dynamic=False
    listed_caps = {
        c.name
        for c in ctrl_sess_denied.catalog.list_visible_tools(
            RunMode.OFFLINE_CTF,
            scope=_scope(
                mode=RunMode.OFFLINE_CTF,
                task_id="task-p6-autowire",
                caps=("analysis.query", "helper.transform", "session.control"),
                exec_classes=(ExecutionClass.STATIC, ExecutionClass.DYNAMIC),
            ),
        )
    }
    assert listed_caps == {"analysis.query", "helper.transform"}

    # 4) net.probe / ctf-scoped-http-probe autowires ScopedHttpProbeAdapter in scoped_ctf
    cfg_net = load_config_file(
        _write_harness_config(
            tmp_path / "cfg-net.json",
            profile="scoped_ctf",
            adapters_enabled=("ctf-static-inspector", "ctf-scoped-http-probe"),
            network_enabled=True,
            allowed_targets=("http://127.0.0.1:8080/",),
        )
    )
    ctrl_net = create_default_controller(
        storage=Storage(tmp_path / "net.db"),
        vault_root=tmp_path / "vault-net",
        cursor_hmac_key=hmac_bytes,
        config=cfg_net,
    )
    assert ctrl_net.allow_dynamic is False
    assert _registered_tools(ctrl_net) == {"analysis.query", "net.probe"}


def test_server_env_and_cli_autowire_and_fastmcp_tools_list(tmp_path: Path) -> None:
    hmac_hex = secrets.token_hex(32)
    base_env = {
        "CTF_MCP_DB_PATH": str(tmp_path / "srv.db"),
        "CTF_MCP_VAULT_ROOT": str(tmp_path / "srv-vault"),
        "CTF_MCP_PROFILE": "offline_ctf",
        "CTF_MCP_TRANSPORT": "stdio",
        "CTF_MCP_CURSOR_HMAC_KEY": hmac_hex,
    }

    # 1) Default build_server_from_env keeps dynamic/transform disabled
    srv_default = build_server_from_env(base_env)
    assert srv_default.controller.allow_dynamic is False
    assert _registered_tools(srv_default.controller) == {"analysis.query"}

    # 2) CTF_MCP_ALLOW_DYNAMIC=1 and =true enable allow_dynamic without implicit adapter registration
    srv_dyn_1 = build_server_from_env({**base_env, "CTF_MCP_ALLOW_DYNAMIC": "1"})
    assert srv_dyn_1.controller.allow_dynamic is True
    assert _registered_tools(srv_dyn_1.controller) == {"analysis.query"}

    srv_dyn_true = build_server_from_env({**base_env, "CTF_MCP_ALLOW_DYNAMIC": "true"})
    assert srv_dyn_true.controller.allow_dynamic is True

    # Invalid CTF_MCP_ALLOW_DYNAMIC fails closed
    with pytest.raises(ConfigurationError):
        build_server_from_env({**base_env, "CTF_MCP_ALLOW_DYNAMIC": "invalid-bool"})

    # 3) Config with ctf-helper-transform + ctf-interactive-session autowires server + tools/list
    cfg_path = _write_harness_config(
        tmp_path / "wsl-debug-cfg.json",
        adapters_enabled=(
            "ctf-static-inspector",
            "ctf-helper-transform",
            "ctf-interactive-session",
        ),
    )
    srv_cfg = build_server_from_env(
        {
            "CTF_MCP_DB_PATH": str(tmp_path / "cfg-srv.db"),
            "CTF_MCP_VAULT_ROOT": str(tmp_path / "cfg-vault"),
            "CTF_MCP_TRANSPORT": "stdio",
            "CTF_MCP_CURSOR_HMAC_KEY": hmac_hex,
        },
        config_path=cfg_path,
    )
    assert srv_cfg.controller.allow_dynamic is True
    assert _registered_tools(srv_cfg.controller) == {
        "analysis.query",
        "helper.transform",
        "session.control",
    }

    # Explicit CTF_MCP_ALLOW_DYNAMIC=0 overrides config session dynamic permission
    srv_cfg_no_dyn = build_server_from_env(
        {
            "CTF_MCP_DB_PATH": str(tmp_path / "cfg-srv-nodyn.db"),
            "CTF_MCP_VAULT_ROOT": str(tmp_path / "cfg-vault-nodyn"),
            "CTF_MCP_TRANSPORT": "stdio",
            "CTF_MCP_CURSOR_HMAC_KEY": hmac_hex,
            "CTF_MCP_ALLOW_DYNAMIC": "0",
        },
        config_path=cfg_path,
    )
    assert srv_cfg_no_dyn.controller.allow_dynamic is False

    # Create a run authorized for analysis.query, helper.transform, session.control and verify MCP tools/list
    rc = admin_main(
        [
            "create-run",
            "--db-path",
            str(tmp_path / "cfg-srv.db"),
            "--vault-root",
            str(tmp_path / "cfg-vault"),
            "--config",
            str(cfg_path),
            "--run-id",
            "run-p6-autowire-01",
            "--allowed-capabilities",
            "analysis.query,helper.transform,session.control",
            "--allowed-execution-classes",
            "static,dynamic",
        ],
        env={"CTF_MCP_CURSOR_HMAC_KEY": hmac_hex},
    )
    assert rc == 0
    srv_cfg.set_active_run("run-p6-autowire-01")

    async def _list_tool_names() -> list[str]:
        async with Client(srv_cfg.mcp) as client:
            tools = await client.list_tools()
            return sorted(tool.name for tool in tools)

    names = anyio.run(_list_tool_names)
    assert names == [
        "analysis.query",
        "evidence.read",
        "helper.transform",
        "hypothesis.update",
        "run.close",
        "run.describe",
        "run.verify",
        "session.control",
    ]

    # 4) Verify server_main CLI parser & entrypoint flags
    parsed = build_server_parser().parse_args(
        ["--allow-dynamic", "--enable-transform-helper", "--enable-interactive-session"]
    )
    assert parsed.allow_dynamic is True
    assert parsed.enable_transform_helper is True
    assert parsed.enable_interactive_session is True

    rc_srv_flags = server_main(
        [
            "--db-path",
            str(tmp_path / "cli-srv.db"),
            "--vault-root",
            str(tmp_path / "cli-vault"),
            "--allow-dynamic",
            "--enable-transform-helper",
            "--enable-interactive-session",
        ],
        env={"CTF_MCP_CURSOR_HMAC_KEY": hmac_hex},
        start_server=False,
    )
    assert rc_srv_flags == 0


def test_admin_main_supports_config_and_net_probe_capabilities(tmp_path: Path) -> None:
    hmac_hex = secrets.token_hex(32)
    cfg_live = _write_harness_config(
        tmp_path / "cfg-live.json",
        profile="scoped_ctf",
        adapters_enabled=(
            "ctf-static-inspector",
            "ctf-helper-transform",
            "ctf-interactive-session",
            "ctf-scoped-http-probe",
        ),
        network_enabled=True,
        allowed_targets=("http://127.0.0.1:8080/",),
        task_id="task-p6-live",
    )
    rc = admin_main(
        [
            "create-run",
            "--db-path",
            str(tmp_path / "live.db"),
            "--vault-root",
            str(tmp_path / "live-vault"),
            "--config",
            str(cfg_live),
            "--run-id",
            "run-p6-live-01",
            "--allowed-capabilities",
            "analysis.query,helper.transform,session.control,net.probe",
            "--allowed-execution-classes",
            "static,dynamic,network",
        ],
        env={"CTF_MCP_CURSOR_HMAC_KEY": hmac_hex},
    )
    assert rc == 0

    ctrl = create_default_controller(
        storage=Storage(tmp_path / "live.db"),
        vault_root=tmp_path / "live-vault",
        cursor_hmac_key=bytes.fromhex(hmac_hex),
        config=load_config_file(cfg_live),
    )
    alice = PrincipalContext(
        principal_id="local-operator",
        auth_method="stdio_local",
        client_kind="OPERATOR_SELECTED",
        model_label="codex-p6-test",
    )
    desc = ctrl.describe_run(principal=alice, run_id="run-p6-live-01")
    assert set(desc["visible_capabilities"]) == {
        "helper.transform",
        "session.control",
        "net.probe",
    }
    assert set(desc["visible_mcp_tools"]) >= {
        "helper.transform",
        "session.control",
        "net.probe",
    }


def test_interactive_session_posix_gdb_helper_and_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    elf_path = tmp_path / "sample.elf"
    elf_path.write_bytes(_build_minimal_elf64())
    state_file = tmp_path / "sess.json"

    # 1) When gdb is absent (or mocked missing), _collect_native_elf_metadata returns None
    #    and _handle_open / _handle_inspect / _handle_step remain purely deterministic.
    monkeypatch.setattr(isess.shutil, "which", lambda _name: None)
    assert (
        isess._collect_native_elf_metadata(elf_path, elf_format="ELF64", pc=0x401000)
        is None
    )
    open_out = isess._handle_open(
        {
            "run_id": "run-fb-1",
            "session_id": "sess-fb-1",
            "artifact_id": "art-fb-1",
            "artifact_path": str(elf_path),
        },
        state_file,
    )
    assert open_out["ok"] is True
    assert "native_inspection" not in open_out

    # 2) Simulated POSIX environment with fixed read-only gdb/readelf/objdump commands
    observed_argvs: list[list[str]] = []
    observed_shell_flags: list[bool] = []

    def _fake_which(tool: str) -> str | None:
        return f"/usr/bin/{tool}" if tool in {"gdb", "readelf", "objdump"} else None

    def _fake_run(argv: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed_argvs.append(list(argv))
        observed_shell_flags.append(bool(kwargs.get("shell", False)))
        tool = Path(argv[0]).name
        if tool == "gdb":
            stdout = (
                f'Symbols from "{elf_path}".\n'
                f"Local exec file:\n"
                f"\t`{elf_path}', file type elf64-x86-64.\n"
                f"\tEntry point: 0x1040\n"
                f"All defined functions:\n"
                f"int main(void);\n"
                f"   0x0000000000001040 <_start>:\tendbr64\n"
            )
            return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")
        if tool == "readelf" and "-h" in argv:
            return subprocess.CompletedProcess(
                argv, 0, stdout="  Entry point address:               0x1040\n", stderr=""
            )
        if tool == "readelf" and "--syms" in argv:
            return subprocess.CompletedProcess(
                argv,
                0,
                stdout=(
                    "Symbol table '.symtab' contains 2 entries:\n"
                    "   Num:    Value          Size Type    Bind   Vis      Ndx Name\n"
                    "     1: 000000000000113c    32 FUNC    GLOBAL DEFAULT   12 main\n"
                ),
                stderr="",
            )
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout="0000000000001040 <_start>:\n    1040:\tf3 0f 1e fa          \tendbr64\n",
            stderr="",
        )

    monkeypatch.setattr(isess.sys, "platform", "linux")
    monkeypatch.setattr(isess.shutil, "which", _fake_which)
    monkeypatch.setattr(isess.subprocess, "run", _fake_run)

    state_posix = tmp_path / "sess_posix.json"
    open_posix = isess._handle_open(
        {
            "run_id": "run-posix-1",
            "session_id": "sess-posix-1",
            "artifact_id": "art-posix-1",
            "artifact_path": str(elf_path),
        },
        state_posix,
    )
    assert "native_inspection" in open_posix
    ni = open_posix["native_inspection"]
    assert ni["source"] == "posix_gdb_binutils_readonly"
    assert ni["entry_point_verified"] == "0x1040"
    assert any("main@" in s for s in ni["symbols"])
    assert any("endbr64" in line for line in ni["disassembly"])
    assert str(elf_path.parent) not in ni["gdb_summary"]
    assert all(flag is False for flag in observed_shell_flags)
    gdb_invocations = [a for a in observed_argvs if Path(a[0]).name == "gdb"]
    assert gdb_invocations
    assert ["--nx", "--nh", "--batch"] == gdb_invocations[0][1:4]

    inspect_summary = isess._handle_inspect(
        {
            "run_id": "run-posix-1",
            "session_id": "sess-posix-1",
            "view": "summary",
            "artifact_path": str(elf_path),
        },
        state_posix,
    )
    assert "native_inspection" in inspect_summary

    inspect_regs = isess._handle_inspect(
        {
            "run_id": "run-posix-1",
            "session_id": "sess-posix-1",
            "view": "registers",
            "artifact_path": str(elf_path),
        },
        state_posix,
    )
    assert "native_inspection" in inspect_regs

    step_out = isess._handle_step(
        {
            "run_id": "run-posix-1",
            "session_id": "sess-posix-1",
            "step_count": 1,
            "artifact_path": str(elf_path),
        },
        state_posix,
    )
    assert "native_inspection" in step_out

    # 3) On actual POSIX host with gdb present, verify real unmocked execution on minimal ELF never crashes
    monkeypatch.undo()
    if sys.platform != "win32" and shutil.which("gdb"):
        real_ni = isess._collect_native_elf_metadata(
            elf_path, elf_format="ELF64", pc=0x401000
        )
        assert real_ni is not None
        assert real_ni["tools"]["gdb"] is True

    # 4) Verify raw gdb command strings are never accepted by InteractiveDebugSessionAdapter schema
    ctrl_fb = create_default_controller(
        storage=Storage(tmp_path / "fb-cmd.db"),
        vault_root=tmp_path / "fb-cmd-vault",
        cursor_hmac_key=secrets.token_bytes(32),
        allow_dynamic=True,
        include_interactive_session=True,
    )
    alice = PrincipalContext(
        principal_id="alice",
        auth_method="stdio_local",
        client_kind="OPERATOR_SELECTED",
        model_label="codex-p6-test",
    )
    manifest = ctrl_fb.create_run(
        principal=alice,
        task_id="task-fb-cmd",
        mode=RunMode.OFFLINE_CTF,
        scope=_scope(
            mode=RunMode.OFFLINE_CTF,
            task_id="task-fb-cmd",
            caps=("analysis.query", "session.control"),
            exec_classes=(ExecutionClass.STATIC, ExecutionClass.DYNAMIC),
        ),
        budget=BudgetSpec(),
    )
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "sample.elf").write_bytes(_build_minimal_elf64())
    ing = ctrl_fb.ingest_artifact(
        principal=alice,
        run_id=manifest.run_id,
        source_root=ws,
        rel_path="sample.elf",
        media_type="application/octet-stream",
    )
    with pytest.raises(ContractViolationError):
        ctrl_fb.execute_action(
            principal=alice,
            request=ActionRequest(
                run_id=manifest.run_id,
                request_id="req-bad-gdb-cmd",
                expected_revision=ctrl_fb.runs.get_run_snapshot(manifest.run_id).revision,
                capability_name="session.control",
                operation="open",
                arguments={"artifact_id": ing.artifact_id, "gdb_cmd": "!id"},
            ),
        )


def test_update_budget_cli_and_controller_preserves_revision_and_restores_calls(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    hmac_hex = secrets.token_hex(32)
    db_path = tmp_path / "budget.db"
    vault_root = tmp_path / "budget-vault"
    cfg_path = _write_harness_config(
        tmp_path / "budget-cfg.json",
        profile="offline_ctf",
        adapters_enabled=("ctf-static-inspector", "ctf-helper-transform"),
        max_tool_calls=2,
        task_id="task-budget-update",
    )

    rc = admin_main(
        [
            "create-run",
            "--db-path",
            str(db_path),
            "--vault-root",
            str(vault_root),
            "--config",
            str(cfg_path),
            "--run-id",
            "run-budget-01",
            "--allowed-capabilities",
            "analysis.query,helper.transform",
            "--allowed-execution-classes",
            "static",
        ],
        env={"CTF_MCP_CURSOR_HMAC_KEY": hmac_hex},
    )
    assert rc == 0
    capsys.readouterr()

    ws = tmp_path / "ws-budget"
    ws.mkdir()
    (ws / "sample.elf").write_bytes(_build_minimal_elf64())
    rc_ing = admin_main(
        [
            "ingest-artifact",
            "--db-path",
            str(db_path),
            "--vault-root",
            str(vault_root),
            "--run-id",
            "run-budget-01",
            "--source-root",
            str(ws),
            "--rel-path",
            "sample.elf",
        ],
        env={"CTF_MCP_CURSOR_HMAC_KEY": hmac_hex},
    )
    assert rc_ing == 0
    ing_out = json.loads(capsys.readouterr().out)
    artifact_id = ing_out["artifact_id"]

    srv = build_server_from_env(
        {
            "CTF_MCP_DB_PATH": str(db_path),
            "CTF_MCP_VAULT_ROOT": str(vault_root),
            "CTF_MCP_TRANSPORT": "stdio",
            "CTF_MCP_CURSOR_HMAC_KEY": hmac_hex,
            "CTF_MCP_CONFIG": str(cfg_path),
        }
    )
    srv.set_active_run("run-budget-01")
    ctrl = srv.controller
    operator = PrincipalContext(
        principal_id="local-operator",
        auth_method="stdio_local",
        client_kind="OPERATOR_SELECTED",
        model_label="codex-p6-test",
    )

    # Consume both of the initial 2 tool calls.
    for idx in (1, 2):
        rev = ctrl.runs.get_run_snapshot("run-budget-01").revision
        env = ctrl.execute_action(
            principal=operator,
            request=ActionRequest(
                run_id="run-budget-01",
                request_id=f"req-consume-{idx}",
                expected_revision=rev,
                capability_name="analysis.query",
                operation="inspect_header",
                arguments={"artifact_id": artifact_id},
            ),
        )
        assert env.status.value == "ok"

    rev_before = ctrl.runs.get_run_snapshot("run-budget-01").revision
    assert ctrl.runs.get_run_snapshot("run-budget-01").remaining_calls == 0
    with pytest.raises(BudgetExceededError):
        ctrl.execute_action(
            principal=operator,
            request=ActionRequest(
                run_id="run-budget-01",
                request_id="req-exhausted-3",
                expected_revision=rev_before,
                capability_name="analysis.query",
                operation="inspect_header",
                arguments={"artifact_id": artifact_id},
            ),
        )

    # Raise max_tool_calls and remaining_calls from 2 -> 500 via admin_main while preserving revision.
    rc_upd = admin_main(
        [
            "update-budget",
            "--db-path",
            str(db_path),
            "--vault-root",
            str(vault_root),
            "--run-id",
            "run-budget-01",
            "--max-tool-calls",
            "500",
            "--remaining-calls",
            "500",
        ],
        env={"CTF_MCP_CURSOR_HMAC_KEY": hmac_hex},
    )
    assert rc_upd == 0
    upd_json = json.loads(capsys.readouterr().out)
    assert upd_json["run_id"] == "run-budget-01"
    assert upd_json["revision"] == rev_before
    assert upd_json["max_tool_calls"] == 500
    assert upd_json["remaining_calls"] == 500
    assert ctrl.runs.get_run_snapshot("run-budget-01").revision == rev_before

    # Caller holding rev_before can immediately execute actions both directly and via FastMCP.
    direct_after = ctrl.execute_action(
        principal=operator,
        request=ActionRequest(
            run_id="run-budget-01",
            request_id="req-after-budget-direct",
            expected_revision=rev_before,
            capability_name="analysis.query",
            operation="inspect_header",
            arguments={"artifact_id": artifact_id},
        ),
    )
    assert direct_after.status.value == "ok"

    rev_after_direct = ctrl.runs.get_run_snapshot("run-budget-01").revision

    async def _call_after_budget() -> dict[str, Any]:
        async with Client(srv.mcp) as client:
            res = await client.call_tool(
                "helper.transform",
                {
                    "run_id": "run-budget-01",
                    "request_id": "req-after-budget-mcp",
                    "expected_revision": rev_after_direct,
                    "operation": "xor_bytes",
                    "arguments": {"data_hex": "666c", "key_hex": "00"},
                },
            )
            return dict(res.structured_content)

    mcp_res = anyio.run(_call_after_budget)
    assert mcp_res["status"] == "ok"

    # Also verify add_calls, positive delta auto-addition, invalid bounds/conflicts, and audit event.
    snap_mid = ctrl.runs.get_run_snapshot("run-budget-01")
    added = ctrl.update_run_budget(
        run_id="run-budget-01",
        principal=operator,
        add_calls=10,
        run_budget_seconds=1200,
        max_evidence_bytes_per_run=20_971_520,
        interactive_session_limit=4,
        heavy_job_concurrency=2,
    )
    assert added["remaining_calls"] == snap_mid.remaining_calls + 10
    assert added["max_tool_calls"] >= snap_mid.usage.tool_calls_used + added["remaining_calls"]
    assert added["remaining_ms"] == snap_mid.remaining_ms + 600_000
    assert added["remaining_bytes"] == snap_mid.remaining_bytes + 10_485_760
    assert added["interactive_session_limit"] == 4
    assert added["heavy_job_concurrency"] == 2
    assert added["revision"] == snap_mid.revision

    with pytest.raises(ContractViolationError):
        ctrl.update_run_budget(
            run_id="run-budget-01",
            remaining_calls=10,
            add_calls=5,
        )
    with pytest.raises(ContractViolationError):
        ctrl.update_run_budget(run_id="run-budget-01", max_tool_calls=0)
    with pytest.raises(ContractViolationError):
        ctrl.update_run_budget(run_id="run-budget-01", remaining_calls=-1)
    with pytest.raises(ContractViolationError):
        ctrl.update_run_budget(
            run_id="run-budget-01",
            max_tool_calls=100,
            remaining_calls=101,
        )
    with pytest.raises(ContractViolationError):
        ctrl.update_run_budget(
            run_id="run-budget-01",
            run_budget_seconds=60,
            remaining_ms=60_001,
        )
    with pytest.raises(ContractViolationError):
        ctrl.update_run_budget(
            run_id="run-budget-01",
            max_evidence_bytes_per_run=1024,
            remaining_bytes=1025,
        )

    with ctrl.storage.read_connection() as conn:
        audit_row = conn.execute(
            "SELECT capability, operation, outcome FROM audit_events "
            "WHERE run_id = ? AND capability = 'budget.control' ORDER BY timestamp DESC LIMIT 1",
            ("run-budget-01",),
        ).fetchone()
    assert audit_row is not None
    assert audit_row["operation"] == "update_budget"
    assert audit_row["outcome"] == "ok"

    ctrl.close_run(principal=operator, run_id="run-budget-01")
    with pytest.raises(BudgetExceededError):
        ctrl.update_run_budget(run_id="run-budget-01", add_calls=5)


def test_vdp_mode_enables_all_four_tools_while_offline_ctf_denies_net_probe(
    tmp_path: Path,
) -> None:
    class _VdpLocalHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            body = b"vdp-local-health-ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            _ = (format, args)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _VdpLocalHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        port = httpd.server_address[1]
        hmac_hex = secrets.token_hex(32)
        db_path = tmp_path / "vdp.db"
        vault_root = tmp_path / "vdp-vault"
        cfg_vdp_path = _write_harness_config(
            tmp_path / "vdp-cfg.json",
            profile="vdp",
            adapters_enabled=(
                "ctf-static-inspector",
                "ctf-helper-transform",
                "ctf-interactive-session",
                "ctf-scoped-http-probe",
            ),
            network_enabled=True,
            allowed_targets=(f"http://127.0.0.1:{port}/",),
            dynamic_execution=True,
            expires_at=(datetime.now(UTC) + timedelta(hours=2)).isoformat(),
            task_id="task-vdp-all-tools",
        )

        # Build single server from env via CTF_MCP_CONFIG (no explicit config_path or allow_dynamic).
        srv = build_server_from_env(
            {
                "CTF_MCP_DB_PATH": str(db_path),
                "CTF_MCP_VAULT_ROOT": str(vault_root),
                "CTF_MCP_TRANSPORT": "stdio",
                "CTF_MCP_CURSOR_HMAC_KEY": hmac_hex,
                "CTF_MCP_CONFIG": str(cfg_vdp_path),
            }
        )
        assert srv.controller.allow_dynamic is True
        assert srv.controller.default_mode == RunMode.VDP

        rc_vdp = admin_main(
            [
                "create-run",
                "--db-path",
                str(db_path),
                "--vault-root",
                str(vault_root),
                "--run-id",
                "run-vdp-01",
                "--allowed-capabilities",
                "analysis.query,helper.transform,session.control,net.probe",
                "--allowed-execution-classes",
                "static,dynamic,network",
            ],
            env={
                "CTF_MCP_CURSOR_HMAC_KEY": hmac_hex,
                "CTF_MCP_CONFIG": str(cfg_vdp_path),
            },
        )
        assert rc_vdp == 0

        ws = tmp_path / "ws-vdp"
        ws.mkdir()
        (ws / "target.elf").write_bytes(_build_minimal_elf64())
        alice = PrincipalContext(
            principal_id="local-operator",
            auth_method="stdio_local",
            client_kind="OPERATOR_SELECTED",
            model_label="codex-p6-test",
        )
        art = srv.controller.ingest_artifact(
            principal=alice,
            run_id="run-vdp-01",
            source_root=ws,
            rel_path="target.elf",
            media_type="application/octet-stream",
        )

        # Create a separate offline_ctf run on the same DB/server without network privileges.
        rc_off = admin_main(
            [
                "create-run",
                "--db-path",
                str(db_path),
                "--vault-root",
                str(vault_root),
                "--run-id",
                "run-offline-01",
                "--task-id",
                "task-off-same-srv",
                "--mode",
                "offline_ctf",
                "--auth-ref",
                "owned-offline-ref",
                "--allowed-capabilities",
                "analysis.query,helper.transform,session.control",
                "--allowed-execution-classes",
                "static,dynamic",
            ],
            env={"CTF_MCP_CURSOR_HMAC_KEY": hmac_hex},
        )
        assert rc_off == 0

        async def _verify_both_runs() -> None:
            srv.set_active_run("run-vdp-01")
            async with Client(srv.mcp) as client:
                vdp_tools = {t.name for t in await client.list_tools()}
                assert {
                    "analysis.query",
                    "helper.transform",
                    "session.control",
                    "net.probe",
                }.issubset(vdp_tools)

                rev = srv.controller.runs.get_run_snapshot("run-vdp-01").revision
                res_analysis = await client.call_tool(
                    "analysis.query",
                    {
                        "run_id": "run-vdp-01",
                        "request_id": "req-vdp-analysis",
                        "expected_revision": rev,
                        "operation": "inspect_header",
                        "arguments": {"artifact_id": art.artifact_id},
                    },
                )
                assert res_analysis.structured_content["status"] == "ok"

                rev = srv.controller.runs.get_run_snapshot("run-vdp-01").revision
                res_tf = await client.call_tool(
                    "helper.transform",
                    {
                        "run_id": "run-vdp-01",
                        "request_id": "req-vdp-tf",
                        "expected_revision": rev,
                        "operation": "xor_bytes",
                        "arguments": {"data_hex": "7664", "key_hex": "00"},
                    },
                )
                assert res_tf.structured_content["status"] == "ok"

                rev = srv.controller.runs.get_run_snapshot("run-vdp-01").revision
                res_sess_open = await client.call_tool(
                    "session.control",
                    {
                        "run_id": "run-vdp-01",
                        "request_id": "req-vdp-sess-open",
                        "expected_revision": rev,
                        "operation": "open",
                        "arguments": {"artifact_id": art.artifact_id},
                    },
                )
                assert res_sess_open.structured_content["status"] == "ok"
                leases = srv.controller.leases.list_leases("run-vdp-01")
                session_id = leases[-1].session_id

                rev = srv.controller.runs.get_run_snapshot("run-vdp-01").revision
                res_sess_close = await client.call_tool(
                    "session.control",
                    {
                        "run_id": "run-vdp-01",
                        "request_id": "req-vdp-sess-close",
                        "expected_revision": rev,
                        "operation": "close",
                        "arguments": {"session_id": session_id},
                    },
                )
                assert res_sess_close.structured_content["status"] == "ok"

                rev = srv.controller.runs.get_run_snapshot("run-vdp-01").revision
                res_net = await client.call_tool(
                    "net.probe",
                    {
                        "run_id": "run-vdp-01",
                        "request_id": "req-vdp-net",
                        "expected_revision": rev,
                        "operation": "get",
                        "arguments": {"url": f"http://127.0.0.1:{port}/health"},
                    },
                )
                assert res_net.structured_content["status"] == "ok"

                # Switch active run to offline_ctf on the same server -> net.probe must be hidden & denied.
                srv.set_active_run("run-offline-01")
                off_tools = {t.name for t in await client.list_tools()}
                assert "net.probe" not in off_tools

                off_rev = srv.controller.runs.get_run_snapshot("run-offline-01").revision
                denied_net = await client.call_tool(
                    "net.probe",
                    {
                        "run_id": "run-offline-01",
                        "request_id": "req-off-net-denied",
                        "expected_revision": off_rev,
                        "operation": "get",
                        "arguments": {"url": f"http://127.0.0.1:{port}/health"},
                    },
                    raise_on_error=False,
                )
                assert denied_net.is_error is True
                assert denied_net.structured_content["status"] == "denied"

        anyio.run(_verify_both_runs)
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_ctf_mcp_config_env_fallback_and_cli_network_flags(tmp_path: Path) -> None:
    hmac_hex = secrets.token_hex(32)
    db_path = tmp_path / "envcfg.db"
    vault_root = tmp_path / "envcfg-vault"
    # Note: session.control is NOT in adapters_enabled; dynamic_execution=True alone enables allow_dynamic.
    cfg_path = _write_harness_config(
        tmp_path / "env-vdp.json",
        profile="vdp",
        adapters_enabled=("ctf-static-inspector", "ctf-helper-transform"),
        network_enabled=False,
        allowed_targets=(),
        dynamic_execution=True,
        task_id="task-env-fallback",
    )

    env_with_cfg = {
        "CTF_MCP_DB_PATH": str(db_path),
        "CTF_MCP_VAULT_ROOT": str(vault_root),
        "CTF_MCP_TRANSPORT": "stdio",
        "CTF_MCP_CURSOR_HMAC_KEY": hmac_hex,
        "CTF_MCP_CONFIG": str(cfg_path),
    }
    srv = build_server_from_env(env_with_cfg)
    assert srv.controller.allow_dynamic is True
    assert srv.controller.default_mode == RunMode.VDP
    assert srv.controller.config is not None
    assert srv.controller.config.scope.task_id == "task-env-fallback"

    # admin_main consumes CTF_MCP_CONFIG when --config is omitted, and CLI network flags override config.network.
    rc_create = admin_main(
        [
            "create-run",
            "--run-id",
            "run-env-cfg-01",
            "--allowed-capabilities",
            "analysis.query,helper.transform,net.probe",
            "--allowed-execution-classes",
            "static,dynamic,network",
            "--network-enabled",
            "--allowed-target",
            "http://127.0.0.1:18080/",
            "--external-submission",
        ],
        env=env_with_cfg,
    )
    assert rc_create == 0

    scope_v1 = srv.controller.scope_validator.get_active_scope("run-env-cfg-01")
    assert scope_v1.mode == RunMode.VDP
    assert scope_v1.network_enabled is True
    assert scope_v1.allowed_targets == ("http://127.0.0.1:18080/",)
    assert scope_v1.external_submission is True

    # register-scope also supports --network-enabled, --allowed-target, --external-submission.
    rc_scope = admin_main(
        [
            "register-scope",
            "--run-id",
            "run-env-cfg-01",
            "--scope-revision",
            "scope-env-v2",
            "--auth-ref",
            "owned-env-v2-ref",
            "--allowed-capabilities",
            "analysis.query,net.probe",
            "--allowed-execution-classes",
            "static,network",
            "--network-enabled",
            "--allowed-target",
            "http://127.0.0.1:18081/",
            "--external-submission",
        ],
        env=env_with_cfg,
    )
    assert rc_scope == 0

    scope_v2 = srv.controller.scope_validator.get_active_scope("run-env-cfg-01")
    assert scope_v2.scope_revision == "scope-env-v2"
    assert scope_v2.network_enabled is True
    assert scope_v2.allowed_targets == ("http://127.0.0.1:18081/",)
    assert scope_v2.external_submission is True
