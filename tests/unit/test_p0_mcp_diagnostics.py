"""Unit tests for Layer 4 read-only MCP diagnostics (`mcp_diagnostics` & CLI)."""

from __future__ import annotations

import json
import os
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ctf_mcp.cli import admin_main
from ctf_mcp.contracts import (
    BudgetSpec,
    PrincipalContext,
    RunMode,
    ScopePolicy,
    canonical_digest,
)
from ctf_mcp.controller import create_default_controller
from ctf_mcp.mcp_diagnostics import collect_mcp_diagnostics
from ctf_mcp.storage import Storage


def _write_valid_vdp_config(path: Path) -> Path:
    payload = {
        "schema_version": "executable-1",
        "executable": True,
        "profile": "vdp",
        "description": "P0 diagnostics test config",
        "client": {
            "kind": "OPERATOR_SELECTED",
            "model_label": "p0-diag-test-client",
            "instruction_revision": "p0-diag-v1",
        },
        "scope": {
            "task_id": "task-p0-diag",
            "revision": "scope-p0-v1",
            "authorization_reference": "owned-p0-diag",
            "expires_at": None,
        },
        "network": {
            "enabled": False,
            "allowed_targets": [],
            "external_submission": False,
        },
        "execution": {
            "adapters_enabled": ["vdp.test"],
            "arbitrary_shell": False,
            "dynamic_execution": True,
            "heavy_job_concurrency": 1,
            "interactive_session_limit": 1,
            "action_timeout_seconds": 30,
            "session_idle_seconds": 300,
            "run_budget_seconds": 600,
            "max_tool_calls": 20,
            "max_output_chars_per_page": 4000,
            "max_evidence_bytes_per_run": 10485760,
        },
        "evidence": {
            "storage": "private_vault",
            "cross_run_access": False,
            "automatic_git_export": False,
            "retention_policy_reference": "local-test-only",
            "audit_raw_output": False,
        },
        "acceptance": {
            "require_pinned_revisions": True,
            "require_scope_validation": True,
            "require_registered_verifier": True,
        },
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _make_fake_docker_diag(tmp_path: Path, *, lingering_c: list[str], lingering_n: list[str]) -> Path:
    bin_path = tmp_path / "fake-docker"
    script = f"""#!{sys.executable}
import sys
args = sys.argv[1:]
if args[:1] == ["ps"]:
    for item in {lingering_c!r}:
        sys.stdout.write(item + "\\n")
    sys.exit(0)
if args[:1] == ["network"]:
    for item in {lingering_n!r}:
        sys.stdout.write(item + "\\n")
    sys.exit(0)
sys.exit(0)
"""
    bin_path.write_text(script, encoding="utf-8")
    bin_path.chmod(bin_path.stat().st_mode | stat.S_IXUSR | stat.S_IRUSR)
    return bin_path


def _seed_vdp_run(tmp_path: Path, *, hmac_key: bytes, run_id: str = "run-p0-diag-01") -> tuple[Path, Path]:
    db_path = tmp_path / "harness.db"
    vault_root = tmp_path / "vault"
    storage = Storage(db_path)
    ctrl = create_default_controller(
        storage=storage,
        vault_root=vault_root,
        export_root=vault_root / "_exports",
        cursor_hmac_key=hmac_key,
        allow_dynamic=True,
        include_vdp_product_test=True,
        initialize=True,
        enable_local_verifier=True,
    )
    principal = PrincipalContext(
        principal_id="local-operator",
        auth_method="stdio_local",
        client_kind="OPERATOR_SELECTED",
        model_label="p0-diag-test",
    )
    now = datetime.now(UTC)
    scope_payload = {
        "mode": "vdp",
        "task_id": "task-p0-diag",
        "scope_revision": "scope-p0-v1",
        "authorization_reference": "owned-p0-diag",
        "allowed_capabilities": ["analysis.query", "vdp.test"],
        "allowed_execution_classes": ["static", "dynamic"],
        "expires_at": (now + timedelta(hours=2)).isoformat(),
        "network_enabled": False,
        "allowed_targets": [],
        "external_submission": False,
    }
    scope = ScopePolicy(
        scope_revision="scope-p0-v1",
        scope_sha256=canonical_digest(scope_payload),
        mode=RunMode.VDP,
        task_id="task-p0-diag",
        authorization_reference="owned-p0-diag",
        allowed_execution_classes=("static", "dynamic"),
        allowed_capabilities=("analysis.query", "vdp.test"),
        expires_at=now + timedelta(hours=2),
        network_enabled=False,
        allowed_targets=(),
        external_submission=False,
    )
    ctrl.create_run(
        principal=principal,
        run_id=run_id,
        task_id="task-p0-diag",
        mode=RunMode.VDP,
        scope=scope,
        budget=BudgetSpec(run_budget_seconds=300, max_tool_calls=20, max_evidence_bytes_per_run=10_485_760),
    )
    return db_path, vault_root


def test_collect_mcp_diagnostics_healthy_and_secret_free(tmp_path: Path) -> None:
    hmac_secret = "unit-test-hmac-secret-value-never-emit-9988776655"
    auth_secret = "unit-test-bearer-token-never-emit-4433221100"
    db_path, vault_root = _seed_vdp_run(tmp_path, hmac_key=hmac_secret.encode("utf-8"))
    cfg_path = _write_valid_vdp_config(tmp_path / "cfg.json")
    fake_docker = _make_fake_docker_diag(tmp_path, lingering_c=[], lingering_n=[])

    env = {
        "CTF_MCP_DB_PATH": str(db_path),
        "CTF_MCP_VAULT_ROOT": str(vault_root),
        "CTF_MCP_CURSOR_HMAC_KEY": hmac_secret,
        "CTF_MCP_AUTH_TOKEN": auth_secret,
        "CTF_MCP_ALLOW_DYNAMIC": "1",
        "CTF_MCP_PROFILE": "vdp",
        "CTF_MCP_TRANSPORT": "stdio",
    }
    report = collect_mcp_diagnostics(
        env=env,
        config_path=cfg_path,
        active_run_id="run-p0-diag-01",
        check_docker=True,
        docker_bin=str(fake_docker),
    )

    assert report["schema"] == "ctf-mcp-diagnostics/1"
    assert report["healthy"] is True
    assert report["issues"] == []
    assert report["config"]["valid"] is True
    assert report["runtime"]["cursor_hmac_key_configured"] is True
    assert report["runtime"]["auth_token_configured"] is True
    assert report["active_run"]["run_id"] == "run-p0-diag-01"
    assert report["active_run"]["scope_active"] is True
    assert "vdp.test" in report["tool_schemas"]
    assert "run.describe" in report["tool_schemas"]
    assert "evidence.import_manual_observation" in report["tool_schemas"]
    assert report["tool_schemas"]["vdp.test"]["additional_properties"] is False
    assert report["tool_schemas"]["evidence.import_manual_observation"]["additional_properties"] is False
    assert report["tool_schemas"]["evidence.import_manual_observation"]["nested_strict_objects_closed"] is True
    assert report["surface_summary"]["vdp_manual_observation_mcp_exposed"] is True
    assert len(report["tool_schemas"]["vdp.test"]["schema_sha256"]) == 64

    serialized = json.dumps(report, ensure_ascii=False)
    assert hmac_secret not in serialized
    assert auth_secret not in serialized


def test_collect_mcp_diagnostics_detects_invalid_config_hmac_and_lingering_docker(tmp_path: Path) -> None:
    db_path, vault_root = _seed_vdp_run(tmp_path, hmac_key=b"a" * 32)
    bad_cfg = tmp_path / "bad.json"
    bad_cfg.write_text("{not-json", encoding="utf-8")
    fake_docker = _make_fake_docker_diag(
        tmp_path,
        lingering_c=["ctf-vdp-stale-1"],
        lingering_n=["ctf-vdp-net-stale-1"],
    )

    report = collect_mcp_diagnostics(
        env={
            "CTF_MCP_DB_PATH": str(db_path),
            "CTF_MCP_VAULT_ROOT": str(vault_root),
            "CTF_MCP_CURSOR_HMAC_KEY": "changeme",
            "CTF_MCP_ALLOW_DYNAMIC": "1",
        },
        config_path=bad_cfg,
        active_run_id="missing-run",
        check_docker=True,
        docker_bin=str(fake_docker),
    )

    assert report["healthy"] is False
    codes = {issue["code"] for issue in report["issues"]}
    assert "invalid_config" in codes
    assert "cursor_hmac_key_invalid" in codes
    assert "active_run_not_found" in codes
    assert "lingering_docker_resources" in codes


def test_cli_diagnose_mcp_exit_codes(tmp_path: Path, capsys) -> None:
    hmac_secret = "cli-diag-test-hmac-secret-value-112233445566"
    db_path, vault_root = _seed_vdp_run(tmp_path, hmac_key=hmac_secret.encode("utf-8"))
    cfg_path = _write_valid_vdp_config(tmp_path / "cfg.json")

    rc_ok = admin_main(
        [
            "diagnose-mcp",
            "--db-path",
            str(db_path),
            "--vault-root",
            str(vault_root),
            "--config",
            str(cfg_path),
            "--active-run",
            "run-p0-diag-01",
        ],
        env={
            "CTF_MCP_CURSOR_HMAC_KEY": hmac_secret,
            "CTF_MCP_ALLOW_DYNAMIC": "1",
            "CTF_MCP_PROFILE": "vdp",
        },
    )
    out_ok = json.loads(capsys.readouterr().out)
    assert rc_ok == 0
    assert out_ok["healthy"] is True

    rc_bad = admin_main(
        [
            "diagnose-mcp",
            "--db-path",
            str(db_path),
            "--vault-root",
            str(vault_root),
            "--active-run",
            "nonexistent-run",
        ],
        env={"CTF_MCP_CURSOR_HMAC_KEY": "changeme"},
    )
    out_bad = json.loads(capsys.readouterr().out)
    assert rc_bad == 1
    assert out_bad["healthy"] is False



def test_collect_mcp_diagnostics_hides_vdp_manual_tool_in_offline_ctf(tmp_path: Path) -> None:
    hmac_secret = "offline-diag-hmac-secret-value-1234567890abcdef"
    db_path, vault_root = _seed_vdp_run(tmp_path, hmac_key=hmac_secret.encode("utf-8"))
    report = collect_mcp_diagnostics(
        env={
            "CTF_MCP_DB_PATH": str(db_path),
            "CTF_MCP_VAULT_ROOT": str(vault_root),
            "CTF_MCP_CURSOR_HMAC_KEY": hmac_secret,
            "CTF_MCP_PROFILE": "offline_ctf",
        },
        check_docker=False,
    )
    assert report["healthy"] is True
    assert "evidence.import_manual_observation" not in report["tool_schemas"]
    assert report["surface_summary"]["mode"] == "offline_ctf"
    assert report["surface_summary"]["vdp_manual_observation_mcp_exposed"] is False
