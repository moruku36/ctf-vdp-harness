"""Layer 4 read-only MCP configuration, schema-fingerprint, and NUC/Windows diagnostics.

Never mutates existing run state, never executes remote/target scans, and never
prints secret values (such as ``CTF_MCP_CURSOR_HMAC_KEY`` or ``CTF_MCP_AUTH_TOKEN``).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ctf_mcp.config import (
    HarnessConfig,
    get_cursor_hmac_key,
    load_config_file,
    load_runtime_settings,
)
from ctf_mcp.contracts import (
    ActionLifecycleState,
    ConfigurationError,
    HarnessError,
    PrincipalContext,
    RunMode,
)
from ctf_mcp.controller import create_default_controller
from ctf_mcp.gateway import ScopeValidator, sanitize_audit_text
from ctf_mcp.server import create_mcp_server
from ctf_mcp.storage import Storage


def _inspect_tool_schemas(
    *,
    config: HarnessConfig | None,
    allow_dynamic: bool | None,
    mode: RunMode,
) -> dict[str, dict[str, Any]]:
    """Build an isolated in-memory/tmp server to extract live FastMCP JSON tool schemas."""
    with tempfile.TemporaryDirectory(prefix="ctf-mcp-diag-") as tmp_dir:
        tmp_path = Path(tmp_dir)
        storage = Storage(tmp_path / "diag.db")
        vault_root = tmp_path / "vault"
        controller = create_default_controller(
            storage=storage,
            vault_root=vault_root,
            export_root=vault_root / "_exports",
            cursor_hmac_key=b"d" * 32,
            config=config,
            allow_synthetic_adapters=False,
            allow_dynamic=allow_dynamic,
            initialize=True,
            enable_local_verifier=True,
        )
        server = create_mcp_server(controller)
        raw_tools = asyncio.run(server.mcp.list_tools())
        schemas: dict[str, dict[str, Any]] = {}
        for tool in sorted(raw_tools, key=lambda t: t.name):
            params = getattr(tool, "parameters", None) or {}
            canonical = json.dumps(params, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            schemas[tool.name] = {
                "schema_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
                "properties": sorted((params.get("properties") or {}).keys()),
                "required": list(params.get("required") or ()),
                "additional_properties": params.get("additionalProperties", True),
            }
        return schemas


def collect_mcp_diagnostics(
    *,
    env: Mapping[str, str] | None = None,
    config_path: Path | None = None,
    active_run_id: str | None = None,
    check_docker: bool = False,
    docker_bin: str = "docker",
    repo_root: Path | None = None,
) -> dict[str, Any]:
    """Run non-destructive MCP server, schema, state, and optional Docker hygiene diagnostics."""
    eff_env = dict(env if env is not None else os.environ)
    issues: list[dict[str, str]] = []

    resolved_cfg_path = config_path
    if resolved_cfg_path is None:
        raw_cfg = str(eff_env.get("CTF_MCP_CONFIG", "")).strip()
        if raw_cfg:
            resolved_cfg_path = Path(raw_cfg)

    config: HarnessConfig | None = None
    config_status: dict[str, Any] = {
        "configured": resolved_cfg_path is not None,
        "path": str(resolved_cfg_path) if resolved_cfg_path is not None else None,
        "valid": False,
        "profile": None,
        "adapters_enabled": [],
    }
    if resolved_cfg_path is not None:
        try:
            config = load_config_file(resolved_cfg_path)
            config_status["valid"] = True
            config_status["profile"] = config.profile.value
            config_status["adapters_enabled"] = list(config.execution.adapters_enabled)
        except (HarnessError, OSError, ValueError) as exc:
            issues.append(
                {
                    "code": "invalid_config",
                    "cause": sanitize_audit_text(str(exc)),
                    "remediation": "Verify --config / CTF_MCP_CONFIG points to a valid executable HarnessConfig JSON.",
                }
            )

    settings_status: dict[str, Any] = {}
    settings = None
    try:
        settings = load_runtime_settings(eff_env)
        settings_status = {
            "db_path": str(settings.db_path) if settings.db_path is not None else None,
            "db_exists": bool(settings.db_path and settings.db_path.exists()),
            "vault_root": str(settings.vault_root) if settings.vault_root is not None else None,
            "vault_exists": bool(settings.vault_root and settings.vault_root.exists()),
            "transport": settings.transport.value,
            "profile": (
                settings.profile.value
                if str(eff_env.get("CTF_MCP_PROFILE", "")).strip() or config is None
                else config.profile.value
            ),
            "auth_token_configured": bool(settings.auth_token),
        }
        if settings.db_path is None or settings.vault_root is None:
            issues.append(
                {
                    "code": "missing_runtime_paths",
                    "cause": "CTF_MCP_DB_PATH or CTF_MCP_VAULT_ROOT is not configured.",
                    "remediation": "Source runtime .env or pass --db-path and --vault-root.",
                }
            )
    except HarnessError as exc:
        issues.append(
            {
                "code": "runtime_settings_invalid",
                "cause": sanitize_audit_text(str(exc)),
                "remediation": "Check CTF_MCP_* environment variables without exposing secrets.",
            }
        )

    cursor_key_ok = False
    try:
        _ = get_cursor_hmac_key(eff_env, allow_ephemeral_dev_key=False)
        cursor_key_ok = True
    except ConfigurationError as exc:
        issues.append(
            {
                "code": "cursor_hmac_key_invalid",
                "cause": sanitize_audit_text(str(exc)),
                "remediation": "Configure a strong non-placeholder CTF_MCP_CURSOR_HMAC_KEY in runtime .env.",
            }
        )

    raw_dyn = str(eff_env.get("CTF_MCP_ALLOW_DYNAMIC", "")).strip().lower()
    env_allow_dynamic: bool | None = None
    if raw_dyn in {"1", "true"}:
        env_allow_dynamic = True
    elif raw_dyn in {"0", "false"}:
        env_allow_dynamic = False
    elif raw_dyn:
        issues.append(
            {
                "code": "invalid_allow_dynamic",
                "cause": f"CTF_MCP_ALLOW_DYNAMIC must be 1/true or 0/false, got {raw_dyn!r}.",
                "remediation": "Set CTF_MCP_ALLOW_DYNAMIC=1 or 0.",
            }
        )

    eff_mode = (
        config.profile
        if config is not None and not str(eff_env.get("CTF_MCP_PROFILE", "")).strip()
        else (settings.profile if settings is not None else RunMode.OFFLINE_CTF)
    )
    tool_schemas = _inspect_tool_schemas(
        config=config,
        allow_dynamic=env_allow_dynamic,
        mode=eff_mode,
    )

    runs_summary: list[dict[str, Any]] = []
    active_run_diag: dict[str, Any] | None = None
    if settings is not None and settings.db_path is not None and settings.db_path.exists():
        storage = Storage(settings.db_path)
        with storage.read_connection() as conn:
            run_rows = conn.execute(
                """
                SELECT run_id, task_id, mode, scope_revision, guest_health, revision,
                       active_heavy_jobs, active_sessions, remaining_calls, closed_at
                FROM runs
                ORDER BY created_at ASC
                """
            ).fetchall()
            for r in run_rows:
                rid = str(r["run_id"])
                rec_cnt_row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM actions WHERE run_id = ? AND state = ?",
                    (rid, ActionLifecycleState.RECONCILIATION_REQUIRED.value),
                ).fetchone()
                rec_cnt = int(rec_cnt_row["cnt"]) if rec_cnt_row else 0
                entry = {
                    "run_id": rid,
                    "task_id": str(r["task_id"]),
                    "mode": str(r["mode"]),
                    "scope_revision": str(r["scope_revision"]),
                    "guest_health": str(r["guest_health"]),
                    "revision": int(r["revision"]),
                    "active_heavy_jobs": int(r["active_heavy_jobs"]),
                    "active_sessions": int(r["active_sessions"]),
                    "remaining_calls": int(r["remaining_calls"]),
                    "closed": r["closed_at"] is not None,
                    "reconciliation_required_count": rec_cnt,
                }
                runs_summary.append(entry)
                if active_run_id and rid == active_run_id:
                    active_run_diag = dict(entry)
                    try:
                        scope_val = ScopeValidator(storage, allow_dynamic=bool(env_allow_dynamic))
                        pol = scope_val.get_active_scope(rid)
                        active_run_diag["scope_active"] = True
                        active_run_diag["allowed_capabilities"] = list(pol.allowed_capabilities)
                        active_run_diag["allowed_execution_classes"] = [
                            c.value for c in pol.allowed_execution_classes
                        ]
                    except HarnessError as exc:
                        active_run_diag["scope_active"] = False
                        active_run_diag["scope_error"] = sanitize_audit_text(str(exc))
                        issues.append(
                            {
                                "code": "active_run_scope_inactive",
                                "cause": sanitize_audit_text(str(exc)),
                                "remediation": "Check active run scope expiry/revocation or switch to an active run.",
                            }
                        )
        if active_run_id and active_run_diag is None:
            issues.append(
                {
                    "code": "active_run_not_found",
                    "cause": f"Active run {active_run_id!r} was not found in {settings.db_path}.",
                    "remediation": "Verify --active-run matches an existing run in harness.db.",
                }
            )

    docker_diag: dict[str, Any] = {"checked": False}
    if check_docker:
        resolved_docker = shutil.which(docker_bin) if docker_bin == "docker" else docker_bin
        if not resolved_docker:
            docker_diag = {"checked": True, "available": False}
            issues.append(
                {
                    "code": "docker_cli_missing",
                    "cause": f"Docker executable {docker_bin!r} not found.",
                    "remediation": "Install Docker CLI/daemon on the execution host.",
                }
            )
        else:
            ps_res = subprocess.run(
                [resolved_docker, "ps", "-aq", "--filter", "name=ctf-vdp-"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            net_res = subprocess.run(
                [resolved_docker, "network", "ls", "-q", "--filter", "name=ctf-vdp-net-"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            lingering_c = [x for x in ps_res.stdout.splitlines() if x.strip()]
            lingering_n = [x for x in net_res.stdout.splitlines() if x.strip()]
            docker_diag = {
                "checked": True,
                "available": ps_res.returncode == 0,
                "lingering_vdp_containers": lingering_c,
                "lingering_vdp_networks": lingering_n,
            }
            if lingering_c or lingering_n:
                issues.append(
                    {
                        "code": "lingering_docker_resources",
                        "cause": f"Found {len(lingering_c)} lingering container(s) and {len(lingering_n)} network(s).",
                        "remediation": "Clean up leftover ctf-vdp-* containers and ctf-vdp-net-* networks before running.",
                    }
                )

    git_commit: str | None = None
    target_repo = repo_root or Path(__file__).resolve().parents[2]
    if (target_repo / ".git").exists() and shutil.which("git"):
        gres = subprocess.run(
            ["git", "-C", str(target_repo), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if gres.returncode == 0:
            git_commit = gres.stdout.strip()

    return {
        "schema": "ctf-mcp-diagnostics/1",
        "healthy": len(issues) == 0,
        "git_commit": git_commit,
        "config": config_status,
        "runtime": {
            **settings_status,
            "cursor_hmac_key_configured": cursor_key_ok,
            "allow_dynamic_env": env_allow_dynamic,
        },
        "tool_schemas": tool_schemas,
        "runs": runs_summary,
        "active_run": active_run_diag,
        "docker": docker_diag,
        "issues": issues,
    }


__all__ = ["collect_mcp_diagnostics"]
