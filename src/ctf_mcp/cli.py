"""Local operator and MCP server CLI entrypoints for the CTF/VDP analysis harness.

Provides two Fail-Closed console commands with zero shell invocation:
- ``ctf-mcp-server``: Launch the FastMCP server wired with
  ``StaticArtifactInspectorAdapter`` and ``LocalCtfVerifier``
  (``allow_synthetic_adapters=False`` strictly enforced).
- ``ctf-mcp-admin``: Local offline administrative operations for run creation,
  scope registration, bounded artifact intake, digest-only verifier expectation
  registration, crash reconciliation, guest recovery, and run state inspection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ctf_mcp.adapters.vdp_product_test import (
    DEFAULT_VDP_TEST_MAX_CPUS,
    DEFAULT_VDP_TEST_MAX_MEMORY_MB,
    DEFAULT_VDP_TEST_MAX_OUTPUT_BYTES,
    DEFAULT_VDP_TEST_TIMEOUT_SECONDS,
    VALID_SELECTOR_ROLES,
    VALID_VDP_NETWORK_MODES,
    VALID_VDP_RUNNER_MODES,
    WEBLATE_2026_11_2_PROFILE_NAME,
    VdpOverlaySpec,
    VdpServiceSpec,
    VdpTargetProfile,
    build_default_weblate_profile,
    load_registered_vdp_profiles,
    run_vdp_environment_check,
    save_registered_vdp_profile,
    validate_vdp_profile_registration,
)
from ctf_mcp.config import (
    HarnessConfig,
    get_cursor_hmac_key,
    load_config_file,
    load_runtime_settings,
)
from ctf_mcp.contracts import (
    ActionLifecycleState,
    BudgetSpec,
    ConfigurationError,
    ContractViolationError,
    ErrorDetail,
    ExecutionClass,
    FindingState,
    HarnessError,
    PrincipalContext,
    RunMode,
    ScopePolicy,
    UsageMetrics,
    canonical_digest,
)
from ctf_mcp.controller import (
    HarnessController,
    create_default_controller,
    save_verifier_expectation,
)
from ctf_mcp.evidence import (
    VALID_CHECKPOINT_GATES,
    CandidatePreconditions,
    KnownIssueCheckpoint,
    ManualObservationRecord,
    VdpDraftSpec,
    evaluate_candidate_gate,
    hash_manual_test_file,
    read_bounded_candidate_json_file,
    read_bounded_manual_json_file,
    summarize_vdp_candidate_metrics,
)
from ctf_mcp.gateway import sanitize_audit_text
from ctf_mcp.mcp_diagnostics import collect_mcp_diagnostics
from ctf_mcp.server import build_server_from_env
from ctf_mcp.storage import Storage
from ctf_mcp.vdp_boundary_map import (
    BOUNDARY_MAP_SUBCOMMAND,
    handle_boundary_map_cli,
    register_boundary_map_subparser,
)
from ctf_mcp.vdp_auth_matrix import (
    AUTH_MATRIX_COMMAND,
    handle_auth_matrix_cli,
    register_auth_matrix_subparser,
)
from ctf_mcp.vdp_overlay_assistant import (
    OVERLAY_ASSISTANT_COMMAND,
    handle_overlay_assistant,
    register_overlay_assistant_subparser,
)
from ctf_mcp.verification import ExpectedChallengeSpec


def _parse_csv_values(values: Sequence[str] | None, *, default: tuple[str, ...]) -> tuple[str, ...]:
    """Parse repeated or comma-separated CLI string arguments while preserving order."""
    if not values:
        return default
    seen: list[str] = []
    for raw in values:
        for part in str(raw).split(","):
            cleaned = part.strip()
            if cleaned and cleaned not in seen:
                seen.append(cleaned)
    return tuple(seen) if seen else default


def _parse_iso_datetime(value: str | None) -> datetime | None:
    """Parse an optional ISO-8601 timestamp string into timezone-aware UTC datetime."""
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    dt = datetime.fromisoformat(cleaned)
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def _merge_runtime_env(
    *,
    env: Mapping[str, str] | None,
    db_path: Path | None,
    vault_root: Path | None,
    transport: str | None = None,
    profile: str | None = None,
) -> dict[str, str]:
    """Build an effective environment mapping overridden by explicit CLI options."""
    merged = dict(env if env is not None else os.environ)
    if db_path is not None:
        merged["CTF_MCP_DB_PATH"] = str(db_path)
    if vault_root is not None:
        merged["CTF_MCP_VAULT_ROOT"] = str(vault_root)
    if transport is not None:
        merged["CTF_MCP_TRANSPORT"] = transport
    if profile is not None:
        merged["CTF_MCP_PROFILE"] = profile
    return merged


def _resolve_admin_context(
    args: argparse.Namespace,
    *,
    env: Mapping[str, str] | None = None,
    initialize: bool = True,
) -> tuple[HarnessController, PrincipalContext, HarnessConfig | None]:
    """Construct local admin HarnessController + PrincipalContext with zero secret output."""
    eff_env = _merge_runtime_env(
        env=env,
        db_path=getattr(args, "db_path", None),
        vault_root=getattr(args, "vault_root", None),
    )
    settings = load_runtime_settings(eff_env)
    if settings.db_path is None or settings.vault_root is None:
        raise ConfigurationError(
            "Both DB path (--db-path or CTF_MCP_DB_PATH) and vault root "
            "(--vault-root or CTF_MCP_VAULT_ROOT) must be specified."
        )

    config_path: Path | None = getattr(args, "config", None)
    if config_path is None:
        env_cfg = str(eff_env.get("CTF_MCP_CONFIG", "")).strip()
        if env_cfg:
            config_path = Path(env_cfg)
    config = load_config_file(config_path) if config_path is not None else None
    if config is not None and not str(eff_env.get("CTF_MCP_PROFILE", "")).strip():
        settings = settings.model_copy(update={"profile": config.profile})

    has_env_key = bool(str(eff_env.get("CTF_MCP_CURSOR_HMAC_KEY", "")).strip())
    cursor_hmac_key = get_cursor_hmac_key(
        eff_env, allow_ephemeral_dev_key=not has_env_key
    )
    raw_allow_dynamic = str(eff_env.get("CTF_MCP_ALLOW_DYNAMIC", "")).strip().lower()
    if raw_allow_dynamic in {"1", "true"}:
        env_allow_dynamic: bool | None = True
    elif raw_allow_dynamic in {"0", "false"}:
        env_allow_dynamic = False
    elif not raw_allow_dynamic:
        env_allow_dynamic = None
    else:
        raise ConfigurationError(
            f"CTF_MCP_ALLOW_DYNAMIC must be 1/true or 0/false (got {raw_allow_dynamic!r})."
        )
    storage = Storage(settings.db_path)
    controller = create_default_controller(
        storage=storage,
        vault_root=settings.vault_root,
        export_root=settings.vault_root / "_exports",
        cursor_hmac_key=cursor_hmac_key,
        config=config,
        runtime_settings=settings,
        allow_ephemeral_cursor_key=not has_env_key,
        allow_synthetic_adapters=False,
        allow_dynamic=env_allow_dynamic,
        enable_local_verifier=True,
        initialize=initialize,
    )

    principal_id = getattr(args, "principal_id", None) or "local-operator"
    client_kind = (
        getattr(args, "client_kind", None)
        or (config.client.kind if config is not None else "OPERATOR_SELECTED")
    )
    model_label = (
        getattr(args, "model_label", None)
        or (config.client.model_label if config is not None else "cli-operator")
    )
    principal = PrincipalContext(
        principal_id=principal_id,
        auth_method="stdio_local",
        client_kind=client_kind,
        model_label=model_label,
    )
    return controller, principal, config


def _build_scope_policy(
    *,
    mode: RunMode,
    task_id: str,
    scope_revision: str,
    authorization_reference: str,
    allowed_capabilities: Sequence[str],
    allowed_execution_classes: Sequence[ExecutionClass] = (ExecutionClass.STATIC,),
    expires_at: datetime | None = None,
    network_enabled: bool = False,
    allowed_targets: Sequence[str] = (),
    external_submission: bool = False,
) -> ScopePolicy:
    """Construct a fail-closed ScopePolicy with canonical SHA-256 digest."""
    caps = tuple(allowed_capabilities)
    exec_classes = tuple(allowed_execution_classes)
    targets = tuple(allowed_targets)
    payload = {
        "mode": mode.value,
        "task_id": task_id,
        "scope_revision": scope_revision,
        "authorization_reference": authorization_reference,
        "allowed_capabilities": list(caps),
        "allowed_execution_classes": [c.value for c in exec_classes],
        "expires_at": expires_at.isoformat() if expires_at is not None else None,
        "network_enabled": bool(network_enabled),
        "allowed_targets": list(targets),
        "external_submission": bool(external_submission),
    }
    return ScopePolicy(
        scope_revision=scope_revision,
        scope_sha256=canonical_digest(payload),
        mode=mode,
        task_id=task_id,
        authorization_reference=authorization_reference,
        allowed_execution_classes=exec_classes,
        allowed_capabilities=caps,
        expires_at=expires_at,
        network_enabled=bool(network_enabled),
        allowed_targets=targets,
        external_submission=bool(external_submission),
    )


def _emit_json(payload: Mapping[str, Any]) -> None:
    """Write formatted sanitized JSON summary to stdout."""
    sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def _add_common_admin_flags(parser: argparse.ArgumentParser, *, suppress_defaults: bool = False) -> None:
    """Attach shared local runtime flags cleanly to root and subcommand parsers."""
    default_none: Any = argparse.SUPPRESS if suppress_defaults else None
    parser.add_argument(
        "--db-path",
        type=Path,
        default=default_none,
        help="Path to SQLite state database (or set CTF_MCP_DB_PATH).",
    )
    parser.add_argument(
        "--vault-root",
        type=Path,
        default=default_none,
        help="Path to private evidence vault root (or set CTF_MCP_VAULT_ROOT).",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=default_none,
        help="Optional validated executable HarnessConfig JSON file.",
    )
    parser.add_argument(
        "--principal-id",
        default=argparse.SUPPRESS if suppress_defaults else "local-operator",
        help="Principal ID owning created runs (default: local-operator).",
    )
    parser.add_argument(
        "--client-kind",
        default=default_none,
        help="Optional client_kind label recorded on the run manifest.",
    )
    parser.add_argument(
        "--model-label",
        default=default_none,
        help="Optional model label recorded on the run manifest.",
    )


def _owner_principal(snapshot: Any, default_principal: PrincipalContext) -> PrincipalContext:
    return PrincipalContext(
        principal_id=snapshot.manifest.owner_principal_id,
        auth_method="stdio_local",
        client_kind=default_principal.client_kind,
        model_label=default_principal.model_label,
    )


def _handle_create_run(args: argparse.Namespace, env: Mapping[str, str] | None) -> int:
    controller, principal, config = _resolve_admin_context(args, env=env)
    mode = RunMode(args.mode) if args.mode else (config.profile if config else controller.default_mode)
    task_id = args.task_id or (config.scope.task_id if config is not None else None)
    if not task_id:
        raise ContractViolationError("--task-id is required (or provide --config).")

    scope_revision = args.scope_revision or (config.scope.revision if config is not None else "scope-v1")
    auth_ref = args.auth_ref or (config.scope.authorization_reference if config is not None else None)
    if not auth_ref:
        raise ContractViolationError("--auth-ref is required (or provide --config).")

    expires_raw = (
        args.expires_at
        if args.expires_at is not None
        else (config.scope.expires_at if config is not None else None)
    )
    default_caps: tuple[str, ...] = ("analysis.query", "artifact.inspect")
    if (
        args.allowed_capabilities is None
        and mode == RunMode.VDP
        and config is not None
        and any(item in {"vdp.test", "ctf-vdp-product-test"} for item in config.execution.adapters_enabled)
    ):
        default_caps = ("analysis.query", "artifact.inspect", "vdp.test")
    allowed_caps = _parse_csv_values(
        args.allowed_capabilities,
        default=default_caps,
    )
    exec_class_strs = _parse_csv_values(
        args.allowed_execution_classes,
        default=(ExecutionClass.STATIC.value,),
    )
    allowed_exec_classes = tuple(ExecutionClass(item) for item in exec_class_strs)
    scope = _build_scope_policy(
        mode=mode,
        task_id=task_id,
        scope_revision=scope_revision,
        authorization_reference=auth_ref,
        allowed_capabilities=allowed_caps,
        allowed_execution_classes=allowed_exec_classes,
        expires_at=_parse_iso_datetime(expires_raw),
        network_enabled=(
            True
            if args.network_enabled
            else (bool(config.network.enabled) if config is not None else False)
        ),
        allowed_targets=_parse_csv_values(
            args.allowed_target,
            default=config.network.allowed_targets if config is not None else (),
        ),
        external_submission=(
            True
            if args.external_submission
            else (bool(config.network.external_submission) if config is not None else False)
        ),
    )

    base_budget = config.execution.to_budget_spec() if config is not None else BudgetSpec()
    budget = BudgetSpec(
        run_budget_seconds=args.run_budget_seconds or base_budget.run_budget_seconds,
        action_timeout_seconds=args.action_timeout_seconds or base_budget.action_timeout_seconds,
        session_idle_seconds=args.session_idle_seconds or base_budget.session_idle_seconds,
        max_tool_calls=args.max_tool_calls or base_budget.max_tool_calls,
        max_output_chars_per_page=base_budget.max_output_chars_per_page,
        max_evidence_bytes_per_run=args.max_evidence_bytes or base_budget.max_evidence_bytes_per_run,
        heavy_job_concurrency=args.heavy_job_concurrency or base_budget.heavy_job_concurrency,
        interactive_session_limit=args.interactive_session_limit or base_budget.interactive_session_limit,
    )
    instruction_rev = (
        args.instruction_revision
        or (config.client.instruction_revision if config is not None else "p3-mvp")
    )
    manifest = controller.create_run(
        principal=principal,
        task_id=task_id,
        mode=mode,
        scope=scope,
        budget=budget,
        run_id=args.run_id,
        instruction_revision=instruction_rev,
    )
    _emit_json(
        {
            "run_id": manifest.run_id,
            "task_id": manifest.task_id,
            "owner_principal_id": manifest.owner_principal_id,
            "mode": manifest.mode.value,
            "scope_revision": manifest.scope_revision,
            "scope_sha256": manifest.scope_sha256,
            "created_at": manifest.created_at.isoformat(),
        }
    )
    return 0


def _handle_register_scope(args: argparse.Namespace, env: Mapping[str, str] | None) -> int:
    controller, principal, _ = _resolve_admin_context(args, env=env)
    snapshot = controller.runs.get_run_snapshot(args.run_id)
    mode = RunMode(args.mode) if args.mode else snapshot.manifest.mode
    task_id = args.task_id or snapshot.manifest.task_id
    allowed_caps = _parse_csv_values(
        args.allowed_capabilities,
        default=("analysis.query", "artifact.inspect"),
    )
    exec_class_strs = _parse_csv_values(
        args.allowed_execution_classes,
        default=(ExecutionClass.STATIC.value,),
    )
    allowed_exec_classes = tuple(ExecutionClass(item) for item in exec_class_strs)
    scope = _build_scope_policy(
        mode=mode,
        task_id=task_id,
        scope_revision=args.scope_revision,
        authorization_reference=args.auth_ref,
        allowed_capabilities=allowed_caps,
        allowed_execution_classes=allowed_exec_classes,
        expires_at=_parse_iso_datetime(args.expires_at),
        network_enabled=bool(args.network_enabled),
        allowed_targets=_parse_csv_values(args.allowed_target, default=()),
        external_submission=bool(args.external_submission),
    )
    registered = controller.register_scope(
        run_id=args.run_id,
        scope=scope,
        principal=principal if snapshot.manifest.owner_principal_id == principal.principal_id else None,
        activate=not args.no_activate,
    )
    _emit_json(
        {
            "run_id": args.run_id,
            "task_id": registered.task_id,
            "mode": registered.mode.value,
            "scope_revision": registered.scope_revision,
            "scope_sha256": registered.scope_sha256,
            "activated": not args.no_activate,
        }
    )
    return 0


def _handle_ingest_artifact(args: argparse.Namespace, env: Mapping[str, str] | None) -> int:
    controller, principal, _ = _resolve_admin_context(args, env=env)
    snapshot = controller.runs.get_run_snapshot(args.run_id)
    owner = _owner_principal(snapshot, principal)
    artifact = controller.ingest_artifact(
        principal=owner,
        run_id=args.run_id,
        source_root=args.source_root,
        rel_path=args.rel_path,
        media_type=args.media_type,
        source_origin=args.source_origin,
    )
    _emit_json(
        {
            "run_id": artifact.run_id,
            "artifact_id": artifact.artifact_id,
            "sha256": artifact.sha256,
            "byte_length": artifact.byte_length,
            "media_type": artifact.media_type,
        }
    )
    return 0


def _handle_register_expectation(args: argparse.Namespace, env: Mapping[str, str] | None) -> int:
    controller, _, _ = _resolve_admin_context(args, env=env, initialize=False)
    spec = ExpectedChallengeSpec(
        expected_flag_sha256=args.flag_sha256,
        expected_evidence_sha256=args.evidence_sha256,
        normalize_whitespace=not args.no_normalize_whitespace,
        salt=args.salt,
        require_complete_capture=not args.allow_incomplete_capture,
        description=sanitize_audit_text(args.description) or "Operator-registered expected digest",
    )
    saved_path = save_verifier_expectation(
        controller.vault_root,
        spec=spec,
        run_id=args.run_id,
        task_id=args.task_id,
    )
    _emit_json(
        {
            "saved_path": str(saved_path),
            "run_id": args.run_id,
            "task_id": args.task_id,
            "has_flag_sha256": spec.expected_flag_sha256 is not None,
            "has_evidence_sha256": spec.expected_evidence_sha256 is not None,
            "require_complete_capture": spec.require_complete_capture,
        }
    )
    return 0


def _handle_reconcile(args: argparse.Namespace, env: Mapping[str, str] | None) -> int:
    controller, _, _ = _resolve_admin_context(args, env=env, initialize=False)
    if args.action_id:
        controller.storage.initialize()
        with controller.storage.transaction() as conn:
            controller._ensure_controller_schemas_in_tx(conn)
        controller.leases.ensure_schema()

        target = ActionLifecycleState(args.target_state)
        err = (
            ErrorDetail(
                code=args.error_code,
                message=sanitize_audit_text(args.error_message) or args.error_code,
                retryable=False,
            )
            if args.error_code
            else None
        )
        usage = UsageMetrics(wall_ms=args.wall_ms, output_bytes=args.output_bytes)
        sub = controller.resolve_reconciled_action(
            action_id=args.action_id,
            target_state=target,
            usage=usage,
            has_tool_receipt=(target == ActionLifecycleState.COMPLETED),
            summary=args.summary,
            error=err,
            retain_reservation=args.retain_reservation,
            usage_unknown=True if args.usage_unknown else None,
            cleanup_confirmed=not args.cleanup_unconfirmed,
        )
        _emit_json(
            {
                "action_id": sub.action.action_id,
                "run_id": sub.action.run_id,
                "state": sub.action.state.value,
                "error_code": (
                    sub.envelope.error.code
                    if sub.envelope is not None and sub.envelope.error is not None
                    else args.error_code
                ),
            }
        )
        return 0

    report = controller.initialize()
    expired = controller.expire_idle_leases() if args.expire_leases else []
    _emit_json(
        {
            "reconciled_to_required": [a.action_id for a in report.reconciled_to_required],
            "expired_reserved": [a.action_id for a in report.expired_reserved],
            "still_running": [a.action_id for a in report.still_running],
            "lost_session_ids": list(report.lost_session_ids),
            "new_supervisor_token": report.new_supervisor_token,
            "expired_leases": [lease.session_id for lease in expired],
        }
    )
    return 0


def _handle_recover_guest(args: argparse.Namespace, env: Mapping[str, str] | None) -> int:
    controller, _, _ = _resolve_admin_context(args, env=env)
    health = controller.recover_guest_ready(
        run_id=args.run_id,
        cleanup_verified=bool(args.cleanup_verified),
        note=args.note,
    )
    _emit_json({"run_id": args.run_id, "guest_health": health.value})
    return 0


def _handle_describe_run(args: argparse.Namespace, env: Mapping[str, str] | None) -> int:
    controller, principal, _ = _resolve_admin_context(args, env=env)
    snapshot = controller.runs.get_run_snapshot(args.run_id)
    owner = _owner_principal(snapshot, principal)
    summary = controller.describe_run(principal=owner, run_id=args.run_id)
    _emit_json(summary)
    return 0


def _handle_update_budget(args: argparse.Namespace, env: Mapping[str, str] | None) -> int:
    controller, _, _ = _resolve_admin_context(args, env=env)
    summary = controller.update_run_budget(
        run_id=args.run_id,
        principal=None,
        max_tool_calls=args.max_tool_calls,
        remaining_calls=args.remaining_calls,
        add_calls=args.add_calls,
        run_budget_seconds=args.run_budget_seconds,
        remaining_ms=args.remaining_ms,
        max_evidence_bytes_per_run=args.max_evidence_bytes,
        remaining_bytes=args.remaining_bytes,
        interactive_session_limit=args.interactive_session_limit,
        heavy_job_concurrency=args.heavy_job_concurrency,
        action_timeout_seconds=args.action_timeout_seconds,
    )
    _emit_json(summary)
    return 0


def _handle_update_scope(args: argparse.Namespace, env: Mapping[str, str] | None) -> int:
    controller, _, _ = _resolve_admin_context(args, env=env)
    allowed_caps = (
        _parse_csv_values(args.allowed_capabilities, default=())
        if args.allowed_capabilities
        else None
    )
    add_caps = _parse_csv_values(args.add_capability, default=())
    exec_classes = (
        tuple(
            ExecutionClass(item)
            for item in _parse_csv_values(args.allowed_execution_classes, default=())
        )
        if args.allowed_execution_classes
        else None
    )
    allowed_targets = (
        _parse_csv_values(args.allowed_target, default=())
        if args.allowed_target
        else None
    )
    network_enabled: bool | None = None
    if args.network_enabled:
        network_enabled = True
    elif args.disable_network:
        network_enabled = False
    summary = controller.update_run_scope(
        run_id=args.run_id,
        scope_revision=args.scope_revision,
        principal=None,
        allowed_capabilities=allowed_caps,
        add_capabilities=add_caps,
        allowed_execution_classes=exec_classes,
        authorization_reference=args.auth_ref,
        expires_at=_parse_iso_datetime(args.expires_at) if args.expires_at else None,
        network_enabled=network_enabled,
        allowed_targets=allowed_targets,
    )
    _emit_json(summary)
    return 0


_REV_SUFFIX_RE = re.compile(r"^(?P<prefix>.*?)(?:^|-)r(?P<num>\d+)$")


def _next_profile_revision(base_revision: str | None) -> str:
    if not base_revision:
        return "r1"
    match = _REV_SUFFIX_RE.match(base_revision.strip())
    if match:
        prefix = match.group("prefix")
        next_num = int(match.group("num")) + 1
        return f"{prefix}-r{next_num}" if prefix else f"r{next_num}"
    return f"{base_revision.strip()}-r2"


def _hash_overlay_file_on_disk(host_dir: Path, filename: str) -> str:
    """Hash a regular non-symlink overlay file inside ``host_dir``."""
    try:
        dir_st = os.lstat(host_dir)
    except FileNotFoundError as exc:
        raise ContractViolationError(f"Overlay host directory {host_dir!s} does not exist.") from exc
    if stat.S_ISLNK(dir_st.st_mode) or not stat.S_ISDIR(dir_st.st_mode):
        raise ContractViolationError(f"Overlay host directory {host_dir!s} must be a non-symlink directory.")
    target = host_dir / filename
    try:
        st = os.lstat(target)
    except FileNotFoundError as exc:
        raise ContractViolationError(f"Overlay file {filename!r} not found in {host_dir!s}.") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise ContractViolationError(f"Overlay file {filename!r} must be a regular non-symlink file.")
    digest = hashlib.sha256()
    with open(target, "rb") as handle:
        while chunk := handle.read(65_536):
            digest.update(chunk)
    return digest.hexdigest()


def _compute_vdp_profile_diff(
    base: VdpTargetProfile | None,
    candidate: VdpTargetProfile,
) -> dict[str, Any]:
    """Compute a concise operator review diff between ``base`` and ``candidate`` profiles."""
    if base is None:
        roles = candidate.resolve_selector_roles()
        return {
            "is_new_profile": True,
            "base_revision": None,
            "new_revision": candidate.profile_revision,
            "added_selectors": [
                {"selector": sel, "role": roles.get(sel, "unassigned")}
                for sel in candidate.allowed_test_selectors
            ],
            "removed_selectors": [],
            "role_changes": [],
            "added_overlays": {
                k: {"container_target": v.container_target, "allowed_files": dict(v.allowed_files)}
                for k, v in sorted(candidate.allowed_overlays.items())
            },
            "updated_overlays": {},
            "pinned_changes": {},
        }

    base_set = set(base.allowed_test_selectors)
    cand_set = set(candidate.allowed_test_selectors)
    base_roles = base.resolve_selector_roles()
    cand_roles = candidate.resolve_selector_roles()

    added_selectors = [
        {"selector": s, "role": cand_roles.get(s, "unassigned")}
        for s in candidate.allowed_test_selectors
        if s not in base_set
    ]
    removed_selectors = [
        {"selector": s, "role": base_roles.get(s, "unassigned")}
        for s in base.allowed_test_selectors
        if s not in cand_set
    ]
    role_changes = [
        {"selector": s, "from": base_roles.get(s, "unassigned"), "to": cand_roles.get(s, "unassigned")}
        for s in candidate.allowed_test_selectors
        if s in base_set and base_roles.get(s, "unassigned") != cand_roles.get(s, "unassigned")
    ]

    added_overlays: dict[str, Any] = {}
    updated_overlays: dict[str, Any] = {}
    for bname, spec in sorted(candidate.allowed_overlays.items()):
        old = base.allowed_overlays.get(bname)
        if old is None:
            added_overlays[bname] = {
                "container_target": spec.container_target,
                "allowed_files": dict(spec.allowed_files),
            }
        elif old.allowed_files != spec.allowed_files or old.host_dir != spec.host_dir:
            updated_overlays[bname] = {
                "before_files": dict(old.allowed_files),
                "after_files": dict(spec.allowed_files),
            }

    pinned_changes: dict[str, Any] = {}
    for field_name in (
        "image_ref",
        "expected_image_digest",
        "expected_source_commit",
        "network_mode",
        "runner_mode",
        "pytest_executable",
        "smoke_selectors",
        "max_cpus",
        "max_memory_mb",
        "max_timeout_seconds",
        "max_output_bytes",
    ):
        before_val = getattr(base, field_name)
        after_val = getattr(candidate, field_name)
        if before_val != after_val:
            pinned_changes[field_name] = {"before": before_val, "after": after_val}
    before_exp = base.expires_at.isoformat() if base.expires_at else None
    after_exp = candidate.expires_at.isoformat() if candidate.expires_at else None
    if before_exp != after_exp:
        pinned_changes["expires_at"] = {"before": before_exp, "after": after_exp}
    before_svcs = [s.to_public_summary() for s in base.services]
    after_svcs = [s.to_public_summary() for s in candidate.services]
    if before_svcs != after_svcs:
        pinned_changes["services"] = {"before": before_svcs, "after": after_svcs}

    return {
        "is_new_profile": False,
        "base_revision": base.profile_revision,
        "new_revision": candidate.profile_revision,
        "added_selectors": added_selectors,
        "removed_selectors": removed_selectors,
        "role_changes": role_changes,
        "added_overlays": added_overlays,
        "updated_overlays": updated_overlays,
        "pinned_changes": pinned_changes,
    }


def _has_nonempty_profile_diff(diff: Mapping[str, Any]) -> bool:
    if diff.get("is_new_profile"):
        return True
    return bool(
        diff.get("added_selectors")
        or diff.get("removed_selectors")
        or diff.get("role_changes")
        or diff.get("added_overlays")
        or diff.get("updated_overlays")
        or diff.get("pinned_changes")
    )


def _handle_register_vdp_profile(args: argparse.Namespace, env: Mapping[str, str] | None) -> int:
    eff_env = _merge_runtime_env(
        env=env,
        db_path=getattr(args, "db_path", None),
        vault_root=getattr(args, "vault_root", None),
    )
    settings = load_runtime_settings(eff_env)
    if settings.vault_root is None:
        raise ConfigurationError(
            "Vault root (--vault-root or CTF_MCP_VAULT_ROOT) must be specified."
        )

    registered = load_registered_vdp_profiles(settings.vault_root)
    base_name = args.base_profile or args.profile_name
    base: VdpTargetProfile | None = None
    if base_name in registered:
        base = registered[base_name]
    elif base_name == WEBLATE_2026_11_2_PROFILE_NAME:
        base = build_default_weblate_profile()
    elif args.base_profile:
        raise ContractViolationError(f"Unknown base VDP profile {args.base_profile!r}.")

    image_ref = args.image_ref or (base.image_ref if base is not None else None)
    if not image_ref:
        raise ContractViolationError("--image-ref is required when registering a new VDP profile.")
    image_digest = args.image_digest or (base.expected_image_digest if base is not None else None)
    if not image_digest:
        raise ContractViolationError("--image-digest is required when registering a new VDP profile.")
    source_commit = args.source_commit or (base.expected_source_commit if base is not None else None)
    if not source_commit:
        raise ContractViolationError("--source-commit is required when registering a new VDP profile.")

    checkout_dir = (
        args.checkout_dir
        if args.checkout_dir is not None
        else (base.checkout_dir if base is not None else None)
    )
    network_mode = (
        args.network_mode
        if getattr(args, "network_mode", None) is not None
        else (base.network_mode if base is not None else "none")
    )
    runner_mode = (
        args.runner_mode
        if getattr(args, "runner_mode", None) is not None
        else (base.runner_mode if base is not None else "oss_scanner")
    )
    pytest_executable = (
        args.pytest_executable
        if getattr(args, "pytest_executable", None) is not None
        else (base.pytest_executable if base is not None else None)
    )
    smoke_selectors = (
        _parse_csv_values(getattr(args, "smoke_selector", None), default=())
        if getattr(args, "smoke_selector", None)
        else (base.smoke_selectors if base is not None else ())
    )
    if getattr(args, "service_json", None) is not None:
        raw_svc_payload = json.loads(Path(args.service_json).read_text(encoding="utf-8"))
        raw_svc_list = raw_svc_payload if isinstance(raw_svc_payload, list) else [raw_svc_payload]
        services = tuple(VdpServiceSpec.model_validate(item) for item in raw_svc_list)
    else:
        services = base.services if base is not None else ()

    extra_allowed = _parse_csv_values(args.allow_selector, default=())
    extra_pos = _parse_csv_values(args.positive_selector, default=())
    extra_neg = _parse_csv_values(
        [*(args.negative_selector or ()), *(getattr(args, "defense_selector", None) or ())],
        default=(),
    )
    extra_anom = _parse_csv_values(getattr(args, "anomaly_repro_selector", None), default=())
    extra_env_sels = _parse_csv_values(getattr(args, "env_check_selector", None), default=())

    explicit_role_assignments: dict[str, str] = {}
    for item in getattr(args, "selector_role", None) or ():
        sel_raw, sep, role_raw = str(item).partition("=")
        sel_s = sel_raw.strip()
        role_s = role_raw.strip()
        if not sep or not sel_s or role_s not in VALID_SELECTOR_ROLES:
            raise ContractViolationError(
                f"--selector-role must be SELECTOR=ROLE with ROLE in {VALID_SELECTOR_ROLES}, got {item!r}."
            )
        explicit_role_assignments[sel_s] = role_s

    role_override_selectors = (
        set(extra_pos)
        | set(extra_neg)
        | set(extra_anom)
        | set(extra_env_sels)
        | set(explicit_role_assignments.keys())
    )

    allowed_selectors = tuple(
        dict.fromkeys(
            [
                *(base.allowed_test_selectors if base is not None else ()),
                *extra_allowed,
                *extra_pos,
                *extra_neg,
                *extra_anom,
                *extra_env_sels,
                *explicit_role_assignments.keys(),
            ]
        )
    )
    if not allowed_selectors:
        raise ContractViolationError("At least one selector (--allow-selector or role selector) is required.")

    positive_selectors = tuple(
        dict.fromkeys(
            [
                *(s for s in (base.positive_selectors if base is not None else ()) if s not in role_override_selectors),
                *extra_pos,
                *(s for s, r in explicit_role_assignments.items() if r == "positive_control"),
            ]
        )
    )
    negative_selectors = tuple(
        dict.fromkeys(
            [
                *(s for s in (base.negative_selectors if base is not None else ()) if s not in role_override_selectors),
                *extra_neg,
                *(s for s, r in explicit_role_assignments.items() if r == "defense_check"),
            ]
        )
    )
    anomaly_repro_selectors = tuple(
        dict.fromkeys(
            [
                *(s for s in (base.anomaly_repro_selectors if base is not None else ()) if s not in role_override_selectors),
                *extra_anom,
                *(s for s, r in explicit_role_assignments.items() if r == "anomaly_repro"),
            ]
        )
    )
    env_check_selectors = tuple(
        dict.fromkeys(
            [
                *(s for s in (base.env_check_selectors if base is not None else ()) if s not in role_override_selectors),
                *extra_env_sels,
                *(s for s, r in explicit_role_assignments.items() if r == "env_check"),
            ]
        )
    )
    selector_roles = dict(base.selector_roles) if base is not None else {}
    for s in role_override_selectors:
        selector_roles.pop(s, None)
    selector_roles.update(explicit_role_assignments)

    overlays = dict(base.allowed_overlays) if base is not None else {}
    overlay_verified_on_disk: dict[str, bool] = {}
    if args.overlay_bundle:
        existing_ov = overlays.get(args.overlay_bundle)
        host_dir = (
            args.overlay_host_dir
            if args.overlay_host_dir is not None
            else (existing_ov.host_dir if existing_ov is not None else None)
        )
        if host_dir is None:
            raise ContractViolationError(
                "--overlay-host-dir is required when specifying a new --overlay-bundle."
            )
        allowed_files = dict(existing_ov.allowed_files) if existing_ov is not None else {}

        def _pin_overlay_entry(raw_entry: str, *, default_auto: bool) -> None:
            fname, sep, digest = str(raw_entry).partition("=")
            fname_clean = fname.strip()
            digest_clean = digest.strip().lower() if sep else ("auto" if default_auto else "")
            if not fname_clean or not digest_clean:
                raise ContractViolationError(
                    f"Invalid overlay pin {raw_entry!r}; expected NAME=SHA256 or NAME=auto."
                )
            if digest_clean == "auto":
                digest_clean = _hash_overlay_file_on_disk(host_dir, fname_clean)
                overlay_verified_on_disk[args.overlay_bundle] = True
            elif (host_dir / fname_clean).exists():
                actual_sha = _hash_overlay_file_on_disk(host_dir, fname_clean)
                if actual_sha != digest_clean:
                    raise ContractViolationError(
                        f"On-disk SHA-256 mismatch for overlay file {fname_clean!r}: "
                        f"disk={actual_sha}, provided={digest_clean}."
                    )
                overlay_verified_on_disk[args.overlay_bundle] = True
            allowed_files[fname_clean] = digest_clean

        for fname_raw in getattr(args, "overlay_file", None) or ():
            _pin_overlay_entry(fname_raw, default_auto=True)

        for raw_pin in args.overlay_file_sha256 or ():
            _pin_overlay_entry(raw_pin, default_auto=False)

        if not allowed_files:
            raise ContractViolationError(
                "--overlay-file or --overlay-file-sha256 NAME=SHA256 is required for --overlay-bundle."
            )
        # If host_dir exists on disk, verify every pinned file in this bundle is clean.
        if host_dir.exists() and not overlay_verified_on_disk.get(args.overlay_bundle):
            for fname_clean, exp_sha in allowed_files.items():
                actual_sha = _hash_overlay_file_on_disk(host_dir, fname_clean)
                if actual_sha != exp_sha:
                    raise ContractViolationError(
                        f"On-disk SHA-256 mismatch for overlay file {fname_clean!r}: "
                        f"disk={actual_sha}, expected={exp_sha}."
                    )
            overlay_verified_on_disk[args.overlay_bundle] = True

        overlays[args.overlay_bundle] = VdpOverlaySpec(
            bundle_name=args.overlay_bundle,
            host_dir=host_dir,
            container_target="/src/vdp-test-overlay",
            allowed_files=allowed_files,
        )
    elif args.overlay_host_dir is not None or args.overlay_file_sha256 or getattr(args, "overlay_file", None):
        raise ContractViolationError(
            "--overlay-bundle is required when specifying --overlay-host-dir, --overlay-file, or --overlay-file-sha256."
        )

    expires_at = (
        _parse_iso_datetime(args.expires_at)
        if args.expires_at
        else (base.expires_at if base is not None else None)
    )
    provisional_revision = args.profile_revision or (
        base.profile_revision if base is not None else "r1"
    )
    candidate = VdpTargetProfile(
        profile_name=args.profile_name,
        profile_revision=provisional_revision,
        image_ref=image_ref,
        expected_image_digest=image_digest.strip().lower(),
        expected_source_commit=source_commit.strip().lower(),
        checkout_dir=checkout_dir,
        network_mode=network_mode,
        services=services,
        runner_mode=runner_mode,
        pytest_executable=pytest_executable,
        smoke_selectors=smoke_selectors,
        allowed_test_selectors=allowed_selectors,
        positive_selectors=positive_selectors,
        negative_selectors=negative_selectors,
        anomaly_repro_selectors=anomaly_repro_selectors,
        env_check_selectors=env_check_selectors,
        selector_roles=selector_roles,
        allowed_overlays=overlays,
        max_cpus=(
            args.max_cpus
            if args.max_cpus is not None
            else (base.max_cpus if base is not None else DEFAULT_VDP_TEST_MAX_CPUS)
        ),
        max_memory_mb=(
            args.max_memory_mb
            if args.max_memory_mb is not None
            else (base.max_memory_mb if base is not None else DEFAULT_VDP_TEST_MAX_MEMORY_MB)
        ),
        max_timeout_seconds=(
            args.max_timeout_seconds
            if args.max_timeout_seconds is not None
            else (
                base.max_timeout_seconds
                if base is not None
                else DEFAULT_VDP_TEST_TIMEOUT_SECONDS
            )
        ),
        max_output_bytes=(
            args.max_output_bytes
            if args.max_output_bytes is not None
            else (base.max_output_bytes if base is not None else DEFAULT_VDP_TEST_MAX_OUTPUT_BYTES)
        ),
        expires_at=expires_at,
    )
    validated = validate_vdp_profile_registration(candidate)
    diff = _compute_vdp_profile_diff(base, validated)
    has_diff = _has_nonempty_profile_diff(diff)

    if base is not None and has_diff:
        if args.profile_revision is None:
            bumped_rev = _next_profile_revision(base.profile_revision)
            validated = validated.model_copy(update={"profile_revision": bumped_rev})
            diff["new_revision"] = bumped_rev
        elif args.profile_revision == base.profile_revision:
            raise ContractViolationError(
                f"--profile-revision {args.profile_revision!r} matches existing revision while profile changed; "
                "provide a new revision or omit --profile-revision to auto-increment."
            )

    summary_payload: dict[str, Any] = {
        "status": "dry_run_validated" if args.dry_run else "registered",
        "dry_run": bool(args.dry_run),
        "previous_revision": base.profile_revision if base is not None else None,
        "limits": {
            "max_cpus": validated.max_cpus,
            "max_memory_mb": validated.max_memory_mb,
            "max_timeout_seconds": validated.max_timeout_seconds,
            "max_output_bytes": validated.max_output_bytes,
            "network_mode": validated.network_mode,
            "runner_mode": validated.runner_mode,
            "service_count": len(validated.services),
        },
        "diff": diff,
        "overlay_verified_on_disk": overlay_verified_on_disk,
        **validated.to_public_summary(),
    }
    if not args.dry_run:
        saved_path = save_registered_vdp_profile(settings.vault_root, validated)
        summary_payload["profiles_file"] = str(saved_path)

    _emit_json(summary_payload)
    return 0


def _handle_check_vdp_env(args: argparse.Namespace, env: Mapping[str, str] | None) -> int:
    eff_env = _merge_runtime_env(
        env=env,
        db_path=getattr(args, "db_path", None),
        vault_root=getattr(args, "vault_root", None),
    )
    settings = load_runtime_settings(eff_env)
    profiles: dict[str, VdpTargetProfile] = {
        WEBLATE_2026_11_2_PROFILE_NAME: build_default_weblate_profile()
    }
    if settings.vault_root is not None:
        profiles.update(load_registered_vdp_profiles(settings.vault_root))

    profile_name = args.profile_name or WEBLATE_2026_11_2_PROFILE_NAME
    profile = profiles.get(profile_name)
    if profile is None:
        hint = next((p for p in profiles.values() if p.profile_revision == profile_name), None)
        if hint is not None:
            raise ContractViolationError(
                f"{profile_name!r} is a profile_revision; pass --profile-name {hint.profile_name!r}."
            )
        raise ContractViolationError(f"Unknown VDP profile {profile_name!r}.")

    report = run_vdp_environment_check(
        profile,
        docker_bin=args.docker_bin,
        overlay_bundle=args.overlay_bundle,
        include_host_paths=True,
    )
    _emit_json(report)
    return 0 if report["healthy"] else 1




def _handle_import_manual_observation(args: argparse.Namespace, env: Mapping[str, str] | None) -> int:
    controller, principal, _ = _resolve_admin_context(args, env=env)
    snapshot = controller.runs.get_run_snapshot(args.run_id)
    owner = _owner_principal(snapshot, principal)

    raw_payload = read_bounded_manual_json_file(Path(args.manifest_json))

    file_hashes = dict(raw_payload.get("test_code_hashes") or {})
    for tf in getattr(args, "test_file", None) or ():
        fname, fhash = hash_manual_test_file(Path(tf))
        if fname in file_hashes and str(file_hashes[fname]).strip().lower() != fhash:
            raise ContractViolationError(
                f"Hash mismatch for manual test file {fname!r}: manifest={file_hashes[fname]!r}, disk={fhash!r}."
            )
        file_hashes[fname] = fhash
    raw_payload["test_code_hashes"] = file_hashes

    if getattr(args, "raw_log_file", None) is not None:
        _, log_hash = hash_manual_test_file(Path(args.raw_log_file), max_bytes=10_485_760)
        raw_payload["raw_log_sha256"] = log_hash

    strict_mode = bool(getattr(args, "strict", False))
    raw_payload.setdefault("intake_channel", "cli")
    observation = ManualObservationRecord.model_validate(raw_payload)
    receipt = controller.import_manual_observation(
        principal=owner,
        run_id=args.run_id,
        observation=observation,
        strict_intake=strict_mode,
        intake_channel="cli",
    )
    _emit_json(
        {
            "run_id": receipt.run_id,
            "action_id": receipt.action_id,
            "evidence_id": receipt.evidence_id,
            "observation_id": observation.observation_id,
            "execution_provenance": observation.execution_provenance,
            "verification_tier": observation.verification_tier,
            "promoted_to_vdp_product_test": False,
            "intake_channel": "cli",
            "verified_sha256": receipt.verified_sha256,
            "test_code_hashes": observation.test_code_hashes,
            "cleanup_confirmation": observation.cleanup_confirmation.model_dump(mode="json"),
        }
    )
    return 0


def _handle_export_vdp_draft(args: argparse.Namespace, env: Mapping[str, str] | None) -> int:
    controller, principal, _ = _resolve_admin_context(args, env=env)
    snapshot = controller.runs.get_run_snapshot(args.run_id)
    owner = _owner_principal(snapshot, principal)
    draft_raw = json.loads(Path(args.draft_json).read_text(encoding="utf-8"))
    draft = VdpDraftSpec.model_validate(draft_raw)
    result = controller.export_vdp_submission_draft(
        principal=owner,
        run_id=args.run_id,
        draft=draft,
        language=args.language,
        output_relpath=args.output_relpath,
        overwrite=bool(args.overwrite),
    )
    _emit_json(
        {
            "run_id": result.run_id,
            "finding_id": result.finding_id,
            "language": result.language,
            "draft_sha256": result.draft_sha256,
            "output_path": result.output_path,
            "state": result.submission_record.state.value,
            "automatic_submission": False,
            "evidence_ids": list(result.submission_record.evidence_ids),
        }
    )
    return 0


def _handle_record_vdp_submission(args: argparse.Namespace, env: Mapping[str, str] | None) -> int:
    controller, principal, _ = _resolve_admin_context(args, env=env)
    snapshot = controller.runs.get_run_snapshot(args.run_id)
    owner = _owner_principal(snapshot, principal)
    updated = controller.record_vdp_submission(
        principal=owner,
        run_id=args.run_id,
        finding_id=args.finding_id,
        target_state=FindingState(args.status),
        report_url=args.report_url,
        recorded_by=args.recorded_by,
        report_ref=args.report_ref,
        triage_status=args.triage_status,
        submitted_at=_parse_iso_datetime(args.submitted_at),
        notes=args.note or "",
    )
    _emit_json(updated.model_dump(mode="json"))
    return 0


def _handle_list_vdp_submissions(args: argparse.Namespace, env: Mapping[str, str] | None) -> int:
    controller, principal, _ = _resolve_admin_context(args, env=env)
    snapshot = controller.runs.get_run_snapshot(args.run_id)
    owner = _owner_principal(snapshot, principal)
    items = controller.list_vdp_submissions(principal=owner, run_id=args.run_id)
    _emit_json(
        {
            "run_id": args.run_id,
            "automatic_submission": False,
            "submissions": [item.model_dump(mode="json") for item in items],
        }
    )
    return 0


_CANDIDATE_JSON_ALLOWED_KEYS = frozenset(
    {
        "candidate_id",
        "title",
        "target_name",
        "target_version",
        "pinned_source_commit",
        "status",
        "preconditions",
        "checkpoint",
        "evidence_ids",
        "first_candidate_observed_at",
    }
)


def _handle_record_vdp_candidate(args: argparse.Namespace, env: Mapping[str, str] | None) -> int:
    controller, principal, _ = _resolve_admin_context(args, env=env)
    snapshot = controller.runs.get_run_snapshot(args.run_id)
    owner = _owner_principal(snapshot, principal)
    raw = read_bounded_candidate_json_file(Path(args.candidate_json))
    unknown_keys = sorted(set(raw.keys()) - _CANDIDATE_JSON_ALLOWED_KEYS)
    if unknown_keys:
        raise ContractViolationError(
            f"Candidate JSON contains unknown field(s): {unknown_keys}."
        )
    preconditions = CandidatePreconditions.model_validate(raw.get("preconditions"))
    raw_cp = raw.get("checkpoint")
    checkpoint = KnownIssueCheckpoint.model_validate(raw_cp) if raw_cp is not None else None
    raw_first = raw.get("first_candidate_observed_at")
    first_obs = _parse_iso_datetime(str(raw_first)) if raw_first is not None else None
    raw_eids = raw.get("evidence_ids") or ()
    if not isinstance(raw_eids, list):
        raise ContractViolationError("evidence_ids in candidate JSON must be a list of strings.")
    record = controller.record_vdp_candidate_checkpoint(
        principal=owner,
        run_id=args.run_id,
        candidate_id=str(raw.get("candidate_id") or ""),
        title=str(raw.get("title") or ""),
        target_name=str(raw.get("target_name") or ""),
        target_version=str(raw.get("target_version") or ""),
        pinned_source_commit=str(raw.get("pinned_source_commit") or ""),
        preconditions=preconditions,
        checkpoint=checkpoint,
        status=raw.get("status", "investigation_candidate"),
        evidence_ids=tuple(str(x) for x in raw_eids),
        first_candidate_observed_at=first_obs,
    )
    now = controller._now()
    _emit_json(
        {
            "run_id": args.run_id,
            "external_search_performed_by_harness": False,
            "auto_promoted_to_confirmed_vulnerability": False,
            "record": record.model_dump(mode="json"),
            "gates": {
                "pre_heavy_test": evaluate_candidate_gate(
                    record, gate="pre_heavy_test", now=now
                ).model_dump(mode="json"),
                "pre_submission": evaluate_candidate_gate(
                    record, gate="pre_submission", now=now
                ).model_dump(mode="json"),
            },
        }
    )
    return 0


def _handle_check_vdp_candidate_gate(args: argparse.Namespace, env: Mapping[str, str] | None) -> int:
    controller, principal, _ = _resolve_admin_context(args, env=env)
    snapshot = controller.runs.get_run_snapshot(args.run_id)
    owner = _owner_principal(snapshot, principal)
    evaluation = controller.evaluate_vdp_candidate_gate(
        principal=owner,
        run_id=args.run_id,
        candidate_id=args.candidate_id,
        gate=args.gate,
    )
    _emit_json(evaluation.model_dump(mode="json"))
    return 0 if evaluation.ready else 1


def _handle_list_vdp_candidates(args: argparse.Namespace, env: Mapping[str, str] | None) -> int:
    controller, principal, _ = _resolve_admin_context(args, env=env)
    snapshot = controller.runs.get_run_snapshot(args.run_id)
    owner = _owner_principal(snapshot, principal)
    items = controller.list_vdp_candidate_checkpoints(principal=owner, run_id=args.run_id)
    metrics = summarize_vdp_candidate_metrics(
        items,
        run_created_at=snapshot.manifest.created_at,
        now=controller._now(),
    )
    _emit_json(
        {
            "run_id": args.run_id,
            "external_search_performed_by_harness": False,
            "auto_promoted_to_confirmed_vulnerability": False,
            "candidates": [item.model_dump(mode="json") for item in items],
            "metrics": metrics,
        }
    )
    return 0


def _handle_diagnose_mcp(args: argparse.Namespace, env: Mapping[str, str] | None) -> int:
    eff_env = _merge_runtime_env(
        env=env,
        db_path=getattr(args, "db_path", None),
        vault_root=getattr(args, "vault_root", None),
    )
    report = collect_mcp_diagnostics(
        env=eff_env,
        config_path=getattr(args, "config", None),
        active_run_id=getattr(args, "active_run", None),
        check_docker=bool(getattr(args, "check_docker", False)),
        docker_bin=getattr(args, "docker_bin", "docker"),
    )
    _emit_json(report)
    return 0 if report["healthy"] else 1

def build_admin_parser() -> argparse.ArgumentParser:
    """Build argument parser for ``ctf-mcp-admin`` local operator commands."""
    parser = argparse.ArgumentParser(
        prog="ctf-mcp-admin",
        description="Local administrative CLI for the CTF/VDP Analysis Harness (fail-closed, shell=False).",
    )
    _add_common_admin_flags(parser, suppress_defaults=False)

    subparsers = parser.add_subparsers(dest="command", required=True)

    p_create = subparsers.add_parser("create-run", help="Create a new bounded run with initial scope.")
    _add_common_admin_flags(p_create, suppress_defaults=True)
    p_create.add_argument("--task-id", default=None, help="Owned task identifier.")
    p_create.add_argument("--run-id", default=None, help="Optional explicit run_id.")
    p_create.add_argument("--mode", choices=[m.value for m in RunMode], default=None)
    p_create.add_argument("--scope-revision", default=None, help="Immutable scope revision label.")
    p_create.add_argument("--auth-ref", default=None, help="Local authorization reference.")
    p_create.add_argument("--allowed-capabilities", action="append", default=None)
    p_create.add_argument("--allowed-execution-classes", action="append", default=None)
    p_create.add_argument("--expires-at", default=None, help="Optional ISO-8601 expiry timestamp.")
    p_create.add_argument("--instruction-revision", default=None)
    p_create.add_argument("--run-budget-seconds", type=int, default=None)
    p_create.add_argument("--action-timeout-seconds", type=int, default=None)
    p_create.add_argument("--session-idle-seconds", type=int, default=None)
    p_create.add_argument("--max-tool-calls", type=int, default=None)
    p_create.add_argument("--max-evidence-bytes", type=int, default=None)
    p_create.add_argument("--heavy-job-concurrency", type=int, default=None)
    p_create.add_argument("--interactive-session-limit", type=int, default=None)
    p_create.add_argument("--network-enabled", action="store_true", default=False)
    p_create.add_argument("--allowed-target", action="append", default=None)
    p_create.add_argument("--external-submission", action="store_true", default=False)

    p_scope = subparsers.add_parser("register-scope", help="Register/activate an immutable scope revision.")
    _add_common_admin_flags(p_scope, suppress_defaults=True)
    p_scope.add_argument("--run-id", required=True)
    p_scope.add_argument("--scope-revision", required=True)
    p_scope.add_argument("--auth-ref", required=True)
    p_scope.add_argument("--task-id", default=None)
    p_scope.add_argument("--mode", choices=[m.value for m in RunMode], default=None)
    p_scope.add_argument("--allowed-capabilities", action="append", default=None)
    p_scope.add_argument("--allowed-execution-classes", action="append", default=None)
    p_scope.add_argument("--expires-at", default=None)
    p_scope.add_argument("--no-activate", action="store_true", default=False)
    p_scope.add_argument("--network-enabled", action="store_true", default=False)
    p_scope.add_argument("--allowed-target", action="append", default=None)
    p_scope.add_argument("--external-submission", action="store_true", default=False)

    p_ingest = subparsers.add_parser("ingest-artifact", help="Ingest a confined input artifact with SHA-256.")
    _add_common_admin_flags(p_ingest, suppress_defaults=True)
    p_ingest.add_argument("--run-id", required=True)
    p_ingest.add_argument("--source-root", type=Path, required=True)
    p_ingest.add_argument("--rel-path", required=True)
    p_ingest.add_argument("--media-type", default="application/octet-stream")
    p_ingest.add_argument("--source-origin", default=None)

    p_expect = subparsers.add_parser(
        "register-expectation",
        help="Register a digest-only expected SHA-256 spec in the private vault.",
    )
    _add_common_admin_flags(p_expect, suppress_defaults=True)
    p_expect.add_argument("--run-id", default=None)
    p_expect.add_argument("--task-id", default=None)
    p_expect.add_argument("--flag-sha256", default=None, help="Lowercase 64-hex expected flag SHA-256.")
    p_expect.add_argument("--evidence-sha256", default=None, help="Lowercase 64-hex expected evidence SHA-256.")
    p_expect.add_argument("--salt", default="", help="Optional verifier salt (never echoed).")
    p_expect.add_argument("--no-normalize-whitespace", action="store_true", default=False)
    p_expect.add_argument("--allow-incomplete-capture", action="store_true", default=False)
    p_expect.add_argument("--description", default="Operator-registered expected digest")

    p_rec = subparsers.add_parser(
        "reconcile",
        help="Run startup crash reconciliation sweep or resolve one reconciliation_required action.",
    )
    _add_common_admin_flags(p_rec, suppress_defaults=True)
    p_rec.add_argument("--action-id", default=None)
    p_rec.add_argument(
        "--target-state",
        choices=["failed", "cancelled", "timeout", "completed", "partial", "expired"],
        default="failed",
    )
    p_rec.add_argument("--summary", default="Resolved by operator crash reconciliation.")
    p_rec.add_argument("--error-code", default=None)
    p_rec.add_argument("--error-message", default=None)
    p_rec.add_argument("--wall-ms", type=int, default=0)
    p_rec.add_argument("--output-bytes", type=int, default=0)
    p_rec.add_argument("--retain-reservation", action="store_true", default=False)
    p_rec.add_argument("--usage-unknown", action="store_true", default=False)
    p_rec.add_argument("--cleanup-unconfirmed", action="store_true", default=False)
    p_rec.add_argument("--expire-leases", action="store_true", default=False)

    p_recover = subparsers.add_parser(
        "recover-guest",
        help="Restore guest_health from cleanup_unconfirmed to ready after cleanup verification.",
    )
    _add_common_admin_flags(p_recover, suppress_defaults=True)
    p_recover.add_argument("--run-id", required=True)
    p_recover.add_argument(
        "--cleanup-verified",
        action="store_true",
        default=False,
        help="Required explicit confirmation that orphan guest processes/state were cleaned up.",
    )
    p_recover.add_argument("--note", required=True, help="Non-empty cleanup verification note.")

    p_desc = subparsers.add_parser("describe-run", help="Print sanitized run state, actions, and leases.")
    _add_common_admin_flags(p_desc, suppress_defaults=True)
    p_desc.add_argument("--run-id", required=True)

    p_budget = subparsers.add_parser(
        "update-budget",
        help="Adjust run budget limits and remaining allowances without incrementing run revision.",
    )
    _add_common_admin_flags(p_budget, suppress_defaults=True)
    p_budget.add_argument("--run-id", required=True)
    p_budget.add_argument("--max-tool-calls", type=int, default=None)
    p_budget.add_argument("--remaining-calls", type=int, default=None)
    p_budget.add_argument("--add-calls", type=int, default=None)
    p_budget.add_argument("--run-budget-seconds", type=int, default=None)
    p_budget.add_argument("--remaining-ms", type=int, default=None)
    p_budget.add_argument("--max-evidence-bytes", type=int, default=None)
    p_budget.add_argument("--remaining-bytes", type=int, default=None)
    p_budget.add_argument("--interactive-session-limit", type=int, default=None)
    p_budget.add_argument("--heavy-job-concurrency", type=int, default=None)
    p_budget.add_argument("--action-timeout-seconds", type=int, default=None)

    p_up_scope = subparsers.add_parser(
        "update-scope",
        help="Register and activate an updated scope revision on an open run without incrementing run revision.",
    )
    _add_common_admin_flags(p_up_scope, suppress_defaults=True)
    p_up_scope.add_argument("--run-id", required=True)
    p_up_scope.add_argument("--scope-revision", required=True)
    p_up_scope.add_argument("--allowed-capabilities", action="append", default=None)
    p_up_scope.add_argument("--add-capability", action="append", default=None)
    p_up_scope.add_argument("--allowed-execution-classes", action="append", default=None)
    p_up_scope.add_argument("--auth-ref", default=None)
    p_up_scope.add_argument("--expires-at", default=None)
    p_up_scope.add_argument("--network-enabled", action="store_true", default=False)
    p_up_scope.add_argument("--disable-network", action="store_true", default=False)
    p_up_scope.add_argument("--allowed-target", action="append", default=None)

    p_vdp_reg = subparsers.add_parser(
        "register-vdp-profile",
        help="Validate and persist a pinned VDP product-test profile under <vault_root>/_vdp/profiles.json.",
    )
    _add_common_admin_flags(p_vdp_reg, suppress_defaults=True)
    p_vdp_reg.add_argument("--profile-name", required=True)
    p_vdp_reg.add_argument("--profile-revision", default=None)
    p_vdp_reg.add_argument("--base-profile", default=None)
    p_vdp_reg.add_argument("--image-ref", default=None)
    p_vdp_reg.add_argument("--image-digest", default=None)
    p_vdp_reg.add_argument("--source-commit", default=None)
    p_vdp_reg.add_argument("--checkout-dir", type=Path, default=None)
    p_vdp_reg.add_argument(
        "--network-mode",
        choices=list(VALID_VDP_NETWORK_MODES),
        default=None,
        help="Network isolation mode ('none' or 'isolated_internal_services').",
    )
    p_vdp_reg.add_argument(
        "--service-json",
        type=Path,
        default=None,
        help="Path to JSON defining pinned internal VdpServiceSpec object(s).",
    )
    p_vdp_reg.add_argument(
        "--runner-mode",
        choices=list(VALID_VDP_RUNNER_MODES),
        default=None,
        help="Container test runner mode ('oss_scanner' or 'direct_pytest').",
    )
    p_vdp_reg.add_argument("--pytest-executable", default=None)
    p_vdp_reg.add_argument("--smoke-selector", action="append", default=None)
    p_vdp_reg.add_argument("--allow-selector", action="append", default=None)
    p_vdp_reg.add_argument("--positive-selector", action="append", default=None)
    p_vdp_reg.add_argument("--negative-selector", action="append", default=None)
    p_vdp_reg.add_argument("--defense-selector", action="append", default=None)
    p_vdp_reg.add_argument("--anomaly-repro-selector", action="append", default=None)
    p_vdp_reg.add_argument("--env-check-selector", action="append", default=None)
    p_vdp_reg.add_argument(
        "--selector-role",
        action="append",
        default=None,
        help="Assign an explicit selector role as SELECTOR=ROLE (positive_control|defense_check|anomaly_repro|env_check).",
    )
    p_vdp_reg.add_argument("--overlay-bundle", default=None)
    p_vdp_reg.add_argument("--overlay-host-dir", type=Path, default=None)
    p_vdp_reg.add_argument("--overlay-file-sha256", action="append", default=None)
    p_vdp_reg.add_argument(
        "--overlay-file",
        action="append",
        default=None,
        help="Pin an overlay file under --overlay-host-dir as REL_PATH=auto or REL_PATH=SHA256.",
    )
    p_vdp_reg.add_argument("--max-cpus", type=int, default=None)
    p_vdp_reg.add_argument("--max-memory-mb", type=int, default=None)
    p_vdp_reg.add_argument("--max-timeout-seconds", type=int, default=None)
    p_vdp_reg.add_argument("--max-output-bytes", type=int, default=None)
    p_vdp_reg.add_argument("--expires-at", default=None)
    p_vdp_reg.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate the profile, inspect the diff, and emit JSON without writing profiles.json.",
    )

    p_vdp_check = subparsers.add_parser(
        "check-vdp-env",
        help="Verify pinned VDP profile expiry, Docker image digest, git checkout HEAD, and overlay file SHA-256s.",
    )
    _add_common_admin_flags(p_vdp_check, suppress_defaults=True)
    p_vdp_check.add_argument("--profile-name", default="weblate")
    p_vdp_check.add_argument("--overlay-bundle", default=None)
    p_vdp_check.add_argument("--docker-bin", default="docker")

    p_boundary = register_boundary_map_subparser(subparsers)
    _add_common_admin_flags(p_boundary, suppress_defaults=True)

    p_auth_mat = register_auth_matrix_subparser(subparsers)
    _add_common_admin_flags(p_auth_mat, suppress_defaults=True)

    register_overlay_assistant_subparser(
        subparsers,
        add_common_flags=lambda p: _add_common_admin_flags(p, suppress_defaults=True),
    )

    p_man = subparsers.add_parser(
        "import-manual-observation",
        help="Import an out-of-harness manual isolated observation with pinned test hashes (never promoted to vdp.product_test).",
    )
    _add_common_admin_flags(p_man, suppress_defaults=True)
    p_man.add_argument("--run-id", required=True)
    p_man.add_argument("--manifest-json", type=Path, required=True)
    p_man.add_argument("--test-file", action="append", type=Path, default=None)
    p_man.add_argument("--raw-log-file", type=Path, default=None)
    p_man.add_argument("--strict", action="store_true", default=False)

    p_draft = subparsers.add_parser(
        "export-vdp-draft",
        help="Render and validate a human-reviewable VDP submission draft (never auto-submits).",
    )
    _add_common_admin_flags(p_draft, suppress_defaults=True)
    p_draft.add_argument("--run-id", required=True)
    p_draft.add_argument("--draft-json", type=Path, required=True)
    p_draft.add_argument("--output-relpath", default=None)
    p_draft.add_argument("--language", choices=["ja", "en"], default="ja")
    p_draft.add_argument("--overwrite", action="store_true", default=False)

    p_sub_rec = subparsers.add_parser(
        "record-vdp-submission",
        help="Manually record report URL and submission status after operator disclosure (no auto-submit).",
    )
    _add_common_admin_flags(p_sub_rec, suppress_defaults=True)
    p_sub_rec.add_argument("--run-id", required=True)
    p_sub_rec.add_argument("--finding-id", required=True)
    p_sub_rec.add_argument("--status", choices=["submitted", "accepted"], default="submitted")
    p_sub_rec.add_argument("--report-url", required=True)
    p_sub_rec.add_argument("--recorded-by", required=True)
    p_sub_rec.add_argument("--report-ref", default=None)
    p_sub_rec.add_argument(
        "--triage-status",
        choices=["not_submitted", "unconfirmed", "triaged", "duplicate", "informative", "accepted", "resolved"],
        default="unconfirmed",
    )
    p_sub_rec.add_argument("--submitted-at", default=None)
    p_sub_rec.add_argument("--note", default="")

    p_sub_list = subparsers.add_parser(
        "list-vdp-submissions",
        help="List manually tracked VDP submission records for a run.",
    )
    _add_common_admin_flags(p_sub_list, suppress_defaults=True)
    p_sub_list.add_argument("--run-id", required=True)

    p_cand_rec = subparsers.add_parser(
        "record-vdp-candidate",
        help="Record or update a VDP candidate's preconditions and known-issue gate checkpoint.",
    )
    _add_common_admin_flags(p_cand_rec, suppress_defaults=True)
    p_cand_rec.add_argument("--run-id", required=True)
    p_cand_rec.add_argument("--candidate-json", type=Path, required=True)

    p_cand_gate = subparsers.add_parser(
        "check-vdp-candidate-gate",
        help="Evaluate a VDP candidate's pre_heavy_test or pre_submission known-issue gate.",
    )
    _add_common_admin_flags(p_cand_gate, suppress_defaults=True)
    p_cand_gate.add_argument("--run-id", required=True)
    p_cand_gate.add_argument("--candidate-id", required=True)
    p_cand_gate.add_argument("--gate", choices=list(VALID_CHECKPOINT_GATES), required=True)

    p_cand_list = subparsers.add_parser(
        "list-vdp-candidates",
        help="List VDP candidate known-issue/precondition checkpoints and metrics for a run.",
    )
    _add_common_admin_flags(p_cand_list, suppress_defaults=True)
    p_cand_list.add_argument("--run-id", required=True)

    p_diag = subparsers.add_parser(
        "diagnose-mcp",
        help="Run read-only MCP config, tool schema fingerprint, run-state, and optional Docker hygiene diagnostics.",
    )
    _add_common_admin_flags(p_diag, suppress_defaults=True)
    p_diag.add_argument("--active-run", default=None)
    p_diag.add_argument("--check-docker", action="store_true", default=False)
    p_diag.add_argument("--docker-bin", default="docker")

    return parser


def admin_main(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> int:
    """Entrypoint for ``ctf-mcp-admin`` local administrative commands."""
    parser = build_admin_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    handlers = {
        "create-run": _handle_create_run,
        "register-scope": _handle_register_scope,
        "ingest-artifact": _handle_ingest_artifact,
        "register-expectation": _handle_register_expectation,
        "reconcile": _handle_reconcile,
        "recover-guest": _handle_recover_guest,
        "describe-run": _handle_describe_run,
        "update-budget": _handle_update_budget,
        "update-scope": _handle_update_scope,
        "register-vdp-profile": _handle_register_vdp_profile,
        "check-vdp-env": _handle_check_vdp_env,
        BOUNDARY_MAP_SUBCOMMAND: handle_boundary_map_cli,
        AUTH_MATRIX_COMMAND: handle_auth_matrix_cli,
        OVERLAY_ASSISTANT_COMMAND: handle_overlay_assistant,
        "import-manual-observation": _handle_import_manual_observation,
        "export-vdp-draft": _handle_export_vdp_draft,
        "record-vdp-submission": _handle_record_vdp_submission,
        "list-vdp-submissions": _handle_list_vdp_submissions,
        "record-vdp-candidate": _handle_record_vdp_candidate,
        "check-vdp-candidate-gate": _handle_check_vdp_candidate_gate,
        "list-vdp-candidates": _handle_list_vdp_candidates,
        "diagnose-mcp": _handle_diagnose_mcp,
    }
    try:
        return handlers[args.command](args, env)
    except (HarnessError, ValueError) as exc:
        msg = sanitize_audit_text(str(exc)) or type(exc).__name__
        sys.stderr.write(f"error ({type(exc).__name__}): {msg}\n")
        return 2


def build_server_parser() -> argparse.ArgumentParser:
    """Build argument parser for ``ctf-mcp-server``."""
    parser = argparse.ArgumentParser(
        prog="ctf-mcp-server",
        description="Launch the CTF/VDP Analysis Harness FastMCP server (StaticInspector + LocalCtfVerifier).",
    )
    parser.add_argument("--db-path", type=Path, default=None, help="SQLite DB path (or CTF_MCP_DB_PATH).")
    parser.add_argument("--vault-root", type=Path, default=None, help="Private vault root (or CTF_MCP_VAULT_ROOT).")
    parser.add_argument("--config", type=Path, default=None, help="Validated executable HarnessConfig JSON.")
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default=None,
        help="MCP transport mode (default from CTF_MCP_TRANSPORT or stdio).",
    )
    parser.add_argument(
        "--profile",
        choices=[m.value for m in RunMode],
        default=None,
        help="Run profile override (or CTF_MCP_PROFILE).",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind host for streamable-http.")
    parser.add_argument("--port", type=int, default=8000, help="Bind port for streamable-http.")
    parser.add_argument("--path", default="/mcp", help="HTTP endpoint path for streamable-http.")
    parser.add_argument("--active-run", default=None, help="Optional default active run_id for stdio listing.")
    parser.add_argument(
        "--allow-ephemeral-cursor-key",
        action="store_true",
        default=False,
        help="Explicit opt-in for ephemeral cursor HMAC key in local dev only.",
    )
    parser.add_argument(
        "--allow-dynamic",
        action="store_true",
        default=False,
        help="Explicit opt-in to allow ExecutionClass.DYNAMIC capabilities (or CTF_MCP_ALLOW_DYNAMIC=1).",
    )
    parser.add_argument(
        "--enable-transform-helper",
        action="store_true",
        default=False,
        help="Explicit opt-in to register helper.transform adapter.",
    )
    parser.add_argument(
        "--enable-interactive-session",
        action="store_true",
        default=False,
        help="Explicit opt-in to register session.control interactive session adapter.",
    )
    parser.add_argument(
        "--enable-vdp-product-test",
        action="store_true",
        default=False,
        help="Explicit opt-in to register vdp.test bounded product-test adapter.",
    )
    return parser


def server_main(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    start_server: bool = True,
) -> int:
    """Entrypoint for ``ctf-mcp-server`` wiring StaticArtifactInspectorAdapter + LocalCtfVerifier."""
    parser = build_server_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    eff_env = _merge_runtime_env(
        env=env,
        db_path=args.db_path,
        vault_root=args.vault_root,
        transport=args.transport,
        profile=args.profile,
    )
    try:
        server = build_server_from_env(
            eff_env,
            config_path=args.config,
            allow_ephemeral_cursor_key=bool(args.allow_ephemeral_cursor_key),
            allow_dynamic=True if args.allow_dynamic else None,
            include_transform_helper=True if args.enable_transform_helper else None,
            include_interactive_session=True if args.enable_interactive_session else None,
            include_vdp_product_test=True if args.enable_vdp_product_test else None,
        )
        if server.controller.allow_synthetic_adapters:
            raise ConfigurationError("SyntheticAdapter cannot be enabled in production server CLI.")
        if args.active_run:
            server.set_active_run(args.active_run)
        if start_server:
            server.run(host=args.host, port=args.port, path=args.path)
        return 0
    except (HarnessError, ValueError) as exc:
        msg = sanitize_audit_text(str(exc)) or type(exc).__name__
        sys.stderr.write(f"error ({type(exc).__name__}): {msg}\n")
        return 2


__all__ = [
    "admin_main",
    "build_admin_parser",
    "build_server_parser",
    "server_main",
]
