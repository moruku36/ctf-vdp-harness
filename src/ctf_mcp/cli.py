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
import json
import os
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
    WEBLATE_2026_11_2_PROFILE_NAME,
    VdpOverlaySpec,
    VdpTargetProfile,
    build_default_weblate_profile,
    load_registered_vdp_profiles,
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
from ctf_mcp.gateway import sanitize_audit_text
from ctf_mcp.server import build_server_from_env
from ctf_mcp.storage import Storage
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

    profile_revision = args.profile_revision or (
        base.profile_revision if base is not None else "r1"
    )
    checkout_dir = (
        args.checkout_dir
        if args.checkout_dir is not None
        else (base.checkout_dir if base is not None else None)
    )

    extra_allowed = _parse_csv_values(args.allow_selector, default=())
    extra_pos = _parse_csv_values(args.positive_selector, default=())
    extra_neg = _parse_csv_values(args.negative_selector, default=())

    allowed_selectors = tuple(
        dict.fromkeys([*(base.allowed_test_selectors if base is not None else ()), *extra_allowed])
    )
    if not allowed_selectors:
        raise ContractViolationError("At least one --allow-selector is required.")
    positive_selectors = tuple(
        dict.fromkeys([*(base.positive_selectors if base is not None else ()), *extra_pos])
    )
    negative_selectors = tuple(
        dict.fromkeys([*(base.negative_selectors if base is not None else ()), *extra_neg])
    )

    overlays = dict(base.allowed_overlays) if base is not None else {}
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
        for raw_pin in args.overlay_file_sha256 or ():
            fname, sep, digest = str(raw_pin).partition("=")
            if not sep or not fname.strip() or not digest.strip():
                raise ContractViolationError(
                    f"--overlay-file-sha256 must have format NAME=SHA256, got {raw_pin!r}."
                )
            allowed_files[fname.strip()] = digest.strip().lower()
        if not allowed_files:
            raise ContractViolationError(
                "--overlay-file-sha256 NAME=SHA256 is required for --overlay-bundle."
            )
        overlays[args.overlay_bundle] = VdpOverlaySpec(
            bundle_name=args.overlay_bundle,
            host_dir=host_dir,
            container_target="/src/vdp-test-overlay",
            allowed_files=allowed_files,
        )
    elif args.overlay_host_dir is not None or args.overlay_file_sha256:
        raise ContractViolationError(
            "--overlay-bundle is required when specifying --overlay-host-dir or --overlay-file-sha256."
        )

    expires_at = (
        _parse_iso_datetime(args.expires_at)
        if args.expires_at
        else (base.expires_at if base is not None else None)
    )
    profile = VdpTargetProfile(
        profile_name=args.profile_name,
        profile_revision=profile_revision,
        image_ref=image_ref,
        expected_image_digest=image_digest.strip().lower(),
        expected_source_commit=source_commit.strip().lower(),
        checkout_dir=checkout_dir,
        allowed_test_selectors=allowed_selectors,
        positive_selectors=positive_selectors,
        negative_selectors=negative_selectors,
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
    validated = validate_vdp_profile_registration(profile)
    saved_path = save_registered_vdp_profile(settings.vault_root, validated)
    _emit_json(
        {
            "status": "registered",
            "profiles_file": str(saved_path),
            **validated.to_public_summary(),
        }
    )
    return 0


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
    p_vdp_reg.add_argument("--allow-selector", action="append", default=None)
    p_vdp_reg.add_argument("--positive-selector", action="append", default=None)
    p_vdp_reg.add_argument("--negative-selector", action="append", default=None)
    p_vdp_reg.add_argument("--overlay-bundle", default=None)
    p_vdp_reg.add_argument("--overlay-host-dir", type=Path, default=None)
    p_vdp_reg.add_argument("--overlay-file-sha256", action="append", default=None)
    p_vdp_reg.add_argument("--max-cpus", type=int, default=None)
    p_vdp_reg.add_argument("--max-memory-mb", type=int, default=None)
    p_vdp_reg.add_argument("--max-timeout-seconds", type=int, default=None)
    p_vdp_reg.add_argument("--max-output-bytes", type=int, default=None)
    p_vdp_reg.add_argument("--expires-at", default=None)

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
