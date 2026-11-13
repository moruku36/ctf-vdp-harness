"""Layer 3 use-case orchestration controller for the CTF/VDP analysis harness.

Coordinates authentication, run lifecycle, scope enforcement, capability
catalog validation, single-source budget accounting, TX-separated bounded
subprocess execution, evidence redaction/paging, hypothesis tracking, local
verification, audit sanitization, crash reconciliation, and ordered run closure.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import sqlite3
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from ctf_mcp.adapters import (
    PRODUCTION_DEFAULT_ENABLED as SYNTHETIC_PRODUCTION_DEFAULT_ENABLED,
    StaticArtifactInspectorAdapter,
    SyntheticAdapter,
    is_os_process_alive,
)
from ctf_mcp.config import (
    HarnessConfig,
    RuntimeSettings,
    get_cursor_hmac_key,
)
from ctf_mcp.contracts import (
    ActionConflictError,
    ActionLifecycleState,
    ActionRecord,
    ActionRequest,
    ArtifactRecord,
    AuditEvent,
    BudgetSpec,
    CapabilityDeniedError,
    CapabilityDescriptor,
    ConfigurationError,
    ContractViolationError,
    EnvelopeStatus,
    ErrorDetail,
    EvidencePage,
    EvidenceRef,
    ExecutionClass,
    FindingRecord,
    GuestBlockedError,
    GuestHealthState,
    HypothesisRecord,
    HypothesisState,
    InvalidStateTransitionError,
    PrincipalContext,
    ProvenanceInfo,
    ResultEnvelope,
    RunManifest,
    RunMode,
    ScopeDeniedError,
    ScopePolicy,
    UsageMetrics,
    VerificationRecord,
    lifecycle_to_envelope_status,
)
from ctf_mcp.evidence import (
    BoundedEvidenceImporter,
    EvidenceRedactor,
    EvidenceVault,
    ExportResult,
    ImportReceipt,
    RedactedViewOutcome,
    ReportMetadata,
    RunReportExporter,
    scan_sensitive_markers,
)
from ctf_mcp.fs_guard import safe_read_bounded, safe_write_atomic
from ctf_mcp.gateway import (
    ArtifactIntakeService,
    AuditLogger,
    BudgetReservation,
    CapabilityCatalog,
    IntakeLimits,
    PrincipalAuthenticator,
    ScopeValidator,
    contains_sensitive_marker,
    get_budget_snapshot_in_tx,
    reserve_run_budget_in_tx,
    sanitize_audit_text,
    settle_run_budget_in_tx,
    summarize_arguments,
)
from ctf_mcp.runs import (
    ActionManager,
    ActionSubmission,
    HypothesisManager,
    LeaseManager,
    ReconciliationReport,
    RecoveryManager,
    RunManifestManager,
    RunSnapshot,
    SessionLease,
    SessionLeaseState,
    assert_no_secrets_in_manifest,
    ensure_action_slots_schema_in_tx,
)
from ctf_mcp.storage import Storage
from ctf_mcp.verification import (
    CloseIntegrityReport,
    ExpectedChallengeSpec,
    LocalCtfVerifier,
    VerifierRegistry,
    evaluate_close_integrity_in_tx,
    load_verifications_for_run,
    save_verification_record_in_tx,
)

CORE_HARNESS_TOOLS: tuple[str, ...] = (
    "run.describe",
    "evidence.read",
    "hypothesis.update",
    "run.verify",
    "run.close",
)
ACTION_DISPATCH_TOOLS: tuple[str, ...] = (
    "artifact.inspect",
    "analysis.query",
    "helper.transform",
)
ALWAYS_FORBIDDEN_TOOLS: frozenset[str] = frozenset(
    {
        "exec_shell",
        "shell",
        "bash",
        "cmd",
        "powershell",
        "run_command",
        "run_shell",
    }
)


@dataclass(frozen=True, slots=True)
class RegisteredAdapterSpec:
    """Metadata tracking a capability adapter bound into the controller."""

    descriptor: CapabilityDescriptor
    adapter: Any
    tool_group: str
    is_heavy_job: bool = False
    is_interactive_session: bool = False


@dataclass(frozen=True, slots=True)
class RunCloseResult:
    """Structured result emitted after ordered close integrity checks and export."""

    manifest: RunManifest
    export_result: ExportResult
    integrity_report: CloseIntegrityReport
    guest_rolled_back: bool


@dataclass(frozen=True, slots=True)
class _ObservedTelemetry:
    """Real OS process identity and resource usage extracted from adapter capture."""

    process_start_id: str | None = None
    peak_rss_bytes: int | None = None
    cpu_ms: int | None = None


HYPOTHESIS_REQUESTS_DDL = """
CREATE TABLE IF NOT EXISTS hypothesis_requests (
    principal_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    hypothesis_id TEXT NOT NULL,
    result_revision INTEGER NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (principal_id, run_id, request_id)
);
"""


def _ensure_hypothesis_requests_schema_in_tx(conn: sqlite3.Connection) -> None:
    """Ensure the hypothesis idempotency ledger table exists inside an active transaction."""
    conn.execute(HYPOTHESIS_REQUESTS_DDL)


def _compute_hypothesis_request_digest(
    *,
    run_id: str,
    hypothesis_id: str | None,
    expected_revision: int | None,
    state: HypothesisState,
    claim: str | None,
    next_observation: str | None,
    supporting_evidence_ids: Sequence[str],
    contradicting_evidence_ids: Sequence[str],
    add_supporting_evidence_ids: Sequence[str],
    add_contradicting_evidence_ids: Sequence[str],
) -> str:
    """Compute canonical SHA-256 digest of sanitized hypothesis update parameters."""
    payload = {
        "run_id": run_id,
        "hypothesis_id": hypothesis_id,
        "expected_revision": expected_revision,
        "state": state.value,
        "claim": claim,
        "next_observation": next_observation,
        "supporting_evidence_ids": list(supporting_evidence_ids),
        "contradicting_evidence_ids": list(contradicting_evidence_ids),
        "add_supporting_evidence_ids": list(add_supporting_evidence_ids),
        "add_contradicting_evidence_ids": list(add_contradicting_evidence_ids),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def _sanitize_value(value: Any) -> Any:
    """Recursively sanitize mapping/sequence values before audit or DB persistence."""
    if isinstance(value, str):
        return sanitize_audit_text(value)
    if isinstance(value, Mapping):
        return {str(k): _sanitize_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize_value(item) for item in value]
    return value


def _sanitize_mapping(mapping: Mapping[str, Any]) -> dict[str, Any]:
    """Return a JSON-safe mapping with sensitive markers redacted."""
    return {str(k): _sanitize_value(v) for k, v in mapping.items()}


def _infer_tool_group(descriptor: CapabilityDescriptor) -> str:
    """Determine the default typed MCP dispatch tool group for a capability."""
    name = descriptor.name.strip()
    if name == "artifact.inspect" or name.startswith("artifact."):
        return "artifact.inspect"
    if name == "helper.transform" or name.startswith("helper."):
        return "helper.transform"
    if name == "session.control" or name.startswith("session."):
        return "session.control"
    if set(descriptor.execution_classes) != {ExecutionClass.STATIC}:
        return "session.control"
    return "analysis.query"


def _supports_kwarg(fn: Any, kwarg: str) -> bool:
    """Return True if callable accepts ``kwarg`` explicitly or via **kwargs."""
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return False
    return kwarg in sig.parameters or any(
        param.kind is inspect.Parameter.VAR_KEYWORD for param in sig.parameters.values()
    )


def _extract_descriptor(adapter: Any, explicit: CapabilityDescriptor | None) -> CapabilityDescriptor:
    """Extract a CapabilityDescriptor from an explicit argument or adapter object."""
    if explicit is not None:
        return explicit
    attr = getattr(adapter, "descriptor", None)
    if callable(attr):
        desc = attr()
        if isinstance(desc, CapabilityDescriptor):
            return desc
    elif isinstance(attr, CapabilityDescriptor):
        return attr
    raw = getattr(adapter, "_descriptor", None)
    if isinstance(raw, CapabilityDescriptor):
        return raw
    raise ContractViolationError(
        "Adapter must provide a CapabilityDescriptor via descriptor() or explicit parameter."
    )


def _map_envelope_to_lifecycle_state(
    envelope: ResultEnvelope,
    *,
    captured_bytes: bytes = b"",
) -> tuple[ActionLifecycleState, ErrorDetail | None, str]:
    """Enforce CTF-11 lifecycle mapping from an adapter ResultEnvelope."""
    status = envelope.status
    summary = sanitize_audit_text(envelope.summary or f"action finished with status={status.value}")

    if status == EnvelopeStatus.OK:
        # CTF-11: unexpected empty output with no evidence cannot report 'ok' / no vulns.
        if (
            envelope.usage.output_bytes == 0
            and len(envelope.evidence) == 0
            and len(captured_bytes) == 0
        ):
            err = ErrorDetail(
                code="empty_tool_output",
                message="Analyzer produced unexpected empty output; mapped to tool_error per CTF-11.",
                retryable=False,
            )
            return ActionLifecycleState.FAILED, err, "Analyzer returned empty output (tool_error)."
        return ActionLifecycleState.COMPLETED, envelope.error, summary

    if status == EnvelopeStatus.PARTIAL:
        return ActionLifecycleState.PARTIAL, envelope.error, summary
    if status == EnvelopeStatus.TIMEOUT:
        err = envelope.error or ErrorDetail(
            code="action_timeout",
            message="Action execution timed out.",
            retryable=False,
        )
        return ActionLifecycleState.TIMEOUT, err, summary
    if status == EnvelopeStatus.CANCELLED:
        err = envelope.error or ErrorDetail(
            code="action_cancelled",
            message="Action execution was cancelled.",
            retryable=False,
        )
        return ActionLifecycleState.CANCELLED, err, summary
    # Running actions that ended with TOOL_ERROR or unexpected post-launch DENIED map to FAILED.
    err = envelope.error or ErrorDetail(
        code="tool_execution_failed",
        message=f"Tool failed with status={status.value}.",
        retryable=False,
    )
    return ActionLifecycleState.FAILED, err, summary


def _sanitize_error_detail(error: ErrorDetail | None) -> ErrorDetail | None:
    """Return a copy of ErrorDetail with sensitive markers removed."""
    if error is None:
        return None
    msg = sanitize_audit_text(error.message)
    if not msg.strip():
        msg = error.code
    return ErrorDetail(code=error.code, message=msg, retryable=error.retryable)


class HarnessController:
    """Layer 3 orchestration controller coordinating gateway, runs, evidence, and adapters."""

    def __init__(
        self,
        *,
        storage: Storage,
        vault_root: str | Path,
        cursor_hmac_key: bytes | None = None,
        allow_ephemeral_cursor_key: bool = False,
        export_root: str | Path | None = None,
        staging_root: str | Path | None = None,
        config: HarnessConfig | None = None,
        runtime_settings: RuntimeSettings | None = None,
        authenticator: PrincipalAuthenticator | None = None,
        catalog: CapabilityCatalog | None = None,
        scope_validator: ScopeValidator | None = None,
        intake_service: ArtifactIntakeService | None = None,
        evidence_vault: EvidenceVault | None = None,
        redactor: EvidenceRedactor | None = None,
        bounded_importer: BoundedEvidenceImporter | None = None,
        verifier_registry: VerifierRegistry | None = None,
        report_exporter: RunReportExporter | None = None,
        audit_logger: AuditLogger | None = None,
        lease_manager: LeaseManager | None = None,
        recovery_manager: RecoveryManager | None = None,
        action_manager: ActionManager | None = None,
        run_manifest_manager: RunManifestManager | None = None,
        hypothesis_manager: HypothesisManager | None = None,
        allow_synthetic_adapters: bool = SYNTHETIC_PRODUCTION_DEFAULT_ENABLED,
        supervisor_key: str = "harness-supervisor",
        supervisor_instance_id: str | None = None,
        is_process_alive: Callable[[ActionRecord], bool] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.storage = storage
        self.vault_root = Path(vault_root)
        self.export_root = Path(export_root) if export_root is not None else None
        self.staging_root = Path(staging_root) if staging_root is not None else (self.vault_root / "_staging")
        self.config = config
        self.runtime_settings = runtime_settings
        self.default_mode = (
            runtime_settings.profile
            if runtime_settings is not None
            else (config.profile if config is not None else RunMode.OFFLINE_CTF)
        )
        self.allow_synthetic_adapters = bool(allow_synthetic_adapters)
        self._supervisor_key = supervisor_key.strip() or "harness-supervisor"
        self._supervisor_instance_id = (
            supervisor_instance_id or f"sup-{os.getpid()}-{uuid4().hex[:8]}"
        )
        self._is_process_alive = (
            is_process_alive
            if is_process_alive is not None
            else (lambda action: is_os_process_alive(action.process_start_id))
        )
        self._clock = clock or (lambda: datetime.now(UTC))

        if authenticator is not None:
            self.authenticator = authenticator
        elif runtime_settings is not None:
            self.authenticator = PrincipalAuthenticator.from_runtime_settings(runtime_settings)
        else:
            self.authenticator = PrincipalAuthenticator()

        self.scope_validator = scope_validator or ScopeValidator(storage)
        self.catalog = catalog or CapabilityCatalog(
            storage,
            allow_dynamic=(self.default_mode != RunMode.OFFLINE_CTF),
        )
        self.audit = audit_logger or AuditLogger(storage)
        self.intake = intake_service or ArtifactIntakeService(storage, self.vault_root)

        if evidence_vault is not None:
            self.evidence_vault = evidence_vault
        else:
            hmac_key = cursor_hmac_key or get_cursor_hmac_key(
                allow_ephemeral_dev_key=allow_ephemeral_cursor_key
            )
            self.evidence_vault = EvidenceVault(
                storage=storage,
                vault_root=self.vault_root,
                cursor_hmac_key=hmac_key,
            )

        self.redactor = redactor or EvidenceRedactor(self.evidence_vault)
        self.bounded_importer = bounded_importer or BoundedEvidenceImporter(
            vault=self.evidence_vault,
            staging_root=self.staging_root,
        )
        self.report_exporter = report_exporter or RunReportExporter(
            storage=storage,
            vault=self.evidence_vault,
            export_root=self.export_root,
            automatic_git_export=False,
        )
        self.verifier_registry = verifier_registry or VerifierRegistry()
        self.runs = run_manifest_manager or RunManifestManager(storage)
        self.actions = action_manager or ActionManager(storage)
        self.hypotheses = hypothesis_manager or HypothesisManager(storage)
        self.leases = lease_manager or LeaseManager(storage)
        self.recovery = recovery_manager or RecoveryManager(storage)

        self._lock = threading.RLock()
        self._adapters: dict[str, RegisteredAdapterSpec] = {}
        self._disabled_or_unaccepted_descriptors: dict[str, CapabilityDescriptor] = {}

    def _now(self) -> datetime:
        ts = self._clock()
        return ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts.astimezone(UTC)

    # ------------------------------------------------------------------
    # Startup, registration, and capability visibility
    # ------------------------------------------------------------------

    def _ensure_controller_schemas_in_tx(self, conn: sqlite3.Connection) -> None:
        """Ensure supplemental runtime schemas exist inside an active transaction."""
        ensure_action_slots_schema_in_tx(conn)
        _ensure_hypothesis_requests_schema_in_tx(conn)

    def _record_reconciliation_audits_in_tx(
        self,
        conn: sqlite3.Connection,
        report: ReconciliationReport,
        *,
        ts: datetime,
    ) -> None:
        """Persist sanitized audit summaries for actions and leases reconciled at startup."""
        for act in report.reconciled_to_required:
            self.audit.record_sanitized_in_tx(
                conn,
                AuditEvent(
                    event_id=f"aud-{uuid4().hex}",
                    timestamp=ts,
                    run_id=act.run_id,
                    principal_id=act.principal_id,
                    action_id=act.action_id,
                    capability=act.capability_name,
                    operation=act.operation,
                    outcome=EnvelopeStatus.TOOL_ERROR.value,
                    usage=None,
                    scope_revision=act.scope_revision,
                    destination_summary=(
                        f"reconcile:reconciliation_required;fencing_token={act.fencing_token};"
                        f"lost_sessions={len(report.lost_session_ids)}"
                    ),
                ),
            )
        for act in report.expired_reserved:
            self.audit.record_sanitized_in_tx(
                conn,
                AuditEvent(
                    event_id=f"aud-{uuid4().hex}",
                    timestamp=ts,
                    run_id=act.run_id,
                    principal_id=act.principal_id,
                    action_id=act.action_id,
                    capability=act.capability_name,
                    operation=act.operation,
                    outcome=EnvelopeStatus.DENIED.value,
                    usage=None,
                    scope_revision=act.scope_revision,
                    destination_summary="reconcile:expired_reserved",
                ),
            )
        for act in report.still_running:
            self.audit.record_sanitized_in_tx(
                conn,
                AuditEvent(
                    event_id=f"aud-{uuid4().hex}",
                    timestamp=ts,
                    run_id=act.run_id,
                    principal_id=act.principal_id,
                    action_id=act.action_id,
                    capability=act.capability_name,
                    operation=act.operation,
                    outcome="still_running",
                    usage=None,
                    scope_revision=act.scope_revision,
                    destination_summary=f"reconcile:still_running;fencing_token={act.fencing_token}",
                ),
            )
        for sid in report.lost_session_ids:
            lease_row = conn.execute(
                """
                SELECT s.run_id, s.principal_id, s.capability_name, r.scope_revision
                FROM session_leases s
                JOIN runs r ON r.run_id = s.run_id
                WHERE s.session_id = ?
                """,
                (sid,),
            ).fetchone()
            if lease_row is not None:
                self.audit.record_sanitized_in_tx(
                    conn,
                    AuditEvent(
                        event_id=f"aud-{uuid4().hex}",
                        timestamp=ts,
                        run_id=str(lease_row["run_id"]),
                        principal_id=str(lease_row["principal_id"]),
                        action_id=None,
                        capability=str(lease_row["capability_name"]),
                        operation="session_lost_on_restart",
                        outcome="lost",
                        usage=None,
                        scope_revision=str(lease_row["scope_revision"]),
                        destination_summary=f"session_id={sid};reason=supervisor_restarted",
                    ),
                )

    def initialize(self) -> ReconciliationReport:
        """Initialize storage schema, lease/slot tables, descriptors, and reconcile crashes."""
        self.storage.initialize()
        with self.storage.transaction() as conn:
            self._ensure_controller_schemas_in_tx(conn)
        self.leases.ensure_schema()
        self.catalog.verify_all_descriptors()

        ts = self._now()
        with self.storage.transaction() as conn:
            report = self.recovery.reconcile_inflight_actions_in_tx(
                conn,
                supervisor_key=self._supervisor_key,
                is_process_alive=self._is_process_alive,
                mark_sessions_lost=True,
                now=ts,
            )
            self._record_reconciliation_audits_in_tx(conn, report, ts=ts)
        return report

    def register_adapter(
        self,
        adapter: Any,
        *,
        descriptor: CapabilityDescriptor | None = None,
        enabled: bool | None = None,
        tool_group: str | None = None,
        is_heavy_job: bool = False,
        is_interactive_session: bool = False,
    ) -> CapabilityDescriptor:
        """Register an accepted capability adapter into catalog and dispatch table.

        SyntheticAdapter is blocked unless ``allow_synthetic_adapters=True`` was
        explicitly set when constructing the controller.
        """
        if isinstance(adapter, SyntheticAdapter) and not self.allow_synthetic_adapters:
            raise CapabilityDeniedError(
                "SyntheticAdapter is disabled in production defaults "
                "(PRODUCTION_DEFAULT_ENABLED=False)."
            )

        desc = _extract_descriptor(adapter, descriptor)
        if desc.name in ALWAYS_FORBIDDEN_TOOLS:
            raise CapabilityDeniedError(
                f"Forbidden capability name {desc.name!r} cannot be registered."
            )

        effective_group = (tool_group or _infer_tool_group(desc)).strip()
        if effective_group in ALWAYS_FORBIDDEN_TOOLS:
            raise CapabilityDeniedError(
                f"Forbidden tool group {effective_group!r} cannot be registered."
            )

        registered = self.catalog.register_capability(desc, replace=True)
        if enabled is not None and bool(enabled) != registered.enabled:
            self.catalog.set_enabled(registered.name, bool(enabled))
            registered = registered.model_copy(update={"enabled": bool(enabled)})
        with self._lock:
            self._adapters[registered.name] = RegisteredAdapterSpec(
                descriptor=registered,
                adapter=adapter,
                tool_group=effective_group,
                is_heavy_job=is_heavy_job,
                is_interactive_session=is_interactive_session,
            )
            self._disabled_or_unaccepted_descriptors.pop(registered.name, None)
        return registered

    def register_catalog_descriptor(
        self,
        descriptor: CapabilityDescriptor,
        *,
        enabled: bool | None = None,
        tool_group: str | None = None,
    ) -> CapabilityDescriptor:
        """Register a catalog descriptor without binding an executable adapter.

        Useful for keeping dynamic/network/unaccepted P1 descriptors inspectable by
        the catalog so visibility filtering excludes them cleanly.
        """
        if descriptor.name in ALWAYS_FORBIDDEN_TOOLS:
            raise CapabilityDeniedError(
                f"Forbidden capability name {descriptor.name!r} cannot be registered."
            )
        registered = self.catalog.register_capability(descriptor, replace=True)
        if enabled is not None and bool(enabled) != registered.enabled:
            self.catalog.set_enabled(registered.name, bool(enabled))
            registered = registered.model_copy(update={"enabled": bool(enabled)})
        with self._lock:
            if registered.name not in self._adapters:
                self._disabled_or_unaccepted_descriptors[registered.name] = registered
        return registered

    def set_capability_enabled(self, name: str, enabled: bool) -> CapabilityDescriptor:
        """Enable or disable a registered capability in the catalog."""
        self.catalog.set_enabled(name, enabled)
        with self._lock:
            spec = self._adapters.get(name)
            if spec is not None:
                updated = spec.descriptor.model_copy(update={"enabled": bool(enabled)})
                self._adapters[name] = RegisteredAdapterSpec(
                    descriptor=updated,
                    adapter=spec.adapter,
                    tool_group=spec.tool_group,
                    is_heavy_job=spec.is_heavy_job,
                    is_interactive_session=spec.is_interactive_session,
                )
                return updated
            stored = self._disabled_or_unaccepted_descriptors.get(name)
            if stored is not None:
                updated = stored.model_copy(update={"enabled": bool(enabled)})
                self._disabled_or_unaccepted_descriptors[name] = updated
                return updated
        return self.catalog.get_capability(name, self.default_mode)

    def register_verifier(self, verifier: Any, *, replace: bool = False) -> None:
        """Register a VerifierPort implementation into VerifierRegistry."""
        self.verifier_registry.register(verifier, replace=replace)

    def _get_owned_snapshot_in_tx(
        self,
        conn: sqlite3.Connection,
        *,
        principal: PrincipalContext,
        run_id: str,
    ) -> RunSnapshot:
        """Load a run snapshot inside TX and verify principal ownership."""
        snapshot = self.runs.get_run_snapshot_in_tx(conn, run_id)
        if snapshot.manifest.owner_principal_id != principal.principal_id:
            raise ScopeDeniedError(
                f"Principal {principal.principal_id!r} does not own run {run_id!r}.",
                details={"run_id": run_id, "principal_id": principal.principal_id},
            )
        return snapshot

    def _get_owned_snapshot(
        self,
        *,
        principal: PrincipalContext,
        run_id: str,
    ) -> RunSnapshot:
        """Load a run snapshot and verify principal ownership."""
        snapshot = self.runs.get_run_snapshot(run_id)
        if snapshot.manifest.owner_principal_id != principal.principal_id:
            raise ScopeDeniedError(
                f"Principal {principal.principal_id!r} does not own run {run_id!r}.",
                details={"run_id": run_id, "principal_id": principal.principal_id},
            )
        return snapshot

    def list_visible_tools(
        self,
        *,
        principal: PrincipalContext | None = None,
        run_id: str | None = None,
        mode: RunMode | None = None,
    ) -> list[CapabilityDescriptor]:
        """List catalog capabilities visible for the given mode or active owned run."""
        if run_id is not None:
            if principal is None:
                raise ScopeDeniedError("Authenticated principal is required to inspect run tools.")
            snapshot = self._get_owned_snapshot(principal=principal, run_id=run_id)
            effective_mode = mode or snapshot.manifest.mode
            if snapshot.manifest.closed_at is not None:
                return []
            try:
                scope = self.scope_validator.get_active_scope(run_id, now=self._now())
            except ScopeDeniedError:
                return []
            return self.catalog.list_visible_tools(effective_mode, scope=scope)

        effective_mode = mode or self.default_mode
        return self.catalog.list_visible_tools(effective_mode, scope=None)

    def get_tool_group_for_capability(self, capability_name: str) -> str | None:
        """Return the typed MCP dispatch tool group associated with a capability."""
        with self._lock:
            spec = self._adapters.get(capability_name)
            if spec is not None:
                return spec.tool_group
            unaccepted = self._disabled_or_unaccepted_descriptors.get(capability_name)
            if unaccepted is not None:
                return _infer_tool_group(unaccepted)
        try:
            cap = self.catalog.get_capability(capability_name, self.default_mode)
            return _infer_tool_group(cap)
        except CapabilityDeniedError:
            return None

    def get_visible_mcp_tool_names(
        self,
        *,
        principal: PrincipalContext | None = None,
        run_id: str | None = None,
        mode: RunMode | None = None,
    ) -> set[str]:
        """Compute the exact set of MCP tool names that should appear in tools/list."""
        visible_tools: set[str] = set(CORE_HARNESS_TOOLS)
        visible_caps = self.list_visible_tools(
            principal=principal,
            run_id=run_id,
            mode=mode,
        )
        for cap in visible_caps:
            group = self.get_tool_group_for_capability(cap.name)
            if group in ACTION_DISPATCH_TOOLS:
                # Only expose a dispatch tool if an executable adapter is bound.
                with self._lock:
                    if cap.name in self._adapters:
                        visible_tools.add(group)
        return visible_tools

    def resolve_capability_for_tool_group(
        self,
        *,
        tool_group: str,
        capability_name: str | None = None,
        principal: PrincipalContext | None = None,
        run_id: str | None = None,
        mode: RunMode | None = None,
    ) -> str:
        """Validate or select the unique visible capability belonging to a typed MCP tool."""
        if capability_name is not None and capability_name.strip():
            chosen = capability_name.strip()
            bound_group = self.get_tool_group_for_capability(chosen)
            if bound_group is not None and bound_group != tool_group:
                raise CapabilityDeniedError(
                    f"Capability {chosen!r} belongs to {bound_group!r}, not {tool_group!r}."
                )
            return chosen

        visible_caps = self.list_visible_tools(principal=principal, run_id=run_id, mode=mode)
        matching = [
            cap.name
            for cap in visible_caps
            if self.get_tool_group_for_capability(cap.name) == tool_group
            and cap.name in self._adapters
        ]
        if len(matching) == 1:
            return matching[0]
        if not matching:
            raise CapabilityDeniedError(
                f"No accepted/visible capability is currently available for {tool_group!r}."
            )
        raise ContractViolationError(
            f"Multiple capabilities are visible for {tool_group!r}; specify capability_name explicitly.",
            details={"candidates": matching},
        )

    # ------------------------------------------------------------------
    # Run & artifact creation / inspection
    # ------------------------------------------------------------------

    def create_run(
        self,
        *,
        principal: PrincipalContext,
        task_id: str,
        mode: RunMode,
        scope: ScopePolicy,
        budget: BudgetSpec,
        run_id: str | None = None,
        adapter_revisions: Mapping[str, str] | None = None,
        artifact_hashes: Mapping[str, str] | None = None,
        instruction_revision: str = "p1-wave2",
        created_at: datetime | None = None,
    ) -> RunManifest:
        """Atomically create a run manifest, activate its scope, and write an audit record."""
        if scope.mode != mode:
            raise ScopeDeniedError(
                f"Scope mode {scope.mode.value!r} does not match run mode {mode.value!r}."
            )
        if scope.task_id != task_id:
            raise ScopeDeniedError(
                f"Scope task_id {scope.task_id!r} does not match run task_id {task_id!r}."
            )

        ts = self._now() if created_at is None else created_at
        resolved_run_id = run_id or f"run-{uuid4().hex[:16]}"
        rev_map = dict(adapter_revisions or {})
        if not rev_map:
            with self._lock:
                rev_map = {
                    name: spec.descriptor.adapter_commit
                    for name, spec in self._adapters.items()
                }
        manifest = RunManifest(
            run_id=resolved_run_id,
            owner_principal_id=principal.principal_id,
            task_id=task_id,
            mode=mode,
            scope_revision=scope.scope_revision,
            scope_sha256=scope.scope_sha256,
            scope_expires_at=scope.expires_at,
            artifact_hashes=dict(artifact_hashes or {}),
            adapter_revisions=rev_map,
            client_label=f"{principal.client_kind}:{principal.model_label}",
            instruction_revision=instruction_revision,
            budget_spec=budget,
            created_at=ts,
            closed_at=None,
        )
        assert_no_secrets_in_manifest(manifest)

        with self.storage.transaction() as conn:
            created = self.runs.create_run_in_tx(
                conn, manifest, initial_guest_health=GuestHealthState.READY
            )
            self.scope_validator.register_scope_in_tx(
                conn, created.run_id, scope, activate=True
            )
            self.audit.record_sanitized_in_tx(
                conn,
                AuditEvent(
                    event_id=f"aud-{uuid4().hex}",
                    timestamp=ts,
                    run_id=created.run_id,
                    principal_id=principal.principal_id,
                    action_id=None,
                    capability="run.create",
                    operation="create",
                    outcome=EnvelopeStatus.OK.value,
                    usage=None,
                    scope_revision=scope.scope_revision,
                    destination_summary=f"mode={mode.value};task_id={task_id}",
                ),
            )
        return created

    def register_scope(
        self,
        *,
        run_id: str,
        scope: ScopePolicy,
        principal: PrincipalContext | None = None,
        activate: bool = True,
    ) -> ScopePolicy:
        """Register and optionally activate a new immutable scope revision on an open run."""
        ts = self._now()
        with self.storage.transaction() as conn:
            snapshot = (
                self._get_owned_snapshot_in_tx(conn, principal=principal, run_id=run_id)
                if principal is not None
                else self.runs.get_run_snapshot_in_tx(conn, run_id)
            )
            registered = self.scope_validator.register_scope_in_tx(
                conn, run_id, scope, activate=activate
            )
            if activate:
                updated_manifest = snapshot.manifest.model_copy(
                    update={
                        "scope_revision": registered.scope_revision,
                        "scope_sha256": registered.scope_sha256,
                        "scope_expires_at": registered.expires_at,
                    }
                )
                assert_no_secrets_in_manifest(updated_manifest)
                conn.execute(
                    "UPDATE runs SET scope_revision = ?, manifest_json = ?, revision = revision + 1 WHERE run_id = ?",
                    (
                        registered.scope_revision,
                        updated_manifest.model_dump_json(),
                        run_id,
                    ),
                )
            eff_principal = (
                principal.principal_id
                if principal is not None
                else snapshot.manifest.owner_principal_id
            )
            self.audit.record_sanitized_in_tx(
                conn,
                AuditEvent(
                    event_id=f"aud-{uuid4().hex}",
                    timestamp=ts,
                    run_id=run_id,
                    principal_id=eff_principal,
                    action_id=None,
                    capability="scope.register",
                    operation="activate" if activate else "register",
                    outcome=EnvelopeStatus.OK.value,
                    usage=None,
                    scope_revision=registered.scope_revision,
                    destination_summary=f"task_id={registered.task_id};activate={bool(activate)}",
                ),
            )
        return registered

    def ingest_artifact(
        self,
        *,
        principal: PrincipalContext,
        run_id: str,
        source_root: str | Path | None = None,
        rel_path: str | Path | None = None,
        data: bytes | None = None,
        media_type: str = "application/octet-stream",
        source_origin: str | None = None,
        filename_hint: str | None = None,
        limits: IntakeLimits | None = None,
    ) -> ArtifactRecord:
        """Ingest an offline workspace file or byte payload into an owned unclosed run."""
        snapshot = self._get_owned_snapshot(principal=principal, run_id=run_id)
        if snapshot.manifest.closed_at is not None:
            raise ScopeDeniedError(f"Cannot ingest artifacts into closed run {run_id!r}.")

        if source_root is not None and rel_path is not None:
            record = self.intake.ingest_from_workspace(
                run_id=run_id,
                principal_id=principal.principal_id,
                source_root=source_root,
                rel_path=rel_path,
                media_type=media_type,
                source_origin=source_origin or "offline_iso",
                limits=limits,
            )
        elif data is not None:
            record = self.intake.ingest_bytes(
                run_id=run_id,
                principal_id=principal.principal_id,
                data=data,
                media_type=media_type,
                source_origin=source_origin or "local_fixture",
                filename_hint=filename_hint,
                limits=limits,
            )
        else:
            raise ContractViolationError(
                "ingest_artifact requires either (source_root and rel_path) or data."
            )

        with self.storage.transaction() as conn:
            self.runs.record_provenance_hashes_in_tx(
                conn,
                run_id,
                artifact_hashes={record.artifact_id: record.sha256},
            )
            self.audit.record_sanitized_in_tx(
                conn,
                AuditEvent(
                    event_id=f"aud-{uuid4().hex}",
                    timestamp=self._now(),
                    run_id=run_id,
                    principal_id=principal.principal_id,
                    action_id=None,
                    capability="artifact.intake",
                    operation="ingest",
                    outcome=EnvelopeStatus.OK.value,
                    usage=UsageMetrics(wall_ms=0, output_bytes=record.byte_length),
                    scope_revision=snapshot.manifest.scope_revision,
                    destination_summary=f"artifact_id={record.artifact_id};sha256={record.sha256[:12]}",
                ),
            )
        return record

    def describe_run(
        self,
        *,
        principal: PrincipalContext,
        run_id: str,
    ) -> dict[str, Any]:
        """Return sanitized run state, artifacts, budget, hypotheses, actions, and tools."""
        with self.storage.transaction() as conn:
            snapshot = self._get_owned_snapshot_in_tx(conn, principal=principal, run_id=run_id)
            budget = get_budget_snapshot_in_tx(conn, run_id)
            err_rows = conn.execute(
                "SELECT action_id, error_code FROM actions WHERE run_id = ?",
                (run_id,),
            ).fetchall()
        error_code_by_id = {
            str(r["action_id"]): (str(r["error_code"]) if r["error_code"] is not None else None)
            for r in err_rows
        }

        artifacts = self.intake.list_artifacts(run_id=run_id, principal_id=principal.principal_id)
        hypotheses = self.hypotheses.list_hypotheses(run_id)
        actions = self.actions.list_actions(run_id)
        leases = self.leases.list_leases(run_id)
        verifications = load_verifications_for_run(self.storage, run_id)
        visible_caps = self.list_visible_tools(principal=principal, run_id=run_id)
        visible_mcp_tools = sorted(
            self.get_visible_mcp_tool_names(principal=principal, run_id=run_id)
        )

        return {
            "run_id": run_id,
            "task_id": snapshot.manifest.task_id,
            "mode": snapshot.manifest.mode.value,
            "revision": snapshot.revision,
            "guest_health": snapshot.guest_health.value,
            "closed_at": (
                snapshot.manifest.closed_at.isoformat()
                if snapshot.manifest.closed_at is not None
                else None
            ),
            "scope_revision": snapshot.manifest.scope_revision,
            "scope_sha256": snapshot.manifest.scope_sha256,
            "scope_expires_at": (
                snapshot.manifest.scope_expires_at.isoformat()
                if snapshot.manifest.scope_expires_at is not None
                else None
            ),
            "budget": {
                "remaining_ms": budget.remaining_ms,
                "remaining_bytes": budget.remaining_bytes,
                "remaining_calls": budget.remaining_calls,
                "active_heavy_jobs": budget.active_heavy_jobs,
                "active_sessions": budget.active_sessions,
            },
            "artifacts": [a.model_dump(mode="json") for a in artifacts],
            "hypotheses": [h.model_dump(mode="json") for h in hypotheses],
            "action_count": len(actions),
            "actions": [
                {
                    "action_id": a.action_id,
                    "request_id": a.request_id,
                    "capability_name": a.capability_name,
                    "operation": a.operation,
                    "state": a.state.value,
                    "fencing_token": a.fencing_token,
                    "process_start_id": a.process_start_id,
                    "error_code": error_code_by_id.get(a.action_id),
                    "used_ms": a.used_ms,
                    "used_bytes": a.used_bytes,
                }
                for a in actions
            ],
            "reconciliation_required": [
                {
                    "action_id": a.action_id,
                    "request_id": a.request_id,
                    "capability_name": a.capability_name,
                    "operation": a.operation,
                    "fencing_token": a.fencing_token,
                    "error_code": error_code_by_id.get(a.action_id),
                }
                for a in actions
                if a.state == ActionLifecycleState.RECONCILIATION_REQUIRED
            ],
            "session_leases": [
                {
                    "session_id": lease.session_id,
                    "capability_name": lease.capability_name,
                    "adapter_revision": lease.adapter_revision,
                    "artifact_id": lease.artifact_id,
                    "state": lease.state.value,
                    "supervisor_instance_id": lease.supervisor_instance_id,
                    "created_at": lease.created_at.isoformat(),
                    "last_activity_at": lease.last_activity_at.isoformat(),
                    "expires_at": lease.expires_at.isoformat(),
                    "closed_at": (
                        lease.closed_at.isoformat() if lease.closed_at is not None else None
                    ),
                    "termination_reason": lease.termination_reason,
                }
                for lease in leases
            ],
            "verifications": [v.model_dump(mode="json") for v in verifications],
            "visible_capabilities": [c.name for c in visible_caps],
            "visible_mcp_tools": visible_mcp_tools,
        }

    # ------------------------------------------------------------------
    # Action execution pipeline (TX1 -> adapter capture -> TX2)
    # ------------------------------------------------------------------

    def _record_denial_in_tx(
        self,
        conn: sqlite3.Connection,
        *,
        principal: PrincipalContext,
        request: ActionRequest,
        adapter_revision: str,
        scope_revision: str,
        error_code: str,
        message: str,
        sanitized_args: dict[str, Any],
        now: datetime,
    ) -> ResultEnvelope:
        """Persist a sanitized proposed->denied action record and audit entry."""
        clean_msg = sanitize_audit_text(message) or error_code
        err = ErrorDetail(code=error_code, message=clean_msg, retryable=False)
        denied_sub = self.actions.record_denied_action_in_tx(
            conn,
            run_id=request.run_id,
            principal_id=principal.principal_id,
            request=request,
            adapter_revision=adapter_revision,
            scope_revision=scope_revision,
            error=err,
            summary=clean_msg,
            sanitized_args=sanitized_args,
            now=now,
        )
        assert denied_sub.envelope is not None
        self.audit.record_sanitized_in_tx(
            conn,
            AuditEvent(
                event_id=f"aud-{uuid4().hex}",
                timestamp=now,
                run_id=request.run_id,
                principal_id=principal.principal_id,
                action_id=denied_sub.action.action_id,
                capability=request.capability_name,
                operation=request.operation,
                outcome=EnvelopeStatus.DENIED.value,
                usage=UsageMetrics(wall_ms=0, output_bytes=0),
                scope_revision=scope_revision,
                destination_summary=summarize_arguments(sanitized_args),
            ),
        )
        return denied_sub.envelope

    def _resolve_run_artifact_context(
        self,
        *,
        principal: PrincipalContext,
        run_id: str,
        arguments: Mapping[str, Any],
    ) -> tuple[dict[str, Path], tuple[str, ...]]:
        """Resolve only artifact_id values and pinned SHA-256 hashes owned by (run_id, principal_id)."""
        paths: dict[str, Path] = {}
        hashes: list[str] = []
        candidate_ids: list[str] = []
        raw_single = arguments.get("artifact_id")
        if isinstance(raw_single, str) and raw_single.strip():
            candidate_ids.append(raw_single.strip())
        raw_many = arguments.get("artifact_ids")
        if isinstance(raw_many, Sequence) and not isinstance(raw_many, (str, bytes)):
            for item in raw_many:
                if isinstance(item, str) and item.strip():
                    candidate_ids.append(item.strip())

        for aid in dict.fromkeys(candidate_ids):
            paths[aid] = self.intake.resolve_artifact_path(
                run_id=run_id,
                principal_id=principal.principal_id,
                artifact_id=aid,
            )
            record = self.intake.get_artifact(
                run_id=run_id,
                principal_id=principal.principal_id,
                artifact_id=aid,
            )
            hashes.append(record.sha256)
        return paths, tuple(dict.fromkeys(hashes))

    def _resolve_run_artifact_paths(
        self,
        *,
        principal: PrincipalContext,
        run_id: str,
        arguments: Mapping[str, Any],
    ) -> dict[str, Path]:
        """Resolve only artifact_id values owned by (run_id, principal_id)."""
        paths, _ = self._resolve_run_artifact_context(
            principal=principal,
            run_id=run_id,
            arguments=arguments,
        )
        return paths

    def _execute_adapter_outside_tx(
        self,
        *,
        adapter: Any,
        started: ActionRecord,
        artifact_paths: dict[str, Path],
        source_artifact_hashes: tuple[str, ...] = (),
        cancel_event: threading.Event | None,
    ) -> tuple[ActionLifecycleState, ResultEnvelope, bool, bytes, _ObservedTelemetry]:
        """Invoke adapter outside SQLite transactions and normalize outcome."""
        telemetry = _ObservedTelemetry()
        try:
            if hasattr(adapter, "execute_with_capture"):
                capture_kwargs: dict[str, Any] = {
                    "artifact_paths": artifact_paths or None,
                    "cancel_event": cancel_event,
                }
                if source_artifact_hashes and _supports_kwarg(
                    adapter.execute_with_capture, "source_artifact_hashes"
                ):
                    capture_kwargs["source_artifact_hashes"] = source_artifact_hashes
                outcome = adapter.execute_with_capture(started, **capture_kwargs)
                envelope = outcome.envelope
                cleanup_confirmed = bool(outcome.cleanup_confirmed)
                captured = outcome.captured_bytes
                sub_res = getattr(outcome, "subprocess_result", None)
                if sub_res is not None:
                    telemetry = _ObservedTelemetry(
                        process_start_id=getattr(sub_res, "process_start_id", None),
                        peak_rss_bytes=getattr(sub_res, "peak_rss_bytes", None),
                        cpu_ms=getattr(sub_res, "cpu_ms", None),
                    )
            else:
                envelope = adapter.execute(started)
                cleanup_confirmed = (
                    envelope.error is None or envelope.error.code != "cleanup_unconfirmed"
                )
                captured = b""
        except Exception as exc:
            err = ErrorDetail(
                code="adapter_execution_error",
                message=sanitize_audit_text(str(exc)) or type(exc).__name__,
                retryable=False,
            )
            fallback_env = ResultEnvelope(
                run_id=started.run_id,
                action_id=started.action_id,
                status=EnvelopeStatus.TOOL_ERROR,
                summary=f"Adapter execution raised {type(exc).__name__}.",
                evidence=(),
                truncated=False,
                next_cursor=None,
                error=err,
                usage=UsageMetrics(wall_ms=0, output_bytes=0),
                provenance=ProvenanceInfo(
                    adapter_revision=started.adapter_revision,
                    scope_revision=started.scope_revision,
                ),
            )
            return ActionLifecycleState.FAILED, fallback_env, False, b"", telemetry

        target_state, normalized_err, clean_summary = _map_envelope_to_lifecycle_state(
            envelope,
            captured_bytes=captured,
        )
        clean_err = _sanitize_error_detail(normalized_err)
        usage = envelope.usage
        usage_updates: dict[str, Any] = {}
        if usage.peak_rss_bytes is None and telemetry.peak_rss_bytes is not None:
            usage_updates["peak_rss_bytes"] = telemetry.peak_rss_bytes
        if usage.cpu_ms is None and telemetry.cpu_ms is not None:
            usage_updates["cpu_ms"] = telemetry.cpu_ms
        if usage_updates:
            usage = usage.model_copy(update=usage_updates)

        normalized_env = envelope.model_copy(
            update={
                "summary": clean_summary,
                "error": clean_err,
                "usage": usage,
                "status": lifecycle_to_envelope_status(
                    target_state,
                    has_tool_receipt=(target_state == ActionLifecycleState.COMPLETED),
                ),
            }
        )
        return target_state, normalized_env, cleanup_confirmed, captured, telemetry

    def execute_action(
        self,
        *,
        principal: PrincipalContext,
        request: ActionRequest,
        cancel_event: threading.Event | None = None,
        pre_launch_expired_reason: str | None = None,
    ) -> ResultEnvelope:
        """Run full Auth -> Scope -> Catalog -> Dedupe/Reserve -> Dispatch -> Settle -> Audit flow."""
        now = self._now()
        sanitized_args = _sanitize_mapping(request.arguments)
        started: ActionRecord | None = None
        reservation: BudgetReservation | None = None
        adapter_spec: RegisteredAdapterSpec | None = None
        active_scope: ScopePolicy | None = None
        artifact_paths: dict[str, Path] = {}

        # ---------------- TX1: Replay, Auth/Scope/Catalog, Reserve, Start + Fencing ----------------
        with self.storage.transaction() as conn:
            snapshot = self._get_owned_snapshot_in_tx(
                conn, principal=principal, run_id=request.run_id
            )

            # #29 Rule 1: Run idempotent replay check BEFORE expected_revision validation.
            replay = self.actions.check_idempotent_replay_in_tx(
                conn,
                principal_id=principal.principal_id,
                request=request,
            )
            if replay is not None:
                if replay.action.state == ActionLifecycleState.RECONCILIATION_REQUIRED:
                    raise InvalidStateTransitionError(
                        f"Action {replay.action.action_id!r} is in reconciliation_required and "
                        "cannot return a terminal ResultEnvelope.",
                        details={
                            "action_id": replay.action.action_id,
                            "state": replay.action.state.value,
                        },
                    )
                if replay.action.state in (
                    ActionLifecycleState.RESERVED,
                    ActionLifecycleState.RUNNING,
                ):
                    raise ActionConflictError(
                        f"Action {replay.action.action_id!r} is already in-flight.",
                        details={
                            "action_id": replay.action.action_id,
                            "state": replay.action.state.value,
                        },
                    )
                if replay.envelope is None:
                    raise ContractViolationError(
                        f"Terminal action {replay.action.action_id!r} is missing an envelope."
                    )
                return replay.envelope

            if request.capability_name in ALWAYS_FORBIDDEN_TOOLS:
                return self._record_denial_in_tx(
                    conn,
                    principal=principal,
                    request=request,
                    adapter_revision="forbidden",
                    scope_revision=snapshot.manifest.scope_revision,
                    error_code="tool_denied",
                    message=f"Forbidden tool {request.capability_name!r} is permanently disabled.",
                    sanitized_args=sanitized_args,
                    now=now,
                )

            if snapshot.manifest.closed_at is not None:
                return self._record_denial_in_tx(
                    conn,
                    principal=principal,
                    request=request,
                    adapter_revision="run_closed",
                    scope_revision=snapshot.manifest.scope_revision,
                    error_code="run_closed",
                    message=f"Run {request.run_id!r} is already closed.",
                    sanitized_args=sanitized_args,
                    now=now,
                )

            if snapshot.guest_health != GuestHealthState.READY:
                return self._record_denial_in_tx(
                    conn,
                    principal=principal,
                    request=request,
                    adapter_revision="guest_blocked",
                    scope_revision=snapshot.manifest.scope_revision,
                    error_code="guest_blocked",
                    message=(
                        f"Run {request.run_id!r} guest health is {snapshot.guest_health.value!r}; "
                        "new actions are blocked until cleanup/rollback completes."
                    ),
                    sanitized_args=sanitized_args,
                    now=now,
                )

            try:
                cap_desc = self.catalog.get_capability(
                    request.capability_name, snapshot.manifest.mode
                )
            except CapabilityDeniedError as exc:
                return self._record_denial_in_tx(
                    conn,
                    principal=principal,
                    request=request,
                    adapter_revision="unregistered",
                    scope_revision=snapshot.manifest.scope_revision,
                    error_code="capability_denied",
                    message=str(exc),
                    sanitized_args=sanitized_args,
                    now=now,
                )

            # Scope check (captures expired scope reason vs permission denial).
            try:
                active_scope = self.scope_validator.validate_action_in_tx(
                    conn,
                    principal,
                    request.run_id,
                    cap_desc,
                    request.operation,
                    now=now,
                )
            except ScopeDeniedError as exc:
                err_code = (
                    "scope_expired"
                    if "expired" in str(exc).lower()
                    else "scope_denied"
                )
                return self._record_denial_in_tx(
                    conn,
                    principal=principal,
                    request=request,
                    adapter_revision=cap_desc.adapter_commit,
                    scope_revision=snapshot.manifest.scope_revision,
                    error_code=err_code,
                    message=str(exc),
                    sanitized_args=sanitized_args,
                    now=now,
                )

            # Catalog invocation check (mode visibility, enabled flag, operation, args schema).
            try:
                validated_cap = self.catalog.validate_invocation(
                    request.capability_name,
                    snapshot.manifest.mode,
                    request.operation,
                    request.arguments,
                    scope=active_scope,
                )
            except CapabilityDeniedError as exc:
                return self._record_denial_in_tx(
                    conn,
                    principal=principal,
                    request=request,
                    adapter_revision=cap_desc.adapter_commit,
                    scope_revision=active_scope.scope_revision,
                    error_code="capability_denied",
                    message=str(exc),
                    sanitized_args=sanitized_args,
                    now=now,
                )

            with self._lock:
                adapter_spec = self._adapters.get(validated_cap.name)
            if adapter_spec is None:
                return self._record_denial_in_tx(
                    conn,
                    principal=principal,
                    request=request,
                    adapter_revision=validated_cap.adapter_commit,
                    scope_revision=active_scope.scope_revision,
                    error_code="adapter_unavailable",
                    message=f"No executable adapter bound for capability {validated_cap.name!r}.",
                    sanitized_args=sanitized_args,
                    now=now,
                )

            # Check optimistic revision lock BEFORE mutating budget or inserting action.
            if request.expected_revision != snapshot.revision:
                raise ActionConflictError(
                    f"Run revision mismatch for {request.run_id!r}: "
                    f"expected {request.expected_revision}, actual {snapshot.revision}.",
                    details={
                        "run_id": request.run_id,
                        "expected_revision": request.expected_revision,
                        "actual_revision": snapshot.revision,
                    },
                )

            # #29 Rule 2: Single-source run budget reservation (manage_run_budget=False on ActionManager).
            reservation = reserve_run_budget_in_tx(
                conn,
                run_id=request.run_id,
                capability=validated_cap,
                is_heavy_job=adapter_spec.is_heavy_job,
                is_interactive_session=adapter_spec.is_interactive_session,
                allow_shrink=True,
            )
            reserved_sub = self.actions.reserve_action_in_tx(
                conn,
                run_id=request.run_id,
                principal_id=principal.principal_id,
                request=request,
                capability=validated_cap,
                scope_revision=active_scope.scope_revision,
                sanitized_args=sanitized_args,
                reserved_ms=reservation.reserved_ms,
                reserved_bytes=reservation.reserved_bytes,
                heavy_job_slot=reservation.heavy_job_slot,
                interactive_session_slot=reservation.interactive_session_slot,
                manage_run_budget=False,
                now=now,
            )

            # Pre-launch expiration path (reserved -> expired -> denied with explicit reason).
            effective_expiry_reason = pre_launch_expired_reason
            if (
                not effective_expiry_reason
                and active_scope.expires_at is not None
                and self._now() >= active_scope.expires_at
            ):
                effective_expiry_reason = (
                    f"Scope {active_scope.scope_revision!r} expired prior to launch."
                )

            if effective_expiry_reason:
                expiry_reason = sanitize_audit_text(effective_expiry_reason)
                settle_run_budget_in_tx(
                    conn,
                    run_id=request.run_id,
                    reserved_ms=reserved_sub.action.reserved_ms,
                    reserved_bytes=reserved_sub.action.reserved_bytes,
                    used_ms=0,
                    used_bytes=0,
                    heavy_job_slot=reservation.heavy_job_slot,
                    interactive_session_slot=reservation.interactive_session_slot,
                    cleanup_confirmed=True,
                )
                expired_sub = self.actions.settle_action_in_tx(
                    conn,
                    action_id=reserved_sub.action.action_id,
                    target_state=ActionLifecycleState.EXPIRED,
                    usage=UsageMetrics(wall_ms=0, output_bytes=0),
                    has_tool_receipt=False,
                    expiry_reason=expiry_reason,
                    summary=f"Action expired before launch: {expiry_reason}",
                    error=ErrorDetail(
                        code="action_expired",
                        message=expiry_reason,
                        retryable=False,
                    ),
                    retain_reservation=False,
                    heavy_job_slot=reservation.heavy_job_slot,
                    interactive_session_slot=reservation.interactive_session_slot,
                    manage_run_budget=False,
                    now=now,
                )
                assert expired_sub.envelope is not None
                self.audit.record_sanitized_in_tx(
                    conn,
                    AuditEvent(
                        event_id=f"aud-{uuid4().hex}",
                        timestamp=now,
                        run_id=request.run_id,
                        principal_id=principal.principal_id,
                        action_id=expired_sub.action.action_id,
                        capability=request.capability_name,
                        operation=request.operation,
                        outcome=expired_sub.envelope.status.value,
                        usage=UsageMetrics(wall_ms=0, output_bytes=0),
                        scope_revision=active_scope.scope_revision,
                        destination_summary=f"expired_before_launch:{expiry_reason}",
                    ),
                )
                return expired_sub.envelope

            artifact_paths, source_artifact_hashes = self._resolve_run_artifact_context(
                principal=principal,
                run_id=request.run_id,
                arguments=request.arguments,
            )

            started = self.actions.start_action_in_tx(
                conn,
                action_id=reserved_sub.action.action_id,
                supervisor_key=self._supervisor_key,
                supervisor_instance_id=self._supervisor_instance_id,
                process_start_id=f"proc-{uuid4().hex[:12]}",
                now=now,
            )

        # ---------------- Outside TX: Bounded subprocess execution + evidence capture ----------------
        assert started is not None
        assert reservation is not None
        assert adapter_spec is not None
        assert active_scope is not None

        target_state, normalized_env, cleanup_confirmed, _, telemetry = (
            self._execute_adapter_outside_tx(
                adapter=adapter_spec.adapter,
                started=started,
                artifact_paths=artifact_paths,
                source_artifact_hashes=source_artifact_hashes,
                cancel_event=cancel_event,
            )
        )

        # ---------------- TX2: Settle budget, settle action, cleanup mark, sanitized audit ----------------
        finish_now = self._now()
        with self.storage.transaction() as conn:
            if telemetry.process_start_id:
                conn.execute(
                    """
                    UPDATE actions
                    SET process_start_id = ?, updated_at = ?
                    WHERE action_id = ? AND fencing_token = ?
                    """,
                    (
                        telemetry.process_start_id,
                        finish_now.isoformat(),
                        started.action_id,
                        started.fencing_token,
                    ),
                )
            settle_run_budget_in_tx(
                conn,
                run_id=request.run_id,
                reserved_ms=started.reserved_ms,
                reserved_bytes=started.reserved_bytes,
                used_ms=normalized_env.usage.wall_ms,
                used_bytes=normalized_env.usage.output_bytes,
                heavy_job_slot=reservation.heavy_job_slot,
                interactive_session_slot=reservation.interactive_session_slot,
                cleanup_confirmed=cleanup_confirmed,
                usage_unknown=not cleanup_confirmed,
            )
            settled = self.actions.settle_action_in_tx(
                conn,
                action_id=started.action_id,
                target_state=target_state,
                usage=normalized_env.usage,
                fencing_token=started.fencing_token,
                has_tool_receipt=(target_state == ActionLifecycleState.COMPLETED),
                summary=normalized_env.summary,
                evidence=normalized_env.evidence,
                truncated=normalized_env.truncated,
                next_cursor=normalized_env.next_cursor,
                error=normalized_env.error,
                retain_reservation=not cleanup_confirmed,
                usage_unknown=not cleanup_confirmed,
                heavy_job_slot=reservation.heavy_job_slot,
                interactive_session_slot=reservation.interactive_session_slot,
                cleanup_confirmed=cleanup_confirmed,
                manage_run_budget=False,
                supervisor_key=self._supervisor_key,
                now=finish_now,
            )
            if not cleanup_confirmed:
                reason = (
                    normalized_env.error.message
                    if normalized_env.error is not None
                    else "Subprocess cleanup could not be confirmed."
                )
                self.recovery.mark_cleanup_unconfirmed_in_tx(
                    conn,
                    request.run_id,
                    reason,
                    action_id=started.action_id,
                    now=finish_now,
                )

            assert settled.envelope is not None
            self.audit.record_sanitized_in_tx(
                conn,
                AuditEvent(
                    event_id=f"aud-{uuid4().hex}",
                    timestamp=finish_now,
                    run_id=request.run_id,
                    principal_id=principal.principal_id,
                    action_id=started.action_id,
                    capability=request.capability_name,
                    operation=request.operation,
                    outcome=settled.envelope.status.value,
                    usage=normalized_env.usage,
                    scope_revision=active_scope.scope_revision,
                    destination_summary=summarize_arguments(sanitized_args),
                ),
            )
            return settled.envelope

    # ------------------------------------------------------------------
    # Evidence paging & redaction
    # ------------------------------------------------------------------

    def read_evidence(
        self,
        *,
        principal: PrincipalContext,
        run_id: str,
        evidence_id: str,
        cursor: str | None = None,
        max_chars: int | None = None,
        max_decode_bytes: int | None = None,
    ) -> EvidencePage:
        """Read a bounded EvidencePage bound strictly to (run_id, owner_principal_id)."""
        snapshot = self._get_owned_snapshot(principal=principal, run_id=run_id)
        cap_chars = snapshot.manifest.budget_spec.max_output_chars_per_page
        effective_max_chars = cap_chars if max_chars is None else min(int(max_chars), cap_chars)
        return self.evidence_vault.read_page(
            run_id=run_id,
            principal_id=principal.principal_id,
            evidence_id=evidence_id,
            cursor=cursor,
            max_chars=effective_max_chars,
            max_decode_bytes=max_decode_bytes,
        )

    def redact_evidence(
        self,
        *,
        principal: PrincipalContext,
        run_id: str,
        evidence_id: str,
        extra_literals: Sequence[str] = (),
        revoke_prior_views: bool = True,
        policy_rev: str | None = None,
    ) -> RedactedViewOutcome:
        """Create a sanitized derived view of an evidence object and optionally revoke raw."""
        snapshot = self._get_owned_snapshot(principal=principal, run_id=run_id)
        outcome = self.redactor.create_redacted_view(
            run_id=run_id,
            principal_id=principal.principal_id,
            evidence_id=evidence_id,
            extra_literals=extra_literals,
            revoke_prior_views=revoke_prior_views,
            policy_rev=policy_rev,
        )
        with self.storage.transaction() as conn:
            self.audit.record_sanitized_in_tx(
                conn,
                AuditEvent(
                    event_id=f"aud-{uuid4().hex}",
                    timestamp=self._now(),
                    run_id=run_id,
                    principal_id=principal.principal_id,
                    action_id=None,
                    capability="evidence.redact",
                    operation="create_redacted_view",
                    outcome=EnvelopeStatus.OK.value,
                    usage=None,
                    scope_revision=snapshot.manifest.scope_revision,
                    destination_summary=f"evidence_id={evidence_id};revoke_prior={revoke_prior_views}",
                ),
            )
        return outcome

    def import_staged_evidence(
        self,
        *,
        principal: PrincipalContext,
        run_id: str,
        action_id: str,
        object_id: str,
        expected_sha256: str,
        media_type: str,
        capture_complete: bool,
        omission_reason: str | None,
        source_artifact_hashes: tuple[str, ...],
        adapter_revision: str,
        sanitized_args_sha256: str,
        expected_size_bytes: int | None = None,
        staging_relpath: str | None = None,
    ) -> ImportReceipt:
        """Import a staged evidence artifact through BoundedEvidenceImporter."""
        snapshot = self._get_owned_snapshot(principal=principal, run_id=run_id)
        if snapshot.manifest.closed_at is not None:
            raise ScopeDeniedError(f"Cannot import evidence into closed run {run_id!r}.")
        return self.bounded_importer.import_object(
            run_id=run_id,
            owner_principal_id=principal.principal_id,
            action_id=action_id,
            object_id=object_id,
            expected_sha256=expected_sha256,
            media_type=media_type,
            capture_complete=capture_complete,
            omission_reason=omission_reason,
            source_artifact_hashes=source_artifact_hashes,
            adapter_revision=adapter_revision,
            sanitized_args_sha256=sanitized_args_sha256,
            expected_size_bytes=expected_size_bytes,
            staging_relpath=staging_relpath,
        )

    # ------------------------------------------------------------------
    # Hypotheses & Local Verification
    # ------------------------------------------------------------------

    def update_hypothesis(
        self,
        *,
        principal: PrincipalContext,
        run_id: str,
        hypothesis_id: str | None = None,
        expected_revision: int | None = None,
        state: HypothesisState | str = HypothesisState.UNKNOWN,
        claim: str | None = None,
        next_observation: str | None = None,
        supporting_evidence_ids: Sequence[str] = (),
        contradicting_evidence_ids: Sequence[str] = (),
        add_supporting_evidence_ids: Sequence[str] = (),
        add_contradicting_evidence_ids: Sequence[str] = (),
        require_existing_evidence: bool = True,
        request_id: str | None = None,
    ) -> HypothesisRecord:
        """Create a new hypothesis or update an existing one with optional request_id idempotency."""
        now = self._now()
        clean_req_id: str | None = None
        if request_id is not None:
            clean_req_id = request_id.strip()
            if not clean_req_id:
                raise ContractViolationError("hypothesis.update request_id cannot be blank.")

        target_state = state if isinstance(state, HypothesisState) else HypothesisState(state)
        clean_claim = sanitize_audit_text(claim) if claim is not None else None
        clean_next = sanitize_audit_text(next_observation) if next_observation is not None else None
        if clean_claim is not None and contains_sensitive_marker(clean_claim):
            raise ContractViolationError("Hypothesis claim must not contain sensitive markers.")
        if clean_next is not None and contains_sensitive_marker(clean_next):
            raise ContractViolationError("Hypothesis next_observation must not contain sensitive markers.")

        req_digest = (
            _compute_hypothesis_request_digest(
                run_id=run_id,
                hypothesis_id=hypothesis_id,
                expected_revision=expected_revision,
                state=target_state,
                claim=clean_claim,
                next_observation=clean_next,
                supporting_evidence_ids=supporting_evidence_ids,
                contradicting_evidence_ids=contradicting_evidence_ids,
                add_supporting_evidence_ids=add_supporting_evidence_ids,
                add_contradicting_evidence_ids=add_contradicting_evidence_ids,
            )
            if clean_req_id is not None
            else None
        )

        with self.storage.transaction() as conn:
            self._ensure_controller_schemas_in_tx(conn)
            snapshot = self._get_owned_snapshot_in_tx(conn, principal=principal, run_id=run_id)

            if clean_req_id is not None and req_digest is not None:
                prior = conn.execute(
                    """
                    SELECT request_digest, response_json
                    FROM hypothesis_requests
                    WHERE principal_id = ? AND run_id = ? AND request_id = ?
                    """,
                    (principal.principal_id, run_id, clean_req_id),
                ).fetchone()
                if prior is not None:
                    if str(prior["request_digest"]) != req_digest:
                        raise ActionConflictError(
                            f"Hypothesis update request_id {clean_req_id!r} was reused with conflicting arguments.",
                            details={"run_id": run_id, "request_id": clean_req_id},
                        )
                    return HypothesisRecord.model_validate_json(str(prior["response_json"]))

            if snapshot.manifest.closed_at is not None:
                raise ScopeDeniedError(f"Cannot modify hypotheses on closed run {run_id!r}.")

            if expected_revision is None:
                if clean_claim is None or clean_next is None:
                    raise ContractViolationError(
                        "Creating a hypothesis requires non-empty claim and next_observation."
                    )
                record = self.hypotheses.create_hypothesis_in_tx(
                    conn,
                    run_id=run_id,
                    claim=clean_claim,
                    next_observation=clean_next,
                    state=target_state,
                    supporting_evidence_ids=tuple(supporting_evidence_ids),
                    contradicting_evidence_ids=tuple(contradicting_evidence_ids),
                    hypothesis_id=hypothesis_id,
                    require_existing_evidence=require_existing_evidence,
                    now=now,
                )
            else:
                if not hypothesis_id:
                    raise ContractViolationError(
                        "Updating an existing hypothesis requires hypothesis_id."
                    )
                sup_tuple = (
                    tuple(supporting_evidence_ids)
                    if supporting_evidence_ids
                    else None
                )
                con_tuple = (
                    tuple(contradicting_evidence_ids)
                    if contradicting_evidence_ids
                    else None
                )
                record = self.hypotheses.update_hypothesis_in_tx(
                    conn,
                    hypothesis_id=hypothesis_id,
                    run_id=run_id,
                    expected_revision=expected_revision,
                    state=target_state,
                    claim=clean_claim,
                    next_observation=clean_next,
                    supporting_evidence_ids=sup_tuple,
                    contradicting_evidence_ids=con_tuple,
                    add_supporting_evidence_ids=tuple(add_supporting_evidence_ids),
                    add_contradicting_evidence_ids=tuple(add_contradicting_evidence_ids),
                    require_existing_evidence=require_existing_evidence,
                    now=now,
                )

            if clean_req_id is not None and req_digest is not None:
                conn.execute(
                    """
                    INSERT INTO hypothesis_requests (
                        principal_id, run_id, request_id, request_digest,
                        hypothesis_id, result_revision, response_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        principal.principal_id,
                        run_id,
                        clean_req_id,
                        req_digest,
                        record.hypothesis_id,
                        record.revision,
                        record.model_dump_json(),
                        now.isoformat(),
                    ),
                )

            self.audit.record_sanitized_in_tx(
                conn,
                AuditEvent(
                    event_id=f"aud-{uuid4().hex}",
                    timestamp=now,
                    run_id=run_id,
                    principal_id=principal.principal_id,
                    action_id=None,
                    capability="hypothesis.update",
                    operation="create" if expected_revision is None else "update",
                    outcome=EnvelopeStatus.OK.value,
                    usage=None,
                    scope_revision=snapshot.manifest.scope_revision,
                    destination_summary=f"hypothesis_id={record.hypothesis_id};rev={record.revision};state={record.state.value}",
                ),
            )
            return record

    def verify_run(
        self,
        *,
        principal: PrincipalContext,
        run_id: str,
        verifier_id: str = "ctf.local_digest",
        evidence_ids: Sequence[str] = (),
        claim: str | None = None,
        auto_redact_after_verify: bool = False,
        extra_redaction_literals: Sequence[str] = (),
    ) -> VerificationRecord:
        """Run a registered VerifierPort before redacting raw views, then optionally redact.

        Enforces the #29 ordering guarantee: LocalCtfVerifier inspects unrevoked raw
        views (or explicit claim) first so digests verify cleanly without ever exposing
        or storing plaintext flags in VerificationRecord or reports.
        """
        snapshot = self._get_owned_snapshot(principal=principal, run_id=run_id)
        if snapshot.manifest.closed_at is not None:
            raise ScopeDeniedError(f"Cannot verify closed run {run_id!r}.")

        # Verify that every referenced evidence_id belongs to this run & principal.
        eid_tuple = tuple(evidence_ids)
        for eid in eid_tuple:
            self.evidence_vault.get_manifest(
                run_id=run_id,
                principal_id=principal.principal_id,
                evidence_id=eid,
            )

        record = self.verifier_registry.verify(
            verifier_id,
            run_id=run_id,
            evidence_ids=eid_tuple,
            claim=claim,
        )
        lim = (
            (record.limitations,)
            if isinstance(record.limitations, str)
            else tuple(record.limitations)
        )
        ver_text = " ".join([*(str(x) for x in record.checks_performed), *(str(x) for x in lim)])
        if scan_sensitive_markers(ver_text):
            raise ContractViolationError(
                "Verifier output contains forbidden sensitive markers."
            )

        with self.storage.transaction() as conn:
            save_verification_record_in_tx(conn, record)
            self.audit.record_sanitized_in_tx(
                conn,
                AuditEvent(
                    event_id=f"aud-{uuid4().hex}",
                    timestamp=self._now(),
                    run_id=run_id,
                    principal_id=principal.principal_id,
                    action_id=None,
                    capability="run.verify",
                    operation=verifier_id,
                    outcome=(
                        EnvelopeStatus.OK.value
                        if record.status.value == "passed"
                        else EnvelopeStatus.TOOL_ERROR.value
                    ),
                    usage=None,
                    scope_revision=snapshot.manifest.scope_revision,
                    destination_summary=f"verifier={verifier_id};status={record.status.value}",
                ),
            )

        if auto_redact_after_verify and eid_tuple:
            for eid in eid_tuple:
                self.redact_evidence(
                    principal=principal,
                    run_id=run_id,
                    evidence_id=eid,
                    extra_literals=extra_redaction_literals,
                    revoke_prior_views=True,
                )

        return record

    # ------------------------------------------------------------------
    # Crash reconciliation resolution, worker fencing, leases, & guest recovery
    # ------------------------------------------------------------------

    @staticmethod
    def _coerce_lifecycle_state(target_state: ActionLifecycleState | str) -> ActionLifecycleState:
        return (
            target_state
            if isinstance(target_state, ActionLifecycleState)
            else ActionLifecycleState(target_state)
        )

    @staticmethod
    def _sanitize_summary_text(summary: str | None) -> str | None:
        if summary is None:
            return None
        cleaned = sanitize_audit_text(summary)
        if contains_sensitive_marker(cleaned):
            raise ContractViolationError("Action summary must not contain sensitive markers.")
        return cleaned

    def _get_snapshot_and_principal_in_tx(
        self,
        conn: sqlite3.Connection,
        *,
        run_id: str,
        principal: PrincipalContext | None,
    ) -> tuple[RunSnapshot, str]:
        snapshot = (
            self._get_owned_snapshot_in_tx(conn, principal=principal, run_id=run_id)
            if principal is not None
            else self.runs.get_run_snapshot_in_tx(conn, run_id)
        )
        eff_principal = (
            principal.principal_id
            if principal is not None
            else snapshot.manifest.owner_principal_id
        )
        return snapshot, eff_principal

    def resolve_reconciled_action(
        self,
        *,
        action_id: str,
        target_state: ActionLifecycleState | str,
        principal: PrincipalContext | None = None,
        usage: UsageMetrics | None = None,
        has_tool_receipt: bool = False,
        summary: str | None = None,
        evidence: Sequence[EvidenceRef] = (),
        error: ErrorDetail | None = None,
        process_start_id: str | None = None,
        retain_reservation: bool = False,
        usage_unknown: bool | None = None,
        cleanup_confirmed: bool = True,
    ) -> ActionSubmission:
        """Resolve an action in ``reconciliation_required`` with audit recording."""
        target_lifecycle = self._coerce_lifecycle_state(target_state)
        clean_summary = self._sanitize_summary_text(summary)
        clean_err = _sanitize_error_detail(error)
        ts = self._now()

        with self.storage.transaction() as conn:
            self._ensure_controller_schemas_in_tx(conn)
            current = self.actions.get_action_with_envelope_in_tx(conn, action_id).action
            snapshot, eff_principal = self._get_snapshot_and_principal_in_tx(
                conn, run_id=current.run_id, principal=principal
            )
            resolved = self.recovery.resolve_reconciled_action_in_tx(
                conn,
                action_id=action_id,
                target_state=target_lifecycle,
                usage=usage,
                has_tool_receipt=has_tool_receipt,
                summary=clean_summary,
                evidence=tuple(evidence),
                error=clean_err,
                supervisor_key=self._supervisor_key,
                supervisor_instance_id=self._supervisor_instance_id,
                process_start_id=process_start_id,
                retain_reservation=retain_reservation,
                usage_unknown=usage_unknown,
                cleanup_confirmed=cleanup_confirmed,
                manage_run_budget=True,
                now=ts,
            )
            self.audit.record_sanitized_in_tx(
                conn,
                AuditEvent(
                    event_id=f"aud-{uuid4().hex}",
                    timestamp=ts,
                    run_id=current.run_id,
                    principal_id=eff_principal,
                    action_id=current.action_id,
                    capability=current.capability_name,
                    operation=f"reconcile_resolve:{target_lifecycle.value}",
                    outcome=(
                        resolved.envelope.status.value
                        if resolved.envelope is not None
                        else target_lifecycle.value
                    ),
                    usage=usage,
                    scope_revision=snapshot.manifest.scope_revision,
                    destination_summary=(
                        f"retain_reservation={bool(retain_reservation)};"
                        f"cleanup_confirmed={bool(cleanup_confirmed)}"
                    ),
                ),
            )
            return resolved

    def commit_worker_result(
        self,
        *,
        action_id: str,
        fencing_token: int,
        target_state: ActionLifecycleState | str,
        usage: UsageMetrics,
        principal: PrincipalContext | None = None,
        has_tool_receipt: bool = True,
        summary: str | None = None,
        evidence: Sequence[EvidenceRef] = (),
        truncated: bool = False,
        next_cursor: str | None = None,
        error: ErrorDetail | None = None,
        usage_unknown: bool = False,
        cleanup_confirmed: bool = True,
    ) -> ActionSubmission:
        """Commit an out-of-band worker result guarded by strict fencing verification."""
        target_lifecycle = self._coerce_lifecycle_state(target_state)
        clean_summary = self._sanitize_summary_text(summary)
        clean_err = _sanitize_error_detail(error)
        ts = self._now()

        with self.storage.transaction() as conn:
            self._ensure_controller_schemas_in_tx(conn)
            current = self.actions.get_action_with_envelope_in_tx(conn, action_id).action
            snapshot, eff_principal = self._get_snapshot_and_principal_in_tx(
                conn, run_id=current.run_id, principal=principal
            )
            committed = self.recovery.commit_worker_result_in_tx(
                conn,
                action_id=action_id,
                fencing_token=fencing_token,
                target_state=target_lifecycle,
                usage=usage,
                has_tool_receipt=has_tool_receipt,
                summary=clean_summary,
                evidence=tuple(evidence),
                truncated=truncated,
                next_cursor=next_cursor,
                error=clean_err,
                supervisor_key=self._supervisor_key,
                usage_unknown=usage_unknown,
                cleanup_confirmed=cleanup_confirmed,
                manage_run_budget=True,
                now=ts,
            )
            self.audit.record_sanitized_in_tx(
                conn,
                AuditEvent(
                    event_id=f"aud-{uuid4().hex}",
                    timestamp=ts,
                    run_id=current.run_id,
                    principal_id=eff_principal,
                    action_id=current.action_id,
                    capability=current.capability_name,
                    operation=f"worker_commit:{target_lifecycle.value}",
                    outcome=(
                        committed.envelope.status.value
                        if committed.envelope is not None
                        else target_lifecycle.value
                    ),
                    usage=usage,
                    scope_revision=snapshot.manifest.scope_revision,
                    destination_summary=(
                        f"fencing_token={fencing_token};cleanup_confirmed={bool(cleanup_confirmed)}"
                    ),
                ),
            )
            return committed

    def acquire_lease(
        self,
        *,
        principal: PrincipalContext,
        run_id: str,
        capability_name: str,
        adapter_revision: str | None = None,
        artifact_id: str | None = None,
        endpoint: str | None = None,
        idle_seconds: int | None = None,
    ) -> SessionLease:
        """Acquire a bounded interactive session lease within run concurrency limits."""
        ts = self._now()
        resolved_rev = adapter_revision
        with self.storage.transaction() as conn:
            snapshot = self._get_owned_snapshot_in_tx(conn, principal=principal, run_id=run_id)
            if not resolved_rev:
                with self._lock:
                    spec = self._adapters.get(capability_name)
                if spec is not None:
                    resolved_rev = spec.descriptor.adapter_commit
                else:
                    try:
                        resolved_rev = self.catalog.get_capability(
                            capability_name, snapshot.manifest.mode
                        ).adapter_commit
                    except CapabilityDeniedError:
                        resolved_rev = "unregistered"
            lease = self.leases.acquire_lease_in_tx(
                conn,
                run_id=run_id,
                principal_id=principal.principal_id,
                capability_name=capability_name,
                adapter_revision=resolved_rev,
                artifact_id=artifact_id,
                endpoint=endpoint,
                supervisor_instance_id=self._supervisor_instance_id,
                idle_seconds=idle_seconds,
                now=ts,
            )
            self.audit.record_sanitized_in_tx(
                conn,
                AuditEvent(
                    event_id=f"aud-{uuid4().hex}",
                    timestamp=ts,
                    run_id=run_id,
                    principal_id=principal.principal_id,
                    action_id=None,
                    capability="session.lease",
                    operation="acquire",
                    outcome=EnvelopeStatus.OK.value,
                    usage=None,
                    scope_revision=snapshot.manifest.scope_revision,
                    destination_summary=f"session_id={lease.session_id};capability={capability_name}",
                ),
            )
            return lease

    def touch_lease(
        self,
        *,
        session_id: str,
        run_id: str | None = None,
        principal: PrincipalContext | None = None,
    ) -> SessionLease:
        """Extend an active session lease heartbeat or fail closed if idle-expired."""
        ts = self._now()
        existing = self.leases.get_lease(session_id)
        if run_id is not None and existing.run_id != run_id:
            raise ScopeDeniedError(
                f"Session lease {session_id!r} does not belong to run {run_id!r}."
            )
        if principal is not None:
            _ = self._get_owned_snapshot(principal=principal, run_id=existing.run_id)
        updated = self.leases.touch_lease(
            session_id,
            run_id=run_id,
            principal_id=(principal.principal_id if principal is not None else None),
            now=ts,
        )
        with self.storage.transaction() as conn:
            snap = self.runs.get_run_snapshot_in_tx(conn, updated.run_id)
            self.audit.record_sanitized_in_tx(
                conn,
                AuditEvent(
                    event_id=f"aud-{uuid4().hex}",
                    timestamp=ts,
                    run_id=updated.run_id,
                    principal_id=(
                        principal.principal_id if principal is not None else updated.principal_id
                    ),
                    action_id=None,
                    capability="session.lease",
                    operation="touch",
                    outcome=EnvelopeStatus.OK.value,
                    usage=None,
                    scope_revision=snap.manifest.scope_revision,
                    destination_summary=f"session_id={updated.session_id};expires_at={updated.expires_at.isoformat()}",
                ),
            )
        return updated

    def expire_idle_leases(
        self,
        *,
        principal: PrincipalContext | None = None,
        run_id: str | None = None,
    ) -> list[SessionLease]:
        """Sweep and expire idle session leases, releasing session concurrency slots."""
        ts = self._now()
        with self.storage.transaction() as conn:
            if principal is not None and run_id is not None:
                _ = self._get_owned_snapshot_in_tx(conn, principal=principal, run_id=run_id)
            expired = self.leases.expire_idle_leases_in_tx(conn, run_id=run_id, now=ts)
            for lease in expired:
                if principal is not None and lease.principal_id != principal.principal_id:
                    continue
                snap = self.runs.get_run_snapshot_in_tx(conn, lease.run_id)
                self.audit.record_sanitized_in_tx(
                    conn,
                    AuditEvent(
                        event_id=f"aud-{uuid4().hex}",
                        timestamp=ts,
                        run_id=lease.run_id,
                        principal_id=lease.principal_id,
                        action_id=None,
                        capability="session.lease",
                        operation="expire_idle",
                        outcome=SessionLeaseState.EXPIRED.value,
                        usage=None,
                        scope_revision=snap.manifest.scope_revision,
                        destination_summary=f"session_id={lease.session_id};reason={lease.termination_reason}",
                    ),
                )
            return expired

    def close_lease(
        self,
        *,
        session_id: str,
        run_id: str | None = None,
        principal: PrincipalContext | None = None,
        reason: str = "closed_by_client",
    ) -> SessionLease:
        """Close an active session lease cleanly and record audit summary."""
        ts = self._now()
        clean_reason = sanitize_audit_text(reason) or "closed_by_client"
        if contains_sensitive_marker(clean_reason):
            raise ContractViolationError("Lease close reason must not contain sensitive markers.")

        with self.storage.transaction() as conn:
            self.leases.ensure_schema()
            row = conn.execute(
                "SELECT * FROM session_leases WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            if row is None:
                raise ContractViolationError(f"Session lease {session_id!r} does not exist.")
            existing_run_id = str(row["run_id"])
            existing_principal = str(row["principal_id"])
            if run_id is not None and existing_run_id != run_id:
                raise ScopeDeniedError(
                    f"Session lease {session_id!r} does not belong to run {run_id!r}."
                )
            if principal is not None:
                snapshot = self._get_owned_snapshot_in_tx(
                    conn, principal=principal, run_id=existing_run_id
                )
                if existing_principal != principal.principal_id:
                    raise ScopeDeniedError(
                        f"Principal {principal.principal_id!r} does not own session {session_id!r}."
                    )
            else:
                snapshot = self.runs.get_run_snapshot_in_tx(conn, existing_run_id)

            closed = self.leases.close_lease_in_tx(
                conn,
                session_id,
                run_id=run_id,
                reason=clean_reason,
                now=ts,
            )
            self.audit.record_sanitized_in_tx(
                conn,
                AuditEvent(
                    event_id=f"aud-{uuid4().hex}",
                    timestamp=ts,
                    run_id=closed.run_id,
                    principal_id=(
                        principal.principal_id if principal is not None else closed.principal_id
                    ),
                    action_id=None,
                    capability="session.lease",
                    operation="close",
                    outcome=SessionLeaseState.CLOSED.value,
                    usage=None,
                    scope_revision=snapshot.manifest.scope_revision,
                    destination_summary=f"session_id={closed.session_id};reason={clean_reason}",
                ),
            )
            return closed

    def recover_guest_ready(
        self,
        *,
        run_id: str,
        cleanup_verified: bool,
        note: str,
        principal: PrincipalContext | None = None,
    ) -> GuestHealthState:
        """Restore a ``cleanup_unconfirmed`` run to ``ready`` after operator cleanup verification."""
        ts = self._now()
        clean_note = sanitize_audit_text(note)
        if contains_sensitive_marker(clean_note):
            raise ContractViolationError("Recovery note must not contain sensitive markers.")

        with self.storage.transaction() as conn:
            snapshot, eff_principal = self._get_snapshot_and_principal_in_tx(
                conn, run_id=run_id, principal=principal
            )
            health = self.recovery.recover_guest_ready_in_tx(
                conn,
                run_id,
                cleanup_verified=cleanup_verified,
                note=clean_note,
                now=ts,
            )
            self.audit.record_sanitized_in_tx(
                conn,
                AuditEvent(
                    event_id=f"aud-{uuid4().hex}",
                    timestamp=ts,
                    run_id=run_id,
                    principal_id=eff_principal,
                    action_id=None,
                    capability="guest.recover",
                    operation="recover_ready",
                    outcome=EnvelopeStatus.OK.value,
                    usage=None,
                    scope_revision=snapshot.manifest.scope_revision,
                    destination_summary=f"note={clean_note}",
                ),
            )
            return health

    # ------------------------------------------------------------------
    # Ordered run closure & report export
    # ------------------------------------------------------------------

    def close_run(
        self,
        *,
        principal: PrincipalContext,
        run_id: str,
        language: Literal["ja", "en"] = "ja",
        output_relpath: str | None = None,
        overwrite: bool = False,
        findings: Sequence[FindingRecord] = (),
        metadata: ReportMetadata | None = None,
        forbidden_literals: Sequence[str] = (),
        require_verification: bool = False,
        child_processes_confirmed_stopped: bool = True,
        unconfirmed_process_ids: Sequence[str | int] = (),
        import_completed: bool = True,
        import_errors: Sequence[str] = (),
        expected_evidence_ids: Sequence[str] = (),
        auto_redact_report: bool = True,
        include_evidence_excerpts: bool = False,
        vm_rollback_hook: Callable[[str], bool] | None = None,
    ) -> RunCloseResult:
        """Close a run cleanly in strict contract order:

        1. Verify pre-rollback integrity (no active heavy/session jobs, zero
           non-terminal actions, guest_health != cleanup_unconfirmed, evidence
           hashes valid, child processes stopped, bounded import confirmed).
        2. Prepare and verify sanitized report IN MEMORY via RunReportExporter BEFORE
           guest rollback (never leaves unconfirmed report files on disk).
        3. Invoke guest rollback hook (defaults to local offline rollback = True)
           and mark guest_health = 'rolled_back' in TX.
        4. Verify final post-rollback close integrity, atomically write the verified
           report via write_verified_report, mark run closed, and record audit event.
        """
        snapshot = self._get_owned_snapshot(principal=principal, run_id=run_id)
        if snapshot.manifest.closed_at is not None:
            raise ScopeDeniedError(f"Run {run_id!r} is already closed.")
        if output_relpath is not None and self.report_exporter.export_root is None:
            raise ConfigurationError("output_relpath requires export_root to be configured.")

        # Step 1: Pre-rollback integrity check.
        with self.storage.read_connection() as conn:
            pre_report = evaluate_close_integrity_in_tx(
                conn,
                run_id=run_id,
                vault_root=self.vault_root,
                child_processes_confirmed_stopped=child_processes_confirmed_stopped,
                unconfirmed_process_ids=unconfirmed_process_ids,
                import_completed=import_completed,
                import_errors=import_errors,
                expected_evidence_ids=expected_evidence_ids,
                vm_rollback_succeeded=False,
                require_verification=require_verification,
                clock=self._now,
            )
        if not pre_report.close_allowed:
            details = pre_report.model_dump(mode="json")
            if not pre_report.cleanup_confirmed:
                raise GuestBlockedError(
                    f"Run {run_id!r} close blocked because cleanup could not be confirmed: "
                    f"{pre_report.blocking_reasons}.",
                    details=details,
                )
            raise ContractViolationError(
                f"Run {run_id!r} close blocked by integrity check: {pre_report.blocking_reasons}.",
                details=details,
            )

        # Step 2: Prepare sanitized report in memory BEFORE guest rollback (no disk write yet).
        prepared_report = self.report_exporter.prepare_run_report(
            run_id=run_id,
            principal_id=principal.principal_id,
            language=language,
            cleanup_confirmed=pre_report.cleanup_confirmed,
            import_confirmed=pre_report.import_verified,
            require_rolled_back=False,
            expected_evidence_ids=expected_evidence_ids,
            findings=findings,
            metadata=metadata,
            auto_redact=auto_redact_report,
            forbidden_literals=forbidden_literals,
            include_evidence_excerpts=include_evidence_excerpts,
        )

        # Step 3: Guest rollback (report verified in memory; failure leaves zero files on disk).
        try:
            rollback_ok = True if vm_rollback_hook is None else bool(vm_rollback_hook(run_id))
        except GuestBlockedError:
            raise
        except Exception as exc:
            raise GuestBlockedError(
                f"Guest rollback hook failed for run {run_id!r}; run remains open.",
                details={"run_id": run_id, "error": sanitize_audit_text(str(exc))},
            ) from exc
        if not rollback_ok:
            raise GuestBlockedError(
                f"Guest rollback failed for run {run_id!r}; run remains open.",
                details={"run_id": run_id},
            )

        with self.storage.transaction() as conn:
            self.recovery.mark_guest_rolled_back_in_tx(conn, run_id)

        # Step 4: Verify final close integrity -> write verified report -> close run -> audit.
        close_ts = self._now()
        with self.storage.transaction() as conn:
            final_report = evaluate_close_integrity_in_tx(
                conn,
                run_id=run_id,
                vault_root=self.vault_root,
                child_processes_confirmed_stopped=child_processes_confirmed_stopped,
                unconfirmed_process_ids=unconfirmed_process_ids,
                import_completed=import_completed,
                import_errors=import_errors,
                expected_evidence_ids=expected_evidence_ids,
                vm_rollback_succeeded=True,
                require_verification=require_verification,
                clock=self._now,
            )
            if not final_report.close_allowed:
                raise ContractViolationError(
                    f"Final close integrity check failed for {run_id!r}: "
                    f"{final_report.blocking_reasons}.",
                    details=final_report.model_dump(mode="json"),
                )
            final_prepared = self.report_exporter.prepare_run_report(
                run_id=run_id,
                principal_id=principal.principal_id,
                language=language,
                cleanup_confirmed=final_report.cleanup_confirmed,
                import_confirmed=final_report.import_verified,
                require_rolled_back=True,
                expected_evidence_ids=expected_evidence_ids,
                findings=findings,
                metadata=metadata,
                auto_redact=auto_redact_report,
                forbidden_literals=forbidden_literals,
                include_evidence_excerpts=include_evidence_excerpts,
                conn=conn,
            )
            _ = prepared_report
            if output_relpath is not None:
                export_result = self.report_exporter.write_verified_report(
                    final_prepared,
                    output_relpath=output_relpath,
                    overwrite=overwrite,
                    forbidden_literals=forbidden_literals,
                )
            else:
                export_result = final_prepared
            closed_manifest = self.runs.close_run_in_tx(conn, run_id, closed_at=close_ts)
            self.audit.record_sanitized_in_tx(
                conn,
                AuditEvent(
                    event_id=f"aud-{uuid4().hex}",
                    timestamp=close_ts,
                    run_id=run_id,
                    principal_id=principal.principal_id,
                    action_id=None,
                    capability="run.close",
                    operation="close",
                    outcome=EnvelopeStatus.OK.value,
                    usage=None,
                    scope_revision=closed_manifest.scope_revision,
                    destination_summary=(
                        f"report_sha256={export_result.report_sha256[:12]};guest_rolled_back=true"
                    ),
                ),
            )

        return RunCloseResult(
            manifest=closed_manifest,
            export_result=export_result,
            integrity_report=final_report,
            guest_rolled_back=True,
        )


def register_default_adapters(
    controller: HarnessController,
    *,
    static_inspector_enabled: bool = True,
    timeout_seconds: int | None = None,
    max_output_bytes: int = 65_536,
    max_decode_bytes: int = 65_536,
    require_running_state: bool = True,
) -> StaticArtifactInspectorAdapter:
    """Register the default P2 static artifact inspector onto ``controller``."""
    effective_timeout = timeout_seconds or (
        controller.config.execution.action_timeout_seconds
        if controller.config is not None
        else 60
    )
    inspector = StaticArtifactInspectorAdapter(
        enabled=static_inspector_enabled,
        timeout_seconds=effective_timeout,
        max_output_bytes=max_output_bytes,
        max_decode_bytes=max_decode_bytes,
        evidence_vault=controller.evidence_vault,
        require_running_state=require_running_state,
    )
    controller.register_adapter(inspector, tool_group="analysis.query")
    return inspector


VERIFIER_EXPECTATIONS_RELPATH = "_verifier/expectations.json"


def load_verifier_expectations(
    vault_root: str | Path,
) -> tuple[dict[str, ExpectedChallengeSpec], dict[str, ExpectedChallengeSpec]]:
    """Load digest-only verifier expectations stored inside the private vault root."""
    vault_path = Path(vault_root)
    target = vault_path / VERIFIER_EXPECTATIONS_RELPATH
    if not target.exists():
        return {}, {}
    raw = safe_read_bounded(
        vault_path,
        VERIFIER_EXPECTATIONS_RELPATH,
        max_bytes=1_048_576,
        allow_truncate=False,
    )
    payload = json.loads(raw.data.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ConfigurationError("Verifier expectations file must contain a JSON object.")
    by_run = {
        str(k): ExpectedChallengeSpec.model_validate(v)
        for k, v in dict(payload.get("runs") or {}).items()
    }
    by_task = {
        str(k): ExpectedChallengeSpec.model_validate(v)
        for k, v in dict(payload.get("tasks") or {}).items()
    }
    return by_run, by_task


def save_verifier_expectation(
    vault_root: str | Path,
    *,
    spec: ExpectedChallengeSpec,
    run_id: str | None = None,
    task_id: str | None = None,
) -> Path:
    """Persist a digest-only ExpectedChallengeSpec for a run_id and/or task_id atomically."""
    if not run_id and not task_id:
        raise ContractViolationError("At least one of run_id or task_id must be specified.")
    vault_path = Path(vault_root)
    vault_path.mkdir(parents=True, exist_ok=True)
    by_run, by_task = load_verifier_expectations(vault_path)
    if run_id:
        by_run[run_id] = spec
    if task_id:
        by_task[task_id] = spec
    data = {
        "runs": {k: v.model_dump(mode="json") for k, v in sorted(by_run.items())},
        "tasks": {k: v.model_dump(mode="json") for k, v in sorted(by_task.items())},
    }
    return safe_write_atomic(
        vault_path,
        VERIFIER_EXPECTATIONS_RELPATH,
        (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        overwrite=True,
        create_parents=True,
    )


def register_default_verifier(
    controller: HarnessController,
    *,
    replace: bool = False,
) -> LocalCtfVerifier:
    """Register the standard LocalCtfVerifier loaded with any private vault expectations."""
    expected_by_run, expected_by_task = load_verifier_expectations(controller.vault_root)
    verifier = LocalCtfVerifier(
        storage=controller.storage,
        vault_root=controller.vault_root,
        expected_by_run=expected_by_run,
        expected_by_task=expected_by_task,
    )
    controller.register_verifier(verifier, replace=replace)
    return verifier


def create_default_controller(
    *,
    storage: Storage,
    vault_root: str | Path,
    export_root: str | Path | None = None,
    staging_root: str | Path | None = None,
    cursor_hmac_key: bytes | None = None,
    config: HarnessConfig | None = None,
    runtime_settings: RuntimeSettings | None = None,
    allow_ephemeral_cursor_key: bool = False,
    allow_synthetic_adapters: bool = False,
    enable_static_inspector: bool | None = None,
    enable_local_verifier: bool = False,
    static_inspector_enabled: bool = True,
    timeout_seconds: int | None = None,
    max_output_bytes: int = 65_536,
    max_decode_bytes: int = 65_536,
    initialize: bool = True,
    **controller_kwargs: Any,
) -> HarnessController:
    """Construct and initialize a ``HarnessController`` with default static inspector."""
    vault_path = Path(vault_root)
    resolved_export_root = (
        Path(export_root) if export_root is not None else (vault_path / "_exports")
    )
    controller = HarnessController(
        storage=storage,
        vault_root=vault_path,
        export_root=resolved_export_root,
        staging_root=staging_root,
        cursor_hmac_key=cursor_hmac_key,
        config=config,
        runtime_settings=runtime_settings,
        allow_ephemeral_cursor_key=allow_ephemeral_cursor_key,
        allow_synthetic_adapters=allow_synthetic_adapters,
        **controller_kwargs,
    )
    if initialize:
        controller.initialize()

    if enable_static_inspector is None:
        if config is not None and config.execution.adapters_enabled:
            should_register = any(
                item
                in {
                    "analysis.query",
                    "artifact.inspect",
                    "ctf-static-inspector",
                    "ctf.static_inspector",
                    "static_inspector",
                }
                for item in config.execution.adapters_enabled
            )
        else:
            should_register = True
    else:
        should_register = bool(enable_static_inspector)

    if not initialize:
        controller.storage.initialize()
        with controller.storage.transaction() as conn:
            controller._ensure_controller_schemas_in_tx(conn)
        controller.leases.ensure_schema()

    if should_register:
        register_default_adapters(
            controller,
            static_inspector_enabled=static_inspector_enabled,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            max_decode_bytes=max_decode_bytes,
            require_running_state=True,
        )

    if enable_local_verifier:
        register_default_verifier(controller)

    return controller
