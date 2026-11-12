"""Layer 0 shared contracts, enums, state transitions, and boundary protocols.

This module has zero dependencies on other ``ctf_mcp`` submodules so that
Wave 1 packages (``gateway/``, ``runs/``, ``evidence/``, ``verification/``,
``adapters/``) can import shared data models and ports without circular imports.

References:
- ``docs/08-analysis-harness(.ja).md``
- ``docs/10-implementation-plan(.ja).md``
- ``docs/11-contracts-and-acceptance(.ja).md``
- ``schemas/evidence-page.schema.json``
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, model_validator

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class RunMode(StrEnum):
    """Execution profile mode for a harness run."""

    OFFLINE_CTF = "offline_ctf"
    SCOPED_CTF = "scoped_ctf"
    VDP = "vdp"


class ExecutionClass(StrEnum):
    """Capability execution boundary classification (docs/11 section 1)."""

    STATIC = "static"
    DYNAMIC = "dynamic"
    NETWORK = "network"
    SUBMISSION = "submission"


class ActionLifecycleState(StrEnum):
    """Action admission and execution lifecycle states (docs/11 section 2)."""

    PROPOSED = "proposed"
    DENIED = "denied"
    RESERVED = "reserved"
    EXPIRED = "expired"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    FAILED = "failed"
    RECONCILIATION_REQUIRED = "reconciliation_required"


class EnvelopeStatus(StrEnum):
    """Result-envelope status values returned to the client (docs/08 section 4)."""

    OK = "ok"
    PARTIAL = "partial"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    DENIED = "denied"
    TOOL_ERROR = "tool_error"


class HypothesisState(StrEnum):
    """Hypothesis ledger state (docs/08 section 3)."""

    SUPPORTED = "supported"
    REFUTED = "refuted"
    UNKNOWN = "unknown"


class FindingState(StrEnum):
    """VDP finding progression state (docs/08 section 7)."""

    CANDIDATE = "candidate"
    REPRODUCED = "reproduced"
    REPORT_READY = "report-ready"
    SUBMITTED = "submitted"
    ACCEPTED = "accepted"


class GuestHealthState(StrEnum):
    """Disposable guest health/cleanup state (docs/11 section 4)."""

    READY = "ready"
    CLEANUP_UNCONFIRMED = "cleanup_unconfirmed"
    ROLLED_BACK = "rolled_back"


class EvidenceRole(StrEnum):
    """Raw captured output vs derived summary/redacted object."""

    RAW = "raw"
    DERIVED = "derived"


class PageEncoding(StrEnum):
    """Allowed content encoding in ``evidence-page/1``."""

    UTF8 = "utf-8"
    BASE64 = "base64"


class VerificationStatus(StrEnum):
    """Outcome from a registered deterministic local verifier."""

    PASSED = "passed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"


class TransportMode(StrEnum):
    """Supported MCP server transports (docs/02 section 4.2)."""

    STDIO = "stdio"
    STREAMABLE_HTTP = "streamable-http"


# ---------------------------------------------------------------------------
# State Transition Tables and Mapping Helpers
# ---------------------------------------------------------------------------

TERMINAL_ACTION_STATES: frozenset[ActionLifecycleState] = frozenset(
    {
        ActionLifecycleState.DENIED,
        ActionLifecycleState.EXPIRED,
        ActionLifecycleState.COMPLETED,
        ActionLifecycleState.PARTIAL,
        ActionLifecycleState.TIMEOUT,
        ActionLifecycleState.CANCELLED,
        ActionLifecycleState.FAILED,
    }
)

ACTION_TRANSITIONS: dict[ActionLifecycleState, frozenset[ActionLifecycleState]] = {
    ActionLifecycleState.PROPOSED: frozenset(
        {ActionLifecycleState.DENIED, ActionLifecycleState.RESERVED}
    ),
    ActionLifecycleState.RESERVED: frozenset(
        {
            ActionLifecycleState.RUNNING,
            ActionLifecycleState.CANCELLED,
            ActionLifecycleState.EXPIRED,
        }
    ),
    ActionLifecycleState.RUNNING: frozenset(
        {
            ActionLifecycleState.COMPLETED,
            ActionLifecycleState.PARTIAL,
            ActionLifecycleState.TIMEOUT,
            ActionLifecycleState.CANCELLED,
            ActionLifecycleState.FAILED,
            ActionLifecycleState.RECONCILIATION_REQUIRED,
        }
    ),
    ActionLifecycleState.RECONCILIATION_REQUIRED: frozenset(
        {
            ActionLifecycleState.RUNNING,
            ActionLifecycleState.COMPLETED,
            ActionLifecycleState.PARTIAL,
            ActionLifecycleState.TIMEOUT,
            ActionLifecycleState.CANCELLED,
            ActionLifecycleState.FAILED,
        }
    ),
    ActionLifecycleState.DENIED: frozenset(),
    ActionLifecycleState.EXPIRED: frozenset(),
    ActionLifecycleState.COMPLETED: frozenset(),
    ActionLifecycleState.PARTIAL: frozenset(),
    ActionLifecycleState.TIMEOUT: frozenset(),
    ActionLifecycleState.CANCELLED: frozenset(),
    ActionLifecycleState.FAILED: frozenset(),
}

FINDING_TRANSITIONS: dict[FindingState, frozenset[FindingState]] = {
    FindingState.CANDIDATE: frozenset({FindingState.REPRODUCED}),
    FindingState.REPRODUCED: frozenset({FindingState.REPORT_READY}),
    FindingState.REPORT_READY: frozenset({FindingState.SUBMITTED}),
    FindingState.SUBMITTED: frozenset({FindingState.ACCEPTED}),
    FindingState.ACCEPTED: frozenset(),
}


# ---------------------------------------------------------------------------
# Domain Exceptions
# ---------------------------------------------------------------------------


class HarnessError(Exception):
    """Base domain error carrying a machine-readable error code."""

    default_code: str = "harness_error"

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code or self.default_code
        self.message = message
        self.details = details or {}


class ConfigurationError(HarnessError):
    default_code = "configuration_error"


class AuthenticationError(HarnessError):
    default_code = "authentication_error"


class ScopeDeniedError(HarnessError):
    default_code = "scope_denied"


class CapabilityDeniedError(HarnessError):
    default_code = "capability_denied"


class ActionConflictError(HarnessError):
    """Raised when ``(principal, run_id, request_id)`` is reused with different args."""

    default_code = "action_conflict"


class BudgetExceededError(HarnessError):
    default_code = "budget_exceeded"


class InvalidStateTransitionError(HarnessError):
    default_code = "invalid_state_transition"


class ContractViolationError(HarnessError):
    default_code = "contract_violation"


class EvidenceNotFoundError(HarnessError):
    default_code = "evidence_not_found"


class EvidenceAccessDeniedError(HarnessError):
    default_code = "evidence_access_denied"


class CursorError(HarnessError):
    default_code = "invalid_cursor"


class BoundsExceededError(HarnessError):
    default_code = "bounds_exceeded"


class PathSecurityError(HarnessError):
    default_code = "path_security_error"


class FencingError(HarnessError):
    default_code = "stale_fencing_token"


class GuestBlockedError(HarnessError):
    """Raised when ``cleanup_unconfirmed`` blocks further actions in a guest."""

    default_code = "guest_cleanup_unconfirmed"


# ---------------------------------------------------------------------------
# Transition & Canonical Hashing Functions
# ---------------------------------------------------------------------------


def validate_action_transition(
    current: ActionLifecycleState,
    target: ActionLifecycleState,
) -> None:
    """Validate that ``current -> target`` is allowed by docs/11 section 2."""
    allowed = ACTION_TRANSITIONS.get(current, frozenset())
    if target not in allowed:
        raise InvalidStateTransitionError(
            f"Action lifecycle transition {current.value!r} -> {target.value!r} is not permitted.",
            details={"current": current.value, "target": target.value},
        )


def validate_finding_transition(current: FindingState, target: FindingState) -> None:
    """Validate VDP finding state progression (docs/08 section 7)."""
    allowed = FINDING_TRANSITIONS.get(current, frozenset())
    if target not in allowed:
        raise InvalidStateTransitionError(
            f"Finding transition {current.value!r} -> {target.value!r} is not permitted.",
            details={"current": current.value, "target": target.value},
        )


def lifecycle_to_envelope_status(
    state: ActionLifecycleState,
    *,
    has_tool_receipt: bool = True,
    expiry_reason: str | None = None,
) -> EnvelopeStatus:
    """Map an action lifecycle state to a ResultEnvelope status (docs/11 section 2).

    Contracts enforced:
    - ``reconciliation_required`` never produces a successful terminal result.
    - Non-terminal states (``proposed``, ``reserved``, ``running``) cannot be mapped.
    - ``completed`` requires ``has_tool_receipt=True``.
    - ``failed`` always maps to ``tool_error`` (never ``ok``).
    - Pre-launch ``expired`` maps to ``denied`` and requires a non-empty ``expiry_reason``.
    """
    if state == ActionLifecycleState.RECONCILIATION_REQUIRED:
        raise InvalidStateTransitionError(
            "reconciliation_required has no terminal ResultEnvelope status.",
            details={"state": state.value},
        )
    if state not in TERMINAL_ACTION_STATES:
        raise InvalidStateTransitionError(
            f"Non-terminal state {state.value!r} cannot be mapped to ResultEnvelope status.",
            details={"state": state.value},
        )
    if state == ActionLifecycleState.COMPLETED:
        if not has_tool_receipt:
            raise ContractViolationError(
                "completed action without a verified tool receipt cannot map to ok."
            )
        return EnvelopeStatus.OK
    if state == ActionLifecycleState.FAILED:
        return EnvelopeStatus.TOOL_ERROR
    if state == ActionLifecycleState.DENIED:
        return EnvelopeStatus.DENIED
    if state == ActionLifecycleState.EXPIRED:
        if not expiry_reason or not expiry_reason.strip():
            raise ContractViolationError(
                "expired action mapping to denied requires an explicit expiry_reason."
            )
        return EnvelopeStatus.DENIED
    if state == ActionLifecycleState.PARTIAL:
        return EnvelopeStatus.PARTIAL
    if state == ActionLifecycleState.TIMEOUT:
        return EnvelopeStatus.TIMEOUT
    if state == ActionLifecycleState.CANCELLED:
        return EnvelopeStatus.CANCELLED
    raise ContractViolationError(f"Unhandled terminal state: {state!r}")


def canonical_json(value: Any) -> str:
    """Serialize any JSON-compatible or Pydantic structure deterministically."""
    if isinstance(value, BaseModel):
        payload: Any = value.model_dump(mode="json")
    else:
        payload = value
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_digest(value: Any) -> str:
    """Compute SHA-256 hex digest of canonical JSON representation."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Compute lowercase SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Strict Base Model & Core Data Contracts
# ---------------------------------------------------------------------------

SHA256_PATTERN = r"^[a-f0-9]{64}$"
MAX_PAGE_CONTENT_CHARS = 4000


class StrictModel(BaseModel):
    """Immutable, extra-field-forbidding base class for harness contracts."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class PrincipalContext(StrictModel):
    """Authenticated caller identity bound to a run and client profile."""

    principal_id: str = Field(min_length=1)
    auth_method: str = Field(min_length=1)
    client_kind: str = Field(min_length=1)
    model_label: str = Field(min_length=1)


class ScopePolicy(StrictModel):
    """Authoritative scope definition enforced outside the AI prompt."""

    scope_revision: str = Field(min_length=1)
    scope_sha256: str = Field(pattern=SHA256_PATTERN)
    mode: RunMode
    task_id: str = Field(min_length=1)
    authorization_reference: str = Field(min_length=1)
    allowed_execution_classes: tuple[ExecutionClass, ...]
    allowed_capabilities: tuple[str, ...]
    expires_at: datetime | None = None
    network_enabled: bool = False
    allowed_targets: tuple[str, ...] = ()
    external_submission: bool = False

    @model_validator(mode="after")
    def _enforce_offline_invariants(self) -> ScopePolicy:
        if self.mode == RunMode.OFFLINE_CTF:
            if self.network_enabled or self.allowed_targets:
                raise ValueError("offline_ctf scope cannot enable network or allowed_targets.")
            if self.external_submission:
                raise ValueError("offline_ctf scope cannot allow external_submission.")
            forbidden = {ExecutionClass.NETWORK, ExecutionClass.SUBMISSION}
            if forbidden.intersection(self.allowed_execution_classes):
                raise ValueError(
                    "offline_ctf scope cannot allow network or submission execution classes."
                )
        return self


class BudgetSpec(StrictModel):
    """Whole-run and per-action budget limits (defaults match offline-pilot.example.json)."""

    run_budget_seconds: int = Field(default=1800, gt=0)
    action_timeout_seconds: int = Field(default=60, gt=0)
    session_idle_seconds: int = Field(default=900, gt=0)
    max_tool_calls: int = Field(default=40, gt=0)
    max_output_chars_per_page: int = Field(default=MAX_PAGE_CONTENT_CHARS, gt=0, le=MAX_PAGE_CONTENT_CHARS)
    max_evidence_bytes_per_run: int = Field(default=104_857_600, gt=0)
    heavy_job_concurrency: int = Field(default=1, gt=0)
    interactive_session_limit: int = Field(default=1, gt=0)


class BudgetUsage(StrictModel):
    """Observed and reserved resource consumption for a run."""

    used_ms: int = Field(default=0, ge=0)
    reserved_ms: int = Field(default=0, ge=0)
    used_evidence_bytes: int = Field(default=0, ge=0)
    reserved_bytes: int = Field(default=0, ge=0)
    tool_calls_used: int = Field(default=0, ge=0)
    active_heavy_jobs: int = Field(default=0, ge=0)
    active_sessions: int = Field(default=0, ge=0)


class CapabilityLimits(StrictModel):
    """Measured and bounded execution limits pinned per capability."""

    timeout_seconds: int = Field(default=60, gt=0)
    max_output_bytes: int = Field(gt=0)
    max_decode_bytes: int = Field(gt=0)
    max_archive_depth: int = Field(default=3, ge=0)
    max_archive_entries: int = Field(default=256, gt=0)
    max_expansion_ratio: float = Field(default=20.0, gt=0.0)


class CapabilityDescriptor(StrictModel):
    """Pinned capability acceptance metadata (docs/11 section 1)."""

    name: str = Field(min_length=1)
    adapter_id: str = Field(min_length=1)
    adapter_commit: str = Field(min_length=1)
    dependency_lock_sha256: str = Field(pattern=SHA256_PATTERN)
    descriptor_sha256: str = Field(pattern=SHA256_PATTERN)
    operations: tuple[str, ...] = Field(min_length=1)
    arg_schema: dict[str, Any]
    execution_classes: tuple[ExecutionClass, ...] = Field(min_length=1)
    required_scope: dict[str, Any]
    limits: CapabilityLimits
    enabled: bool = True
    profile_modes: tuple[RunMode, ...] = (RunMode.OFFLINE_CTF,)


class ArtifactRecord(StrictModel):
    """Immutable intake artifact bound to a run via opaque ID (no client paths)."""

    artifact_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    sha256: str = Field(pattern=SHA256_PATTERN)
    byte_length: int = Field(ge=0)
    media_type: str = Field(min_length=1)
    source_origin: str = Field(min_length=1)
    storage_relpath: str = Field(min_length=1)


class RunManifest(StrictModel):
    """Immutable run manifest (must never contain credentials or flags)."""

    run_id: str = Field(min_length=1)
    owner_principal_id: str = Field(min_length=1)
    task_id: str = Field(min_length=1)
    mode: RunMode
    scope_revision: str = Field(min_length=1)
    scope_sha256: str = Field(pattern=SHA256_PATTERN)
    scope_expires_at: datetime | None = None
    artifact_hashes: dict[str, str] = Field(default_factory=dict)
    adapter_revisions: dict[str, str] = Field(default_factory=dict)
    client_label: str = Field(min_length=1)
    instruction_revision: str = Field(min_length=1)
    budget_spec: BudgetSpec
    created_at: datetime
    closed_at: datetime | None = None


class ActionRequest(StrictModel):
    """Typed action request carrying idempotency and revision keys."""

    run_id: str = Field(min_length=1)
    request_id: str = Field(min_length=1)
    expected_revision: int = Field(ge=0)
    capability_name: str = Field(min_length=1)
    operation: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)
    repeat_of: str | None = None


class ActionRecord(StrictModel):
    """Persisted action record including fencing and budget reservations."""

    run_id: str = Field(min_length=1)
    action_id: str = Field(min_length=1)
    request_id: str = Field(min_length=1)
    principal_id: str = Field(min_length=1)
    expected_revision: int = Field(ge=0)
    capability_name: str = Field(min_length=1)
    operation: str = Field(min_length=1)
    adapter_revision: str = Field(min_length=1)
    canonical_args_sha256: str = Field(pattern=SHA256_PATTERN)
    sanitized_args: dict[str, Any] = Field(default_factory=dict)
    scope_revision: str = Field(min_length=1)
    repeat_of: str | None = None
    state: ActionLifecycleState
    reserved_ms: int = Field(ge=0)
    reserved_bytes: int = Field(ge=0)
    used_ms: int = Field(default=0, ge=0)
    used_bytes: int = Field(default=0, ge=0)
    fencing_token: int | None = Field(default=None, ge=1)
    supervisor_instance_id: str | None = None
    process_start_id: str | None = None
    created_at: datetime
    updated_at: datetime


class EvidenceRef(StrictModel):
    """Reference to an evidence object inside ResultEnvelope."""

    id: str = Field(min_length=1)
    sha256: str = Field(pattern=SHA256_PATTERN)
    kind: str = Field(min_length=1)


class ErrorDetail(StrictModel):
    """Structured error payload for denied / failed envelopes."""

    code: str = Field(min_length=1)
    message: str = Field(min_length=1)
    retryable: bool = False


class UsageMetrics(StrictModel):
    """Measured analyzer execution cost."""

    wall_ms: int = Field(ge=0)
    output_bytes: int = Field(ge=0)


class ProvenanceInfo(StrictModel):
    """Adapter and scope provenance attached to every ResultEnvelope."""

    adapter_revision: str = Field(min_length=1)
    scope_revision: str = Field(min_length=1)


class ResultEnvelope(StrictModel):
    """Common action result envelope (docs/08 section 4 & docs/11 section 2)."""

    run_id: str = Field(min_length=1)
    action_id: str = Field(min_length=1)
    status: EnvelopeStatus
    summary: str = Field(min_length=1)
    evidence: tuple[EvidenceRef, ...] = ()
    truncated: bool = False
    next_cursor: str | None = None
    error: ErrorDetail | None = None
    usage: UsageMetrics
    provenance: ProvenanceInfo

    @model_validator(mode="after")
    def _validate_status_invariants(self) -> ResultEnvelope:
        if self.status in {EnvelopeStatus.TOOL_ERROR, EnvelopeStatus.DENIED}:
            if self.error is None:
                raise ValueError(f"ResultEnvelope with status={self.status.value!r} requires error.")
        if self.status == EnvelopeStatus.OK and self.error is not None:
            raise ValueError("ResultEnvelope with status='ok' must have error=None.")
        return self


class EvidenceManifest(StrictModel):
    """Evidence provenance manifest owned by the evidence service (docs/11 section 3)."""

    evidence_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    owner_principal_id: str = Field(min_length=1)
    action_id: str = Field(min_length=1)
    source_artifact_hashes: tuple[str, ...] = ()
    adapter_revision: str = Field(min_length=1)
    sanitized_args_sha256: str = Field(pattern=SHA256_PATTERN)
    captured_at: datetime
    byte_length: int = Field(ge=0)
    media_type: str = Field(min_length=1)
    capture_complete: bool
    omission_reason: str | None = None
    role: EvidenceRole
    parent_evidence_ids: tuple[str, ...] = ()
    view_revision: str = Field(min_length=1)
    view_sha256: str = Field(pattern=SHA256_PATTERN)
    storage_relpath: str = Field(min_length=1)
    redaction_policy_rev: str | None = None
    revoked_at: datetime | None = None

    @model_validator(mode="after")
    def _validate_completeness(self) -> EvidenceManifest:
        if not self.capture_complete and (not self.omission_reason or not self.omission_reason.strip()):
            raise ValueError("Incomplete capture requires non-empty omission_reason.")
        if self.capture_complete and self.omission_reason is not None:
            raise ValueError("Complete capture must set omission_reason=None.")
        if self.role == EvidenceRole.DERIVED and not self.parent_evidence_ids:
            raise ValueError("Derived evidence view must link parent_evidence_ids.")
        return self


class EvidencePage(StrictModel):
    """Immutable evidence page matching schemas/evidence-page.schema.json (evidence-page/1)
    plus runtime semantic checks from schemas/README.md and docs/11 section 3.
    """

    schema_version: Literal["evidence-page/1"] = "evidence-page/1"
    run_id: str = Field(min_length=1)
    evidence_id: str = Field(min_length=1)
    view_sha256: str = Field(pattern=SHA256_PATTERN)
    view_revision: str = Field(min_length=1)
    encoding: PageEncoding
    offset_bytes: int = Field(ge=0)
    next_offset_bytes: int = Field(ge=0)
    view_bytes: int = Field(ge=0)
    content: str = Field(max_length=MAX_PAGE_CONTENT_CHARS)
    capture_complete: bool
    omission_reason: str | None
    next_cursor: str | None

    @model_validator(mode="after")
    def _validate_page_invariants(self) -> EvidencePage:
        if not self.capture_complete:
            if not self.omission_reason or not self.omission_reason.strip():
                raise ValueError("capture_complete=False requires a non-empty omission_reason.")
        elif self.omission_reason is not None:
            raise ValueError("capture_complete=True requires omission_reason=None.")

        if not (0 <= self.offset_bytes <= self.next_offset_bytes <= self.view_bytes):
            raise ValueError(
                "Page offsets must satisfy 0 <= offset_bytes <= next_offset_bytes <= view_bytes."
            )

        if self.next_cursor is not None:
            if not self.next_cursor.strip():
                raise ValueError("next_cursor cannot be blank whitespace.")
            if self.next_offset_bytes <= self.offset_bytes:
                raise ValueError("Non-terminal page (next_cursor != None) must advance offset.")
            if self.next_offset_bytes >= self.view_bytes:
                raise ValueError("Terminal offset cannot emit non-null next_cursor.")
        else:
            if self.next_offset_bytes != self.view_bytes:
                raise ValueError("Terminal page (next_cursor == None) must reach view_bytes.")

        expected_span = self.next_offset_bytes - self.offset_bytes
        if self.encoding == PageEncoding.UTF8:
            actual_bytes = len(self.content.encode("utf-8"))
        else:
            try:
                actual_bytes = len(base64.b64decode(self.content, validate=True))
            except Exception as exc:
                raise ValueError(f"Invalid base64 content in EvidencePage: {exc}") from exc

        if actual_bytes != expected_span:
            raise ValueError(
                f"Decoded content byte span ({actual_bytes}) does not match "
                f"next_offset_bytes - offset_bytes ({expected_span})."
            )
        return self


class CursorPayload(StrictModel):
    """Structured fields bound inside an opaque authenticated evidence cursor."""

    run_id: str = Field(min_length=1)
    principal_id: str = Field(min_length=1)
    evidence_id: str = Field(min_length=1)
    view_sha256: str = Field(pattern=SHA256_PATTERN)
    view_revision: str = Field(min_length=1)
    offset_bytes: int = Field(ge=0)
    issued_at: datetime


class HypothesisRecord(StrictModel):
    """Recoverable hypothesis ledger entry (docs/08 section 3)."""

    hypothesis_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    claim: str = Field(min_length=1)
    state: HypothesisState
    supporting_evidence_ids: tuple[str, ...] = ()
    contradicting_evidence_ids: tuple[str, ...] = ()
    next_observation: str = Field(min_length=1)
    revision: int = Field(default=1, ge=1)
    updated_at: datetime


class FindingRecord(StrictModel):
    """Structured finding record separate from empty-result tool errors."""

    finding_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    location: str = Field(min_length=1)
    affected_version: str = Field(min_length=1)
    observation: str = Field(min_length=1)
    preconditions: str = Field(min_length=1)
    impact_hypothesis: str = Field(min_length=1)
    reproducer_evidence_ids: tuple[str, ...] = ()
    contradictory_evidence_ids: tuple[str, ...] = ()
    verification_state: FindingState = FindingState.CANDIDATE


class VerificationRecord(StrictModel):
    """Outcome produced by an independent local verifier."""

    verification_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    verifier_id: str = Field(min_length=1)
    verifier_revision: str = Field(min_length=1)
    status: VerificationStatus
    checks_performed: tuple[str, ...] = Field(min_length=1)
    limitations: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    verified_at: datetime


class AuditEvent(StrictModel):
    """Sanitized audit summary (never stores raw args, raw output, flags, or secrets)."""

    event_id: str = Field(min_length=1)
    timestamp: datetime
    run_id: str = Field(min_length=1)
    principal_id: str = Field(min_length=1)
    action_id: str | None = None
    capability: str | None = None
    operation: str | None = None
    outcome: str = Field(min_length=1)
    usage: UsageMetrics | None = None
    scope_revision: str | None = None
    destination_summary: str | None = None


# ---------------------------------------------------------------------------
# Boundary Protocols for Wave 1 Modules
# ---------------------------------------------------------------------------


@runtime_checkable
class ScopeValidatorPort(Protocol):
    """Validates scope presence, expiry, mode, and operation permissions."""

    def validate_action(
        self,
        principal: PrincipalContext,
        run_id: str,
        capability: CapabilityDescriptor,
        operation: str,
        *,
        now: datetime | None = None,
    ) -> ScopePolicy: ...


@runtime_checkable
class CatalogPort(Protocol):
    """Manages accepted capabilities and filters disabled tools from visibility."""

    def list_visible_tools(self, mode: RunMode) -> list[CapabilityDescriptor]: ...

    def get_capability(self, name: str, mode: RunMode) -> CapabilityDescriptor: ...


@runtime_checkable
class BudgetManagerPort(Protocol):
    """Atomically reserves and settles run budgets."""

    def reserve_action(
        self,
        *,
        run_id: str,
        principal_id: str,
        request: ActionRequest,
        capability: CapabilityDescriptor,
        scope_revision: str,
    ) -> ActionRecord: ...

    def settle_action(
        self,
        *,
        action_id: str,
        target_state: ActionLifecycleState,
        usage: UsageMetrics,
        fencing_token: int | None = None,
    ) -> ActionRecord: ...


@runtime_checkable
class AuditLoggerPort(Protocol):
    """Records sanitized audit events without raw arguments or secret markers."""

    def record(self, event: AuditEvent) -> None: ...


@runtime_checkable
class EvidenceVaultPort(Protocol):
    """Stores immutable captured evidence and serves bounded, authorized pages."""

    def store_raw(
        self,
        *,
        run_id: str,
        owner_principal_id: str,
        action_id: str,
        data: bytes,
        media_type: str,
        capture_complete: bool,
        omission_reason: str | None,
        source_artifact_hashes: tuple[str, ...],
        adapter_revision: str,
        sanitized_args_sha256: str,
    ) -> EvidenceManifest: ...

    def read_page(
        self,
        *,
        run_id: str,
        principal_id: str,
        evidence_id: str,
        cursor: str | None = None,
    ) -> EvidencePage: ...


@runtime_checkable
class AdapterPort(Protocol):
    """Guest-side narrow adapter interface."""

    def descriptor(self) -> CapabilityDescriptor: ...

    def execute(
        self,
        action: ActionRecord,
        *,
        artifact_paths: dict[str, Any] | None = None,
    ) -> ResultEnvelope: ...


@runtime_checkable
class VerifierPort(Protocol):
    """Registered deterministic local verification check."""

    verifier_id: str
    verifier_revision: str

    def verify(
        self,
        *,
        run_id: str,
        evidence_ids: tuple[str, ...],
        claim: str | None = None,
    ) -> VerificationRecord: ...


__all__ = [
    "ACTION_TRANSITIONS",
    "ActionConflictError",
    "ActionLifecycleState",
    "ActionRecord",
    "ActionRequest",
    "AdapterPort",
    "ArtifactRecord",
    "AuditEvent",
    "AuditLoggerPort",
    "AuthenticationError",
    "BoundsExceededError",
    "BudgetExceededError",
    "BudgetManagerPort",
    "BudgetSpec",
    "BudgetUsage",
    "CapabilityDeniedError",
    "CapabilityDescriptor",
    "CapabilityLimits",
    "CatalogPort",
    "ConfigurationError",
    "ContractViolationError",
    "CursorError",
    "CursorPayload",
    "EnvelopeStatus",
    "ErrorDetail",
    "EvidenceAccessDeniedError",
    "EvidenceManifest",
    "EvidenceNotFoundError",
    "EvidencePage",
    "EvidenceRef",
    "EvidenceRole",
    "EvidenceVaultPort",
    "ExecutionClass",
    "FINDING_TRANSITIONS",
    "FencingError",
    "FindingRecord",
    "FindingState",
    "GuestBlockedError",
    "GuestHealthState",
    "HarnessError",
    "HypothesisRecord",
    "HypothesisState",
    "InvalidStateTransitionError",
    "MAX_PAGE_CONTENT_CHARS",
    "PageEncoding",
    "PathSecurityError",
    "PrincipalContext",
    "ProvenanceInfo",
    "ResultEnvelope",
    "RunManifest",
    "RunMode",
    "SHA256_PATTERN",
    "ScopeDeniedError",
    "ScopePolicy",
    "ScopeValidatorPort",
    "StrictModel",
    "TERMINAL_ACTION_STATES",
    "TransportMode",
    "UsageMetrics",
    "VerificationRecord",
    "VerificationStatus",
    "VerifierPort",
    "canonical_digest",
    "canonical_json",
    "lifecycle_to_envelope_status",
    "sha256_bytes",
    "validate_action_transition",
    "validate_finding_transition",
]
