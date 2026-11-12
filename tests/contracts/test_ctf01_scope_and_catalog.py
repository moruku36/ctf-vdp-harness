"""Contract tests for CTF-01, principal auth, budget atomicity, and audit sanitization."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ctf_mcp.config import RuntimeSettings
from ctf_mcp.contracts import (
    AuditEvent,
    AuthenticationError,
    BudgetExceededError,
    BudgetSpec,
    CapabilityDeniedError,
    CapabilityDescriptor,
    CapabilityLimits,
    ContractViolationError,
    ExecutionClass,
    GuestBlockedError,
    GuestHealthState,
    PrincipalContext,
    RunMode,
    ScopeDeniedError,
    ScopePolicy,
    TransportMode,
    UsageMetrics,
    canonical_digest,
)
from ctf_mcp.gateway import (
    AuditLogger,
    CapabilityCatalog,
    PrincipalAuthenticator,
    RunBudgetManager,
    ScopeValidator,
    build_capability_descriptor,
    contains_sensitive_marker,
    summarize_arguments,
)
from ctf_mcp.storage import Storage


def _seed_run(
    storage: Storage,
    *,
    run_id: str = "run-1",
    owner_principal_id: str = "alice",
    mode: RunMode = RunMode.OFFLINE_CTF,
    scope_revision: str = "scope-1",
    budget_spec: BudgetSpec | None = None,
    closed_at: str | None = None,
) -> BudgetSpec:
    spec = budget_spec or BudgetSpec()
    with storage.transaction() as conn:
        conn.execute(
            """
            INSERT INTO runs (
                run_id, owner_principal_id, task_id, mode, scope_revision,
                manifest_json, budget_spec_json, remaining_ms, remaining_bytes,
                remaining_calls, active_heavy_jobs, active_sessions,
                guest_health, revision, created_at, closed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 'ready', 1, ?, ?)
            """,
            (
                run_id,
                owner_principal_id,
                "task-1",
                mode.value,
                scope_revision,
                "{}",
                spec.model_dump_json(),
                spec.run_budget_seconds * 1000,
                spec.max_evidence_bytes_per_run,
                spec.max_tool_calls,
                "2026-11-13T00:00:00+00:00",
                closed_at,
            ),
        )
    return spec


def _make_static_descriptor(
    *,
    name: str = "artifact.inspect",
    enabled: bool = True,
    profile_modes: tuple[RunMode, ...] = (RunMode.OFFLINE_CTF,),
    execution_classes: tuple[ExecutionClass, ...] = (ExecutionClass.STATIC,),
    required_scope: dict[str, object] | None = None,
) -> CapabilityDescriptor:
    return build_capability_descriptor(
        name=name,
        adapter_id="static-core",
        adapter_commit="1234567890abcdef",
        dependency_lock_sha256="a" * 64,
        operations=("header", "strings"),
        arg_schema={
            "type": "object",
            "additionalProperties": False,
            "required": ["artifact_id"],
            "properties": {
                "artifact_id": {"type": "string", "pattern": "^art_[a-f0-9]+$"},
                "max_lines": {"type": "integer", "minimum": 1, "maximum": 200},
            },
        },
        execution_classes=execution_classes,
        required_scope=required_scope if required_scope is not None else {"mode": "offline_ctf"},
        limits=CapabilityLimits(timeout_seconds=60, max_output_bytes=65536, max_decode_bytes=4096),
        enabled=enabled,
        profile_modes=profile_modes,
    )


def _make_scope(
    *,
    scope_revision: str = "scope-1",
    mode: RunMode = RunMode.OFFLINE_CTF,
    allowed_execution_classes: tuple[ExecutionClass, ...] = (ExecutionClass.STATIC,),
    allowed_capabilities: tuple[str, ...] = ("artifact.inspect",),
    expires_at: datetime | None = None,
    network_enabled: bool = False,
    allowed_targets: tuple[str, ...] = (),
    external_submission: bool = False,
) -> ScopePolicy:
    payload = {
        "scope_revision": scope_revision,
        "mode": mode.value,
        "task_id": "task-1",
        "authorization_reference": "local-fixture-auth",
        "allowed_execution_classes": [c.value for c in allowed_execution_classes],
        "allowed_capabilities": list(allowed_capabilities),
        "expires_at": expires_at.isoformat() if expires_at else None,
        "network_enabled": network_enabled,
        "allowed_targets": list(allowed_targets),
        "external_submission": external_submission,
    }
    return ScopePolicy(
        scope_revision=scope_revision,
        scope_sha256=canonical_digest(payload),
        mode=mode,
        task_id="task-1",
        authorization_reference="local-fixture-auth",
        allowed_execution_classes=allowed_execution_classes,
        allowed_capabilities=allowed_capabilities,
        expires_at=expires_at,
        network_enabled=network_enabled,
        allowed_targets=allowed_targets,
        external_submission=external_submission,
    )


# ---------------------------------------------------------------------------
# 1. Principal Authentication (Fail-Closed)
# ---------------------------------------------------------------------------


def test_principal_authentication_http_and_stdio_fail_closed() -> None:
    auth = PrincipalAuthenticator()
    alice = PrincipalContext(
        principal_id="alice",
        auth_method="bearer_token",
        client_kind="Codex",
        model_label="gpt-5-codex",
    )

    with pytest.raises(AuthenticationError):
        auth.register_token("PLACEHOLDER_SECRET", alice)
    with pytest.raises(AuthenticationError):
        auth.register_token("   ", alice)

    exp = datetime(2026, 11, 14, 0, 0, tzinfo=UTC)
    auth.register_token("real-secret-token-01", alice, expires_at=exp)

    # Valid Bearer before expiry
    ctx = auth.authenticate(
        TransportMode.STREAMABLE_HTTP,
        authorization="Bearer real-secret-token-01",
        now=datetime(2026, 11, 13, 12, 0, tzinfo=UTC),
    )
    assert ctx == alice

    # Missing, wrong, malformed, or expired credentials must fail
    with pytest.raises(AuthenticationError):
        auth.authenticate(TransportMode.STREAMABLE_HTTP)
    with pytest.raises(AuthenticationError):
        auth.authenticate(TransportMode.STREAMABLE_HTTP, authorization="Basic abc")
    with pytest.raises(AuthenticationError):
        auth.authenticate(TransportMode.STREAMABLE_HTTP, authorization="Bearer wrong-token")
    with pytest.raises(AuthenticationError):
        auth.authenticate(
            TransportMode.STREAMABLE_HTTP,
            authorization="Bearer real-secret-token-01",
            now=exp,
        )

    # Revocation immediately rejects
    assert auth.revoke_token("real-secret-token-01") is True
    with pytest.raises(AuthenticationError):
        auth.authenticate_bearer("Bearer real-secret-token-01", now=datetime(2026, 11, 13, 12, 0, tzinfo=UTC))

    # stdio local principal construction and optional token verification
    local_ctx = auth.authenticate(
        TransportMode.STDIO,
        stdio_principal_id="bob",
        client_kind="Codex",
        model_label="local-cli",
    )
    assert local_ctx.principal_id == "bob"
    assert local_ctx.auth_method == "stdio_local"

    strict_stdio = PrincipalAuthenticator.from_runtime_settings(
        RuntimeSettings(
            transport=TransportMode.STREAMABLE_HTTP,
            auth_token="runtime-token-xyz123",  # type: ignore[arg-type]
        ),
        principal_id="alice",
    )
    assert strict_stdio.authenticate_bearer("Bearer runtime-token-xyz123").principal_id == "alice"

    token_stdio = PrincipalAuthenticator(require_token_for_stdio=True)
    token_stdio.register_token("stdio-secret-1", alice)
    with pytest.raises(AuthenticationError):
        token_stdio.authenticate_stdio(principal_id="alice")
    with pytest.raises(AuthenticationError):
        token_stdio.authenticate_stdio(principal_id="bob", token="stdio-secret-1")
    assert token_stdio.authenticate_stdio(principal_id="alice", token="stdio-secret-1") == alice


# ---------------------------------------------------------------------------
# 2. CTF-01: Scope Validation & Catalog Visibility / Direct Call Denial
# ---------------------------------------------------------------------------


def test_ctf01_scope_missing_expired_revoked_and_ownership(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "harness.db")
    storage.initialize()
    scope_validator = ScopeValidator(storage)

    alice = PrincipalContext(
        principal_id="alice", auth_method="stdio_local", client_kind="Codex", model_label="m1"
    )
    mallory = PrincipalContext(
        principal_id="mallory", auth_method="stdio_local", client_kind="Codex", model_label="m1"
    )
    cap = _make_static_descriptor()

    # Unknown run -> denied
    with pytest.raises(ScopeDeniedError):
        scope_validator.validate_action(alice, "missing-run", cap, "header")

    _seed_run(storage, run_id="run-1", owner_principal_id="alice")

    # Missing scope row -> denied
    with pytest.raises(ScopeDeniedError):
        scope_validator.validate_action(alice, "run-1", cap, "header")

    t0 = datetime(2026, 11, 13, 12, 0, tzinfo=UTC)
    scope = _make_scope(expires_at=t0 + timedelta(minutes=30))
    scope_validator.register_scope("run-1", scope)

    # Valid principal & active scope -> allowed
    validated = scope_validator.validate_action(alice, "run-1", cap, "header", now=t0)
    assert validated.scope_revision == "scope-1"

    # Cross-principal call -> denied
    with pytest.raises(ScopeDeniedError):
        scope_validator.validate_action(mallory, "run-1", cap, "header", now=t0)

    # Expired scope -> denied
    with pytest.raises(ScopeDeniedError):
        scope_validator.validate_action(
            alice, "run-1", cap, "header", now=t0 + timedelta(minutes=30)
        )

    # Revoked scope -> denied even before expiry
    assert scope_validator.revoke_scope("run-1", "scope-1") == 1
    with pytest.raises(ScopeDeniedError):
        scope_validator.validate_action(alice, "run-1", cap, "header", now=t0)


def test_ctf01_offline_ctf_rejects_network_dynamic_submission_and_hidden_tools(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "harness.db")
    storage.initialize()
    catalog = CapabilityCatalog(storage)
    scope_validator = ScopeValidator(storage)

    alice = PrincipalContext(
        principal_id="alice", auth_method="stdio_local", client_kind="Codex", model_label="m1"
    )
    _seed_run(storage, run_id="run-off", owner_principal_id="alice", mode=RunMode.OFFLINE_CTF)

    # Even if a caller attempts a permissive offline scope listing DYNAMIC, baseline forbids it
    scope = _make_scope(
        mode=RunMode.OFFLINE_CTF,
        allowed_execution_classes=(ExecutionClass.STATIC, ExecutionClass.DYNAMIC),
        allowed_capabilities=("artifact.inspect", "session.control", "web.probe", "ctfd.submit"),
    )
    scope_validator.register_scope("run-off", scope)

    static_ok = _make_static_descriptor(name="artifact.inspect", enabled=True)
    disabled_static = _make_static_descriptor(name="analysis.disabled", enabled=False)
    scoped_only = _make_static_descriptor(
        name="analysis.scoped_only",
        profile_modes=(RunMode.SCOPED_CTF,),
        required_scope={"mode": "scoped_ctf"},
    )
    dynamic_tool = _make_static_descriptor(
        name="session.control",
        execution_classes=(ExecutionClass.DYNAMIC,),
        profile_modes=(RunMode.OFFLINE_CTF, RunMode.SCOPED_CTF),
        required_scope={"mode": "offline_ctf"},
    )
    network_tool = _make_static_descriptor(
        name="web.probe",
        execution_classes=(ExecutionClass.NETWORK,),
        profile_modes=(RunMode.OFFLINE_CTF, RunMode.SCOPED_CTF),
        required_scope={"mode": "offline_ctf"},
    )
    submission_tool = _make_static_descriptor(
        name="ctfd.submit",
        execution_classes=(ExecutionClass.SUBMISSION,),
        profile_modes=(RunMode.OFFLINE_CTF, RunMode.SCOPED_CTF),
        required_scope={"mode": "offline_ctf"},
    )

    for cap in (static_ok, disabled_static, scoped_only, dynamic_tool, network_tool, submission_tool):
        catalog.register_capability(cap)

    # tools/list exposes ONLY enabled static offline capability
    visible = catalog.list_visible_tools(RunMode.OFFLINE_CTF, scope=scope)
    assert [c.name for c in visible] == ["artifact.inspect"]

    # Direct invocation of hidden/unregistered/disallowed capabilities must be denied
    for hidden_name in (
        "analysis.disabled",
        "analysis.scoped_only",
        "session.control",
        "web.probe",
        "ctfd.submit",
        "exec_shell",
    ):
        with pytest.raises(CapabilityDeniedError):
            catalog.get_capability(hidden_name, RunMode.OFFLINE_CTF, scope=scope)

    # Scope validator independently refuses dynamic / network / submission in offline_ctf
    for forbidden_cap in (dynamic_tool, network_tool, submission_tool):
        with pytest.raises(ScopeDeniedError):
            scope_validator.validate_action(alice, "run-off", forbidden_cap, "header")

    # Toggling operational disable removes tool from visibility and direct calls
    catalog.set_enabled("artifact.inspect", False)
    assert catalog.list_visible_tools(RunMode.OFFLINE_CTF, scope=scope) == []
    with pytest.raises(CapabilityDeniedError):
        catalog.get_capability("artifact.inspect", RunMode.OFFLINE_CTF, scope=scope)


def test_ctf01_descriptor_tampering_and_argument_schema_rejection(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "harness.db")
    storage.initialize()
    catalog = CapabilityCatalog(storage)

    valid = _make_static_descriptor()
    tampered_initial = valid.model_copy(update={"descriptor_sha256": "f" * 64})
    with pytest.raises(CapabilityDeniedError):
        catalog.register_capability(tampered_initial)

    catalog.register_capability(valid)

    # Valid invocation passes
    resolved = catalog.validate_invocation(
        "artifact.inspect",
        RunMode.OFFLINE_CTF,
        "strings",
        {"artifact_id": "art_0123abcd", "max_lines": 50},
    )
    assert resolved.name == "artifact.inspect"

    # Unknown operation denied
    with pytest.raises(CapabilityDeniedError):
        catalog.validate_invocation(
            "artifact.inspect",
            RunMode.OFFLINE_CTF,
            "raw_shell",
            {"artifact_id": "art_0123abcd"},
        )

    # Invalid arguments (extra path field / missing required / bad pattern) rejected
    with pytest.raises(ContractViolationError):
        catalog.validate_invocation(
            "artifact.inspect",
            RunMode.OFFLINE_CTF,
            "strings",
            {"artifact_id": "art_0123abcd", "guest_path": "/etc/passwd"},
        )
    with pytest.raises(ContractViolationError):
        catalog.validate_invocation(
            "artifact.inspect",
            RunMode.OFFLINE_CTF,
            "strings",
            {"artifact_id": "../escape"},
        )

    # Tampering descriptor_json directly in SQLite must fail closed
    conn = sqlite3.connect(str(tmp_path / "harness.db"))
    try:
        conn.execute(
            """
            UPDATE capabilities
            SET descriptor_json = replace(descriptor_json, '"strings"', '"exec_shell"')
            WHERE name = 'artifact.inspect'
            """
        )
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(CapabilityDeniedError):
        catalog.get_capability("artifact.inspect", RunMode.OFFLINE_CTF)
    with pytest.raises(CapabilityDeniedError):
        catalog.list_visible_tools(RunMode.OFFLINE_CTF)
    with pytest.raises(CapabilityDeniedError):
        catalog.verify_all_descriptors()


# ---------------------------------------------------------------------------
# 3. Budget Reservation, Shrinking, Settlement, and Guest Health Blocking
# ---------------------------------------------------------------------------


def test_budget_atomic_reservation_shrink_and_cleanup_unconfirmed_block(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "harness.db")
    storage.initialize()
    budget = RunBudgetManager(storage)
    cap = _make_static_descriptor()

    spec = BudgetSpec(
        run_budget_seconds=90,
        action_timeout_seconds=60,
        max_tool_calls=3,
        max_evidence_bytes_per_run=100_000,
        heavy_job_concurrency=1,
        interactive_session_limit=1,
    )
    _seed_run(storage, run_id="run-b", owner_principal_id="alice", budget_spec=spec)

    # Action 1 takes heavy slot: reserves 60_000 ms, 65_536 B
    res1 = budget.reserve_run_budget(run_id="run-b", capability=cap, is_heavy_job=True)
    assert res1.reserved_ms == 60_000
    assert res1.reserved_bytes == 65_536
    assert res1.shrunk is False

    # Second concurrent heavy job must fail
    with pytest.raises(BudgetExceededError):
        budget.reserve_run_budget(run_id="run-b", capability=cap, is_heavy_job=True)

    # Settle action 1 with actual usage (10_000 ms, 5_536 B) -> remaining = 80_000 ms, 94_464 B, calls = 2
    snap1 = budget.settle_run_budget(
        run_id="run-b",
        reserved_ms=res1.reserved_ms,
        reserved_bytes=res1.reserved_bytes,
        used_ms=10_000,
        used_bytes=5_536,
        heavy_job_slot=True,
    )
    assert snap1.remaining_ms == 80_000
    assert snap1.remaining_bytes == 94_464
    assert snap1.remaining_calls == 2
    assert snap1.active_heavy_jobs == 0

    # Reserve action 2 with unknown usage -> retains full 60_000 ms and 65_536 B
    res2 = budget.reserve_run_budget(run_id="run-b", capability=cap, is_heavy_job=True)
    snap2 = budget.settle_run_budget(
        run_id="run-b",
        reserved_ms=res2.reserved_ms,
        reserved_bytes=res2.reserved_bytes,
        heavy_job_slot=True,
        usage_unknown=True,
    )
    assert snap2.remaining_ms == 20_000
    assert snap2.remaining_bytes == 28_928
    assert snap2.remaining_calls == 1

    # Action 3: remaining is 20_000 ms < 60_000 ms -> shrinks allowance to 20_000 ms
    with pytest.raises(BudgetExceededError):
        budget.reserve_run_budget(run_id="run-b", capability=cap, allow_shrink=False)
    res3 = budget.reserve_run_budget(run_id="run-b", capability=cap, allow_shrink=True)
    assert res3.shrunk is True
    assert res3.reserved_ms == 20_000
    assert res3.reserved_bytes == 28_928

    # Unconfirmed cleanup retains conservative reservation and blocks future guest actions
    snap3 = budget.settle_run_budget(
        run_id="run-b",
        reserved_ms=res3.reserved_ms,
        reserved_bytes=res3.reserved_bytes,
        cleanup_confirmed=False,
    )
    assert snap3.guest_health == GuestHealthState.CLEANUP_UNCONFIRMED
    assert snap3.remaining_ms == 0
    with pytest.raises(GuestBlockedError):
        budget.reserve_run_budget(run_id="run-b", capability=cap)


# ---------------------------------------------------------------------------
# 4. Audit Sanitization (CTF-12)
# ---------------------------------------------------------------------------


def test_audit_logger_rejects_and_sanitizes_sensitive_markers(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "harness.db")
    storage.initialize()
    audit = AuditLogger(storage)

    ts = datetime(2026, 11, 13, 12, 0, tzinfo=UTC)

    for forbidden in (
        "SYNTHETIC_SECRET_12345",
        "leak CTF_SENSITIVE_MARKER_99",
        "flag{do_not_log_me}",
        "Bearer abcdef123456",
        "line1\nline2",
    ):
        assert contains_sensitive_marker(forbidden) or "\n" in forbidden
        bad_event = AuditEvent(
            event_id="ev-bad",
            timestamp=ts,
            run_id="run-1",
            principal_id="alice",
            capability="artifact.inspect",
            operation="strings",
            outcome="ok",
            destination_summary=forbidden,
        )
        with pytest.raises(ContractViolationError):
            audit.record(bad_event)

    arg_summary = summarize_arguments({"artifact_id": "art_01", "secret": "SYNTHETIC_SECRET_ABC"})
    assert "SYNTHETIC_SECRET" not in arg_summary
    assert "digest12=" in arg_summary

    dirty = AuditEvent(
        event_id="ev-clean-1",
        timestamp=ts,
        run_id="run-1",
        principal_id="alice",
        action_id="act-1",
        capability="artifact.inspect",
        operation="strings",
        outcome="ok",
        usage=UsageMetrics(wall_ms=15, output_bytes=120),
        scope_revision="scope-1",
        destination_summary="SYNTHETIC_SECRET_ABC CTF_SENSITIVE_MARKER flag{abc}",
    )
    stored = audit.record_sanitized(dirty)
    assert stored.destination_summary == "[REDACTED] [REDACTED] [REDACTED]"

    events = audit.list_events("run-1")
    assert len(events) == 1
    assert "SYNTHETIC_SECRET" not in (events[0].destination_summary or "")
    assert "CTF_SENSITIVE_MARKER" not in (events[0].destination_summary or "")
    assert "flag{" not in (events[0].destination_summary or "")
