"""Gateway subsystem (Wave 1): principal auth, scope, catalog, budget, audit, intake."""

from __future__ import annotations

from ctf_mcp.gateway.audit import (
    MAX_AUDIT_SUMMARY_CHARS,
    AuditLogger,
    contains_sensitive_marker,
    sanitize_audit_text,
    summarize_arguments,
)
from ctf_mcp.gateway.budget import (
    BudgetReservation,
    BudgetSnapshot,
    RunBudgetManager,
    get_budget_snapshot_in_tx,
    reserve_run_budget_in_tx,
    set_guest_health_in_tx,
    settle_run_budget_in_tx,
)
from ctf_mcp.gateway.catalog import (
    CapabilityCatalog,
    build_capability_descriptor,
    compute_descriptor_sha256,
    verify_descriptor_hash,
)
from ctf_mcp.gateway.intake import (
    ArtifactIntakeService,
    IntakeLimits,
    validate_archive_safety,
)
from ctf_mcp.gateway.principal import (
    PrincipalAuthenticator,
    TokenBinding,
    extract_bearer_token,
)
from ctf_mcp.gateway.network_guard import (
    AllowedTargetRule,
    PinnedNetworkTarget,
    ScopedNetworkPolicyGuard,
)
from ctf_mcp.gateway.scope import ScopeValidator

__all__ = [
    "ArtifactIntakeService",
    "AuditLogger",
    "BudgetReservation",
    "BudgetSnapshot",
    "CapabilityCatalog",
    "IntakeLimits",
    "MAX_AUDIT_SUMMARY_CHARS",
    "PrincipalAuthenticator",
    "RunBudgetManager",
    "AllowedTargetRule",
    "PinnedNetworkTarget",
    "ScopedNetworkPolicyGuard",
    "ScopeValidator",
    "TokenBinding",
    "build_capability_descriptor",
    "compute_descriptor_sha256",
    "contains_sensitive_marker",
    "extract_bearer_token",
    "get_budget_snapshot_in_tx",
    "reserve_run_budget_in_tx",
    "sanitize_audit_text",
    "set_guest_health_in_tx",
    "settle_run_budget_in_tx",
    "summarize_arguments",
    "validate_archive_safety",
    "verify_descriptor_hash",
]
