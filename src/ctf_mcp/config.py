"""Layer 0 configuration models, fail-closed defaults, and environment loaders.

Aligns with ``configs/offline-pilot.example.json`` while strictly rejecting
``executable: false`` design examples as live runtime configurations.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, SecretStr, model_validator

from ctf_mcp.contracts import (
    BudgetSpec,
    ConfigurationError,
    RunMode,
    StrictModel,
    TransportMode,
)

PLACEHOLDER_PREFIXES: tuple[str, ...] = (
    "CHANGE_ME",
    "EXAMPLE",
    "PLACEHOLDER",
    "RECORD_",
    "REQUIRED_",
    "PIN_",
    "SET_FROM_",
)

MIN_HMAC_KEY_BYTES = 16


def _is_placeholder(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return True
    upper = stripped.upper()
    return any(upper.startswith(prefix) for prefix in PLACEHOLDER_PREFIXES)


class ClientConfig(StrictModel):
    kind: str = "OPERATOR_SELECTED"
    model_label: str = Field(min_length=1)
    instruction_revision: str = Field(min_length=1)


class ScopeConfig(StrictModel):
    task_id: str = Field(min_length=1)
    revision: str = Field(min_length=1)
    authorization_reference: str = Field(min_length=1)
    expires_at: str | None = None


class NetworkConfig(StrictModel):
    enabled: bool = False
    allowed_targets: tuple[str, ...] = ()
    external_submission: bool = False


class ExecutionConfig(StrictModel):
    adapters_enabled: tuple[str, ...] = ()
    arbitrary_shell: bool = False
    dynamic_execution: bool = False
    heavy_job_concurrency: int = Field(default=1, gt=0)
    interactive_session_limit: int = Field(default=1, gt=0)
    action_timeout_seconds: int = Field(default=60, gt=0)
    session_idle_seconds: int = Field(default=900, gt=0)
    run_budget_seconds: int = Field(default=1800, gt=0)
    max_tool_calls: int = Field(default=40, gt=0)
    max_output_chars_per_page: int = Field(default=4000, gt=0, le=4000)
    max_evidence_bytes_per_run: int = Field(default=104_857_600, gt=0)

    def to_budget_spec(self) -> BudgetSpec:
        return BudgetSpec(
            run_budget_seconds=self.run_budget_seconds,
            action_timeout_seconds=self.action_timeout_seconds,
            session_idle_seconds=self.session_idle_seconds,
            max_tool_calls=self.max_tool_calls,
            max_output_chars_per_page=self.max_output_chars_per_page,
            max_evidence_bytes_per_run=self.max_evidence_bytes_per_run,
            heavy_job_concurrency=self.heavy_job_concurrency,
            interactive_session_limit=self.interactive_session_limit,
        )


class EvidenceConfig(StrictModel):
    storage: str = Field(min_length=1)
    cross_run_access: bool = False
    automatic_git_export: bool = False
    retention_policy_reference: str = Field(min_length=1)
    audit_raw_output: bool = False


class AcceptanceConfig(StrictModel):
    require_pinned_revisions: bool = True
    require_scope_validation: bool = True
    require_registered_verifier: bool = True


class HarnessConfig(StrictModel):
    """Typed runtime configuration schema aligned with offline-pilot.example.json."""

    schema_version: str = Field(min_length=1)
    executable: Literal[True]
    profile: RunMode = RunMode.OFFLINE_CTF
    description: str = ""
    client: ClientConfig
    scope: ScopeConfig
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    evidence: EvidenceConfig
    acceptance: AcceptanceConfig = Field(default_factory=AcceptanceConfig)

    @model_validator(mode="after")
    def _enforce_fail_closed_security(self) -> HarnessConfig:
        if self.execution.arbitrary_shell:
            raise ValueError("arbitrary_shell must remain False (N1).")
        if self.evidence.cross_run_access:
            raise ValueError("cross_run_access must remain False.")
        if self.evidence.automatic_git_export:
            raise ValueError("automatic_git_export must remain False.")
        if self.evidence.audit_raw_output:
            raise ValueError("audit_raw_output must remain False (docs/05 section 6).")
        if not self.acceptance.require_pinned_revisions:
            raise ValueError("require_pinned_revisions cannot be disabled.")
        if not self.acceptance.require_scope_validation:
            raise ValueError("require_scope_validation cannot be disabled.")
        if not self.acceptance.require_registered_verifier:
            raise ValueError("require_registered_verifier cannot be disabled.")

        if self.profile == RunMode.OFFLINE_CTF:
            if self.network.enabled or self.network.allowed_targets or self.network.external_submission:
                raise ValueError("offline_ctf forbids enabled network, targets, or submission.")
            if self.execution.dynamic_execution:
                raise ValueError("offline_ctf baseline forbids dynamic_execution.")
        return self


class RuntimeSettings(StrictModel):
    """Environment-derived local runtime paths and transport settings."""

    profile: RunMode = RunMode.OFFLINE_CTF
    transport: TransportMode = TransportMode.STDIO
    vault_root: Path | None = None
    db_path: Path | None = None
    workspace_root: Path | None = None
    auth_token: SecretStr | None = None
    log_level: str = "INFO"

    @model_validator(mode="after")
    def _validate_transport_auth(self) -> RuntimeSettings:
        if self.transport == TransportMode.STREAMABLE_HTTP:
            if self.auth_token is None or _is_placeholder(self.auth_token.get_secret_value()):
                raise ValueError(
                    "HTTP transport requires a non-placeholder CTF_MCP_AUTH_TOKEN (fail closed)."
                )
        return self


def load_config_file(path: str | Path) -> HarnessConfig:
    """Load and validate an executable harness config JSON file.

    Refuses design-only examples (such as ``configs/offline-pilot.example.json``)
    whose ``executable`` flag is ``false`` or not strictly ``True``.
    """
    config_path = Path(path)
    try:
        raw_text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(f"Failed to read configuration file: {exc}") from exc

    try:
        data: Any = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ConfigurationError(f"Configuration file is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigurationError("Configuration root must be a JSON object.")

    if data.get("executable") is not True:
        raise ConfigurationError(
            "Configuration file has executable != true and cannot be loaded as live runtime config.",
            details={"path": str(config_path), "executable": data.get("executable")},
        )

    try:
        return HarnessConfig.model_validate(data)
    except Exception as exc:
        raise ConfigurationError(f"Configuration validation failed: {exc}") from exc


def get_cursor_hmac_key(
    env: Mapping[str, str] | None = None,
    *,
    allow_ephemeral_dev_key: bool = False,
) -> bytes:
    """Retrieve the HMAC-SHA256 signing key for opaque evidence cursors.

    Rejects missing, placeholder, or short (<16 decoded bytes) keys unless
    ``allow_ephemeral_dev_key=True`` is explicitly passed for isolated local tests.
    """
    source = os.environ if env is None else env
    raw = source.get("CTF_MCP_CURSOR_HMAC_KEY", "").strip()
    if not raw or _is_placeholder(raw):
        if allow_ephemeral_dev_key:
            return os.urandom(32)
        raise ConfigurationError(
            "CTF_MCP_CURSOR_HMAC_KEY is missing or still set to a placeholder."
        )

    # Interpret >=32-char even-length hex strings as raw key bytes; otherwise UTF-8 bytes.
    if len(raw) >= MIN_HMAC_KEY_BYTES * 2 and len(raw) % 2 == 0:
        try:
            key_bytes = bytes.fromhex(raw)
        except ValueError:
            key_bytes = raw.encode("utf-8")
    else:
        key_bytes = raw.encode("utf-8")

    if len(key_bytes) < MIN_HMAC_KEY_BYTES:
        raise ConfigurationError(
            f"CTF_MCP_CURSOR_HMAC_KEY must provide at least {MIN_HMAC_KEY_BYTES} bytes."
        )
    return key_bytes


def load_runtime_settings(env: Mapping[str, str] | None = None) -> RuntimeSettings:
    """Load fail-closed RuntimeSettings from environment mapping."""
    source = os.environ if env is None else env

    def _opt_path(name: str) -> Path | None:
        val = source.get(name, "").strip()
        if not val or _is_placeholder(val):
            return None
        return Path(val)

    raw_profile = source.get("CTF_MCP_PROFILE", RunMode.OFFLINE_CTF.value).strip()
    raw_transport = source.get("CTF_MCP_TRANSPORT", TransportMode.STDIO.value).strip()
    raw_token = source.get("CTF_MCP_AUTH_TOKEN", "").strip()
    raw_log = source.get("CTF_MCP_LOG_LEVEL", "INFO").strip() or "INFO"

    try:
        profile = RunMode(raw_profile)
        transport = TransportMode(raw_transport)
        return RuntimeSettings(
            profile=profile,
            transport=transport,
            vault_root=_opt_path("CTF_MCP_VAULT_ROOT"),
            db_path=_opt_path("CTF_MCP_DB_PATH"),
            workspace_root=_opt_path("CTF_MCP_WORKSPACE_ROOT"),
            auth_token=SecretStr(raw_token) if raw_token else None,
            log_level=raw_log,
        )
    except Exception as exc:
        raise ConfigurationError(f"Invalid runtime environment settings: {exc}") from exc


__all__ = [
    "AcceptanceConfig",
    "ClientConfig",
    "EvidenceConfig",
    "ExecutionConfig",
    "HarnessConfig",
    "MIN_HMAC_KEY_BYTES",
    "NetworkConfig",
    "RuntimeSettings",
    "ScopeConfig",
    "get_cursor_hmac_key",
    "load_config_file",
    "load_runtime_settings",
]
