"""Test-vs-production setting difference auto-recorder for isolated VDP tests.

Prevents isolated test shortcuts (eager async execution, loopback HTTP/Git fixtures,
test CA bundles, private IP allowlists, auth middleware shortcuts, or ephemeral DBs)
from being silently mistaken for production parity by capturing structured, redacted
``SettingDiffEntry`` receipts inside ``VDP_EVIDENCE_MARKER`` payloads.

Design boundaries (``docs/vdp-next-stage-plan.md`` section 3):
- Imported only by Layer 2 fixtures/adapters/tests without importing ``gateway``,
  ``runs``, or ``evidence``.
- Automatically scrubs embedded URL credentials, Bearer/Basic tokens, and synthetic
  or prefixed secret markers before storing any entry.
- Sub-steps confirmed against a local loopback fixture can carry a narrow
  ``verification_status="confirmed"`` tag (such as ``loopback_git_http_sync_confirmed``)
  while keeping the corresponding remote-transport parity tag ``"unverified"``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, Literal

from pydantic import Field, model_validator

from ctf_mcp.contracts import ContractViolationError, StrictModel
from ctf_mcp.vdp_fixtures.local_git_http import (
    emit_vdp_evidence_marker,
    redact_sensitive_text,
    redact_structure,
)

SETTING_DIFF_SCHEMA = "vdp-setting-diff/1"
MAX_SETTING_DIFF_ENTRIES = 32

VALID_SETTING_CATEGORIES: tuple[str, ...] = (
    "async_execution",
    "service_transport",
    "tls_network_policy",
    "auth_middleware",
    "storage_backend",
    "other",
)
VALID_VERIFICATION_STATUSES: tuple[str, ...] = ("confirmed", "unverified")
VALID_DIFF_SOURCES: tuple[str, ...] = (
    "runtime_introspection",
    "registration_config_diff",
    "stage_comparison",
    "operator_declared",
)

_CONDITION_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{1,127}$")
_EXTRA_SECRET_RE = re.compile(
    r"(?:"
    r"SYNTHETIC_SECRET(?:_[A-Za-z0-9._:/=+-]+)?|"
    r"CTF_SENSITIVE_MARKER(?:[:_=-][A-Za-z0-9._:/=+-]+)?|"
    r"\b(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{16,}|gho_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16})\b|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\b|"
    r"(?:flag|ctf|vdp)\{[^{}\r\n]+\}|"
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:password|passwd|secret|secret_key|api_key|access_token|auth_token|token)\s*[:=]\s*(?!\[REDACTED\])[^\s\"',;]+"
    r")",
    re.IGNORECASE,
)


def _redact_setting_text(value: Any, *, max_len: int = 300) -> str:
    """Redact credentials, tokens, and secret markers and enforce bounded string length."""
    cleaned = redact_sensitive_text(str(value))
    cleaned = _EXTRA_SECRET_RE.sub("[REDACTED]", cleaned).strip()
    if len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 3] + "..."
    return cleaned


def _is_truthy_setting(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on", "eager"}
    return False


def _is_loopback_reference(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    low = value.lower()
    return any(tok in low for tok in ("127.0.0.1", "://localhost", "://[::1]", "localhost:", "[::1]"))


def _infer_registration_diff_category(raw_diff: str) -> Literal[
    "async_execution",
    "service_transport",
    "tls_network_policy",
    "auth_middleware",
    "storage_backend",
    "other",
]:
    low = raw_diff.lower()
    if any(k in low for k in ("celery", "eager", "async", "worker", "queue")):
        return "async_execution"
    if any(k in low for k in ("loopback", "127.0.0.1", "fixture", "vcs", "git_http", "webhook")):
        return "service_transport"
    if any(k in low for k in ("ca", "tls", "ssl", "allowlist", "private_ip", "network")):
        return "tls_network_policy"
    if any(k in low for k in ("auth", "csrf", "force_login", "debug", "rate_limit", "middleware")):
        return "auth_middleware"
    if any(k in low for k in ("sqlite", "memory", "database", "db", "locmem", "cache", "redis")):
        return "storage_backend"
    return "other"


class SettingDiffEntry(StrictModel):
    """Typed, redacted record of a difference between test settings and production baseline."""

    category: Literal[
        "async_execution",
        "service_transport",
        "tls_network_policy",
        "auth_middleware",
        "storage_backend",
        "other",
    ]
    setting_name: str = Field(min_length=1, max_length=120)
    test_value: str = Field(min_length=1, max_length=300)
    production_baseline: str = Field(min_length=1, max_length=300)
    verification_status: Literal["confirmed", "unverified"] = "unverified"
    condition_tag: str = Field(min_length=2, max_length=128)
    source: Literal[
        "runtime_introspection",
        "registration_config_diff",
        "stage_comparison",
        "operator_declared",
    ] = "runtime_introspection"
    note: str = Field(default="", max_length=400)

    @model_validator(mode="after")
    def _validate_and_redact(self) -> SettingDiffEntry:
        clean_name = _redact_setting_text(self.setting_name, max_len=120)
        if not clean_name or "[REDACTED]" in clean_name:
            raise ContractViolationError(
                "SettingDiffEntry.setting_name must be a non-empty non-secret identifier."
            )
        clean_test = _redact_setting_text(self.test_value, max_len=300)
        clean_prod = _redact_setting_text(self.production_baseline, max_len=300)
        if not clean_test or not clean_prod:
            raise ContractViolationError(
                "SettingDiffEntry.test_value and production_baseline must be non-empty."
            )
        clean_tag = str(self.condition_tag).strip().lower()
        if not _CONDITION_TAG_RE.fullmatch(clean_tag) or _EXTRA_SECRET_RE.search(clean_tag):
            raise ContractViolationError(
                f"Invalid or secret-bearing condition_tag {self.condition_tag!r}."
            )
        clean_note = _redact_setting_text(self.note, max_len=400) if self.note else ""

        object.__setattr__(self, "setting_name", clean_name)
        object.__setattr__(self, "test_value", clean_test)
        object.__setattr__(self, "production_baseline", clean_prod)
        object.__setattr__(self, "condition_tag", clean_tag)
        object.__setattr__(self, "note", clean_note)
        return self


def normalize_setting_diff_entries(
    raw_entries: Sequence[Any],
    *,
    max_entries: int = MAX_SETTING_DIFF_ENTRIES,
) -> list[dict[str, Any]]:
    """Validate, redact, and deduplicate raw setting diff dicts (preferring unverified on conflict)."""
    deduped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in raw_entries:
        if not isinstance(item, Mapping):
            continue
        try:
            entry = SettingDiffEntry.model_validate(redact_structure(dict(item)))
        except Exception:
            continue
        key = (entry.category, entry.setting_name, entry.condition_tag)
        dumped = entry.model_dump(mode="json")
        prior = deduped.get(key)
        if prior is None or (
            prior.get("verification_status") == "confirmed"
            and dumped["verification_status"] == "unverified"
        ):
            deduped[key] = dumped
        if len(deduped) >= max_entries:
            break
    return list(deduped.values())


class SettingDiffRecorder:
    """Collect, auto-detect, and emit redacted test-vs-production setting differences."""

    def __init__(self, *, max_entries: int = MAX_SETTING_DIFF_ENTRIES) -> None:
        if max_entries <= 0 or max_entries > MAX_SETTING_DIFF_ENTRIES:
            raise ContractViolationError(
                f"max_entries must be 1..{MAX_SETTING_DIFF_ENTRIES}."
            )
        self._max_entries = max_entries
        self._entries_by_key: dict[tuple[str, str, str], SettingDiffEntry] = {}

    @property
    def entries(self) -> tuple[SettingDiffEntry, ...]:
        """Return recorded entries in deterministic sorted order."""
        return tuple(
            self._entries_by_key[k]
            for k in sorted(self._entries_by_key.keys())
        )

    def record_entry(self, entry: SettingDiffEntry, *, allow_truncate: bool = False) -> bool:
        """Add or merge one ``SettingDiffEntry`` while never downgrading ``unverified`` to ``confirmed``."""
        validated = SettingDiffEntry.model_validate(entry)
        key = (validated.category, validated.setting_name, validated.condition_tag)
        existing = self._entries_by_key.get(key)
        if existing is None and len(self._entries_by_key) >= self._max_entries:
            if allow_truncate:
                return False
            raise ContractViolationError(
                f"SettingDiffRecorder cannot store more than {self._max_entries} entries."
            )
        if existing is not None and existing.verification_status == "unverified":
            if validated.verification_status == "confirmed":
                return True
        self._entries_by_key[key] = validated
        return True

    def record_diff(
        self,
        *,
        category: Literal[
            "async_execution",
            "service_transport",
            "tls_network_policy",
            "auth_middleware",
            "storage_backend",
            "other",
        ],
        setting_name: str,
        test_value: Any,
        production_baseline: Any,
        condition_tag: str,
        verification_status: Literal["confirmed", "unverified"] = "unverified",
        source: Literal[
            "runtime_introspection",
            "registration_config_diff",
            "stage_comparison",
            "operator_declared",
        ] = "operator_declared",
        note: str = "",
    ) -> SettingDiffEntry:
        """Build, validate, redact, and store a single setting diff entry."""
        entry = SettingDiffEntry(
            category=category,
            setting_name=setting_name,
            test_value=_redact_setting_text(test_value, max_len=300),
            production_baseline=_redact_setting_text(production_baseline, max_len=300),
            verification_status=verification_status,
            condition_tag=condition_tag,
            source=source,
            note=_redact_setting_text(note, max_len=400) if note else "",
        )
        self.record_entry(entry)
        return entry

    def detect_from_settings(
        self,
        settings_map: Mapping[str, Any],
        *,
        env: Mapping[str, str] | None = None,
        registration_config_diffs: Sequence[str] = (),
        stage_verification: Mapping[str, Any] | None = None,
    ) -> list[SettingDiffEntry]:
        """Inspect sanitized settings/env maps and record standard category diffs."""
        merged: dict[str, Any] = {}
        if env:
            for k, v in env.items():
                merged[str(k)] = v
        for k, v in settings_map.items():
            merged[str(k)] = v
        lowered = {str(k).lower(): (str(k), v) for k, v in merged.items()}

        recorded_now: list[SettingDiffEntry] = []

        def _add_detected(**kwargs: Any) -> None:
            entry = SettingDiffEntry(**kwargs)
            if self.record_entry(entry, allow_truncate=True):
                recorded_now.append(entry)

        # 1. async_execution (Celery always-eager / synchronous stub)
        for key_low in (
            "celery_task_always_eager",
            "task_always_eager",
            "celery_always_eager",
            "sync_task_stub",
            "eager_tasks",
        ):
            if key_low in lowered and _is_truthy_setting(lowered[key_low][1]):
                orig_name, orig_val = lowered[key_low]
                _add_detected(
                    category="async_execution",
                    setting_name=orig_name,
                    test_value=_redact_setting_text(orig_val, max_len=300),
                    production_baseline="brokered_async_worker_queue",
                    verification_status="unverified",
                    condition_tag="celery_eager_test_settings_async_unverified",
                    source="runtime_introspection",
                    note="Tasks execute inline instead of across serialized async workers.",
                )
                break

        # 2. service_transport (loopback HTTP/Git fixture vs remote endpoint)
        loopback_hits: list[tuple[str, Any]] = []
        for key_low in (
            "use_loopback_fixture",
            "repo_url",
            "vcs_url",
            "service_url",
            "fixture_url",
            "webhook_url",
            "target_url",
            "remote_url",
        ):
            if key_low in lowered:
                orig_name, orig_val = lowered[key_low]
                if (key_low == "use_loopback_fixture" and _is_truthy_setting(orig_val)) or _is_loopback_reference(orig_val):
                    loopback_hits.append((orig_name, orig_val))
        if loopback_hits:
            first_name, first_val = loopback_hits[0]
            _add_detected(
                category="service_transport",
                setting_name=first_name,
                test_value=_redact_setting_text(first_val, max_len=300),
                production_baseline="remote_vcs_or_external_service_endpoint",
                verification_status="unverified",
                condition_tag="loopback_fixture_vs_real_vcs_transport_unverified",
                source="runtime_introspection",
                note="Tested against local loopback fixture rather than live external endpoint.",
            )
        if isinstance(stage_verification, Mapping) and stage_verification.get("sync_completed") is True:
            _add_detected(
                category="service_transport",
                setting_name="loopback_stage_sync_completed",
                test_value="sync_completed=True",
                production_baseline="local_protocol_sync_stage_exercised",
                verification_status="confirmed",
                condition_tag="loopback_git_http_sync_confirmed",
                source="stage_comparison",
                note="Local loopback Git HTTP protocol sync completed without proving remote TLS/network parity.",
            )

        # 3. tls_network_policy (test CA bundle, private IP allowlist, TLS disabled, network=none)
        tls_candidates: list[tuple[str, str, str]] = []
        for key_low in ("test_ca_bundle", "requests_ca_bundle", "ssl_cert_file", "curl_ca_bundle"):
            if key_low in lowered and str(lowered[key_low][1]).strip():
                orig_name, orig_val = lowered[key_low]
                tls_candidates.append(
                    (
                        orig_name,
                        _redact_setting_text(orig_val, max_len=300),
                        "Custom test CA bundle replaces system/production trust store.",
                    )
                )
        for key_low in (
            "private_ip_allowlist",
            "allow_private_urls",
            "ssrf_allow_private_ips",
            "allowed_private_hosts",
        ):
            if key_low in lowered:
                orig_name, orig_val = lowered[key_low]
                if (isinstance(orig_val, (list, tuple, set)) and len(orig_val) > 0) or _is_truthy_setting(orig_val) or (
                    isinstance(orig_val, str) and orig_val.strip() and orig_val.strip().lower() not in {"0", "false", "none", "[]"}
                ):
                    tls_candidates.append(
                        (
                            orig_name,
                            _redact_setting_text(orig_val, max_len=300),
                            "Private/loopback IP allowlist relaxed relative to production SSRF policy.",
                        )
                    )
        for key_low in ("tls_verify", "verify_tls", "ssl_verify"):
            if key_low in lowered and lowered[key_low][1] is False:
                orig_name, orig_val = lowered[key_low]
                tls_candidates.append(
                    (
                        orig_name,
                        str(orig_val),
                        "TLS certificate verification disabled in test settings.",
                    )
                )
        if "network_mode" in lowered and str(lowered["network_mode"][1]).strip().lower() == "none":
            tls_candidates.append(
                (
                    "network_mode",
                    "none",
                    "Container launched with --network=none (external network/DNS/TLS paths isolated).",
                )
            )
        for setting_name, test_val, note in tls_candidates:
            _add_detected(
                category="tls_network_policy",
                setting_name=setting_name,
                test_value=test_val,
                production_baseline="prod_system_ca_and_strict_egress_policy",
                verification_status="unverified",
                condition_tag="test_ca_or_private_allowlist_vs_prod_tls_policy_unverified",
                source="runtime_introspection",
                note=note,
            )

        # 4. auth_middleware (auth shortcuts vs full middleware exercised)
        auth_shortcuts: list[tuple[str, Any]] = []
        for key_low in (
            "force_login",
            "auth_shortcut",
            "bypass_auth_middleware",
            "csrf_disabled",
            "rate_limit_disabled",
            "debug",
            "allow_any_temp_override",
        ):
            if key_low in lowered and _is_truthy_setting(lowered[key_low][1]):
                auth_shortcuts.append(lowered[key_low])
        if "csrf_enforced" in lowered and lowered["csrf_enforced"][1] is False:
            auth_shortcuts.append(lowered["csrf_enforced"])
        if auth_shortcuts:
            for orig_name, orig_val in auth_shortcuts:
                _add_detected(
                    category="auth_middleware",
                    setting_name=orig_name,
                    test_value=_redact_setting_text(orig_val, max_len=300),
                    production_baseline="full_auth_csrf_ratelimit_middleware_debug_false",
                    verification_status="unverified",
                    condition_tag="auth_shortcut_unverified",
                    source="runtime_introspection",
                    note="Test shortcut/DEBUG mode differs from production middleware enforcement.",
                )
        elif "real_auth_middleware_exercised" in lowered and _is_truthy_setting(
            lowered["real_auth_middleware_exercised"][1]
        ):
            _add_detected(
                category="auth_middleware",
                setting_name="real_auth_middleware_exercised",
                test_value="True",
                production_baseline="full_auth_csrf_middleware_exercised",
                verification_status="confirmed",
                condition_tag="auth_middleware_parity_confirmed",
                source="runtime_introspection",
                note="Request exercised real authentication/authorization middleware without test shortcuts.",
            )

        # 5. storage_backend (SQLite / in-memory / ephemeral DB / locmem cache)
        storage_hits: list[tuple[str, str]] = []
        if "ephemeral_db" in lowered and _is_truthy_setting(lowered["ephemeral_db"][1]):
            storage_hits.append(("ephemeral_db", "True"))
        for key_low in ("db_engine", "database_engine", "database_url", "databases"):
            if key_low in lowered:
                raw_text = str(lowered[key_low][1])
                low_text = raw_text.lower()
                if "sqlite" in low_text or ":memory:" in low_text:
                    storage_hits.append(
                        (lowered[key_low][0], _redact_setting_text(raw_text, max_len=300))
                    )
        for key_low in ("cache_backend",):
            if key_low in lowered and any(
                tok in str(lowered[key_low][1]).lower() for tok in ("locmem", "dummy")
            ):
                storage_hits.append(
                    (lowered[key_low][0], _redact_setting_text(lowered[key_low][1], max_len=300))
                )
        for setting_name, test_val in storage_hits:
            _add_detected(
                category="storage_backend",
                setting_name=setting_name,
                test_value=test_val,
                production_baseline="production_rdbms_and_shared_cache_locking",
                verification_status="unverified",
                condition_tag="ephemeral_db_concurrency_unverified",
                source="runtime_introspection",
                note="Ephemeral/SQLite/local-memory backend differs from production locking and isolation.",
            )

        # 6. Registration-time declared config_diffs
        for idx, raw_diff in enumerate(registration_config_diffs):
            cleaned_diff = _redact_setting_text(raw_diff, max_len=300)
            if not cleaned_diff:
                continue
            cat = _infer_registration_diff_category(cleaned_diff)
            tag_map = {
                "async_execution": "celery_eager_test_settings_async_unverified",
                "service_transport": "loopback_fixture_vs_real_vcs_transport_unverified",
                "tls_network_policy": "test_ca_or_private_allowlist_vs_prod_tls_policy_unverified",
                "auth_middleware": "auth_shortcut_unverified",
                "storage_backend": "ephemeral_db_concurrency_unverified",
                "other": f"registration_config_diff_{idx + 1}_unverified",
            }
            _add_detected(
                category=cat,
                setting_name=f"registration_config_diff_{idx + 1}",
                test_value=cleaned_diff,
                production_baseline="production_baseline_unspecified_in_registration_diff",
                verification_status="unverified",
                condition_tag=tag_map[cat],
                source="registration_config_diff",
                note="Captured from profile/overlay registration config_diffs.",
            )

        return recorded_now

    def to_marker_payload(self) -> dict[str, Any]:
        """Serialize redacted ``setting_diffs`` plus ``confirmed_conditions`` / ``unverified_conditions``."""
        confirmed: list[str] = []
        unverified: list[str] = []
        serialized_entries: list[dict[str, Any]] = []
        for entry in self.entries:
            dumped = entry.model_dump(mode="json")
            serialized_entries.append(dumped)
            if entry.verification_status == "confirmed":
                if entry.condition_tag not in confirmed:
                    confirmed.append(entry.condition_tag)
            else:
                if entry.condition_tag not in unverified:
                    unverified.append(entry.condition_tag)
        payload: dict[str, Any] = {
            "setting_diff_schema": SETTING_DIFF_SCHEMA,
            "setting_diffs": serialized_entries,
            "confirmed_conditions": confirmed,
            "unverified_conditions": unverified,
        }
        return redact_structure(payload)

    def emit_marker(self) -> dict[str, Any]:
        """Emit a single-line redacted ``VDP_EVIDENCE_MARKER`` JSON payload to stdout."""
        payload = self.to_marker_payload()
        emit_vdp_evidence_marker(payload)
        return payload


def emit_setting_diff_evidence_marker(
    settings_map: Mapping[str, Any],
    *,
    env: Mapping[str, str] | None = None,
    registration_config_diffs: Sequence[str] = (),
    stage_verification: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Convenience one-call helper for overlay tests to auto-detect and emit setting diffs."""
    recorder = SettingDiffRecorder()
    recorder.detect_from_settings(
        settings_map,
        env=env,
        registration_config_diffs=registration_config_diffs,
        stage_verification=stage_verification,
    )
    return recorder.emit_marker()


__all__ = [
    "MAX_SETTING_DIFF_ENTRIES",
    "SETTING_DIFF_SCHEMA",
    "VALID_DIFF_SOURCES",
    "VALID_SETTING_CATEGORIES",
    "VALID_VERIFICATION_STATUSES",
    "SettingDiffEntry",
    "SettingDiffRecorder",
    "emit_setting_diff_evidence_marker",
    "normalize_setting_diff_entries",
]
