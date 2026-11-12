"""Sanitized gateway audit logger preventing raw outputs, secrets, or flags.

Implements ``AuditLoggerPort`` (``docs/05`` sections 6 & 9, ``docs/11`` CTF-12)
backed by the SQLite ``audit_events`` table.
"""

from __future__ import annotations

import re
import sqlite3
from collections import Counter
from collections.abc import Mapping
from typing import Any

from ctf_mcp.contracts import (
    AuditEvent,
    AuditLoggerPort,
    ContractViolationError,
    canonical_digest,
)
from ctf_mcp.storage import Storage

MAX_AUDIT_SUMMARY_CHARS = 256

_SENSITIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"SYNTHETIC_SECRET_[A-Za-z0-9_=-]*"),
    re.compile(r"CTF_SENSITIVE_MARKER[A-Za-z0-9_=-]*"),
    re.compile(r"(?:flag|ctf)\{[^}\r\n]*\}", re.IGNORECASE),
    re.compile(r"Bearer\s+[A-Za-z0-9._~+/-]+=*", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(
        r"\b(?:api[_-]?key|auth[_-]?token|access[_-]?token|secret[_-]?key|password|passwd|authorization)\s*[:=]\s*[^\s,;]+",
        re.IGNORECASE,
    ),
)


def contains_sensitive_marker(text: str | None) -> bool:
    """Return True if ``text`` matches any synthetic secret, token, key, or flag pattern."""
    if not text:
        return False
    return any(pattern.search(text) is not None for pattern in _SENSITIVE_PATTERNS)


def sanitize_audit_text(
    text: str | None,
    *,
    max_len: int = MAX_AUDIT_SUMMARY_CHARS,
) -> str | None:
    """Redact sensitive markers, collapse whitespace, and bound audit summary length."""
    if text is None:
        return None
    cleaned = re.sub(r"[\r\n\t]+", " ", text).strip()
    for pattern in _SENSITIVE_PATTERNS:
        cleaned = pattern.sub("[REDACTED]", cleaned)
    if len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 3] + "..." if max_len > 3 else cleaned[:max_len]
    return cleaned


def summarize_arguments(arguments: Mapping[str, Any], *, max_len: int = MAX_AUDIT_SUMMARY_CHARS) -> str:
    """Build a value-free deterministic summary of tool argument keys and canonical digest."""
    keys = ",".join(sorted(str(k) for k in arguments.keys()))
    digest_prefix = canonical_digest(dict(arguments))[:12]
    summary = f"keys=[{keys}];digest12={digest_prefix}"
    if contains_sensitive_marker(summary):
        summary = f"key_count={len(arguments)};digest12={digest_prefix}"
    if len(summary) > max_len:
        summary = f"key_count={len(arguments)};digest12={digest_prefix}"
    return summary[:max_len]


def _validate_clean_event(event: AuditEvent) -> None:
    text_fields = (
        ("event_id", event.event_id),
        ("run_id", event.run_id),
        ("principal_id", event.principal_id),
        ("action_id", event.action_id),
        ("capability", event.capability),
        ("operation", event.operation),
        ("outcome", event.outcome),
        ("scope_revision", event.scope_revision),
        ("destination_summary", event.destination_summary),
    )
    for field_name, value in text_fields:
        if value is None:
            continue
        if contains_sensitive_marker(value):
            raise ContractViolationError(
                f"AuditEvent.{field_name} contains forbidden secret or flag marker.",
                details={"field": field_name},
            )
        if "\n" in value or "\r" in value:
            raise ContractViolationError(
                f"AuditEvent.{field_name} cannot contain raw multiline content.",
                details={"field": field_name},
            )
    if event.destination_summary is not None and len(event.destination_summary) > MAX_AUDIT_SUMMARY_CHARS:
        raise ContractViolationError(
            f"AuditEvent.destination_summary exceeds {MAX_AUDIT_SUMMARY_CHARS} characters."
        )


def _sanitize_event(event: AuditEvent) -> AuditEvent:
    sanitized = event.model_copy(
        update={
            "outcome": sanitize_audit_text(event.outcome, max_len=128) or "unknown",
            "destination_summary": sanitize_audit_text(
                event.destination_summary, max_len=MAX_AUDIT_SUMMARY_CHARS
            ),
        }
    )
    _validate_clean_event(sanitized)
    return sanitized


class AuditLogger(AuditLoggerPort):
    """Stores and retrieves sanitized audit summaries in SQLite ``audit_events``."""

    def __init__(self, storage: Storage, *, reject_unsanitized: bool = True) -> None:
        self._storage = storage
        self._reject_unsanitized = reject_unsanitized

    def record_in_tx(self, conn: sqlite3.Connection, event: AuditEvent) -> None:
        """Persist an ``AuditEvent`` inside ``conn`` after strict secret/marker validation."""
        stored = event
        if self._reject_unsanitized:
            _validate_clean_event(stored)
        else:
            stored = _sanitize_event(stored)

        conn.execute(
            """
            INSERT INTO audit_events (
                event_id, timestamp, run_id, principal_id, action_id,
                capability, operation, outcome, usage_json,
                scope_revision, destination_summary, event_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                stored.event_id,
                stored.timestamp.isoformat(),
                stored.run_id,
                stored.principal_id,
                stored.action_id,
                stored.capability,
                stored.operation,
                stored.outcome,
                stored.usage.model_dump_json() if stored.usage is not None else None,
                stored.scope_revision,
                stored.destination_summary,
                stored.model_dump_json(),
            ),
        )

    def record(self, event: AuditEvent) -> None:
        """Implement ``AuditLoggerPort.record`` atomically."""
        with self._storage.transaction() as conn:
            self.record_in_tx(conn, event)

    def record_sanitized_in_tx(self, conn: sqlite3.Connection, event: AuditEvent) -> AuditEvent:
        """Sanitize an ``AuditEvent`` before persisting and verify no sensitive markers remain."""
        cleaned = _sanitize_event(event)
        conn.execute(
            """
            INSERT INTO audit_events (
                event_id, timestamp, run_id, principal_id, action_id,
                capability, operation, outcome, usage_json,
                scope_revision, destination_summary, event_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cleaned.event_id,
                cleaned.timestamp.isoformat(),
                cleaned.run_id,
                cleaned.principal_id,
                cleaned.action_id,
                cleaned.capability,
                cleaned.operation,
                cleaned.outcome,
                cleaned.usage.model_dump_json() if cleaned.usage is not None else None,
                cleaned.scope_revision,
                cleaned.destination_summary,
                cleaned.model_dump_json(),
            ),
        )
        return cleaned

    def record_sanitized(self, event: AuditEvent) -> AuditEvent:
        """Sanitize and record an ``AuditEvent`` atomically."""
        with self._storage.transaction() as conn:
            return self.record_sanitized_in_tx(conn, event)

    def list_events(
        self,
        run_id: str,
        *,
        principal_id: str | None = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Retrieve sanitized audit events for ``run_id`` ordered chronologically."""
        if limit < 1:
            raise ValueError("limit must be >= 1.")
        with self._storage.read_connection() as conn:
            if principal_id is None:
                rows = conn.execute(
                    """
                    SELECT event_json FROM audit_events
                    WHERE run_id = ?
                    ORDER BY timestamp ASC, event_id ASC
                    LIMIT ?
                    """,
                    (run_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT event_json FROM audit_events
                    WHERE run_id = ? AND principal_id = ?
                    ORDER BY timestamp ASC, event_id ASC
                    LIMIT ?
                    """,
                    (run_id, principal_id, limit),
                ).fetchall()
            return [AuditEvent.model_validate_json(row["event_json"]) for row in rows]

    def summarize_run(
        self,
        run_id: str,
        *,
        principal_id: str | None = None,
    ) -> dict[str, Any]:
        """Return an operator-reviewable audit count summary without sensitive data."""
        events = self.list_events(run_id, principal_id=principal_id, limit=10000)
        outcomes = Counter(ev.outcome for ev in events)
        capabilities = Counter(ev.capability or "none" for ev in events)
        total_wall_ms = sum(ev.usage.wall_ms for ev in events if ev.usage is not None)
        total_output_bytes = sum(ev.usage.output_bytes for ev in events if ev.usage is not None)
        return {
            "run_id": run_id,
            "total_events": len(events),
            "outcomes": dict(outcomes),
            "capabilities": dict(capabilities),
            "total_wall_ms": total_wall_ms,
            "total_output_bytes": total_output_bytes,
        }


__all__ = [
    "AuditLogger",
    "MAX_AUDIT_SUMMARY_CHARS",
    "contains_sensitive_marker",
    "sanitize_audit_text",
    "summarize_arguments",
]
