"""Sensitive marker redaction and derived view generation for evidence and exports.

Implements ``docs/11`` section 3 and CTF-04 / CTF-12:
- Replaces synthetic sensitive markers (``SYNTHETIC_SECRET_...``,
  ``CTF_SENSITIVE_MARKER``), bearer/token/credential patterns, and ``flag{...}``
  strings with ``[REDACTED]``.
- Scans text/bytes for residual sensitive material without leaking matched
  secrets in error messages or logs.
- Creates a new derived view revision in ``evidence_views`` with a newly
  computed ``view_sha256`` (never reusing the original hash on redacted bytes)
  and optionally revokes prior views (such as ``raw-v1``) to invalidate stale
  cursors.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass

from ctf_mcp.contracts import sha256_bytes
from ctf_mcp.evidence.vault import EvidenceVault, EvidenceViewRecord

REDACTED_PLACEHOLDER = "[REDACTED]"
REDACTED_PLACEHOLDER_BYTES = b"[REDACTED]"


@dataclass(frozen=True)
class _RedactionRule:
    name: str
    text_pattern: re.Pattern[str]
    text_replacement: str
    bytes_pattern: re.Pattern[bytes]
    bytes_replacement: bytes


_RULES: tuple[_RedactionRule, ...] = (
    _RedactionRule(
        name="synthetic_secret_marker",
        text_pattern=re.compile(r"(?<![A-Za-z0-9_])SYNTHETIC_SECRET(?:_[A-Za-z0-9._:/=+-]+)?"),
        text_replacement=REDACTED_PLACEHOLDER,
        bytes_pattern=re.compile(rb"(?<![A-Za-z0-9_])SYNTHETIC_SECRET(?:_[A-Za-z0-9._:/=+-]+)?"),
        bytes_replacement=REDACTED_PLACEHOLDER_BYTES,
    ),
    _RedactionRule(
        name="ctf_sensitive_marker",
        text_pattern=re.compile(r"(?<![A-Za-z0-9_])CTF_SENSITIVE_MARKER(?:[:_=-][A-Za-z0-9._:/=+-]+)?"),
        text_replacement=REDACTED_PLACEHOLDER,
        bytes_pattern=re.compile(rb"(?<![A-Za-z0-9_])CTF_SENSITIVE_MARKER(?:[:_=-][A-Za-z0-9._:/=+-]+)?"),
        bytes_replacement=REDACTED_PLACEHOLDER_BYTES,
    ),
    _RedactionRule(
        name="flag_braced",
        text_pattern=re.compile(r"(?i)\b(?:flag|ctf|vdp)\{[^{}\r\n]+\}"),
        text_replacement=REDACTED_PLACEHOLDER,
        bytes_pattern=re.compile(rb"(?i)\b(?:flag|ctf|vdp)\{[^{}\r\n]+\}"),
        bytes_replacement=REDACTED_PLACEHOLDER_BYTES,
    ),
    _RedactionRule(
        name="bearer_token",
        text_pattern=re.compile(r"(?i)\bBearer\s+(?!\[REDACTED\])[A-Za-z0-9\-._~+/]+=*"),
        text_replacement=f"Bearer {REDACTED_PLACEHOLDER}",
        bytes_pattern=re.compile(rb"(?i)\bBearer\s+(?!\[REDACTED\])[A-Za-z0-9\-._~+/]+=*"),
        bytes_replacement=b"Bearer " + REDACTED_PLACEHOLDER_BYTES,
    ),
    _RedactionRule(
        name="jwt_token",
        text_pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\b"),
        text_replacement=REDACTED_PLACEHOLDER,
        bytes_pattern=re.compile(rb"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\b"),
        bytes_replacement=REDACTED_PLACEHOLDER_BYTES,
    ),
    _RedactionRule(
        name="prefixed_secret_key",
        text_pattern=re.compile(
            r"(?<![A-Za-z0-9_])(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{16,}|gho_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16})"
        ),
        text_replacement=REDACTED_PLACEHOLDER,
        bytes_pattern=re.compile(
            rb"(?<![A-Za-z0-9_])(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{16,}|gho_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16})"
        ),
        bytes_replacement=REDACTED_PLACEHOLDER_BYTES,
    ),
    _RedactionRule(
        name="key_value_credential_dquote",
        text_pattern=re.compile(
            r"(?i)([\"']?)\b(access_token|refresh_token|auth_token|bearer_token|bearer|api_key|apikey|"
            r"secret_key|hmac_key|private_key|client_secret|password|passwd|secret|token|flag)"
            r"\b\1(\s*[:=]\s*)\"(?!\[REDACTED\])[^\"\r\n]+\""
        ),
        text_replacement=rf'\1\2\1\3"{REDACTED_PLACEHOLDER}"',
        bytes_pattern=re.compile(
            rb"(?i)([\"']?)\b(access_token|refresh_token|auth_token|bearer_token|bearer|api_key|apikey|"
            rb"secret_key|hmac_key|private_key|client_secret|password|passwd|secret|token|flag)"
            rb"\b\1(\s*[:=]\s*)\"(?!\[REDACTED\])[^\"\r\n]+\""
        ),
        bytes_replacement=rb'\1\2\1\3"' + REDACTED_PLACEHOLDER_BYTES + b'"',
    ),
    _RedactionRule(
        name="key_value_credential_squote",
        text_pattern=re.compile(
            r"(?i)([\"']?)\b(access_token|refresh_token|auth_token|bearer_token|bearer|api_key|apikey|"
            r"secret_key|hmac_key|private_key|client_secret|password|passwd|secret|token|flag)"
            r"\b\1(\s*[:=]\s*)'(?!\[REDACTED\])[^'\r\n]+'"
        ),
        text_replacement=rf"\1\2\1\3'{REDACTED_PLACEHOLDER}'",
        bytes_pattern=re.compile(
            rb"(?i)([\"']?)\b(access_token|refresh_token|auth_token|bearer_token|bearer|api_key|apikey|"
            rb"secret_key|hmac_key|private_key|client_secret|password|passwd|secret|token|flag)"
            rb"\b\1(\s*[:=]\s*)'(?!\[REDACTED\])[^'\r\n]+'"
        ),
        bytes_replacement=rb"\1\2\1\3'" + REDACTED_PLACEHOLDER_BYTES + b"'",
    ),
    _RedactionRule(
        name="key_value_credential",
        text_pattern=re.compile(
            r"(?i)([\"']?)\b(access_token|refresh_token|auth_token|bearer_token|bearer|api_key|apikey|"
            r"secret_key|hmac_key|private_key|client_secret|password|passwd|secret|token|flag)"
            r"\b\1(\s*[:=]\s*)(?![\"']?\[REDACTED\])([^\s\"',;\]\}]+)"
        ),
        text_replacement=rf"\1\2\1\3{REDACTED_PLACEHOLDER}",
        bytes_pattern=re.compile(
            rb"(?i)([\"']?)\b(access_token|refresh_token|auth_token|bearer_token|bearer|api_key|apikey|"
            rb"secret_key|hmac_key|private_key|client_secret|password|passwd|secret|token|flag)"
            rb"\b\1(\s*[:=]\s*)(?![\"']?\[REDACTED\])([^\s\"',;\]\}]+)"
        ),
        bytes_replacement=rb"\1\2\1\3" + REDACTED_PLACEHOLDER_BYTES,
    ),
)


@dataclass(frozen=True)
class TextRedactionOutcome:
    """Result of redacting text without echoing raw secret material."""

    redacted_text: str
    redactions_applied: int
    rules_triggered: tuple[str, ...]
    changed: bool


@dataclass(frozen=True)
class BytesRedactionOutcome:
    """Result of redacting raw bytes along with fresh SHA-256."""

    redacted_bytes: bytes
    original_sha256: str
    new_sha256: str
    redactions_applied: int
    rules_triggered: tuple[str, ...]
    changed: bool


@dataclass(frozen=True)
class RedactedViewOutcome:
    """Result of creating a redacted derived view in ``EvidenceVault``."""

    source_view: EvidenceViewRecord
    redacted_view: EvidenceViewRecord
    redactions_applied: int
    rules_triggered: tuple[str, ...]
    prior_views_revoked: int


def _compile_extra_literals(extra_literals: Sequence[str]) -> list[str]:
    unique = {lit for lit in extra_literals if lit and lit != REDACTED_PLACEHOLDER}
    return sorted(unique, key=len, reverse=True)


def redact_text(
    text: str,
    *,
    extra_literals: Sequence[str] = (),
) -> TextRedactionOutcome:
    """Redact synthetic markers, bearer/token strings, and flags from ``text``."""
    updated = text
    total_replacements = 0
    triggered: list[str] = []

    literals = _compile_extra_literals(extra_literals)
    if literals:
        lit_pattern = re.compile("|".join(re.escape(lit) for lit in literals))
        updated, count = lit_pattern.subn(REDACTED_PLACEHOLDER, updated)
        if count > 0:
            total_replacements += count
            triggered.append("explicit_literal")

    for rule in _RULES:
        updated, count = rule.text_pattern.subn(rule.text_replacement, updated)
        if count > 0:
            total_replacements += count
            triggered.append(rule.name)

    return TextRedactionOutcome(
        redacted_text=updated,
        redactions_applied=total_replacements,
        rules_triggered=tuple(triggered),
        changed=(updated != text),
    )


def redact_bytes(
    data: bytes,
    *,
    extra_literals: Sequence[str] = (),
) -> BytesRedactionOutcome:
    """Redact sensitive markers from UTF-8 or raw binary bytes and recompute SHA-256."""
    orig_hash = sha256_bytes(data)
    try:
        decoded = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        updated = data
        total_replacements = 0
        triggered: list[str] = []

        literals = _compile_extra_literals(extra_literals)
        if literals:
            byte_lits = [lit.encode("utf-8") for lit in literals]
            lit_pattern = re.compile(b"|".join(re.escape(lit) for lit in byte_lits))
            updated, count = lit_pattern.subn(REDACTED_PLACEHOLDER_BYTES, updated)
            if count > 0:
                total_replacements += count
                triggered.append("explicit_literal")

        for rule in _RULES:
            updated, count = rule.bytes_pattern.subn(rule.bytes_replacement, updated)
            if count > 0:
                total_replacements += count
                triggered.append(rule.name)

        return BytesRedactionOutcome(
            redacted_bytes=updated,
            original_sha256=orig_hash,
            new_sha256=sha256_bytes(updated),
            redactions_applied=total_replacements,
            rules_triggered=tuple(triggered),
            changed=(updated != data),
        )

    outcome = redact_text(decoded, extra_literals=extra_literals)
    redacted_bytes = outcome.redacted_text.encode("utf-8")
    return BytesRedactionOutcome(
        redacted_bytes=redacted_bytes,
        original_sha256=orig_hash,
        new_sha256=sha256_bytes(redacted_bytes),
        redactions_applied=outcome.redactions_applied,
        rules_triggered=outcome.rules_triggered,
        changed=(redacted_bytes != data),
    )


def scan_sensitive_markers(
    text: str,
    *,
    extra_literals: Sequence[str] = (),
) -> tuple[str, ...]:
    """Return rule names that match residual sensitive material in ``text``.

    Never returns raw matched secret strings so callers cannot leak them.
    """
    matched_rules: list[str] = []
    for lit in _compile_extra_literals(extra_literals):
        if lit in text:
            matched_rules.append("explicit_literal")
            break
    for rule in _RULES:
        if rule.text_pattern.search(text) is not None:
            matched_rules.append(rule.name)
    return tuple(matched_rules)


class EvidenceRedactor:
    """Applies redaction to stored evidence and registers new derived views."""

    def __init__(
        self,
        vault: EvidenceVault,
        *,
        policy_rev: str = "redact-v1",
        extra_literals: Sequence[str] = (),
    ) -> None:
        if not policy_rev or not policy_rev.strip():
            raise ValueError("policy_rev must be non-empty.")
        self.vault = vault
        self.policy_rev = policy_rev
        self.extra_literals = tuple(extra_literals)

    def _next_redacted_revision(
        self,
        *,
        run_id: str,
        principal_id: str,
        evidence_id: str,
        conn: sqlite3.Connection | None,
    ) -> str:
        existing = {
            v.view_revision
            for v in self.vault.list_views(
                run_id=run_id,
                principal_id=principal_id,
                evidence_id=evidence_id,
                conn=conn,
            )
        }
        idx = 1
        while f"redacted-v{idx}" in existing:
            idx += 1
        return f"redacted-v{idx}"

    def create_redacted_view(
        self,
        *,
        run_id: str,
        principal_id: str,
        evidence_id: str,
        source_view_revision: str | None = None,
        new_view_revision: str | None = None,
        policy_rev: str | None = None,
        extra_literals: Sequence[str] = (),
        revoke_prior_views: bool = True,
        conn: sqlite3.Connection | None = None,
    ) -> RedactedViewOutcome:
        """Create a redacted derived view in ``evidence_views`` with a fresh ``view_sha256``.

        Never reuses the original ``view_sha256`` when content changes, and
        optionally revokes prior views (including ``raw-v1``) so old cursors
        can no longer access pre-redaction pages.
        """
        source_view, raw_bytes = self.vault.read_view_bytes(
            run_id=run_id,
            principal_id=principal_id,
            evidence_id=evidence_id,
            view_revision=source_view_revision,
            conn=conn,
        )

        combined_literals = (*self.extra_literals, *extra_literals)
        outcome = redact_bytes(raw_bytes, extra_literals=combined_literals)

        if outcome.changed and outcome.new_sha256 == source_view.view_sha256:
            raise AssertionError("Redacted view hash must differ from modified source view.")

        target_revision = new_view_revision or self._next_redacted_revision(
            run_id=run_id,
            principal_id=principal_id,
            evidence_id=evidence_id,
            conn=conn,
        )
        effective_policy = policy_rev or self.policy_rev

        existing_views = self.vault.list_views(
            run_id=run_id,
            principal_id=principal_id,
            evidence_id=evidence_id,
            conn=conn,
        )
        active_before = sum(1 for v in existing_views if v.revoked_at is None)

        new_view = self.vault.add_view(
            run_id=run_id,
            principal_id=principal_id,
            evidence_id=evidence_id,
            view_revision=target_revision,
            data=outcome.redacted_bytes,
            redaction_policy_rev=effective_policy,
            revoke_prior_views=revoke_prior_views,
            conn=conn,
        )

        revoked_count = active_before if revoke_prior_views else 0
        return RedactedViewOutcome(
            source_view=source_view,
            redacted_view=new_view,
            redactions_applied=outcome.redactions_applied,
            rules_triggered=outcome.rules_triggered,
            prior_views_revoked=revoked_count,
        )


__all__ = [
    "BytesRedactionOutcome",
    "EvidenceRedactor",
    "REDACTED_PLACEHOLDER",
    "RedactedViewOutcome",
    "TextRedactionOutcome",
    "redact_bytes",
    "redact_text",
    "scan_sensitive_markers",
]
