"""Immutable evidence paging engine and HMAC-authenticated opaque cursors.

Implements ``schemas/evidence-page.schema.json`` (``evidence-page/1``) and
runtime semantic invariants from ``schemas/README.md`` and ``docs/11`` section 3
(CTF-03, CTF-04):
- UTF-8 paging without splitting multi-byte characters, bounded by both
  character cap (<= 4,000) and optional decoded-byte cap.
- Base64 paging bounded by both encoded-character cap (<= 4,000) and
  decoded-byte cap.
- Single empty terminal page allowed for empty views.
- Opaque HMAC-SHA256 signed URL-safe base64 cursors binding ``run_id``,
  ``principal_id``, ``evidence_id``, ``view_sha256``, ``view_revision``,
  ``offset_bytes``, and ``issued_at``.
"""

from __future__ import annotations

import base64
import codecs
import hashlib
import hmac
import json
import re
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import jsonschema

from ctf_mcp.config import MIN_HMAC_KEY_BYTES
from ctf_mcp.contracts import (
    MAX_PAGE_CONTENT_CHARS,
    BoundsExceededError,
    ConfigurationError,
    ContractViolationError,
    CursorError,
    CursorPayload,
    EvidencePage,
    PageEncoding,
    canonical_json,
    sha256_bytes,
)

_URLSAFE_B64_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
_DEFAULT_SCHEMA_PATH = (
    Path(__file__).resolve().parents[3] / "schemas" / "evidence-page.schema.json"
)
_HMAC_TAG_LEN = 32


@lru_cache(maxsize=4)
def _load_page_validator(schema_path: str) -> jsonschema.Draft202012Validator:
    path = Path(schema_path)
    try:
        raw_schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(
            f"Failed to load pinned evidence-page schema from {path}: {exc}"
        ) from exc
    return jsonschema.Draft202012Validator(
        raw_schema,
        format_checker=jsonschema.FormatChecker(),
    )


def validate_evidence_page_schema(
    page: EvidencePage | dict[str, Any],
    *,
    schema_path: Path | None = None,
) -> None:
    """Validate an ``EvidencePage`` against the local pinned ``evidence-page/1`` JSON Schema."""
    payload = page.model_dump(mode="json") if isinstance(page, EvidencePage) else page
    validator = _load_page_validator(str((schema_path or _DEFAULT_SCHEMA_PATH).resolve()))
    errors = sorted(validator.iter_errors(payload), key=lambda err: list(err.path))
    if errors:
        first = errors[0]
        raise ContractViolationError(
            f"EvidencePage failed pinned JSON Schema validation: {first.message}",
            details={"path": [str(p) for p in first.path]},
        )


def validate_evidence_page_runtime(
    page: EvidencePage,
    *,
    view_bytes_data: bytes | None = None,
    max_chars: int = MAX_PAGE_CONTENT_CHARS,
    max_decode_bytes: int | None = None,
) -> None:
    """Run all runtime semantic checks required by ``schemas/README.md``."""
    if len(page.content) > max_chars:
        raise ContractViolationError(
            f"Page content length ({len(page.content)}) exceeds max_chars ({max_chars})."
        )
    if page.encoding == PageEncoding.UTF8:
        decoded_chunk = page.content.encode("utf-8")
    else:
        try:
            decoded_chunk = base64.b64decode(page.content, validate=True)
        except Exception as exc:
            raise ContractViolationError(f"Invalid base64 content in page: {exc}") from exc

    if max_decode_bytes is not None and len(decoded_chunk) > max_decode_bytes:
        raise ContractViolationError(
            f"Decoded page byte length ({len(decoded_chunk)}) exceeds max_decode_bytes ({max_decode_bytes})."
        )

    if view_bytes_data is not None:
        if len(view_bytes_data) != page.view_bytes:
            raise ContractViolationError(
                f"View byte length mismatch: expected {page.view_bytes}, got {len(view_bytes_data)}."
            )
        actual_hash = sha256_bytes(view_bytes_data)
        if actual_hash != page.view_sha256:
            raise ContractViolationError(
                f"View SHA-256 mismatch: expected {page.view_sha256}, got {actual_hash}."
            )
        expected_slice = view_bytes_data[page.offset_bytes : page.next_offset_bytes]
        if decoded_chunk != expected_slice:
            raise ContractViolationError("Page content does not match underlying view byte slice.")


class CursorSigner:
    """Issues and verifies HMAC-SHA256 authenticated URL-safe base64 cursors."""

    def __init__(self, hmac_key: bytes) -> None:
        if not isinstance(hmac_key, (bytes, bytearray)) or len(hmac_key) < MIN_HMAC_KEY_BYTES:
            raise ConfigurationError(
                f"Cursor HMAC key must be at least {MIN_HMAC_KEY_BYTES} bytes."
            )
        self._key = bytes(hmac_key)

    def sign(self, payload: CursorPayload) -> str:
        """Encode ``CursorPayload`` as canonical JSON + HMAC-SHA256 + URL-safe base64."""
        canonical_bytes = canonical_json(payload).encode("utf-8")
        tag = hmac.new(self._key, canonical_bytes, hashlib.sha256).digest()
        token = base64.urlsafe_b64encode(tag + canonical_bytes).decode("ascii")
        return token

    def verify(self, cursor: str) -> CursorPayload:
        """Verify HMAC signature and decode ``CursorPayload`` or raise ``CursorError``."""
        if not isinstance(cursor, str) or not cursor or len(cursor) % 4 != 0:
            raise CursorError("Malformed or empty cursor token.")
        if not _URLSAFE_B64_RE.fullmatch(cursor):
            raise CursorError("Cursor token is not valid URL-safe base64.")
        try:
            decoded = base64.urlsafe_b64decode(cursor.encode("ascii"))
        except Exception as exc:
            raise CursorError(f"Failed to base64-decode cursor: {exc}") from exc

        # Enforce canonical padding/round-trip representation to prevent trailing-bit malleability.
        if base64.urlsafe_b64encode(decoded).decode("ascii") != cursor:
            raise CursorError("Cursor token is not canonically encoded.")

        if len(decoded) <= _HMAC_TAG_LEN:
            raise CursorError("Cursor token is truncated.")

        tag = decoded[:_HMAC_TAG_LEN]
        payload_bytes = decoded[_HMAC_TAG_LEN:]
        expected_tag = hmac.new(self._key, payload_bytes, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected_tag):
            raise CursorError("Cursor HMAC signature verification failed.")

        try:
            payload_text = payload_bytes.decode("utf-8")
            raw_obj = json.loads(payload_text)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CursorError(f"Cursor payload JSON is invalid: {exc}") from exc

        if not isinstance(raw_obj, dict):
            raise CursorError("Cursor payload must be a JSON object.")

        try:
            payload = CursorPayload.model_validate(raw_obj)
        except Exception as exc:
            raise CursorError(f"Cursor payload failed contract validation: {exc}") from exc
        return payload


def slice_view_page(
    raw_bytes: bytes,
    *,
    encoding: PageEncoding,
    offset_bytes: int,
    max_chars: int = MAX_PAGE_CONTENT_CHARS,
    max_decode_bytes: int | None = None,
) -> tuple[str, int, bool]:
    """Slice one bounded page starting at ``offset_bytes``.

    Returns ``(content, next_offset_bytes, is_terminal)``.
    Raises ``CursorError`` for invalid/out-of-range/mid-codepoint offsets.
    """
    if max_chars <= 0 or max_chars > MAX_PAGE_CONTENT_CHARS:
        raise ValueError(f"max_chars must be in 1..{MAX_PAGE_CONTENT_CHARS}.")
    if max_decode_bytes is not None and max_decode_bytes <= 0:
        raise ValueError("max_decode_bytes must be positive when specified.")

    view_bytes = len(raw_bytes)
    if offset_bytes < 0:
        raise CursorError("Cursor offset_bytes cannot be negative.")

    if view_bytes == 0:
        if offset_bytes != 0:
            raise CursorError("Cursor offset_bytes is out of range for an empty view.")
        return "", 0, True

    if offset_bytes >= view_bytes:
        raise CursorError(
            f"Cursor offset_bytes ({offset_bytes}) is out of range for view_bytes ({view_bytes})."
        )

    remaining = view_bytes - offset_bytes

    if encoding == PageEncoding.UTF8:
        if (raw_bytes[offset_bytes] & 0xC0) == 0x80:
            raise CursorError("Cursor offset_bytes points inside a multi-byte UTF-8 sequence.")

        byte_cap = min(remaining, max_decode_bytes) if max_decode_bytes is not None else remaining
        window_limit = min(byte_cap, max_chars * 4)
        candidate = raw_bytes[offset_bytes : offset_bytes + window_limit]

        try:
            decoded, consumed = codecs.utf_8_decode(candidate, "strict", False)
        except UnicodeDecodeError as exc:
            raise ContractViolationError(
                f"View marked as utf-8 contains invalid UTF-8 bytes at offset {offset_bytes}: {exc}"
            ) from exc

        if not decoded:
            if max_decode_bytes is not None and max_decode_bytes < 4:
                raise BoundsExceededError(
                    "max_decode_bytes is too small to decode a single multi-byte UTF-8 character."
                )
            raise ContractViolationError(
                f"Incomplete trailing UTF-8 sequence encountered at offset {offset_bytes}."
            )

        if len(decoded) > max_chars:
            decoded = decoded[:max_chars]
            consumed = len(decoded.encode("utf-8"))

        if consumed <= 0:
            raise ContractViolationError("UTF-8 page slicer failed to make forward progress.")

        next_offset = offset_bytes + consumed
        return decoded, next_offset, next_offset == view_bytes

    # Base64 encoding path
    if max_chars < 4:
        raise BoundsExceededError(
            "max_chars must be at least 4 to encode non-empty data as base64."
        )
    max_raw_for_chars = 3 * (max_chars // 4)
    raw_cap = min(remaining, max_raw_for_chars)
    if max_decode_bytes is not None:
        raw_cap = min(raw_cap, max_decode_bytes)
    if raw_cap <= 0:
        raise BoundsExceededError("Page byte cap does not allow encoding any base64 chunk.")

    chunk = raw_bytes[offset_bytes : offset_bytes + raw_cap]
    encoded = base64.b64encode(chunk).decode("ascii")
    next_offset = offset_bytes + len(chunk)
    return encoded, next_offset, next_offset == view_bytes


def build_evidence_page(
    *,
    run_id: str,
    principal_id: str,
    evidence_id: str,
    view_sha256: str,
    view_revision: str,
    encoding: PageEncoding,
    raw_bytes: bytes,
    offset_bytes: int,
    capture_complete: bool,
    omission_reason: str | None,
    signer: CursorSigner,
    issued_at: datetime | None = None,
    max_chars: int = MAX_PAGE_CONTENT_CHARS,
    max_decode_bytes: int | None = None,
    validate_schema: bool = True,
) -> EvidencePage:
    """Slice ``raw_bytes`` into an immutable ``EvidencePage`` and sign ``next_cursor``."""
    actual_sha = sha256_bytes(raw_bytes)
    if actual_sha != view_sha256:
        raise ContractViolationError(
            f"View bytes SHA-256 ({actual_sha}) does not match expected view_sha256 ({view_sha256})."
        )

    content, next_offset_bytes, is_terminal = slice_view_page(
        raw_bytes,
        encoding=encoding,
        offset_bytes=offset_bytes,
        max_chars=max_chars,
        max_decode_bytes=max_decode_bytes,
    )

    next_cursor: str | None = None
    if not is_terminal:
        next_payload = CursorPayload(
            run_id=run_id,
            principal_id=principal_id,
            evidence_id=evidence_id,
            view_sha256=view_sha256,
            view_revision=view_revision,
            offset_bytes=next_offset_bytes,
            issued_at=issued_at or datetime.now(UTC),
        )
        next_cursor = signer.sign(next_payload)

    page = EvidencePage(
        schema_version="evidence-page/1",
        run_id=run_id,
        evidence_id=evidence_id,
        view_sha256=view_sha256,
        view_revision=view_revision,
        encoding=encoding,
        offset_bytes=offset_bytes,
        next_offset_bytes=next_offset_bytes,
        view_bytes=len(raw_bytes),
        content=content,
        capture_complete=capture_complete,
        omission_reason=omission_reason,
        next_cursor=next_cursor,
    )
    validate_evidence_page_runtime(
        page,
        view_bytes_data=raw_bytes,
        max_chars=max_chars,
        max_decode_bytes=max_decode_bytes,
    )
    if validate_schema:
        validate_evidence_page_schema(page)
    return page


__all__ = [
    "CursorSigner",
    "build_evidence_page",
    "slice_view_page",
    "validate_evidence_page_runtime",
    "validate_evidence_page_schema",
]
