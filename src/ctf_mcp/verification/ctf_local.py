"""Deterministic local CTF verifier and SQLite persistence helpers.

Verifies submitted claims and/or stored evidence against controlled SHA-256
expectations without ever emitting plaintext flags into ``VerificationRecord``
fields, logs, or reports.
"""

from __future__ import annotations

import hmac
import json
import sqlite3
import uuid
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path

from pydantic import Field, model_validator

from ctf_mcp.contracts import (
    SHA256_PATTERN,
    ContractViolationError,
    StrictModel,
    VerificationRecord,
    VerificationStatus,
    sha256_bytes,
)
from ctf_mcp.fs_guard import safe_read_bounded
from ctf_mcp.storage import Storage

DEFAULT_MAX_VERIFY_READ_BYTES = 10 * 1024 * 1024


class ExpectedChallengeSpec(StrictModel):
    """Controlled expected digest specification for a local CTF run or task."""

    expected_flag_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    expected_evidence_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    normalize_whitespace: bool = True
    salt: str = ""
    require_complete_capture: bool = True
    description: str = Field(default="Controlled SHA-256 verification", min_length=1)

    @model_validator(mode="after")
    def _require_at_least_one_digest(self) -> ExpectedChallengeSpec:
        if self.expected_flag_sha256 is None and self.expected_evidence_sha256 is None:
            raise ValueError(
                "ExpectedChallengeSpec requires expected_flag_sha256 and/or expected_evidence_sha256."
            )
        return self


def _coerce_spec(raw: ExpectedChallengeSpec | str) -> ExpectedChallengeSpec:
    if isinstance(raw, ExpectedChallengeSpec):
        return raw
    if isinstance(raw, str):
        return ExpectedChallengeSpec(expected_flag_sha256=raw.strip().lower())
    raise ContractViolationError("Invalid expected challenge specification type.")


def save_verification_record_in_tx(
    conn: sqlite3.Connection,
    record: VerificationRecord,
) -> None:
    """Persist a ``VerificationRecord`` inside an active SQLite transaction."""
    conn.execute(
        """
        INSERT INTO verifications (
            verification_id, run_id, verifier_id, verifier_revision,
            status, checks_json, limitations_json, evidence_ids_json, verified_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record.verification_id,
            record.run_id,
            record.verifier_id,
            record.verifier_revision,
            record.status.value,
            json.dumps(list(record.checks_performed), ensure_ascii=False),
            json.dumps(list(record.limitations), ensure_ascii=False),
            json.dumps(list(record.evidence_ids), ensure_ascii=False),
            record.verified_at.isoformat(),
        ),
    )


def save_verification_record(storage: Storage, record: VerificationRecord) -> None:
    """Atomically persist a ``VerificationRecord`` into the ``verifications`` table."""
    with storage.transaction() as conn:
        save_verification_record_in_tx(conn, record)


def load_verifications_for_run(
    storage: Storage,
    run_id: str,
) -> list[VerificationRecord]:
    """Load persisted ``VerificationRecord`` rows for ``run_id``."""
    with storage.read_connection() as conn:
        rows = conn.execute(
            """
            SELECT verification_id, run_id, verifier_id, verifier_revision,
                   status, checks_json, limitations_json, evidence_ids_json, verified_at
            FROM verifications
            WHERE run_id = ?
            ORDER BY verified_at ASC, verification_id ASC
            """,
            (run_id,),
        ).fetchall()

    results: list[VerificationRecord] = []
    for row in rows:
        results.append(
            VerificationRecord(
                verification_id=str(row["verification_id"]),
                run_id=str(row["run_id"]),
                verifier_id=str(row["verifier_id"]),
                verifier_revision=str(row["verifier_revision"]),
                status=VerificationStatus(str(row["status"])),
                checks_performed=tuple(json.loads(str(row["checks_json"]))),
                limitations=tuple(json.loads(str(row["limitations_json"]))),
                evidence_ids=tuple(json.loads(str(row["evidence_ids_json"]))),
                verified_at=datetime.fromisoformat(str(row["verified_at"])),
            )
        )
    return results


class LocalCtfVerifier:
    """Deterministic local CTF verifier implementing ``VerifierPort``.

    Compares candidate claims or stored evidence artifacts against controlled
    SHA-256 digests. Plaintext flags are never placed into ``checks_performed``,
    ``limitations``, or persisted verification records.
    """

    def __init__(
        self,
        *,
        verifier_id: str = "ctf.local_digest",
        verifier_revision: str = "1.0.0",
        storage: Storage | None = None,
        vault_root: str | Path | None = None,
        expected_by_run: Mapping[str, ExpectedChallengeSpec | str] | None = None,
        expected_by_task: Mapping[str, ExpectedChallengeSpec | str] | None = None,
        max_read_bytes: int = DEFAULT_MAX_VERIFY_READ_BYTES,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not verifier_id.strip() or not verifier_revision.strip():
            raise ContractViolationError("verifier_id and verifier_revision must be non-empty.")
        if max_read_bytes <= 0:
            raise ContractViolationError("max_read_bytes must be positive.")

        self.verifier_id = verifier_id
        self.verifier_revision = verifier_revision
        self._storage = storage
        self._vault_root = Path(vault_root) if vault_root is not None else None
        self._max_read_bytes = max_read_bytes
        self._clock = clock or (lambda: datetime.now(UTC))
        self._expected_by_run: dict[str, ExpectedChallengeSpec] = {
            k: _coerce_spec(v) for k, v in (expected_by_run or {}).items()
        }
        self._expected_by_task: dict[str, ExpectedChallengeSpec] = {
            k: _coerce_spec(v) for k, v in (expected_by_task or {}).items()
        }

    def register_run_expectation(
        self,
        run_id: str,
        spec: ExpectedChallengeSpec | str,
    ) -> None:
        """Bind a controlled expected digest specification to a specific ``run_id``."""
        if not run_id.strip():
            raise ContractViolationError("run_id must be non-empty.")
        self._expected_by_run[run_id] = _coerce_spec(spec)

    def register_task_expectation(
        self,
        task_id: str,
        spec: ExpectedChallengeSpec | str,
    ) -> None:
        """Bind a controlled expected digest specification to a ``task_id``."""
        if not task_id.strip():
            raise ContractViolationError("task_id must be non-empty.")
        self._expected_by_task[task_id] = _coerce_spec(spec)

    def _hash_text_candidate(self, text: str, salt: str) -> str:
        return sha256_bytes((salt + text).encode("utf-8"))

    def _collect_evidence_material(
        self,
        *,
        run_id: str,
        evidence_ids: tuple[str, ...],
        checks: list[str],
        limitations: list[str],
    ) -> tuple[bool, bool, list[str], list[bytes]]:
        """Validate evidence ownership/completeness and optionally read active views.

        Returns ``(integrity_ok, incomplete_found, raw_sha256s, view_payloads)``.
        """
        if self._storage is None or not evidence_ids:
            return True, False, [], []

        raw_hashes: list[str] = []
        view_payloads: list[bytes] = []
        incomplete_found = False

        with self._storage.read_connection() as conn:
            for eid in evidence_ids:
                obj_row = conn.execute(
                    """
                    SELECT evidence_id, run_id, raw_sha256, capture_complete
                    FROM evidence_objects
                    WHERE evidence_id = ?
                    """,
                    (eid,),
                ).fetchone()
                if obj_row is None:
                    checks.append("evidence_lookup:missing")
                    limitations.append(
                        f"Referenced evidence object {eid!r} was not found."
                    )
                    return False, incomplete_found, raw_hashes, view_payloads

                if str(obj_row["run_id"]) != run_id:
                    checks.append("evidence_run_ownership:failed")
                    limitations.append(
                        "Cross-run evidence reference is forbidden and cannot be verified."
                    )
                    return False, incomplete_found, raw_hashes, view_payloads

                raw_hashes.append(str(obj_row["raw_sha256"]).lower())
                if int(obj_row["capture_complete"]) == 0:
                    incomplete_found = True

                if self._vault_root is None:
                    any_view = conn.execute(
                        "SELECT 1 FROM evidence_views WHERE evidence_id = ? AND run_id = ? LIMIT 1",
                        (eid, run_id),
                    ).fetchone()
                    if any_view is not None:
                        active_view = conn.execute(
                            "SELECT 1 FROM evidence_views WHERE evidence_id = ? AND run_id = ? AND revoked_at IS NULL LIMIT 1",
                            (eid, run_id),
                        ).fetchone()
                        if active_view is None:
                            checks.append("evidence_view_lookup:revoked")
                            limitations.append(
                                f"All evidence views for {eid!r} have been revoked."
                            )
                            return False, incomplete_found, raw_hashes, view_payloads

                if self._vault_root is not None:
                    view_row = conn.execute(
                        """
                        SELECT view_sha256, storage_relpath, capture_complete
                        FROM evidence_views
                        WHERE evidence_id = ? AND run_id = ? AND revoked_at IS NULL
                        ORDER BY created_at DESC
                        LIMIT 1
                        """,
                        (eid, run_id),
                    ).fetchone()
                    if view_row is None:
                        checks.append("evidence_view_lookup:no_active_view")
                        limitations.append(
                            f"No non-revoked view is available for evidence {eid!r}."
                        )
                        continue

                    if int(view_row["capture_complete"]) == 0:
                        incomplete_found = True

                    try:
                        read_res = safe_read_bounded(
                            self._vault_root,
                            str(view_row["storage_relpath"]),
                            max_bytes=self._max_read_bytes,
                            allow_truncate=False,
                        )
                    except Exception:
                        checks.append("evidence_blob_read:failed")
                        limitations.append(
                            f"Stored evidence payload for {eid!r} could not be read safely."
                        )
                        return False, incomplete_found, raw_hashes, view_payloads

                    actual_view_sha = sha256_bytes(read_res.data)
                    expected_view_sha = str(view_row["view_sha256"]).lower()
                    if not hmac.compare_digest(actual_view_sha, expected_view_sha):
                        checks.append("evidence_blob_integrity:mismatch")
                        limitations.append(
                            f"Stored payload SHA-256 mismatch detected for evidence {eid!r}."
                        )
                        return False, incomplete_found, raw_hashes, view_payloads

                    view_payloads.append(read_res.data)

        checks.append("evidence_run_ownership:verified")
        if self._vault_root is not None and view_payloads:
            checks.append("evidence_blob_integrity:verified")
        if incomplete_found:
            checks.append("evidence_completeness:incomplete")
            limitations.append(
                "At least one referenced evidence object has capture_complete=False."
            )
        return True, incomplete_found, raw_hashes, view_payloads

    def _resolve_spec(
        self,
        *,
        run_id: str,
        checks: list[str],
        limitations: list[str],
    ) -> tuple[bool, ExpectedChallengeSpec | None]:
        spec = self._expected_by_run.get(run_id)
        if spec is not None:
            checks.append("expected_digest_lookup:matched_run")
            if self._storage is not None:
                with self._storage.read_connection() as conn:
                    row = conn.execute(
                        "SELECT task_id FROM runs WHERE run_id = ?",
                        (run_id,),
                    ).fetchone()
                if row is None:
                    checks.append("run_lookup:missing")
                    limitations.append("Run record does not exist in storage.")
                    return False, None
                checks.append("run_lookup:found")
            return True, spec

        if self._storage is None:
            return True, None

        with self._storage.read_connection() as conn:
            row = conn.execute(
                "SELECT task_id FROM runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        if row is None:
            checks.append("run_lookup:missing")
            limitations.append("Run record does not exist in storage.")
            return False, None

        checks.append("run_lookup:found")
        task_id = str(row["task_id"])
        spec = self._expected_by_task.get(task_id)
        if spec is not None:
            checks.append("expected_digest_lookup:matched_task")
        return True, spec

    def verify(
        self,
        *,
        run_id: str,
        evidence_ids: tuple[str, ...] = (),
        claim: str | None = None,
    ) -> VerificationRecord:
        """Deterministically verify evidence/claim against controlled digests.

        Never embeds plaintext candidate claims or flags into the output record.
        """
        if not isinstance(run_id, str) or not run_id.strip():
            raise ContractViolationError("run_id must be a non-empty string.")

        deduped_eids = tuple(dict.fromkeys(evidence_ids))
        checks: list[str] = []
        limitations: list[str] = [
            "Local digest verification evaluates exact SHA-256 equality without live target execution; plaintext flags are omitted."
        ]

        run_ok, spec = self._resolve_spec(
            run_id=run_id, checks=checks, limitations=limitations
        )
        integrity_ok, incomplete_found, raw_hashes, view_payloads = (
            self._collect_evidence_material(
                run_id=run_id,
                evidence_ids=deduped_eids,
                checks=checks,
                limitations=limitations,
            )
        )

        if not run_ok or not integrity_ok:
            return self._make_record(
                run_id=run_id,
                status=VerificationStatus.FAILED,
                checks=checks,
                limitations=limitations,
                evidence_ids=deduped_eids,
            )

        if spec is None:
            checks.append("expected_digest_lookup:not_configured")
            limitations.append(
                "No controlled expected SHA-256 specification is registered for this run or task."
            )
            return self._make_record(
                run_id=run_id,
                status=VerificationStatus.INCONCLUSIVE,
                checks=checks,
                limitations=limitations,
                evidence_ids=deduped_eids,
            )

        evidence_check_passed: bool | None = None
        flag_check_passed: bool | None = None
        inconclusive_reason = False

        if spec.expected_evidence_sha256 is not None:
            if not deduped_eids:
                checks.append("expected_evidence_sha256:no_evidence_provided")
                limitations.append(
                    "expected_evidence_sha256 requires at least one evidence_id."
                )
                inconclusive_reason = True
            elif self._storage is None and not view_payloads:
                checks.append("expected_evidence_sha256:storage_unavailable")
                limitations.append(
                    "Storage is required to verify stored evidence SHA-256."
                )
                inconclusive_reason = True
            else:
                matched_raw = any(
                    hmac.compare_digest(h, spec.expected_evidence_sha256)
                    for h in raw_hashes
                )
                matched_view = any(
                    hmac.compare_digest(sha256_bytes(b), spec.expected_evidence_sha256)
                    for b in view_payloads
                )
                if spec.require_complete_capture and incomplete_found:
                    checks.append("expected_evidence_sha256:rejected_incomplete_capture")
                    evidence_check_passed = False
                elif matched_raw or matched_view:
                    checks.append("expected_evidence_sha256:matched")
                    evidence_check_passed = True
                else:
                    checks.append("expected_evidence_sha256:mismatched")
                    evidence_check_passed = False

        if spec.expected_flag_sha256 is not None:
            candidate_digests: list[tuple[str, str]] = []
            if claim is not None and claim != "":
                candidate_digests.append(
                    ("claim", self._hash_text_candidate(claim, spec.salt))
                )
                if spec.normalize_whitespace:
                    stripped = claim.strip()
                    if stripped and stripped != claim:
                        candidate_digests.append(
                            ("claim", self._hash_text_candidate(stripped, spec.salt))
                        )

            for payload in view_payloads:
                text = payload.decode("utf-8", errors="replace")
                candidate_digests.append(
                    ("evidence", self._hash_text_candidate(text, spec.salt))
                )
                if spec.normalize_whitespace:
                    stripped_full = text.strip()
                    if stripped_full:
                        candidate_digests.append(
                            ("evidence", self._hash_text_candidate(stripped_full, spec.salt))
                        )
                for line in text.splitlines():
                    if line:
                        candidate_digests.append(
                            ("evidence", self._hash_text_candidate(line, spec.salt))
                        )
                    if spec.normalize_whitespace:
                        stripped_line = line.strip()
                        if stripped_line:
                            candidate_digests.append(
                                (
                                    "evidence",
                                    self._hash_text_candidate(stripped_line, spec.salt),
                                )
                            )

            if not candidate_digests:
                checks.append("expected_flag_sha256:no_candidate_material")
                limitations.append(
                    "No claim or readable evidence content was supplied for expected flag digest comparison."
                )
                inconclusive_reason = True
            else:
                matched_sources: list[str] = []
                for source, digest in candidate_digests:
                    if hmac.compare_digest(digest, spec.expected_flag_sha256):
                        if source not in matched_sources:
                            matched_sources.append(source)

                if (
                    spec.require_complete_capture
                    and incomplete_found
                    and "claim" not in matched_sources
                ):
                    checks.append("expected_flag_sha256:rejected_incomplete_capture")
                    limitations.append(
                        "Cannot pass expected_flag_sha256 solely from an incomplete/truncated capture."
                    )
                    flag_check_passed = False
                elif matched_sources:
                    checks.append(
                        f"expected_flag_sha256:matched({'+'.join(matched_sources)})"
                    )
                    flag_check_passed = True
                else:
                    checks.append("expected_flag_sha256:mismatched")
                    flag_check_passed = False

        if evidence_check_passed is False or flag_check_passed is False:
            status = VerificationStatus.FAILED
        elif inconclusive_reason:
            status = VerificationStatus.INCONCLUSIVE
        elif evidence_check_passed is True or flag_check_passed is True:
            status = VerificationStatus.PASSED
        else:
            status = VerificationStatus.INCONCLUSIVE

        return self._make_record(
            run_id=run_id,
            status=status,
            checks=checks,
            limitations=limitations,
            evidence_ids=deduped_eids,
        )

    def _make_record(
        self,
        *,
        run_id: str,
        status: VerificationStatus,
        checks: list[str],
        limitations: list[str],
        evidence_ids: tuple[str, ...],
    ) -> VerificationRecord:
        if not checks:
            checks = ["verification_executed"]
        return VerificationRecord(
            verification_id=f"ver-{uuid.uuid4().hex[:16]}",
            run_id=run_id,
            verifier_id=self.verifier_id,
            verifier_revision=self.verifier_revision,
            status=status,
            checks_performed=tuple(checks),
            limitations=tuple(limitations),
            evidence_ids=evidence_ids,
            verified_at=self._clock(),
        )


__all__ = [
    "DEFAULT_MAX_VERIFY_READ_BYTES",
    "ExpectedChallengeSpec",
    "LocalCtfVerifier",
    "load_verifications_for_run",
    "save_verification_record",
    "save_verification_record_in_tx",
]
