"""Deterministic verifier for bounded VDP product test evidence (`vdp.product_test`).

Enforces strict separation between:
- Local HTTP 200 responses (`net.probe`, rejected as product smoke/repro),
- Incomplete/uncleaned runs (`capture_complete=False`, `cleanup_confirmed=False`),
- Non-conclusive executions (`not_executed`, `skipped`, `timeout`, `environment_failure`),
- Broken positive baselines (`baseline_failed` -> never accepted as defense success),
- Conclusive falsifications (`hypothesis_falsified`) and reproductions (`deviation_reproduced`).
"""

from __future__ import annotations

import hmac
import json
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ctf_mcp.contracts import (
    ContractViolationError,
    VerificationRecord,
    VerificationStatus,
    sha256_bytes,
)
from ctf_mcp.fs_guard import safe_read_bounded
from ctf_mcp.storage import Storage

DEFAULT_MAX_VDP_VERIFY_READ_BYTES = 10 * 1024 * 1024

_MANDATORY_LIMITATIONS: tuple[str, ...] = (
    "synthetic_data_only",
    "network_isolated",
    "celery_eager_test_settings_async_unverified",
)


class VdpProductTestVerifier:
    """Deterministic local verifier implementing ``VerifierPort`` for ``vdp.test`` evidence."""

    def __init__(
        self,
        *,
        verifier_id: str = "vdp.product_test",
        verifier_revision: str = "vdp-product-test-verifier/1",
        storage: Storage | None = None,
        vault_root: str | Path | None = None,
        max_read_bytes: int = DEFAULT_MAX_VDP_VERIFY_READ_BYTES,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not verifier_id.strip() or not verifier_revision.strip():
            raise ContractViolationError(
                "verifier_id and verifier_revision must be non-empty."
            )
        if max_read_bytes <= 0:
            raise ContractViolationError("max_read_bytes must be positive.")

        self.verifier_id = verifier_id
        self.verifier_revision = verifier_revision
        self._storage = storage
        self._vault_root = Path(vault_root) if vault_root is not None else None
        self._max_read_bytes = max_read_bytes
        self._clock = clock or (lambda: datetime.now(UTC))

    def _load_evidence_payloads(
        self,
        *,
        run_id: str,
        evidence_ids: tuple[str, ...],
        checks: list[str],
        limitations: list[str],
    ) -> tuple[bool, bool, list[dict[str, Any]]]:
        """Load and integrity-verify JSON evidence payloads for ``run_id``."""
        if self._storage is None or self._vault_root is None:
            checks.append("verifier_storage_binding:missing")
            limitations.append(
                "VdpProductTestVerifier requires storage and vault_root bindings."
            )
            return False, False, []

        payloads: list[dict[str, Any]] = []
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
                    limitations.append(f"Referenced evidence {eid!r} was not found.")
                    return False, incomplete_found, payloads

                if str(obj_row["run_id"]) != run_id:
                    checks.append("evidence_run_ownership:failed")
                    limitations.append("Cross-run evidence reference is forbidden.")
                    return False, incomplete_found, payloads

                if int(obj_row["capture_complete"]) == 0:
                    incomplete_found = True

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
                        f"No active unrevoked view is available for evidence {eid!r}."
                    )
                    return False, incomplete_found, payloads

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
                        f"Stored evidence payload for {eid!r} could not be read."
                    )
                    return False, incomplete_found, payloads

                actual_sha = sha256_bytes(read_res.data)
                expected_sha = str(view_row["view_sha256"]).lower()
                if not hmac.compare_digest(actual_sha, expected_sha):
                    checks.append("evidence_blob_integrity:mismatch")
                    limitations.append(
                        f"Evidence SHA-256 mismatch detected for {eid!r}."
                    )
                    return False, incomplete_found, payloads

                try:
                    parsed = json.loads(read_res.data.decode("utf-8", errors="strict"))
                except Exception:
                    checks.append("http_200_or_non_json_rejected")
                    limitations.append(
                        f"Evidence {eid!r} is not valid vdp-product-test-evidence/1 JSON."
                    )
                    return False, incomplete_found, payloads

                if not isinstance(parsed, dict) or parsed.get("schema") != "vdp-product-test-evidence/1":
                    if isinstance(parsed, dict) and (
                        "pinned_ip" in parsed or "status_code" in parsed or "hops" in parsed
                    ):
                        checks.append("http_200_rejected_as_product_verification")
                        limitations.append(
                            "Local HTTP probe (net.probe / HTTP 200) cannot verify product smoke or VDP findings."
                        )
                    else:
                        checks.append("evidence_schema:mismatch")
                        limitations.append(
                            f"Evidence {eid!r} does not have schema 'vdp-product-test-evidence/1'."
                        )
                    return False, incomplete_found, payloads

                payloads.append(parsed)

        checks.append("evidence_integrity:verified")
        return True, incomplete_found, payloads

    def verify(
        self,
        *,
        run_id: str,
        evidence_ids: Sequence[str] = (),
        claim: str | None = None,
    ) -> VerificationRecord:
        if not run_id.strip():
            raise ContractViolationError("run_id must be non-empty.")

        eid_tuple = tuple(evidence_ids)
        checks: list[str] = []
        limitations: list[str] = list(_MANDATORY_LIMITATIONS)

        if not eid_tuple:
            checks.append("evidence_ids:empty")
            limitations.append(
                "At least one vdp.test evidence_id is required for product test verification."
            )
            return VerificationRecord(
                verification_id=f"ver-{uuid.uuid4().hex}",
                run_id=run_id,
                verifier_id=self.verifier_id,
                verifier_revision=self.verifier_revision,
                status=VerificationStatus.FAILED,
                checks_performed=tuple(checks),
                limitations=tuple(limitations),
                evidence_ids=eid_tuple,
                verified_at=self._clock(),
            )

        integrity_ok, incomplete_found, payloads = self._load_evidence_payloads(
            run_id=run_id,
            evidence_ids=eid_tuple,
            checks=checks,
            limitations=limitations,
        )
        if not integrity_ok:
            return VerificationRecord(
                verification_id=f"ver-{uuid.uuid4().hex}",
                run_id=run_id,
                verifier_id=self.verifier_id,
                verifier_revision=self.verifier_revision,
                status=VerificationStatus.FAILED,
                checks_performed=tuple(checks),
                limitations=tuple(limitations),
                evidence_ids=eid_tuple,
                verified_at=self._clock(),
            )

        for p in payloads:
            if not p.get("container_cleanup_confirmed") or not p.get("process_cleanup_confirmed"):
                checks.append("cleanup_confirmation:unconfirmed")
                limitations.append(
                    "Container or child-process cleanup was not confirmed."
                )
                return VerificationRecord(
                    verification_id=f"ver-{uuid.uuid4().hex}",
                    run_id=run_id,
                    verifier_id=self.verifier_id,
                    verifier_revision=self.verifier_revision,
                    status=VerificationStatus.FAILED,
                    checks_performed=tuple(checks),
                    limitations=tuple(limitations),
                    evidence_ids=eid_tuple,
                    verified_at=self._clock(),
                )
            if p.get("network_mode") != "none":
                checks.append("network_isolation:violated")
                limitations.append("Product tests must execute with network_mode='none'.")
                return VerificationRecord(
                    verification_id=f"ver-{uuid.uuid4().hex}",
                    run_id=run_id,
                    verifier_id=self.verifier_id,
                    verifier_revision=self.verifier_revision,
                    status=VerificationStatus.FAILED,
                    checks_performed=tuple(checks),
                    limitations=tuple(limitations),
                    evidence_ids=eid_tuple,
                    verified_at=self._clock(),
                )
            if p.get("execution_provenance", "harness_docker_isolated") != "harness_docker_isolated":
                checks.append("execution_provenance:unverified_external")
                limitations.append(
                    "Product tests must include harness_docker_isolated execution provenance."
                )
                return VerificationRecord(
                    verification_id=f"ver-{uuid.uuid4().hex}",
                    run_id=run_id,
                    verifier_id=self.verifier_id,
                    verifier_revision=self.verifier_revision,
                    status=VerificationStatus.FAILED,
                    checks_performed=tuple(checks),
                    limitations=tuple(limitations),
                    evidence_ids=eid_tuple,
                    verified_at=self._clock(),
                )

        smoke_payloads = [p for p in payloads if p.get("operation") == "run_smoke"]
        pytest_payloads = [p for p in payloads if p.get("operation") == "run_pytest"]
        verdicts = [str(p.get("verdict") or "") for p in payloads]

        if "timeout" in verdicts:
            checks.append("outcome_state:timeout")
            limitations.append(
                "Run includes non-conclusive test outcome 'timeout'."
            )
            return VerificationRecord(
                verification_id=f"ver-{uuid.uuid4().hex}",
                run_id=run_id,
                verifier_id=self.verifier_id,
                verifier_revision=self.verifier_revision,
                status=VerificationStatus.INCONCLUSIVE,
                checks_performed=tuple(checks),
                limitations=tuple(limitations),
                evidence_ids=eid_tuple,
                verified_at=self._clock(),
            )

        if incomplete_found or any(bool(p.get("log_truncated")) for p in payloads):
            checks.append("capture_completeness:incomplete")
            limitations.append(
                "Truncated or incomplete capture cannot establish final product verification."
            )
            return VerificationRecord(
                verification_id=f"ver-{uuid.uuid4().hex}",
                run_id=run_id,
                verifier_id=self.verifier_id,
                verifier_revision=self.verifier_revision,
                status=VerificationStatus.FAILED,
                checks_performed=tuple(checks),
                limitations=tuple(limitations),
                evidence_ids=eid_tuple,
                verified_at=self._clock(),
            )

        # Non-conclusive states remain strictly separated from PASSED and from each other.
        for bad_state in ("environment_failure", "skipped", "not_executed"):
            if bad_state in verdicts:
                checks.append(f"outcome_state:{bad_state}")
                limitations.append(
                    f"Run includes non-conclusive test outcome {bad_state!r}."
                )
                return VerificationRecord(
                    verification_id=f"ver-{uuid.uuid4().hex}",
                    run_id=run_id,
                    verifier_id=self.verifier_id,
                    verifier_revision=self.verifier_revision,
                    status=VerificationStatus.INCONCLUSIVE,
                    checks_performed=tuple(checks),
                    limitations=tuple(limitations),
                    evidence_ids=eid_tuple,
                    verified_at=self._clock(),
                )

        if "baseline_failed" in verdicts:
            checks.append("outcome_state:baseline_failed")
            limitations.append(
                "Positive control did not pass; negative no-change cannot be claimed as defense success."
            )
            return VerificationRecord(
                verification_id=f"ver-{uuid.uuid4().hex}",
                run_id=run_id,
                verifier_id=self.verifier_id,
                verifier_revision=self.verifier_revision,
                status=VerificationStatus.FAILED,
                checks_performed=tuple(checks),
                limitations=tuple(limitations),
                evidence_ids=eid_tuple,
                verified_at=self._clock(),
            )

        smoke_ok = any(p.get("verdict") == "smoke_passed" for p in smoke_payloads)
        if smoke_ok:
            checks.append("smoke_receipt:verified")

        normalized_claim = claim.strip().lower() if isinstance(claim, str) and claim.strip() else None

        if not pytest_payloads:
            if smoke_ok and normalized_claim in {None, "smoke_passed"}:
                checks.append("outcome_state:smoke_passed")
                return VerificationRecord(
                    verification_id=f"ver-{uuid.uuid4().hex}",
                    run_id=run_id,
                    verifier_id=self.verifier_id,
                    verifier_revision=self.verifier_revision,
                    status=VerificationStatus.PASSED,
                    checks_performed=tuple(checks),
                    limitations=tuple(limitations),
                    evidence_ids=eid_tuple,
                    verified_at=self._clock(),
                )
            checks.append("outcome_state:missing_pytest_or_claim_mismatch")
            return VerificationRecord(
                verification_id=f"ver-{uuid.uuid4().hex}",
                run_id=run_id,
                verifier_id=self.verifier_id,
                verifier_revision=self.verifier_revision,
                status=VerificationStatus.FAILED,
                checks_performed=tuple(checks),
                limitations=tuple(limitations),
                evidence_ids=eid_tuple,
                verified_at=self._clock(),
            )

        if not smoke_ok:
            checks.append("smoke_receipt:missing")
            limitations.append(
                "Verifying product pytest outcomes requires an accompanying 'smoke_passed' evidence receipt."
            )
            return VerificationRecord(
                verification_id=f"ver-{uuid.uuid4().hex}",
                run_id=run_id,
                verifier_id=self.verifier_id,
                verifier_revision=self.verifier_revision,
                status=VerificationStatus.FAILED,
                checks_performed=tuple(checks),
                limitations=tuple(limitations),
                evidence_ids=eid_tuple,
                verified_at=self._clock(),
            )

        # Ensure every pytest payload shares the same pinned source commit & image digest as smoke.
        pinned_pairs = {
            (str(p.get("source_commit")), str(p.get("image_digest")))
            for p in payloads
        }
        if len(pinned_pairs) != 1:
            checks.append("provenance_pin:mismatch_across_evidence")
            limitations.append(
                "Smoke and pytest evidence reference different source commits or image digests."
            )
            return VerificationRecord(
                verification_id=f"ver-{uuid.uuid4().hex}",
                run_id=run_id,
                verifier_id=self.verifier_id,
                verifier_revision=self.verifier_revision,
                status=VerificationStatus.FAILED,
                checks_performed=tuple(checks),
                limitations=tuple(limitations),
                evidence_ids=eid_tuple,
                verified_at=self._clock(),
            )
        checks.append("provenance_pin:matched")

        total_pos_passed = sum(int(p.get("positive_passed") or 0) for p in pytest_payloads)
        total_pos_failed = sum(int(p.get("positive_failed") or 0) for p in pytest_payloads)
        total_neg_passed = sum(int(p.get("negative_passed") or 0) for p in pytest_payloads)
        total_neg_failed = sum(int(p.get("negative_failed") or 0) for p in pytest_payloads)

        if total_pos_passed < 1 or total_pos_failed > 0:
            checks.append("outcome_state:baseline_failed")
            limitations.append(
                "Positive control did not pass cleanly across referenced pytest evidence."
            )
            return VerificationRecord(
                verification_id=f"ver-{uuid.uuid4().hex}",
                run_id=run_id,
                verifier_id=self.verifier_id,
                verifier_revision=self.verifier_revision,
                status=VerificationStatus.FAILED,
                checks_performed=tuple(checks),
                limitations=tuple(limitations),
                evidence_ids=eid_tuple,
                verified_at=self._clock(),
            )

        checks.append("positive_baseline:passed")

        if any(p.get("verdict") == "deviation_reproduced" for p in pytest_payloads) or total_neg_failed > 0:
            final_verdict = "deviation_reproduced"
        elif all(p.get("verdict") in {"hypothesis_falsified", "baseline_passed"} for p in pytest_payloads) and total_neg_passed >= 1:
            final_verdict = "hypothesis_falsified"
        elif all(p.get("verdict") == "baseline_passed" for p in pytest_payloads):
            final_verdict = "baseline_passed"
        else:
            checks.append("outcome_state:unclassified")
            return VerificationRecord(
                verification_id=f"ver-{uuid.uuid4().hex}",
                run_id=run_id,
                verifier_id=self.verifier_id,
                verifier_revision=self.verifier_revision,
                status=VerificationStatus.FAILED,
                checks_performed=tuple(checks),
                limitations=tuple(limitations),
                evidence_ids=eid_tuple,
                verified_at=self._clock(),
            )

        if normalized_claim is not None and normalized_claim != final_verdict:
            checks.append(f"claim_mismatch:expected={normalized_claim}:actual={final_verdict}")
            return VerificationRecord(
                verification_id=f"ver-{uuid.uuid4().hex}",
                run_id=run_id,
                verifier_id=self.verifier_id,
                verifier_revision=self.verifier_revision,
                status=VerificationStatus.FAILED,
                checks_performed=tuple(checks),
                limitations=tuple(limitations),
                evidence_ids=eid_tuple,
                verified_at=self._clock(),
            )

        checks.append(f"outcome_state:{final_verdict}")
        return VerificationRecord(
            verification_id=f"ver-{uuid.uuid4().hex}",
            run_id=run_id,
            verifier_id=self.verifier_id,
            verifier_revision=self.verifier_revision,
            status=VerificationStatus.PASSED,
            checks_performed=tuple(checks),
            limitations=tuple(limitations),
            evidence_ids=eid_tuple,
            verified_at=self._clock(),
        )


__all__ = [
    "DEFAULT_MAX_VDP_VERIFY_READ_BYTES",
    "VdpProductTestVerifier",
]
