"""Registry for approved deterministic local verifiers (docs/08 & docs/11)."""

from __future__ import annotations

import threading
from collections.abc import Sequence

from pydantic import Field

from ctf_mcp.contracts import (
    CapabilityDeniedError,
    ContractViolationError,
    StrictModel,
    VerificationRecord,
    VerifierPort,
)


class VerifierInfo(StrictModel):
    """Public metadata for a registered local verifier."""

    verifier_id: str = Field(min_length=1)
    verifier_revision: str = Field(min_length=1)


class VerifierRegistry:
    """In-memory registry enforcing explicit registration of local verifiers.

    Unregistered verifier IDs are rejected fail-closed with ``CapabilityDeniedError``
    matching ``AcceptanceConfig.require_registered_verifier = True``.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._verifiers: dict[str, VerifierPort] = {}

    def register(self, verifier: VerifierPort, *, replace: bool = False) -> None:
        """Register a ``VerifierPort`` implementation under its ``verifier_id``."""
        if not isinstance(verifier, VerifierPort):
            raise ContractViolationError(
                "Verifier must implement the VerifierPort protocol."
            )

        verifier_id = getattr(verifier, "verifier_id", "")
        verifier_revision = getattr(verifier, "verifier_revision", "")
        if not isinstance(verifier_id, str) or not verifier_id.strip():
            raise ContractViolationError("Verifier must expose a non-empty verifier_id.")
        if not isinstance(verifier_revision, str) or not verifier_revision.strip():
            raise ContractViolationError(
                "Verifier must expose a non-empty verifier_revision."
            )
        if verifier_id != verifier_id.strip() or verifier_revision != verifier_revision.strip():
            raise ContractViolationError(
                "verifier_id and verifier_revision must not have leading/trailing whitespace."
            )

        with self._lock:
            if verifier_id in self._verifiers and not replace:
                raise ContractViolationError(
                    f"Verifier {verifier_id!r} is already registered.",
                    details={"verifier_id": verifier_id},
                )
            self._verifiers[verifier_id] = verifier

    def unregister(self, verifier_id: str) -> None:
        """Remove a registered verifier by ID."""
        with self._lock:
            if verifier_id not in self._verifiers:
                raise CapabilityDeniedError(
                    f"Verifier {verifier_id!r} is not registered.",
                    details={"verifier_id": verifier_id},
                )
            del self._verifiers[verifier_id]

    def has(self, verifier_id: str) -> bool:
        """Return True if ``verifier_id`` is registered."""
        with self._lock:
            return verifier_id in self._verifiers

    def __contains__(self, verifier_id: object) -> bool:
        if not isinstance(verifier_id, str):
            return False
        return self.has(verifier_id)

    def get(self, verifier_id: str) -> VerifierPort:
        """Return the registered verifier or raise ``CapabilityDeniedError``."""
        if not isinstance(verifier_id, str) or not verifier_id.strip():
            raise CapabilityDeniedError(
                "Verifier ID must be a non-empty string.",
                details={"verifier_id": verifier_id},
            )
        with self._lock:
            verifier = self._verifiers.get(verifier_id)
        if verifier is None:
            raise CapabilityDeniedError(
                f"Verifier {verifier_id!r} is not registered.",
                details={"verifier_id": verifier_id},
            )
        return verifier

    def list_verifiers(self) -> list[VerifierInfo]:
        """List registered verifiers sorted by ``verifier_id``."""
        with self._lock:
            items = sorted(self._verifiers.items(), key=lambda kv: kv[0])
            return [
                VerifierInfo(
                    verifier_id=vid,
                    verifier_revision=v.verifier_revision,
                )
                for vid, v in items
            ]

    def verify(
        self,
        verifier_id: str,
        *,
        run_id: str,
        evidence_ids: Sequence[str] = (),
        claim: str | None = None,
    ) -> VerificationRecord:
        """Execute a registered verifier and validate the returned record contract."""
        verifier = self.get(verifier_id)
        record = verifier.verify(
            run_id=run_id,
            evidence_ids=tuple(evidence_ids),
            claim=claim,
        )
        if not isinstance(record, VerificationRecord):
            raise ContractViolationError(
                "Verifier did not return a VerificationRecord instance.",
                details={"verifier_id": verifier_id},
            )
        if record.verifier_id != verifier.verifier_id:
            raise ContractViolationError(
                "VerificationRecord verifier_id mismatch.",
                details={
                    "expected": verifier.verifier_id,
                    "actual": record.verifier_id,
                },
            )
        if record.verifier_revision != verifier.verifier_revision:
            raise ContractViolationError(
                "VerificationRecord verifier_revision mismatch.",
                details={
                    "expected": verifier.verifier_revision,
                    "actual": record.verifier_revision,
                },
            )
        if record.run_id != run_id:
            raise ContractViolationError(
                "VerificationRecord run_id mismatch.",
                details={"expected": run_id, "actual": record.run_id},
            )
        return record


__all__ = [
    "VerifierInfo",
    "VerifierRegistry",
]
