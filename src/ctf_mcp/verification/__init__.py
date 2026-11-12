"""Layer 2 verification subsystem: registered local verifiers and close checks."""

from __future__ import annotations

from ctf_mcp.verification.cleanup_check import (
    CloseIntegrityChecker,
    CloseIntegrityReport,
    assert_close_ready,
    evaluate_close_integrity,
    evaluate_close_integrity_in_tx,
)
from ctf_mcp.verification.ctf_local import (
    ExpectedChallengeSpec,
    LocalCtfVerifier,
    load_verifications_for_run,
    save_verification_record,
    save_verification_record_in_tx,
)
from ctf_mcp.verification.registry import VerifierInfo, VerifierRegistry

__all__ = [
    "CloseIntegrityChecker",
    "CloseIntegrityReport",
    "ExpectedChallengeSpec",
    "LocalCtfVerifier",
    "VerifierInfo",
    "VerifierRegistry",
    "assert_close_ready",
    "evaluate_close_integrity",
    "evaluate_close_integrity_in_tx",
    "load_verifications_for_run",
    "save_verification_record",
    "save_verification_record_in_tx",
]
