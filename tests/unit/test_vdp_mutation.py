"""Unit tests for isolated bounded differential/mutation testing (PR-2B / ACC-F3-01..04)."""

from __future__ import annotations

import json
import socket

import pytest
from pydantic import ValidationError

from ctf_mcp.contracts import ContractViolationError
from ctf_mcp.vdp_boundary_map import BoundaryDiffFinding, DiffCategory, EntrypointKind
from ctf_mcp.vdp_mutation import (
    MAX_MUTATION_ITERATIONS,
    MAX_MUTATION_TARGET_FIELDS,
    MUTATION_SCHEMA,
    BoundedMutationRunner,
    EntrypointPair,
    LoopbackOnlyEgressGuard,
    MutationPolicySpec,
    OutboundEgressBlockedError,
    validate_loopback_only_value,
)


def _baseline_handler(payload: dict[str, object]) -> dict[str, object]:
    url = str(payload.get("repo_url") or "")
    normalized = url.split("#", 1)[0].strip()
    is_ok = (normalized.startswith("https://127.0.0.1/") or normalized.startswith("http://127.0.0.1/")) and (
        ".." not in normalized and "%2e" not in normalized.lower() and "\uff0e" not in normalized
    )
    return {"accepted": is_ok, "normalized": normalized}


def _vulnerable_candidate_handler(payload: dict[str, object]) -> dict[str, object]:
    url = str(payload.get("repo_url") or "")
    # Deliberate normalization gap: fails to strip fragment & fails to decode %2e / fullwidth dots before check
    is_ok = (url.startswith("https://127.0.0.1/") or url.startswith("http://127.0.0.1/")) and (".." not in url)
    return {"accepted": is_ok, "normalized": url}


def test_deterministic_seed_replay_and_preflight_caps() -> None:
    policy = MutationPolicySpec(
        seed=42,
        max_iterations=16,
        wall_time_cap_seconds=10,
        target_fields=("repo_url",),
        entrypoint_pair=EntrypointPair(
            baseline_entrypoint="api",
            candidate_entrypoint="webhook",
            feature_name="repo_url_normalization",
        ),
    )
    runner1 = BoundedMutationRunner(policy)
    runner2 = BoundedMutationRunner(policy)

    r1 = runner1.run(
        baseline_input={"repo_url": "https://127.0.0.1/org/repo.git"},
        baseline_fn=_baseline_handler,
        candidate_fn=_vulnerable_candidate_handler,
    )
    r2 = runner2.run(
        baseline_input={"repo_url": "https://127.0.0.1/org/repo.git"},
        baseline_fn=_baseline_handler,
        candidate_fn=_vulnerable_candidate_handler,
    )
    assert r1.schema_version == MUTATION_SCHEMA
    assert r1.verdict == "anomaly_observed"
    assert r1.finding_qualification == "separate_assessment_required_not_judged_from_pass_count"
    assert r1.positive_control_passed is True
    assert r1.iterations_executed == r2.iterations_executed
    assert r1.stop_reason == r2.stop_reason
    assert r1.minimal_repro_cases == r2.minimal_repro_cases

    # Preflight caps must reject >256 iterations, >3 target fields, external egress
    with pytest.raises((ValidationError, ValueError)):
        MutationPolicySpec(
            seed=42,
            max_iterations=MAX_MUTATION_ITERATIONS + 1,
            target_fields=("repo_url",),
            entrypoint_pair=policy.entrypoint_pair,
        )
    with pytest.raises((ValidationError, ValueError)):
        MutationPolicySpec(
            seed=42,
            target_fields=tuple(f"f{i}" for i in range(MAX_MUTATION_TARGET_FIELDS + 1)),
            entrypoint_pair=policy.entrypoint_pair,
        )
    with pytest.raises((ValidationError, ValueError)):
        MutationPolicySpec(
            seed=42,
            target_fields=("repo_url",),
            entrypoint_pair=policy.entrypoint_pair,
            allow_external_egress=True,  # type: ignore[arg-type]
        )


def test_minimal_repro_shrinker_paired_control_and_secret_redaction() -> None:
    def _long_sensitive_diverging_candidate(payload: dict[str, object]) -> dict[str, object]:
        val = str(payload.get("repo_url") or "")
        # Trigger divergence whenever "%2e" or "#" appears, echoing a dummy credential to verify redaction
        if "%2e" in val.lower() or "#" in val:
            return {
                "accepted": True,
                "echo": "https://user:SYNTHETIC_SECRET_SHOULD_REDACT@127.0.0.1/path token Bearer mysecret123456",
            }
        return _baseline_handler(payload)

    policy = MutationPolicySpec(
        seed=7,
        max_iterations=32,
        wall_time_cap_seconds=10,
        max_shrink_steps=24,
        target_fields=("repo_url",),
        entrypoint_pair=EntrypointPair(
            baseline_entrypoint="api",
            candidate_entrypoint="webhook",
        ),
        allowed_operators=("encoding_normalization", "whitespace_delimiter"),
    )
    runner = BoundedMutationRunner(policy)
    res = runner.run(
        baseline_input={"repo_url": "https://127.0.0.1/org/repo.git"},
        baseline_fn=_baseline_handler,
        candidate_fn=_long_sensitive_diverging_candidate,
    )
    assert res.verdict == "anomaly_observed"
    assert len(res.minimal_repro_cases) >= 1
    case = res.minimal_repro_cases[0]
    assert case.paired_control_input == "https://127.0.0.1/org/repo.git"
    assert len(case.minimal_input) > 0
    assert case.shrink_steps <= 24
    # Confirm shrinking produced a true differential reproducer shorter or equal
    dumped = json.dumps(res.to_marker_payload(), sort_keys=True)
    assert "SYNTHETIC_SECRET_SHOULD_REDACT" not in dumped
    assert "mysecret123456" not in dumped
    assert "separate_assessment_required_not_judged_from_pass_count" in dumped


def test_broken_positive_baseline_aborts_immediately() -> None:
    def _broken_candidate(payload: dict[str, object]) -> dict[str, object]:
        return {"accepted": False, "error": f"500 on {payload.get('repo_url')}"}

    policy = MutationPolicySpec(
        seed=99,
        max_iterations=16,
        target_fields=("repo_url",),
        entrypoint_pair=EntrypointPair(
            baseline_entrypoint="ui",
            candidate_entrypoint="api",
        ),
    )
    res = BoundedMutationRunner(policy).run(
        baseline_input={"repo_url": "https://127.0.0.1/org/repo.git"},
        baseline_fn=_baseline_handler,
        candidate_fn=_broken_candidate,
    )
    assert res.positive_control_passed is False
    assert res.stop_reason == "baseline_failed"
    assert res.verdict == "baseline_failed"
    assert res.iterations_executed == 0
    assert res.minimal_repro_cases == ()


def test_egress_guard_blocks_external_hosts_and_permits_loopback() -> None:
    with pytest.raises(OutboundEgressBlockedError):
        validate_loopback_only_value("https://remote.example.invalid/webhook")
    validate_loopback_only_value("https://127.0.0.1:8080/repo.git")
    validate_loopback_only_value("http://localhost:8000/hook")

    with LoopbackOnlyEgressGuard():
        # Non-loopback DNS or socket connect must fail closed immediately
        with pytest.raises(OutboundEgressBlockedError):
            socket.getaddrinfo("remote.example.invalid", 443)
        with pytest.raises(OutboundEgressBlockedError):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect(("93.184.216.34", 80))
            finally:
                sock.close()

    # Inside runner, baseline attempting outbound socket aborts as egress_blocked
    def _outbound_candidate(payload: dict[str, object]) -> dict[str, object]:
        del payload
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect(("93.184.216.34", 443))
        finally:
            s.close()
        return {"accepted": True}

    policy = MutationPolicySpec(
        seed=5,
        max_iterations=8,
        target_fields=("repo_url",),
        entrypoint_pair=EntrypointPair(baseline_entrypoint="api", candidate_entrypoint="webhook"),
    )
    res_out = BoundedMutationRunner(policy).run(
        baseline_input={"repo_url": "https://127.0.0.1/org/repo.git"},
        baseline_fn=_baseline_handler,
        candidate_fn=_outbound_candidate,
    )
    assert res_out.egress_violation_detected is True
    assert res_out.stop_reason == "egress_blocked"
    assert res_out.verdict == "environment_failure"

    # Non-loopback baseline URL also blocked cleanly before running
    res_url = BoundedMutationRunner(policy).run(
        baseline_input={"repo_url": "https://remote.example.invalid/org/repo.git"},
        baseline_fn=_baseline_handler,
        candidate_fn=_baseline_handler,
    )
    assert res_url.egress_violation_detected is True
    assert res_url.stop_reason == "egress_blocked"
    assert res_url.verdict == "environment_failure"


def test_boundary_map_candidate_handoff_creates_bounded_policy() -> None:
    finding = BoundaryDiffFinding(
        finding_id="BM-SYNTH-01",
        category=DiffCategory.INPUT_NORMALIZATION_MISMATCH,
        baseline_entrypoint_id="ep-api",
        compared_entrypoint_id="ep-webhook",
        baseline_kind=EntrypointKind.API,
        compared_kind=EntrypointKind.WEBHOOK,
        summary="Webhook normalization differs from API handler.",
        evidence_locations=("app/views.py:10", "app/webhooks.py:22"),
    )
    policy = MutationPolicySpec.from_boundary_map_candidate(
        finding,
        seed=123,
        target_fields=("repo_url",),
        max_iterations=12,
    )
    assert policy.entrypoint_pair.baseline_entrypoint == "api"
    assert policy.entrypoint_pair.candidate_entrypoint == "webhook"
    assert policy.entrypoint_pair.feature_name == "BM-SYNTH-01"
    assert policy.target_fields == ("repo_url",)
    assert policy.allow_external_egress is False
