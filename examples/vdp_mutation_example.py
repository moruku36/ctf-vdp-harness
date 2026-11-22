"""Synthetic runnable example demonstrating isolated bounded differential/mutation testing."""

from __future__ import annotations

import json

from ctf_mcp.vdp_mutation import (
    BoundedMutationRunner,
    EntrypointPair,
    MutationPolicySpec,
)


def api_endpoint(payload: dict[str, object]) -> dict[str, object]:
    raw_url = str(payload.get("repo_url") or "")
    normalized = raw_url.split("#", 1)[0].strip()
    allowed = normalized.startswith("https://127.0.0.1/") or normalized.startswith("http://127.0.0.1/")
    return {"accepted": allowed and ".." not in normalized, "normalized_url": normalized}


def webhook_endpoint(payload: dict[str, object]) -> dict[str, object]:
    raw_url = str(payload.get("repo_url") or "")
    # Simulated normalization mismatch: fails to decode %2e%2e before path check
    allowed = raw_url.startswith("https://127.0.0.1/") or raw_url.startswith("http://127.0.0.1/")
    return {"accepted": allowed, "normalized_url": raw_url}


def main() -> None:
    policy = MutationPolicySpec(
        seed=42,
        max_iterations=24,
        wall_time_cap_seconds=15,
        target_fields=("repo_url",),
        entrypoint_pair=EntrypointPair(
            baseline_entrypoint="api",
            candidate_entrypoint="webhook",
            feature_name="repo_url_normalization",
        ),
    )
    runner = BoundedMutationRunner(policy)
    result = runner.run(
        baseline_input={"repo_url": "https://127.0.0.1/org/repo.git"},
        baseline_fn=api_endpoint,
        candidate_fn=webhook_endpoint,
    )
    print(json.dumps(result.to_marker_payload(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
