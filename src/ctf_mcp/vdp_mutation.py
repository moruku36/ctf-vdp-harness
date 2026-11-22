"""Bounded, deterministic differential & mutation testing engine for VDP overlays.

Executes bounded single- or small-tuple input mutations against paired entrypoints
(e.g., baseline UI/API vs candidate webhook/async handler) inside a ``--network=none``
isolated environment while enforcing:

- Explicit allowlisting of target fields (``1..3`` fields) and entrypoint pairs.
- Deterministic RNG replay from an explicit ``uint64`` seed.
- Hard caps on iterations (``<= 256``), wall time (``<= 300s``), per-iteration
  timeout (``<= 2000ms``), shrink steps (``<= 64``), and redacted output size.
- Paired ``positive_control`` gating: broken baselines abort immediately as
  ``baseline_failed`` rather than masquerading as defense success or anomalies.
- Fail-closed outbound egress blocking: both URL inspection and an in-process
  ``LoopbackOnlyEgressGuard`` permit only loopback (``127.0.0.1`` / ``::1`` /
  ``localhost``) targets and reject external hosts/DNS as ``environment_failure``.
- Strict separation between observed divergence (``anomaly_observed``) and
  vulnerability qualification (``separate_assessment_required_not_judged_from_pass_count``).
"""

from __future__ import annotations

import ipaddress
import random
import re
import socket
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import Field, model_validator

from ctf_mcp.contracts import ContractViolationError, StrictModel
from ctf_mcp.vdp_fixtures.local_git_http import (
    emit_vdp_evidence_marker,
    redact_sensitive_text,
    redact_structure,
)

MUTATION_SCHEMA = "vdp-bounded-mutation/1"
MAX_MUTATION_TARGET_FIELDS = 3
MAX_MUTATION_ITERATIONS = 256
MAX_MUTATION_WALL_TIME_SECONDS = 300
MAX_PER_ITERATION_TIMEOUT_MS = 2000
MAX_SHRINK_STEPS = 64
MAX_ANOMALIES_RECORDED = 3
MAX_MINIMAL_INPUT_CHARS = 1024
MAX_MUTATION_OUTPUT_BYTES = 32_768

MUTATION_OPERATORS: tuple[
    Literal[
        "boundary_length",
        "encoding_normalization",
        "scheme_or_path_variant",
        "empty_null_type",
        "whitespace_delimiter",
    ],
    ...,
] = (
    "boundary_length",
    "encoding_normalization",
    "scheme_or_path_variant",
    "empty_null_type",
    "whitespace_delimiter",
)
VALID_ENTRYPOINT_KINDS: tuple[str, ...] = ("ui", "api", "webhook", "async")

_FIELD_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
_URL_SCHEME_TOKEN_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"'<>]+)")
_SECRET_SCRUB_RE = re.compile(
    r"(?:"
    r"SYNTHETIC_SECRET(?:_[A-Za-z0-9._:/=+-]+)?|"
    r"CTF_SENSITIVE_MARKER(?:[:_=-][A-Za-z0-9._:/=+-]+)?|"
    r"\b(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{16,}|gho_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16})\b|"
    r"(?:flag|ctf|vdp)\{[^{}\r\n]+\}|"
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
    r")",
    re.IGNORECASE,
)


class OutboundEgressBlockedError(ContractViolationError):
    """Raised fail-closed when a non-loopback host, URL, socket, or DNS target is attempted."""


def _redact_bounded_text(value: Any, *, max_len: int = MAX_MINIMAL_INPUT_CHARS) -> str:
    cleaned = redact_sensitive_text(str(value))
    cleaned = _SECRET_SCRUB_RE.sub("[REDACTED]", cleaned)
    if len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 3] + "..."
    return cleaned


def _is_loopback_host(host: str) -> bool:
    clean = str(host).strip().lower().strip("[]")
    if not clean:
        return True
    if clean == "localhost":
        return True
    try:
        ip_obj = ipaddress.ip_address(clean)
        return bool(ip_obj.is_loopback)
    except ValueError:
        return False


def validate_loopback_only_value(value: Any, *, field_name: str = "input") -> None:
    """Reject any URL/network reference targeting a non-loopback host."""
    if isinstance(value, str):
        for match in _URL_SCHEME_TOKEN_RE.findall(value):
            parsed = urlsplit(match)
            host = parsed.hostname or ""
            if parsed.scheme.lower() in {"http", "https", "ws", "wss", "ftp", "ssh", "git"}:
                if not host or not _is_loopback_host(host):
                    raise OutboundEgressBlockedError(
                        f"Outbound non-loopback URL blocked in {field_name!r}: host={host!r}.",
                        code="network_isolation_violated",
                    )
    elif isinstance(value, Mapping):
        for k, v in value.items():
            validate_loopback_only_value(v, field_name=f"{field_name}.{k}")
    elif isinstance(value, (list, tuple)):
        for idx, item in enumerate(value):
            validate_loopback_only_value(item, field_name=f"{field_name}[{idx}]")


def _extract_socket_target_host(address: Any) -> str | None:
    if isinstance(address, tuple) and len(address) >= 2 and isinstance(address[0], str):
        return address[0]
    return None


class LoopbackOnlyEgressGuard:
    """Reentrant context manager blocking non-loopback socket/DNS egress inside tests."""

    _lock = threading.Lock()
    _depth = 0
    _orig_connect: Any = None
    _orig_connect_ex: Any = None
    _orig_create_connection: Any = None
    _orig_getaddrinfo: Any = None

    def __enter__(self) -> LoopbackOnlyEgressGuard:
        with self._lock:
            if self.__class__._depth == 0:
                orig_connect = socket.socket.connect
                orig_connect_ex = socket.socket.connect_ex
                orig_create_conn = socket.create_connection
                orig_getaddrinfo = socket.getaddrinfo
                self.__class__._orig_connect = orig_connect
                self.__class__._orig_connect_ex = orig_connect_ex
                self.__class__._orig_create_connection = orig_create_conn
                self.__class__._orig_getaddrinfo = orig_getaddrinfo

                def _guarded_connect(sock: socket.socket, address: Any) -> Any:
                    host = _extract_socket_target_host(address)
                    if host is not None and not _is_loopback_host(host):
                        raise OutboundEgressBlockedError(
                            f"Outbound socket connect blocked to non-loopback host {host!r}.",
                            code="network_isolation_violated",
                        )
                    return orig_connect(sock, address)

                def _guarded_connect_ex(sock: socket.socket, address: Any) -> int:
                    host = _extract_socket_target_host(address)
                    if host is not None and not _is_loopback_host(host):
                        raise OutboundEgressBlockedError(
                            f"Outbound socket connect_ex blocked to non-loopback host {host!r}.",
                            code="network_isolation_violated",
                        )
                    return orig_connect_ex(sock, address)

                def _guarded_create_connection(address: Any, *args: Any, **kwargs: Any) -> Any:
                    host = _extract_socket_target_host(address)
                    if host is not None and not _is_loopback_host(host):
                        raise OutboundEgressBlockedError(
                            f"Outbound create_connection blocked to non-loopback host {host!r}.",
                            code="network_isolation_violated",
                        )
                    return orig_create_conn(address, *args, **kwargs)

                def _guarded_getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
                    if isinstance(host, (str, bytes)):
                        host_str = host.decode("utf-8", errors="replace") if isinstance(host, bytes) else host
                        if host_str and not _is_loopback_host(host_str):
                            raise OutboundEgressBlockedError(
                                f"Outbound DNS lookup blocked for non-loopback host {host_str!r}.",
                                code="network_isolation_violated",
                            )
                    return orig_getaddrinfo(host, *args, **kwargs)

                socket.socket.connect = _guarded_connect  # type: ignore[method-assign]
                socket.socket.connect_ex = _guarded_connect_ex  # type: ignore[method-assign]
                socket.create_connection = _guarded_create_connection  # type: ignore[assignment]
                socket.getaddrinfo = _guarded_getaddrinfo  # type: ignore[assignment]
            self.__class__._depth += 1
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        del exc_type, exc, tb
        with self._lock:
            self.__class__._depth = max(0, self.__class__._depth - 1)
            if self.__class__._depth == 0:
                if self.__class__._orig_connect is not None:
                    socket.socket.connect = self.__class__._orig_connect  # type: ignore[method-assign]
                if self.__class__._orig_connect_ex is not None:
                    socket.socket.connect_ex = self.__class__._orig_connect_ex  # type: ignore[method-assign]
                if self.__class__._orig_create_connection is not None:
                    socket.create_connection = self.__class__._orig_create_connection  # type: ignore[assignment]
                if self.__class__._orig_getaddrinfo is not None:
                    socket.getaddrinfo = self.__class__._orig_getaddrinfo  # type: ignore[assignment]


class EntrypointPair(StrictModel):
    """Explicit pair of baseline (reference) vs candidate entrypoints for differential checks."""

    baseline_entrypoint: Literal["ui", "api", "webhook", "async"]
    candidate_entrypoint: Literal["ui", "api", "webhook", "async"]
    feature_name: str = Field(default="differential_check", min_length=1, max_length=120)


class MutationPolicySpec(StrictModel):
    """Fail-closed policy controlling isolated bounded differential/mutation testing."""

    seed: int = Field(ge=0, le=2**63 - 1)
    max_iterations: int = Field(default=32, ge=1, le=MAX_MUTATION_ITERATIONS)
    wall_time_cap_seconds: int = Field(default=60, ge=5, le=MAX_MUTATION_WALL_TIME_SECONDS)
    per_iteration_timeout_ms: int = Field(default=500, ge=10, le=MAX_PER_ITERATION_TIMEOUT_MS)
    max_shrink_steps: int = Field(default=24, ge=0, le=MAX_SHRINK_STEPS)
    max_anomalies: int = Field(default=MAX_ANOMALIES_RECORDED, ge=1, le=MAX_ANOMALIES_RECORDED)
    target_fields: tuple[str, ...] = Field(min_length=1, max_length=MAX_MUTATION_TARGET_FIELDS)
    entrypoint_pair: EntrypointPair
    allowed_operators: tuple[
        Literal[
            "boundary_length",
            "encoding_normalization",
            "scheme_or_path_variant",
            "empty_null_type",
            "whitespace_delimiter",
        ],
        ...,
    ] = Field(default=MUTATION_OPERATORS, min_length=1)
    allow_loopback_only: Literal[True] = True
    allow_external_egress: Literal[False] = False
    max_output_bytes: int = Field(default=MAX_MUTATION_OUTPUT_BYTES, ge=1024, le=262_144)

    @model_validator(mode="after")
    def _validate_fields(self) -> MutationPolicySpec:
        cleaned: list[str] = []
        for idx, raw_f in enumerate(self.target_fields):
            f_clean = str(raw_f).strip()
            if not _FIELD_NAME_RE.fullmatch(f_clean):
                raise ContractViolationError(
                    f"target_fields[{idx}] ({raw_f!r}) must match [A-Za-z_][A-Za-z0-9_.-]{{0,63}}."
                )
            if f_clean not in cleaned:
                cleaned.append(f_clean)
        if not cleaned or len(cleaned) > MAX_MUTATION_TARGET_FIELDS:
            raise ContractViolationError(
                f"target_fields must specify 1..{MAX_MUTATION_TARGET_FIELDS} unique field names."
            )
        dedup_ops = tuple(dict.fromkeys(self.allowed_operators))
        object.__setattr__(self, "target_fields", tuple(cleaned))
        object.__setattr__(self, "allowed_operators", dedup_ops)
        return self

    @classmethod
    def from_boundary_map_candidate(
        cls,
        candidate: Any,
        *,
        seed: int,
        target_fields: Sequence[str],
        feature_name: str | None = None,
        max_iterations: int = 32,
        wall_time_cap_seconds: int = 60,
        max_shrink_steps: int = 24,
    ) -> MutationPolicySpec:
        """Build a bounded ``MutationPolicySpec`` from a Feature-1 ``vdp-boundary-map`` candidate."""
        if isinstance(candidate, Mapping):
            base_kind = candidate.get("baseline_kind") or "api"
            comp_kind = candidate.get("compared_kind") or candidate.get("kind") or "webhook"
            feat = feature_name or str(candidate.get("finding_id") or candidate.get("feature") or "boundary_candidate")
        else:
            raw_base = getattr(candidate, "baseline_kind", None) or "api"
            raw_comp = getattr(candidate, "compared_kind", None) or getattr(candidate, "kind", None) or "webhook"
            base_kind = raw_base.value if hasattr(raw_base, "value") else str(raw_base)
            comp_kind = raw_comp.value if hasattr(raw_comp, "value") else str(raw_comp)
            feat = feature_name or str(getattr(candidate, "finding_id", "boundary_candidate"))

        return cls(
            seed=seed,
            max_iterations=max_iterations,
            wall_time_cap_seconds=wall_time_cap_seconds,
            max_shrink_steps=max_shrink_steps,
            target_fields=tuple(str(f) for f in target_fields),
            entrypoint_pair=EntrypointPair(
                baseline_entrypoint=str(base_kind).lower(),  # type: ignore[arg-type]
                candidate_entrypoint=str(comp_kind).lower(),  # type: ignore[arg-type]
                feature_name=feat[:120],
            ),
        )


class MinimalReproCase(StrictModel):
    """Redacted, shrunk minimal reproducing mutation input paired with its positive control."""

    field_name: str = Field(min_length=1, max_length=64)
    operator: Literal[
        "boundary_length",
        "encoding_normalization",
        "scheme_or_path_variant",
        "empty_null_type",
        "whitespace_delimiter",
    ]
    minimal_input: str = Field(max_length=MAX_MINIMAL_INPUT_CHARS)
    paired_control_input: str = Field(max_length=MAX_MINIMAL_INPUT_CHARS)
    candidate_outcome: str = Field(min_length=1, max_length=400)
    control_outcome: str = Field(min_length=1, max_length=400)
    differential_summary: str = Field(min_length=1, max_length=400)
    shrink_steps: int = Field(ge=0, le=MAX_SHRINK_STEPS)


class MutationRunResult(StrictModel):
    """Structured result emitted by ``BoundedMutationRunner``."""

    schema_version: Literal["vdp-bounded-mutation/1"] = MUTATION_SCHEMA
    seed: int
    target_fields: tuple[str, ...]
    entrypoint_pair: EntrypointPair
    iterations_executed: int = Field(ge=0)
    wall_ms: int = Field(ge=0)
    stop_reason: Literal[
        "completed",
        "anomaly_found",
        "wall_time_cap",
        "baseline_failed",
        "egress_blocked",
    ]
    positive_control_passed: bool
    egress_violation_detected: bool
    verdict: Literal[
        "hypothesis_falsified",
        "anomaly_observed",
        "baseline_failed",
        "environment_failure",
        "inconclusive",
    ]
    finding_qualification: Literal[
        "separate_assessment_required_not_judged_from_pass_count"
    ] = "separate_assessment_required_not_judged_from_pass_count"
    minimal_repro_cases: tuple[MinimalReproCase, ...] = ()
    output_truncated: bool = False
    error_detail: str | None = Field(default=None, max_length=400)

    def to_marker_payload(self) -> dict[str, Any]:
        """Serialize a redacted ``VDP_EVIDENCE_MARKER`` payload with ``mutation_summary``."""
        summary = self.model_dump(mode="json")
        confirmed: list[str] = []
        unverified: list[str] = ["bounded_mutation_scope_not_exhaustive"]
        if self.positive_control_passed:
            confirmed.append("mutation_positive_control_passed")
        if self.egress_violation_detected:
            unverified.append("network_isolation:violated")
        if self.verdict == "anomaly_observed":
            confirmed.append("differential_divergence_reproduced_with_paired_control")
            unverified.append("vulnerability_eligibility_and_impact_require_separate_assessment")
        elif self.verdict == "hypothesis_falsified":
            confirmed.append("differential_mutation_no_divergence_within_bounds")
        return redact_structure(
            {
                "mutation_summary": summary,
                "confirmed_conditions": confirmed,
                "unverified_conditions": unverified,
            }
        )

    def emit_marker(self) -> dict[str, Any]:
        """Print a redacted single-line ``VDP_EVIDENCE_MARKER`` JSON record to stdout."""
        payload = self.to_marker_payload()
        emit_vdp_evidence_marker(payload)
        return payload


@dataclass(frozen=True)
class _TargetInvocationError(Exception):
    message: str


def _default_divergence_predicate(baseline_out: Any, candidate_out: Any) -> bool:
    return baseline_out != candidate_out


class BoundedMutationRunner:
    """Execute deterministic, loopback-only bounded differential/mutation tests with shrinking."""

    def __init__(self, policy: MutationPolicySpec) -> None:
        self.policy = MutationPolicySpec.model_validate(policy)

    @staticmethod
    def _mutate_value(
        *,
        base_value: Any,
        operator: str,
        rng: random.Random,
    ) -> Any:
        base_str = "" if base_value is None else str(base_value)
        is_loopback_url = _is_loopback_host(urlsplit(base_str).hostname or "") and "://" in base_str

        if operator == "boundary_length":
            sizes = (1, 16, 64, 128, 255)
            pad_len = rng.choice(sizes)
            ch = rng.choice(("a", "x", "0"))
            return base_str + ("/" + ch * pad_len if base_str else ch * pad_len)

        if operator == "encoding_normalization":
            variants = (
                f"{base_str}%2e%2e%2fadmin",
                f"{base_str}%2f..%2fadmin",
                f"{base_str}\uff0e\uff0e/check",
                base_str.upper() if base_str else "ENCODED",
                f"%2e{base_str}" if base_str else "%2e%2e",
            )
            return rng.choice(variants)

        if operator == "scheme_or_path_variant":
            if is_loopback_url:
                parsed = urlsplit(base_str)
                netloc = parsed.netloc or "127.0.0.1"
                base_path = parsed.path or "/repo.git"
                variants = (
                    f"{parsed.scheme}://{netloc}//..{base_path}",
                    f"{parsed.scheme}://{netloc}{base_path}/./admin",
                    f"{parsed.scheme}://{netloc}{base_path.upper()}",
                    f"http://{netloc}{base_path}?variant=1",
                )
            else:
                variants = (
                    f"//{base_str.lstrip('/')}" if base_str else "//internal",
                    f"{base_str}/../private",
                    f"{base_str}/./check",
                    f"{base_str};param=1",
                )
            return rng.choice(variants)

        if operator == "empty_null_type":
            return rng.choice(("", "null", "None", "0", "[]"))

        # whitespace_delimiter
        variants = (
            f" {base_str} ",
            f"{base_str}\t",
            f"{base_str}\n",
            f"{base_str}#frag",
            f"{base_str},extra",
        )
        return rng.choice(variants)

    @staticmethod
    def _candidate_shrinks(val: Any) -> list[Any]:
        if not isinstance(val, str):
            return ["", str(val)] if val is not None else [""]
        if len(val) <= 1:
            return []
        proposals: list[Any] = [""]
        mid = len(val) // 2
        if mid > 0:
            proposals.append(val[:mid])
            proposals.append(val[mid:])
        if len(val) > 2:
            proposals.append(val[:-1])
            proposals.append(val[1:])
        # Dedup preserving order
        seen: list[Any] = []
        for item in proposals:
            if item != val and item not in seen:
                seen.append(item)
        return seen

    def _shrink_mutated_value(
        self,
        *,
        baseline_payload: dict[str, Any],
        field_name: str,
        failing_value: Any,
        baseline_fn: Callable[[Mapping[str, Any]], Any],
        candidate_fn: Callable[[Mapping[str, Any]], Any],
        divergence_predicate: Callable[[Any, Any], bool],
        deadline_mono: float,
    ) -> tuple[Any, Any, Any, int]:
        """Deterministically delta-shrink ``failing_value`` within ``max_shrink_steps``."""
        best_val = failing_value
        best_ctrl_out: Any = None
        best_cand_out: Any = None
        steps = 0
        for _ in range(self.policy.max_shrink_steps):
            if time.monotonic() >= deadline_mono:
                break
            improved = False
            for candidate_val in self._candidate_shrinks(best_val):
                if steps >= self.policy.max_shrink_steps or time.monotonic() >= deadline_mono:
                    break
                steps += 1
                validate_loopback_only_value(candidate_val, field_name=field_name)
                trial_payload = dict(baseline_payload)
                trial_payload[field_name] = candidate_val
                ctrl_out = baseline_fn(dict(trial_payload))
                cand_out = candidate_fn(dict(trial_payload))
                if divergence_predicate(ctrl_out, cand_out):
                    best_val = candidate_val
                    best_ctrl_out = ctrl_out
                    best_cand_out = cand_out
                    improved = True
                    break
            if not improved:
                break
        if best_cand_out is None or best_ctrl_out is None:
            trial_payload = dict(baseline_payload)
            trial_payload[field_name] = best_val
            best_ctrl_out = baseline_fn(dict(trial_payload))
            best_cand_out = candidate_fn(dict(trial_payload))
        return best_val, best_ctrl_out, best_cand_out, steps

    def run(
        self,
        *,
        baseline_input: Mapping[str, Any],
        baseline_fn: Callable[[Mapping[str, Any]], Any],
        candidate_fn: Callable[[Mapping[str, Any]], Any],
        baseline_validator: Callable[[Any, Any], bool] | None = None,
        divergence_predicate: Callable[[Any, Any], bool] | None = None,
    ) -> MutationRunResult:
        """Run positive baseline check, bounded mutation loop, and shrinker under egress guard."""
        start_mono = time.monotonic()
        deadline_mono = start_mono + float(self.policy.wall_time_cap_seconds)
        diff_fn = divergence_predicate or _default_divergence_predicate
        base_payload = dict(baseline_input)

        # Ensure every target field exists or starts cleanly
        try:
            validate_loopback_only_value(base_payload, field_name="baseline_input")
        except OutboundEgressBlockedError as exc:
            return MutationRunResult(
                seed=self.policy.seed,
                target_fields=self.policy.target_fields,
                entrypoint_pair=self.policy.entrypoint_pair,
                iterations_executed=0,
                wall_ms=int((time.monotonic() - start_mono) * 1000),
                stop_reason="egress_blocked",
                positive_control_passed=False,
                egress_violation_detected=True,
                verdict="environment_failure",
                minimal_repro_cases=(),
                error_detail=_redact_bounded_text(str(exc), max_len=400),
            )

        # Step A: Mandatory Positive Control Gate
        try:
            with LoopbackOnlyEgressGuard():
                base_ctrl_out = baseline_fn(dict(base_payload))
                cand_ctrl_out = candidate_fn(dict(base_payload))
        except OutboundEgressBlockedError as exc:
            return MutationRunResult(
                seed=self.policy.seed,
                target_fields=self.policy.target_fields,
                entrypoint_pair=self.policy.entrypoint_pair,
                iterations_executed=0,
                wall_ms=int((time.monotonic() - start_mono) * 1000),
                stop_reason="egress_blocked",
                positive_control_passed=False,
                egress_violation_detected=True,
                verdict="environment_failure",
                minimal_repro_cases=(),
                error_detail=_redact_bounded_text(str(exc), max_len=400),
            )
        except Exception as exc:
            return MutationRunResult(
                seed=self.policy.seed,
                target_fields=self.policy.target_fields,
                entrypoint_pair=self.policy.entrypoint_pair,
                iterations_executed=0,
                wall_ms=int((time.monotonic() - start_mono) * 1000),
                stop_reason="baseline_failed",
                positive_control_passed=False,
                egress_violation_detected=False,
                verdict="baseline_failed",
                minimal_repro_cases=(),
                error_detail=_redact_bounded_text(f"Baseline execution error: {exc}", max_len=400),
            )

        pos_ok = (
            bool(baseline_validator(base_ctrl_out, cand_ctrl_out))
            if baseline_validator is not None
            else (base_ctrl_out == cand_ctrl_out)
        )
        if not pos_ok:
            return MutationRunResult(
                seed=self.policy.seed,
                target_fields=self.policy.target_fields,
                entrypoint_pair=self.policy.entrypoint_pair,
                iterations_executed=0,
                wall_ms=int((time.monotonic() - start_mono) * 1000),
                stop_reason="baseline_failed",
                positive_control_passed=False,
                egress_violation_detected=False,
                verdict="baseline_failed",
                minimal_repro_cases=(),
                error_detail="Paired positive control did not satisfy baseline invariant.",
            )

        # Step B + C: Deterministic Bounded Differential Loop & Shrinker
        rng = random.Random(self.policy.seed)
        iterations_executed = 0
        stop_reason: Literal[
            "completed",
            "anomaly_found",
            "wall_time_cap",
            "baseline_failed",
            "egress_blocked",
        ] = "completed"
        seen_classes: set[tuple[str, str]] = set()
        repro_cases: list[MinimalReproCase] = []
        egress_err_msg: str | None = None
        setup_err_msg: str | None = None

        try:
            with LoopbackOnlyEgressGuard():
                for _ in range(self.policy.max_iterations):
                    if time.monotonic() >= deadline_mono:
                        stop_reason = "wall_time_cap"
                        break
                    field_name = rng.choice(self.policy.target_fields)
                    operator = rng.choice(self.policy.allowed_operators)
                    orig_val = base_payload.get(field_name, "")
                    mutated_val = self._mutate_value(
                        base_value=orig_val,
                        operator=operator,
                        rng=rng,
                    )
                    validate_loopback_only_value(mutated_val, field_name=field_name)

                    iterations_executed += 1
                    mutated_payload = dict(base_payload)
                    mutated_payload[field_name] = mutated_val

                    iter_start = time.monotonic()
                    ctrl_out = baseline_fn(dict(mutated_payload))
                    cand_out = candidate_fn(dict(mutated_payload))
                    iter_ms = (time.monotonic() - iter_start) * 1000.0
                    if iter_ms > float(self.policy.per_iteration_timeout_ms):
                        # Soft stop after bounded per-iteration budget overrun
                        stop_reason = "wall_time_cap"
                        break

                    if diff_fn(ctrl_out, cand_out) and (field_name, operator) not in seen_classes:
                        min_val, min_ctrl_out, min_cand_out, shrink_steps = self._shrink_mutated_value(
                            baseline_payload=base_payload,
                            field_name=field_name,
                            failing_value=mutated_val,
                            baseline_fn=baseline_fn,
                            candidate_fn=candidate_fn,
                            divergence_predicate=diff_fn,
                            deadline_mono=deadline_mono,
                        )
                        seen_classes.add((field_name, operator))
                        repro_cases.append(
                            MinimalReproCase(
                                field_name=field_name,
                                operator=operator,
                                minimal_input=_redact_bounded_text(min_val),
                                paired_control_input=_redact_bounded_text(orig_val),
                                candidate_outcome=_redact_bounded_text(min_cand_out, max_len=400),
                                control_outcome=_redact_bounded_text(min_ctrl_out, max_len=400),
                                differential_summary=_redact_bounded_text(
                                    f"{self.policy.entrypoint_pair.baseline_entrypoint} vs "
                                    f"{self.policy.entrypoint_pair.candidate_entrypoint} diverged on "
                                    f"{field_name} ({operator})",
                                    max_len=400,
                                ),
                                shrink_steps=shrink_steps,
                            )
                        )
                        if len(repro_cases) >= self.policy.max_anomalies:
                            stop_reason = "anomaly_found"
                            break
        except OutboundEgressBlockedError as exc:
            stop_reason = "egress_blocked"
            egress_err_msg = _redact_bounded_text(str(exc), max_len=400)
        except Exception as exc:
            setup_err_msg = _redact_bounded_text(f"Mutation iteration error: {exc}", max_len=400)

        wall_ms = int((time.monotonic() - start_mono) * 1000)

        if egress_err_msg is not None:
            return MutationRunResult(
                seed=self.policy.seed,
                target_fields=self.policy.target_fields,
                entrypoint_pair=self.policy.entrypoint_pair,
                iterations_executed=iterations_executed,
                wall_ms=wall_ms,
                stop_reason="egress_blocked",
                positive_control_passed=True,
                egress_violation_detected=True,
                verdict="environment_failure",
                minimal_repro_cases=(),
                error_detail=egress_err_msg,
            )

        if setup_err_msg is not None:
            return MutationRunResult(
                seed=self.policy.seed,
                target_fields=self.policy.target_fields,
                entrypoint_pair=self.policy.entrypoint_pair,
                iterations_executed=iterations_executed,
                wall_ms=wall_ms,
                stop_reason=stop_reason,
                positive_control_passed=True,
                egress_violation_detected=False,
                verdict="inconclusive",
                minimal_repro_cases=(),
                error_detail=setup_err_msg,
            )

        if repro_cases:
            if stop_reason == "completed":
                stop_reason = "anomaly_found"
            verdict: Literal[
                "hypothesis_falsified",
                "anomaly_observed",
                "baseline_failed",
                "environment_failure",
                "inconclusive",
            ] = "anomaly_observed"
        else:
            verdict = "hypothesis_falsified"

        output_truncated = False
        cases_tuple = tuple(repro_cases)
        result = MutationRunResult(
            seed=self.policy.seed,
            target_fields=self.policy.target_fields,
            entrypoint_pair=self.policy.entrypoint_pair,
            iterations_executed=iterations_executed,
            wall_ms=wall_ms,
            stop_reason=stop_reason,
            positive_control_passed=True,
            egress_violation_detected=False,
            verdict=verdict,
            minimal_repro_cases=cases_tuple,
            output_truncated=False,
        )
        encoded = result.model_dump_json().encode("utf-8")
        if len(encoded) > self.policy.max_output_bytes and cases_tuple:
            result = result.model_copy(
                update={"minimal_repro_cases": (cases_tuple[0],), "output_truncated": True}
            )
        return result


__all__ = [
    "MAX_ANOMALIES_RECORDED",
    "MAX_MINIMAL_INPUT_CHARS",
    "MAX_MUTATION_ITERATIONS",
    "MAX_MUTATION_OUTPUT_BYTES",
    "MAX_MUTATION_TARGET_FIELDS",
    "MAX_MUTATION_WALL_TIME_SECONDS",
    "MAX_PER_ITERATION_TIMEOUT_MS",
    "MAX_SHRINK_STEPS",
    "MUTATION_OPERATORS",
    "MUTATION_SCHEMA",
    "VALID_ENTRYPOINT_KINDS",
    "BoundedMutationRunner",
    "EntrypointPair",
    "LoopbackOnlyEgressGuard",
    "MinimalReproCase",
    "MutationPolicySpec",
    "MutationRunResult",
    "OutboundEgressBlockedError",
    "validate_loopback_only_value",
]
