"""P5 offline comparative evaluation harness for Conditions A / B / C / D and VDP pairs.

Implements ``docs/09-evaluation.ja.md`` §§1–6 using real stdlib + Layer 0–3
harness components (``StaticArtifactInspectorAdapter``, ``HarnessController``,
``EvidenceVault``, ``HypothesisManager``, ``LocalCtfVerifier``, ``RunReportExporter``).

Strict design invariants:
- Never stores plaintext expected flags inside ``EvalTaskSpec`` or evaluation reports.
- Keeps ``pass@1`` strictly scoped to attempt 1 (distinct from ``best_of_k``).
- Keeps VDP vulnerable/fixed pair precision/recall strictly separated from CTF denominators.
- Records flat results, regressions, category-level trade-offs, and unmeasured metrics
  (``not_measured``) transparently without extrapolation.
"""

from __future__ import annotations

import base64
import codecs
import io
import math
import re
import statistics
import struct
import time
import zipfile
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from pydantic import Field, model_validator

from ctf_mcp.adapters.static_inspector import StaticArtifactInspectorAdapter
from ctf_mcp.contracts import (
    SHA256_PATTERN,
    ActionLifecycleState,
    ActionRecord,
    ActionRequest,
    BudgetExceededError,
    BudgetSpec,
    EnvelopeStatus,
    ExecutionClass,
    FindingRecord,
    FindingState,
    HypothesisState,
    PrincipalContext,
    RunMode,
    ScopePolicy,
    StrictModel,
    VerificationStatus,
    canonical_digest,
    sha256_bytes,
)
from ctf_mcp.controller import (
    HarnessController,
    create_default_controller,
    register_default_verifier,
    save_verifier_expectation,
)
from ctf_mcp.evidence.export import ReportMetadata, assert_report_clean
from ctf_mcp.evidence.redaction import scan_sensitive_markers
from ctf_mcp.storage import Storage
from ctf_mcp.verification.ctf_local import ExpectedChallengeSpec, LocalCtfVerifier

# ---------------------------------------------------------------------------
# Enums & Constants (docs/09 §§1, 2, 3, 5)
# ---------------------------------------------------------------------------

_FLAG_TOKEN_RE = re.compile(r"CTF\{[A-Za-z0-9_]+\}")
_SLICE_HINT_RE = re.compile(r"SLICE_OFFSET=(0x[0-9a-fA-F]+|\d+)\s+LEN=(\d+)")
_FASTPATH_B64_RE = re.compile(r"HINT_B64_FASTPATH:\s*([A-Za-z0-9+/=]+)")
_B64_MARKER_RE = re.compile(r"(?<![A-Z0-9_])B64:([A-Za-z0-9+/=]{8,})")
_ROT13_MARKER_RE = re.compile(r"(?<![A-Z0-9_])ROT13:([A-Za-z0-9_{}]{8,})")
_XOR1B_MARKER_RE = re.compile(r"(?<![A-Z0-9_])XOR1B:([0-9a-fA-F]{2}):([0-9a-fA-F]{16,})")
_REV_MARKER_RE = re.compile(r"(?<![A-Z0-9_])REV:([A-Za-z0-9_{}]{8,})")
_SEG_A_RE = re.compile(r'SEG_A\s*=\s*"([^"]+)"')
_SEG_B_RE = re.compile(r'SEG_B\s*=\s*"([^"]+)"')
_HEX_LINE_RE = re.compile(r"^0x[0-9a-fA-F]{8}:\s+([0-9a-fA-F ]+?)\s+\|")

CONDITION_A_TEXT_CAP_BYTES = 1200
CONDITION_B_MAX_MATCHES = 10


class EvalCondition(StrEnum):
    """Experimental comparison arms defined in ``docs/09`` §1."""

    A = "A"  # No MCP tools: fixed plain-text baseline
    B = "B"  # Baseline + single stateless StaticArtifactInspectorAdapter call
    C = "C"  # Full HarnessController + EvidenceVault paging + hypotheses + LocalCtfVerifier
    D = "D"  # Condition C + frozen dev-failure-informed guide


class FailureCategory(StrEnum):
    """Exact nine failure categories required by ``docs/09`` §5."""

    INTAKE_SCOPE = "intake_scope"
    MISSING_CAPABILITY = "missing_capability"
    SPEC_AMBIGUITY = "spec_ambiguity"
    STATE_LOSS = "state_loss"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    PREMATURE_CONCLUSION = "premature_conclusion"
    VERIFIER_LIMIT = "verifier_limit"
    RESOURCE_LIMIT = "resource_limit"
    REASONING_LIMIT = "reasoning_limit"


class EvalCategory(StrEnum):
    """Fixed offline benchmark task categories (4 categories)."""

    REV = "rev"
    FORENSICS = "forensics"
    CRYPTO_TRANSFORM = "crypto_transform"
    SOURCE_AUDIT = "source_audit"


class EvalSplit(StrEnum):
    """Strict separation between development-tuning and holdout evaluation tasks."""

    DEV = "dev"
    EVAL = "eval"


# ---------------------------------------------------------------------------
# Strict Data Models
# ---------------------------------------------------------------------------


class GuideSpec(StrictModel):
    """Frozen procedural guidance derived exclusively from ``split='dev'`` failure analysis."""

    guide_revision: str = Field(min_length=1)
    derived_from_split: Literal["dev"] = "dev"
    source_dev_task_ids: tuple[str, ...] = Field(min_length=1)
    enable_utf16le_fallback: bool = True
    enable_static_transforms: tuple[str, ...] = ("B64", "ROT13", "XOR1B", "REV")
    enable_source_split_assembly: bool = True
    enable_hint_fastpath: bool = True
    require_complete_capture_guard: bool = True
    summary_rules: tuple[str, ...] = Field(min_length=1)

    def digest(self) -> str:
        """Compute canonical SHA-256 digest of the frozen guide."""
        return canonical_digest(self.model_dump(mode="json"))


DEV_INFORMED_GUIDE = GuideSpec(
    guide_revision="dev-guide-v1",
    derived_from_split="dev",
    source_dev_task_ids=(
        "dev-01",
        "dev-02",
        "dev-03",
        "dev-04",
        "dev-05",
        "dev-06",
        "dev-07",
        "dev-08",
        "dev-09",
        "dev-10",
    ),
    enable_utf16le_fallback=True,
    enable_static_transforms=("B64", "ROT13", "XOR1B", "REV"),
    enable_source_split_assembly=True,
    enable_hint_fastpath=True,
    require_complete_capture_guard=True,
    summary_rules=(
        "If ASCII string scan finds no direct or SLICE_OFFSET lead, retry extract_strings with encoding='both' for UTF-16LE.",
        "When B64:/ROT13:/XOR1B:/REV: markers appear in extracted evidence, apply the matching static decoder.",
        "In source_audit artifacts, assemble split SEG_A + SEG_B string literals.",
        "Prioritize HINT_B64_FASTPATH annotations when present (dev-inspired heuristic).",
        "Reject truncated capture_complete=False evidence as verifier_limit rather than guessing.",
    ),
)


class EvalTaskSpec(StrictModel):
    """Offline synthetic benchmark task storing expected SHA-256 digest only (never plaintext flag)."""

    task_id: str = Field(min_length=1)
    split: EvalSplit
    category: EvalCategory
    title: str = Field(min_length=1)
    artifact_filename: str = Field(min_length=1)
    media_type: str = Field(min_length=1)
    artifact_bytes: bytes
    artifact_sha256: str = Field(pattern=SHA256_PATTERN)
    expected_flag_sha256: str = Field(pattern=SHA256_PATTERN)
    salt: str = ""
    require_complete_capture: bool = True
    difficulty: Literal["easy", "medium", "hard", "unsolvable_limit"]
    solvable_without_mcp: bool
    solvable_with_static_inspector: bool = True
    max_tool_calls: int = Field(default=10, gt=0)
    max_output_bytes: int = Field(default=65_536, gt=0)
    max_output_chars_per_page: int = Field(default=400, gt=0, le=4000)
    description: str = Field(min_length=1)
    limitation_note: str | None = None

    @model_validator(mode="after")
    def _validate_digest_consistency(self) -> EvalTaskSpec:
        actual = sha256_bytes(self.artifact_bytes)
        if actual != self.artifact_sha256:
            raise ValueError("artifact_sha256 must match sha256_bytes(artifact_bytes).")
        return self


class VdpFindingTruth(StrictModel):
    """Ground-truth expectation for one matched vulnerable/fixed VDP pair."""

    vuln_kind: str = Field(min_length=1)
    vulnerable_version_label: str = Field(min_length=1)
    fixed_version_label: str = Field(min_length=1)
    sink_regex: str = Field(min_length=1)
    guard_regex: str = Field(min_length=1)


class VdpEvalPairSpec(StrictModel):
    """Independent matched vulnerable vs fixed source pair for VDP precision/recall."""

    pair_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    vulnerable_filename: str = Field(min_length=1)
    vulnerable_bytes: bytes
    fixed_filename: str = Field(min_length=1)
    fixed_bytes: bytes
    truth: VdpFindingTruth


class VdpPairOutcome(StrictModel):
    """Observed findings and TP/FP/FN outcome on one VDP pair under one arm."""

    pair_id: str
    condition: EvalCondition
    run_id_vulnerable: str
    run_id_fixed: str
    workspace_vulnerable: str
    workspace_fixed: str
    reported_findings: tuple[FindingRecord, ...] = ()
    true_positives: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    false_negatives: int = Field(ge=0)
    wall_ms: int = Field(ge=0)
    policy_violations: int = Field(ge=0)


class VdpEvalSummary(StrictModel):
    """VDP precision/recall summary strictly excluded from CTF denominators."""

    condition: EvalCondition
    total_pairs: int = Field(ge=0)
    known_vulnerable_count: int = Field(ge=0)
    reported_total: int = Field(ge=0)
    true_positives: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    false_negatives: int = Field(ge=0)
    vdp_precision: float = Field(ge=0.0, le=1.0)
    vdp_recall: float = Field(ge=0.0, le=1.0)
    excluded_from_ctf_denominator: bool = True
    policy_violations: int = Field(ge=0)
    pair_outcomes: tuple[VdpPairOutcome, ...] = ()


class TaskAttemptRecord(StrictModel):
    """Single task attempt execution record with verified pass@1 status & OS metrics."""

    task_id: str
    split: EvalSplit
    category: EvalCategory
    condition: EvalCondition
    attempt_index: int = Field(ge=1)
    run_id: str
    workspace_dir: str
    verified_solved: bool
    verification_status: VerificationStatus
    failure_category: FailureCategory | None = None
    failure_reason: str | None = None
    wall_ms: int = Field(ge=0)
    cpu_ms: int | None = Field(default=None, ge=0)
    peak_rss_bytes: int | None = Field(default=None, ge=0)
    tool_calls: int = Field(ge=0)
    pages_read: int = Field(ge=0)
    hypotheses_recorded: int = Field(ge=0)
    evidence_reproducible: bool
    cleanup_confirmed: bool
    policy_violations: int = Field(ge=0)
    api_cost_usd: float | None = None
    token_usage: int | None = None
    report_path: str | None = None


class CategoryBreakdown(StrictModel):
    """Per-category pass@1 and failure profile to prevent masking regressions."""

    category: EvalCategory
    total_tasks: int = Field(ge=0)
    solved_count: int = Field(ge=0)
    pass_at_1: float = Field(ge=0.0, le=1.0)
    wilson_ci_low: float = Field(ge=0.0, le=1.0)
    wilson_ci_high: float = Field(ge=0.0, le=1.0)
    avg_wall_ms: float = Field(ge=0.0)
    avg_tool_calls: float = Field(ge=0.0)
    failure_counts: dict[str, int]


class EvalConditionSummary(StrictModel):
    """Aggregated offline benchmark metrics for one experimental condition."""

    condition: EvalCondition
    split: EvalSplit
    total_tasks: int = Field(ge=0)
    solved_count: int = Field(ge=0)
    ctf_verified_solve_rate: float = Field(ge=0.0, le=1.0)
    wilson_ci_95: tuple[float, float]
    best_of_k_solve_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    best_of_k_value: int | None = Field(default=None, ge=2)
    total_wall_ms: int = Field(ge=0)
    median_wall_ms: float = Field(ge=0.0)
    total_cpu_ms: int | None = Field(default=None, ge=0)
    max_peak_rss_bytes: int | None = Field(default=None, ge=0)
    total_tool_calls: int = Field(ge=0)
    mean_tool_calls: float = Field(ge=0.0)
    evidence_reproducible_rate: float = Field(ge=0.0, le=1.0)
    operational_reliability: float = Field(ge=0.0, le=1.0)
    policy_violations: int = Field(ge=0)
    api_cost_usd_status: Literal["not_measured"] = "not_measured"
    token_usage_status: Literal["not_measured"] = "not_measured"
    by_category: dict[str, CategoryBreakdown]
    failure_counts: dict[str, int]


class PairedComparison(StrictModel):
    """Paired per-task transition comparison preserving regressions and flat cases."""

    from_condition: EvalCondition
    to_condition: EvalCondition
    total_tasks: int = Field(ge=0)
    improved_tasks: tuple[str, ...]
    regressed_tasks: tuple[str, ...]
    unchanged_solved_tasks: tuple[str, ...]
    unchanged_unsolved_tasks: tuple[str, ...]
    delta_pass_at_1: float
    delta_by_category: dict[str, float]
    regression_and_flat_summary: str = Field(min_length=1)


class OfflineEvaluationReport(StrictModel):
    """Complete reproducible A/B/C/D + VDP comparative evaluation report."""

    report_id: str
    generated_at: datetime
    split: EvalSplit
    guide_revision: str
    guide_sha256: str = Field(pattern=SHA256_PATTERN)
    task_ids: tuple[str, ...]
    condition_summaries: dict[str, EvalConditionSummary]
    paired_comparisons: tuple[PairedComparison, ...]
    attempts: tuple[TaskAttemptRecord, ...]
    vdp_summaries: dict[str, VdpEvalSummary]
    small_sample_warnings: tuple[str, ...]


# ---------------------------------------------------------------------------
# Metric Calculation Helpers
# ---------------------------------------------------------------------------


def wilson_confidence_interval(
    successes: int,
    total: int,
    *,
    z: float = 1.96,
) -> tuple[float, float]:
    """Compute the 95% Wilson score interval for a binomial proportion."""
    if total <= 0:
        return 0.0, 0.0
    p = max(0.0, min(1.0, successes / total))
    z2 = z * z
    denom = 1.0 + z2 / total
    center = (p + z2 / (2.0 * total)) / denom
    half = (z * math.sqrt((p * (1.0 - p) + z2 / (4.0 * total)) / total)) / denom
    return round(max(0.0, center - half), 4), round(min(1.0, center + half), 4)


def _empty_failure_counts() -> dict[str, int]:
    return {cat.value: 0 for cat in FailureCategory}


def summarize_condition_attempts(
    *,
    condition: EvalCondition,
    split: EvalSplit,
    attempts: Sequence[TaskAttemptRecord],
) -> EvalConditionSummary:
    """Compute condition summary where ``ctf_verified_solve_rate`` is strictly pass@1."""
    cond_attempts = [a for a in attempts if a.condition == condition]
    if not cond_attempts:
        raise ValueError(f"No attempt records supplied for condition {condition.value!r}.")

    first_attempts = [a for a in cond_attempts if a.attempt_index == 1]
    if not first_attempts:
        raise ValueError(f"Condition {condition.value!r} is missing attempt_index=1 records.")

    # Enforce strict pass@1 denominator: only attempt_index == 1 counts here.
    by_task_first: dict[str, TaskAttemptRecord] = {a.task_id: a for a in first_attempts}
    total_tasks = len(by_task_first)
    solved_count = sum(1 for a in by_task_first.values() if a.verified_solved)
    pass_at_1 = round(solved_count / total_tasks, 6)
    ci_low, ci_high = wilson_confidence_interval(solved_count, total_tasks)

    max_attempt_idx = max(a.attempt_index for a in cond_attempts)
    best_of_k_rate: float | None = None
    best_of_k_val: int | None = None
    if max_attempt_idx > 1:
        solved_any_by_task: dict[str, bool] = {tid: False for tid in by_task_first}
        for rec in cond_attempts:
            if rec.verified_solved and rec.task_id in solved_any_by_task:
                solved_any_by_task[rec.task_id] = True
        best_of_k_val = max_attempt_idx
        best_of_k_rate = round(
            sum(1 for ok in solved_any_by_task.values() if ok) / total_tasks,
            6,
        )

    ordered_first = [by_task_first[tid] for tid in by_task_first]
    walls = [a.wall_ms for a in ordered_first]
    cpus = [a.cpu_ms for a in ordered_first if a.cpu_ms is not None]
    rss_vals = [a.peak_rss_bytes for a in ordered_first if a.peak_rss_bytes is not None]
    failure_counts = _empty_failure_counts()
    for rec in ordered_first:
        if rec.failure_category is not None:
            failure_counts[rec.failure_category.value] += 1

    by_category: dict[str, CategoryBreakdown] = {}
    for cat in EvalCategory:
        cat_recs = [a for a in ordered_first if a.category == cat]
        if not cat_recs:
            continue
        c_solved = sum(1 for a in cat_recs if a.verified_solved)
        c_total = len(cat_recs)
        c_lo, c_hi = wilson_confidence_interval(c_solved, c_total)
        c_fail = _empty_failure_counts()
        for rec in cat_recs:
            if rec.failure_category is not None:
                c_fail[rec.failure_category.value] += 1
        by_category[cat.value] = CategoryBreakdown(
            category=cat,
            total_tasks=c_total,
            solved_count=c_solved,
            pass_at_1=round(c_solved / c_total, 6),
            wilson_ci_low=c_lo,
            wilson_ci_high=c_hi,
            avg_wall_ms=round(sum(r.wall_ms for r in cat_recs) / c_total, 2),
            avg_tool_calls=round(sum(r.tool_calls for r in cat_recs) / c_total, 2),
            failure_counts=c_fail,
        )

    total_calls = sum(a.tool_calls for a in ordered_first)
    reproducible_count = sum(1 for a in ordered_first if a.evidence_reproducible)
    reliable_count = sum(
        1 for a in ordered_first if a.cleanup_confirmed and a.policy_violations == 0
    )

    return EvalConditionSummary(
        condition=condition,
        split=split,
        total_tasks=total_tasks,
        solved_count=solved_count,
        ctf_verified_solve_rate=pass_at_1,
        wilson_ci_95=(ci_low, ci_high),
        best_of_k_solve_rate=best_of_k_rate,
        best_of_k_value=best_of_k_val,
        total_wall_ms=sum(walls),
        median_wall_ms=round(float(statistics.median(walls)), 2),
        total_cpu_ms=sum(cpus) if cpus else None,
        max_peak_rss_bytes=max(rss_vals) if rss_vals else None,
        total_tool_calls=total_calls,
        mean_tool_calls=round(total_calls / total_tasks, 3),
        evidence_reproducible_rate=round(reproducible_count / total_tasks, 6),
        operational_reliability=round(reliable_count / total_tasks, 6),
        policy_violations=sum(a.policy_violations for a in cond_attempts),
        by_category=by_category,
        failure_counts=failure_counts,
    )


def compute_paired_comparison(
    *,
    from_summary: EvalConditionSummary,
    to_summary: EvalConditionSummary,
    attempts: Sequence[TaskAttemptRecord],
) -> PairedComparison:
    """Compare attempt_index=1 outcomes per task between two conditions."""
    from_map = {
        a.task_id: a
        for a in attempts
        if a.condition == from_summary.condition and a.attempt_index == 1
    }
    to_map = {
        a.task_id: a
        for a in attempts
        if a.condition == to_summary.condition and a.attempt_index == 1
    }
    shared_ids = sorted(set(from_map) & set(to_map))

    improved: list[str] = []
    regressed: list[str] = []
    unchanged_solved: list[str] = []
    unchanged_unsolved: list[str] = []
    for tid in shared_ids:
        a_ok = from_map[tid].verified_solved
        b_ok = to_map[tid].verified_solved
        if not a_ok and b_ok:
            improved.append(tid)
        elif a_ok and not b_ok:
            regressed.append(tid)
        elif a_ok and b_ok:
            unchanged_solved.append(tid)
        else:
            unchanged_unsolved.append(tid)

    delta_by_cat: dict[str, float] = {}
    for cat_key, to_cat in to_summary.by_category.items():
        from_cat = from_summary.by_category.get(cat_key)
        if from_cat is not None:
            delta_by_cat[cat_key] = round(to_cat.pass_at_1 - from_cat.pass_at_1, 6)

    cat_regressed = [f"{k}({v:+.3f})" for k, v in delta_by_cat.items() if v < 0.0]
    cat_flat = [f"{k}(0.000)" for k, v in delta_by_cat.items() if v == 0.0]
    summary_parts = [
        f"{from_summary.condition.value}->{to_summary.condition.value}:",
        f"improved={len(improved)} {improved},",
        f"regressed={len(regressed)} {regressed},",
        f"flat_unsolved={len(unchanged_unsolved)} {unchanged_unsolved},",
        f"flat_solved={len(unchanged_solved)}.",
    ]
    if cat_regressed:
        summary_parts.append(f"Category drops: {', '.join(cat_regressed)}.")
    if cat_flat:
        summary_parts.append(f"Flat categories: {', '.join(cat_flat)}.")

    return PairedComparison(
        from_condition=from_summary.condition,
        to_condition=to_summary.condition,
        total_tasks=len(shared_ids),
        improved_tasks=tuple(improved),
        regressed_tasks=tuple(regressed),
        unchanged_solved_tasks=tuple(unchanged_solved),
        unchanged_unsolved_tasks=tuple(unchanged_unsolved),
        delta_pass_at_1=round(
            to_summary.ctf_verified_solve_rate - from_summary.ctf_verified_solve_rate, 6
        ),
        delta_by_category=delta_by_cat,
        regression_and_flat_summary=" ".join(summary_parts),
    )


# ---------------------------------------------------------------------------
# Deterministic Synthetic Task & Container Builders
# ---------------------------------------------------------------------------


def _synthesize_flag(split: EvalSplit, index: int, slug: str) -> str:
    """Create a deterministic synthetic CTF flag string for artifact construction only."""
    tag = hashlib_sha256_short(f"{split.value}:{index:02d}:{slug}:ctf-vdp-eval-v1")
    return f"CTF{{{split.value}_{index:02d}_{slug}_{tag}}}"


def hashlib_sha256_short(seed: str) -> str:
    """Return an 8-char deterministic SHA-256 prefix using contracts helper."""
    return sha256_bytes(seed.encode("utf-8"))[:8]


def _build_minimal_elf64(payload: bytes) -> bytes:
    """Construct a valid minimal ELF64 little-endian x86_64 binary embedding ``payload``."""
    ehdr_size = 64
    sh_offset_payload = ehdr_size
    padded_payload = payload + b"\x00"
    strtab = b"\x00.rodata\x00.shstrtab\x00"
    strtab_offset = sh_offset_payload + len(padded_payload)
    align_pad = (-((strtab_offset + len(strtab)) % 8)) % 8
    shoff = strtab_offset + len(strtab) + align_pad

    e_ident = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,  # ET_EXEC
        62,  # EM_X86_64
        1,  # EV_CURRENT
        0x401000,  # e_entry
        0,  # e_phoff
        shoff,  # e_shoff
        0,  # e_flags
        ehdr_size,
        0,  # e_phentsize
        0,  # e_phnum
        64,  # e_shentsize
        3,  # e_shnum
        2,  # e_shstrndx
    )

    sh_null = b"\x00" * 64
    sh_rodata = struct.pack(
        "<IIQQQQIIQQ",
        1,  # .rodata
        1,  # SHT_PROGBITS
        2,  # SHF_ALLOC
        0x402000,
        sh_offset_payload,
        len(padded_payload),
        0,
        0,
        8,
        0,
    )
    sh_strtab = struct.pack(
        "<IIQQQQIIQQ",
        9,  # .shstrtab
        3,  # SHT_STRTAB
        0,
        0,
        strtab_offset,
        len(strtab),
        0,
        0,
        1,
        0,
    )
    return ehdr + padded_payload + strtab + (b"\x00" * align_pad) + sh_null + sh_rodata + sh_strtab


def _build_stored_zip(entries: Mapping[str, bytes]) -> bytes:
    """Construct a reproducible deterministic uncompressed ZIP container."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_STORED) as zf:
        for name, data in sorted(entries.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 11, 13, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o644 << 16
            zf.writestr(info, data)
    return buf.getvalue()


def _encode_b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _encode_rot13(text: str) -> str:
    return codecs.encode(text, "rot_13")


def _encode_xor1b(text: str, key: int) -> tuple[str, str]:
    cipher = bytes(b ^ key for b in text.encode("utf-8"))
    return f"{key:02x}", cipher.hex()


def _encode_nulsliced(flag: str) -> bytes:
    """Split ASCII into 2-byte segments separated by NUL so strings extractor ignores it."""
    parts = [flag[i : i + 2].encode("ascii") for i in range(0, len(flag), 2)]
    return b"\x00".join(parts) + b"\x00\x00"


def _deterministic_high_entropy_blob(seed: str, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hashlib_sha256_bytes(f"{seed}:{counter}")
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def hashlib_sha256_bytes(seed: str) -> bytes:
    return bytes.fromhex(sha256_bytes(seed.encode("utf-8")))


def _build_spec_with_flag(
    *,
    task_id: str,
    split: EvalSplit,
    category: EvalCategory,
    title: str,
    artifact_filename: str,
    media_type: str,
    artifact_bytes: bytes,
    plain_flag: str,
    salt: str = "",
    require_complete_capture: bool = True,
    difficulty: Literal["easy", "medium", "hard", "unsolvable_limit"],
    solvable_without_mcp: bool,
    solvable_with_static_inspector: bool = True,
    max_tool_calls: int = 10,
    max_output_bytes: int = 65_536,
    max_output_chars_per_page: int = 400,
    description: str,
    limitation_note: str | None = None,
) -> EvalTaskSpec:
    digest = sha256_bytes((salt + plain_flag).encode("utf-8"))
    return EvalTaskSpec(
        task_id=task_id,
        split=split,
        category=category,
        title=title,
        artifact_filename=artifact_filename,
        media_type=media_type,
        artifact_bytes=artifact_bytes,
        artifact_sha256=sha256_bytes(artifact_bytes),
        expected_flag_sha256=digest,
        salt=salt,
        require_complete_capture=require_complete_capture,
        difficulty=difficulty,
        solvable_without_mcp=solvable_without_mcp,
        solvable_with_static_inspector=solvable_with_static_inspector,
        max_tool_calls=max_tool_calls,
        max_output_bytes=max_output_bytes,
        max_output_chars_per_page=max_output_chars_per_page,
        description=description,
        limitation_note=limitation_note,
    )


def _make_nulsliced_elf(prefix_notes: bytes, flag: str) -> bytes:
    """Embed SLICE_OFFSET hint pointing to NUL-fragmented payload inside ELF64 .rodata."""
    sliced = _encode_nulsliced(flag)
    padding = b"".join(f"DECOY_SECTION_ITEM_{i:02d}\n".encode("ascii") for i in range(16))
    # Header size is 64 bytes -> .rodata begins at 0x40.
    prelim_header = f"{prefix_notes.decode('ascii')}{padding.decode('ascii')}SLICE_OFFSET=0x".encode(
        "ascii"
    )
    hint_placeholder = b"0000 LEN=000\n"
    blob_offset_in_payload = len(prelim_header) + len(hint_placeholder) + 16
    abs_offset = 64 + blob_offset_in_payload
    hint_line = f"SLICE_OFFSET=0x{abs_offset:04x} LEN={len(sliced):03d}\n".encode("ascii")
    # Recompute exact length match to keep offset aligned cleanly.
    exact_offset = 64 + len(prefix_notes) + len(padding) + len(hint_line) + 16
    if exact_offset != abs_offset:
        hint_line = f"SLICE_OFFSET=0x{exact_offset:04x} LEN={len(sliced):03d}\n".encode("ascii")
    payload = prefix_notes + padding + hint_line + (b"\x01\x02" * 8) + sliced
    return _build_minimal_elf64(payload)


def build_dev_tasks() -> tuple[EvalTaskSpec, ...]:
    """Build 10 deterministic synthetic development tasks across all 4 categories."""
    tasks: list[EvalTaskSpec] = []

    # dev-01: plain short UTF-8 source_audit (A/B/C/D pass)
    f01 = _synthesize_flag(EvalSplit.DEV, 1, "plain_cfg")
    b01 = f'# audit sample\nAUDIT_SAMPLE_TOKEN = "{f01}"\n'.encode("utf-8")
    tasks.append(
        _build_spec_with_flag(
            task_id="dev-01",
            split=EvalSplit.DEV,
            category=EvalCategory.SOURCE_AUDIT,
            title="Plain Python config token leak",
            artifact_filename="dev_config.py",
            media_type="text/x-python",
            artifact_bytes=b01,
            plain_flag=f01,
            difficulty="easy",
            solvable_without_mcp=True,
            description="Short plain UTF-8 source file containing direct flag literal.",
        )
    )

    # dev-02: ELF64 direct ASCII (fails A, passes B/C/D)
    f02 = _synthesize_flag(EvalSplit.DEV, 2, "elf_direct")
    b02 = _build_minimal_elf64(f"BANNER_OK\n{f02}\n".encode("ascii"))
    tasks.append(
        _build_spec_with_flag(
            task_id="dev-02",
            split=EvalSplit.DEV,
            category=EvalCategory.FORENSICS,
            title="ELF64 single-pass ASCII note",
            artifact_filename="dev_note.elf",
            media_type="application/octet-stream",
            artifact_bytes=b02,
            plain_flag=f02,
            difficulty="easy",
            solvable_without_mcp=False,
            description="ELF64 binary holding a direct ASCII note string in .rodata.",
        )
    )

    # dev-03: ELF64 multi-page > 15 decoy strings (fails A/B, passes C/D)
    f03 = _synthesize_flag(EvalSplit.DEV, 3, "paged_rodata")
    decoys03 = "\n".join(f"DEV_PADDING_SYMBOL_{i:02d}_IGNORED" for i in range(18))
    b03 = _build_minimal_elf64(f"{decoys03}\n{f03}\n".encode("ascii"))
    tasks.append(
        _build_spec_with_flag(
            task_id="dev-03",
            split=EvalSplit.DEV,
            category=EvalCategory.REV,
            title="ELF64 paged symbol list",
            artifact_filename="dev_paged.elf",
            media_type="application/octet-stream",
            artifact_bytes=b03,
            plain_flag=f03,
            difficulty="medium",
            solvable_without_mcp=False,
            max_output_chars_per_page=320,
            description="ELF64 with 18 decoy strings ahead of target across EvidenceVault pages.",
        )
    )

    # dev-04: ELF64 SLICE_OFFSET -> hex_slice (fails A/B, passes C/D)
    f04 = _synthesize_flag(EvalSplit.DEV, 4, "slice_reassemble")
    b04 = _make_nulsliced_elf(b"TRACE_INDEX_HEADER\n", f04)
    tasks.append(
        _build_spec_with_flag(
            task_id="dev-04",
            split=EvalSplit.DEV,
            category=EvalCategory.FORENSICS,
            title="Offset-indexed hex_slice binary",
            artifact_filename="dev_slice.bin",
            media_type="application/octet-stream",
            artifact_bytes=b04,
            plain_flag=f04,
            difficulty="medium",
            solvable_without_mcp=False,
            description="Binary containing SLICE_OFFSET cue pointing to fragmented .rodata chunk.",
        )
    )

    # dev-05: ELF64 UTF-16LE only (fails A/B/C, passes D)
    f05 = _synthesize_flag(EvalSplit.DEV, 5, "utf16le_wide")
    b05 = _build_minimal_elf64(b"HEAD_WIDE\x00" + f05.encode("utf-16le") + b"\x00\x00")
    tasks.append(
        _build_spec_with_flag(
            task_id="dev-05",
            split=EvalSplit.DEV,
            category=EvalCategory.REV,
            title="UTF-16LE wide-string binary",
            artifact_filename="dev_wide.bin",
            media_type="application/octet-stream",
            artifact_bytes=b05,
            plain_flag=f05,
            difficulty="hard",
            solvable_without_mcp=False,
            description="Binary storing target token strictly in UTF-16LE.",
        )
    )

    # dev-06: Stored ZIP B64 transform (fails A/B/C, passes D)
    f06 = _synthesize_flag(EvalSplit.DEV, 6, "zip_b64")
    b06 = _build_stored_zip({"payload.txt": f"CIPHER_KIND=base64\nB64:{_encode_b64(f06)}\n".encode("ascii")})
    tasks.append(
        _build_spec_with_flag(
            task_id="dev-06",
            split=EvalSplit.DEV,
            category=EvalCategory.CRYPTO_TRANSFORM,
            title="ZIP container Base64 transform",
            artifact_filename="dev_b64.zip",
            media_type="application/zip",
            artifact_bytes=b06,
            plain_flag=f06,
            difficulty="medium",
            solvable_without_mcp=False,
            description="Stored ZIP containing B64:-encoded flag line.",
        )
    )

    # dev-07: ELF64 single-byte XOR transform (fails A/B/C, passes D)
    f07 = _synthesize_flag(EvalSplit.DEV, 7, "xor1b_key")
    k07, x07 = _encode_xor1b(f07, 0x37)
    b07 = _build_minimal_elf64(f"CIPHER_SPEC=single_byte_xor\nXOR1B:{k07}:{x07}\n".encode("ascii"))
    tasks.append(
        _build_spec_with_flag(
            task_id="dev-07",
            split=EvalSplit.DEV,
            category=EvalCategory.CRYPTO_TRANSFORM,
            title="Single-byte XOR transform blob",
            artifact_filename="dev_xor.bin",
            media_type="application/octet-stream",
            artifact_bytes=b07,
            plain_flag=f07,
            difficulty="hard",
            solvable_without_mcp=False,
            description="Binary storing XOR1B:<key>:<hex> encoded payload.",
        )
    )

    # dev-08: Long Python source_audit with SEG_A + SEG_B (fails A/B/C, passes D)
    f08 = _synthesize_flag(EvalSplit.DEV, 8, "split_vars")
    mid08 = len(f08) // 2
    preamble08 = "\n".join(f"# dev_audit_comment_{i:02d} = placeholder" for i in range(42))
    src08 = (
        f"{preamble08}\n"
        f'SEG_A = "{f08[:mid08]}"\n'
        f'SEG_B = "{f08[mid08:]}"\n'
        "COMBINED = SEG_A + SEG_B\n"
    ).encode("utf-8")
    tasks.append(
        _build_spec_with_flag(
            task_id="dev-08",
            split=EvalSplit.DEV,
            category=EvalCategory.SOURCE_AUDIT,
            title="Split-segment source assembly",
            artifact_filename="dev_split.py",
            media_type="text/x-python",
            artifact_bytes=src08,
            plain_flag=f08,
            difficulty="medium",
            solvable_without_mcp=False,
            description="Long Python source file splitting the flag across SEG_A and SEG_B.",
        )
    )

    # dev-09: Unsolvable limit (dynamic runtime-only entropy blob, fails all A/B/C/D)
    f09 = _synthesize_flag(EvalSplit.DEV, 9, "dynamic_limit")
    blob09 = _deterministic_high_entropy_blob("dev-09-unrecoverable", 256)
    b09 = _build_minimal_elf64(b"KEY_DERIVED_AT_RUNTIME_ONLY\x00" + blob09)
    tasks.append(
        _build_spec_with_flag(
            task_id="dev-09",
            split=EvalSplit.DEV,
            category=EvalCategory.REV,
            title="Runtime-keyed encrypted ELF64 (limit)",
            artifact_filename="dev_runtime_limit.elf",
            media_type="application/octet-stream",
            artifact_bytes=b09,
            plain_flag=f09,
            difficulty="unsolvable_limit",
            solvable_without_mcp=False,
            solvable_with_static_inspector=False,
            description="Binary with runtime-only key; no static path recovers plaintext.",
            limitation_note="Requires dynamic execution/trace; intentionally unsolvable statically.",
        )
    )

    # dev-10: Oversized output > max_output_bytes rejected by LocalCtfVerifier (fails all)
    f10 = _synthesize_flag(EvalSplit.DEV, 10, "truncated_capture")
    long_logs10 = "\n".join(f"DEV_ARCHIVE_RECORD_{i:04d}_NOISE_BLOCK" for i in range(180))
    b10 = _build_minimal_elf64(f"{long_logs10}\n{f10}\n".encode("ascii"))
    tasks.append(
        _build_spec_with_flag(
            task_id="dev-10",
            split=EvalSplit.DEV,
            category=EvalCategory.FORENSICS,
            title="Oversized truncated forensics capture (limit)",
            artifact_filename="dev_oversized.bin",
            media_type="application/octet-stream",
            artifact_bytes=b10,
            plain_flag=f10,
            require_complete_capture=True,
            difficulty="unsolvable_limit",
            solvable_without_mcp=False,
            solvable_with_static_inspector=False,
            max_output_bytes=1600,
            description="Artifact exceeding max_output_bytes causing partial capture rejection.",
            limitation_note="capture_complete=False blocks verification under require_complete_capture=True.",
        )
    )

    return tuple(tasks)


def build_eval_tasks() -> tuple[EvalTaskSpec, ...]:
    """Build 20 disjoint holdout evaluation tasks (5 per category across 4 categories)."""
    tasks: list[EvalTaskSpec] = []

    # ---- REV (eval-01 .. eval-05) ----
    # eval-01: ELF64 direct ASCII (A fail, B/C/D pass)
    fe01 = _synthesize_flag(EvalSplit.EVAL, 1, "rev_direct_ascii")
    tasks.append(
        _build_spec_with_flag(
            task_id="eval-01",
            split=EvalSplit.EVAL,
            category=EvalCategory.REV,
            title="Holdout ELF64 direct rodata string",
            artifact_filename="eval01_bin.elf",
            media_type="application/octet-stream",
            artifact_bytes=_build_minimal_elf64(f"SECTION_INIT\n{fe01}\n".encode("ascii")),
            plain_flag=fe01,
            salt="eval-salt-01:",
            difficulty="easy",
            solvable_without_mcp=False,
            description="Minimal ELF64 embedding a direct ASCII marker near the start of .rodata.",
        )
    )

    # eval-02: ELF64 multi-page 20 decoy strings (A/B fail, C/D pass)
    fe02 = _synthesize_flag(EvalSplit.EVAL, 2, "rev_multipage_rodata")
    decoys02 = "\n".join(f"EVAL_SYM_TAB_ENTRY_{i:02d}_PAD" for i in range(20))
    tasks.append(
        _build_spec_with_flag(
            task_id="eval-02",
            split=EvalSplit.EVAL,
            category=EvalCategory.REV,
            title="Holdout ELF64 multi-page string table",
            artifact_filename="eval02_paged.elf",
            media_type="application/octet-stream",
            artifact_bytes=_build_minimal_elf64(f"{decoys02}\n{fe02}\n".encode("ascii")),
            plain_flag=fe02,
            salt="eval-salt-02:",
            difficulty="medium",
            solvable_without_mcp=False,
            max_output_chars_per_page=320,
            description="ELF64 placing target beyond initial 10-string window and across pages.",
        )
    )

    # eval-03: ELF64 UTF-16LE only (A/B/C fail, D passes via dev UTF-16LE fallback)
    fe03 = _synthesize_flag(EvalSplit.EVAL, 3, "rev_utf16le")
    tasks.append(
        _build_spec_with_flag(
            task_id="eval-03",
            split=EvalSplit.EVAL,
            category=EvalCategory.REV,
            title="Holdout ELF64 UTF-16LE wide constant",
            artifact_filename="eval03_wide.elf",
            media_type="application/octet-stream",
            artifact_bytes=_build_minimal_elf64(b"WCHAR\x00" + fe03.encode("utf-16le") + b"\x00\x00"),
            plain_flag=fe03,
            salt="eval-salt-03:",
            difficulty="hard",
            solvable_without_mcp=False,
            description="ELF64 containing flag encoded exclusively in UTF-16LE.",
        )
    )

    # eval-04: Tight budget max_tool_calls=1 (A fail, B pass, C/D REGRESS -> resource_limit)
    fe04 = _synthesize_flag(EvalSplit.EVAL, 4, "rev_tight_budget")
    tasks.append(
        _build_spec_with_flag(
            task_id="eval-04",
            split=EvalSplit.EVAL,
            category=EvalCategory.REV,
            title="Holdout ELF64 under max_tool_calls=1 budget",
            artifact_filename="eval04_budget.elf",
            media_type="application/octet-stream",
            artifact_bytes=_build_minimal_elf64(f"BUDGET_CAP_TEST\n{fe04}\n".encode("ascii")),
            plain_flag=fe04,
            salt="eval-salt-04:",
            difficulty="medium",
            solvable_without_mcp=False,
            max_tool_calls=1,
            description="ELF64 solvable in 1 direct extract_strings call; two-step header+strings triage hits BudgetSpec limit.",
            limitation_note="Intentional B->C budget regression benchmark: max_tool_calls=1.",
        )
    )

    # eval-05: Dynamic runtime-only encrypted binary (all A/B/C/D fail -> missing_capability)
    fe05 = _synthesize_flag(EvalSplit.EVAL, 5, "rev_runtime_crypto")
    blob05 = _deterministic_high_entropy_blob("eval-05-runtime-blob", 256)
    tasks.append(
        _build_spec_with_flag(
            task_id="eval-05",
            split=EvalSplit.EVAL,
            category=EvalCategory.REV,
            title="Holdout runtime-keyed encrypted ELF64 (limit)",
            artifact_filename="eval05_opaque.elf",
            media_type="application/octet-stream",
            artifact_bytes=_build_minimal_elf64(b"NO_STATIC_KEY_PRESENT\x00" + blob05),
            plain_flag=fe05,
            salt="eval-salt-05:",
            difficulty="unsolvable_limit",
            solvable_without_mcp=False,
            solvable_with_static_inspector=False,
            description="Opaque high-entropy ELF64 requiring dynamic tracing.",
            limitation_note="Static inspector cannot decrypt dynamic runtime-keyed payload.",
        )
    )

    # ---- FORENSICS (eval-06 .. eval-10) ----
    # eval-06: Plain short UTF-8 log (all A/B/C/D pass)
    fe06 = _synthesize_flag(EvalSplit.EVAL, 6, "forensics_plain_log")
    b_e06 = f"2026-11-13T00:00:01Z audit event notice\nTOKEN_NOTE={fe06}\n".encode("utf-8")
    tasks.append(
        _build_spec_with_flag(
            task_id="eval-06",
            split=EvalSplit.EVAL,
            category=EvalCategory.FORENSICS,
            title="Holdout plain UTF-8 audit log slice",
            artifact_filename="eval06_audit.log",
            media_type="text/plain",
            artifact_bytes=b_e06,
            plain_flag=fe06,
            salt="eval-salt-06:",
            difficulty="easy",
            solvable_without_mcp=True,
            description="Short plain-text log solvable without MCP tools.",
        )
    )

    # eval-07: Binary SLICE_OFFSET -> hex_slice (A/B fail, C/D pass)
    fe07 = _synthesize_flag(EvalSplit.EVAL, 7, "forensics_slice_reasm")
    b_e07 = _make_nulsliced_elf(b"FORENSIC_DUMP_V2\n", fe07)
    tasks.append(
        _build_spec_with_flag(
            task_id="eval-07",
            split=EvalSplit.EVAL,
            category=EvalCategory.FORENSICS,
            title="Holdout binary carve via hex_slice",
            artifact_filename="eval07_dump.bin",
            media_type="application/octet-stream",
            artifact_bytes=b_e07,
            plain_flag=fe07,
            salt="eval-salt-07:",
            difficulty="medium",
            solvable_without_mcp=False,
            description="Fragmented NUL-separated bytes at SLICE_OFFSET requiring hex_slice follow-up.",
        )
    )

    # eval-08: Decoy HINT_B64_FASTPATH + real SLICE_OFFSET (C passes, D REGRESSES -> premature_conclusion)
    fe08 = _synthesize_flag(EvalSplit.EVAL, 8, "forensics_decoy_trap")
    decoy_b64_08 = _encode_b64("UNVERIFIED_FASTPATH_DECOY_EVAL08")
    b_e08 = _make_nulsliced_elf(f"HINT_B64_FASTPATH: {decoy_b64_08}\n".encode("ascii"), fe08)
    tasks.append(
        _build_spec_with_flag(
            task_id="eval-08",
            split=EvalSplit.EVAL,
            category=EvalCategory.FORENSICS,
            title="Holdout forensics trap with fastpath decoy",
            artifact_filename="eval08_decoy_slice.bin",
            media_type="application/octet-stream",
            artifact_bytes=b_e08,
            plain_flag=fe08,
            salt="eval-salt-08:",
            difficulty="hard",
            solvable_without_mcp=False,
            description="Includes misleading HINT_B64_FASTPATH before real SLICE_OFFSET evidence.",
            limitation_note="Tests dev-overfit regression: eager fastpath guess fails pass@1 in Condition D.",
        )
    )

    # eval-09: Stored ZIP direct entry (A fail, B/C/D pass)
    fe09 = _synthesize_flag(EvalSplit.EVAL, 9, "forensics_zip_entry")
    b_e09 = _build_stored_zip({"evidence_note.txt": f"ARCHIVE_NOTE\n{fe09}\n".encode("ascii")})
    tasks.append(
        _build_spec_with_flag(
            task_id="eval-09",
            split=EvalSplit.EVAL,
            category=EvalCategory.FORENSICS,
            title="Holdout ZIP archive note extraction",
            artifact_filename="eval09_bundle.zip",
            media_type="application/zip",
            artifact_bytes=b_e09,
            plain_flag=fe09,
            salt="eval-salt-09:",
            difficulty="easy",
            solvable_without_mcp=False,
            description="Stored ZIP bundle carrying direct note entry.",
        )
    )

    # eval-10: Oversized forensics capture > max_output_bytes (all A/B/C/D fail; C/D -> verifier_limit)
    fe10 = _synthesize_flag(EvalSplit.EVAL, 10, "forensics_oversized")
    logs10 = "\n".join(f"EVAL_PACKET_TRACE_LINE_{i:04d}_SYNTH" for i in range(180))
    b_e10 = _build_minimal_elf64(f"{logs10}\n{fe10}\n".encode("ascii"))
    tasks.append(
        _build_spec_with_flag(
            task_id="eval-10",
            split=EvalSplit.EVAL,
            category=EvalCategory.FORENSICS,
            title="Holdout oversized partial output limit",
            artifact_filename="eval10_truncated.bin",
            media_type="application/octet-stream",
            artifact_bytes=b_e10,
            plain_flag=fe10,
            salt="eval-salt-10:",
            require_complete_capture=True,
            difficulty="unsolvable_limit",
            solvable_without_mcp=False,
            solvable_with_static_inspector=False,
            max_output_bytes=1600,
            description="Exceeds bounded static output cap so LocalCtfVerifier rejects incomplete capture.",
            limitation_note="Intentional flat/limit case across all conditions.",
        )
    )

    # ---- CRYPTO_TRANSFORM (eval-11 .. eval-15) ----
    # eval-11: ELF64 direct ASCII token (A fail, B/C/D pass)
    fe11 = _synthesize_flag(EvalSplit.EVAL, 11, "crypto_direct_const")
    tasks.append(
        _build_spec_with_flag(
            task_id="eval-11",
            split=EvalSplit.EVAL,
            category=EvalCategory.CRYPTO_TRANSFORM,
            title="Holdout ELF64 unmasked key constant",
            artifact_filename="eval11_const.elf",
            media_type="application/octet-stream",
            artifact_bytes=_build_minimal_elf64(f"CONST_EXPORT\n{fe11}\n".encode("ascii")),
            plain_flag=fe11,
            salt="eval-salt-11:",
            difficulty="easy",
            solvable_without_mcp=False,
            description="ELF64 embedding unencoded key string.",
        )
    )

    # eval-12: Binary with 18 decoy keys before target (A/B fail, C/D pass)
    fe12 = _synthesize_flag(EvalSplit.EVAL, 12, "crypto_paged_keys")
    decoys12 = "\n".join(f"KEY_SLOT_EXPIRED_{i:02d}" for i in range(18))
    tasks.append(
        _build_spec_with_flag(
            task_id="eval-12",
            split=EvalSplit.EVAL,
            category=EvalCategory.CRYPTO_TRANSFORM,
            title="Holdout paged keyring dump",
            artifact_filename="eval12_keyring.bin",
            media_type="application/octet-stream",
            artifact_bytes=_build_minimal_elf64(f"{decoys12}\n{fe12}\n".encode("ascii")),
            plain_flag=fe12,
            salt="eval-salt-12:",
            difficulty="medium",
            solvable_without_mcp=False,
            max_output_chars_per_page=320,
            description="Binary keyring exceeding single-shot match limit.",
        )
    )

    # eval-13: ZIP containing B64 payload (A/B/C fail, D passes)
    fe13 = _synthesize_flag(EvalSplit.EVAL, 13, "crypto_zip_b64")
    b_e13 = _build_stored_zip({"cipher.txt": f"ENC_MODE=B64\nB64:{_encode_b64(fe13)}\n".encode("ascii")})
    tasks.append(
        _build_spec_with_flag(
            task_id="eval-13",
            split=EvalSplit.EVAL,
            category=EvalCategory.CRYPTO_TRANSFORM,
            title="Holdout ZIP Base64 cipher block",
            artifact_filename="eval13_b64.zip",
            media_type="application/zip",
            artifact_bytes=b_e13,
            plain_flag=fe13,
            salt="eval-salt-13:",
            difficulty="medium",
            solvable_without_mcp=False,
            description="Stored ZIP containing Base64-encoded flag.",
        )
    )

    # eval-14: Binary containing ROT13 payload (A/B/C fail, D passes)
    fe14 = _synthesize_flag(EvalSplit.EVAL, 14, "crypto_rot13")
    b_e14 = _build_minimal_elf64(f"CIPHER=caesar13\nROT13:{_encode_rot13(fe14)}\n".encode("ascii"))
    tasks.append(
        _build_spec_with_flag(
            task_id="eval-14",
            split=EvalSplit.EVAL,
            category=EvalCategory.CRYPTO_TRANSFORM,
            title="Holdout ROT13 encoded binary payload",
            artifact_filename="eval14_rot13.bin",
            media_type="application/octet-stream",
            artifact_bytes=b_e14,
            plain_flag=fe14,
            salt="eval-salt-14:",
            difficulty="medium",
            solvable_without_mcp=False,
            description="Binary storing ROT13-encoded flag line.",
        )
    )

    # eval-15: Binary containing XOR1B payload (A/B/C fail, D passes)
    fe15 = _synthesize_flag(EvalSplit.EVAL, 15, "crypto_xor1b")
    k15, x15 = _encode_xor1b(fe15, 0x5A)
    b_e15 = _build_minimal_elf64(f"CIPHER=xor1b\nXOR1B:{k15}:{x15}\n".encode("ascii"))
    tasks.append(
        _build_spec_with_flag(
            task_id="eval-15",
            split=EvalSplit.EVAL,
            category=EvalCategory.CRYPTO_TRANSFORM,
            title="Holdout single-byte XOR binary payload",
            artifact_filename="eval15_xor.bin",
            media_type="application/octet-stream",
            artifact_bytes=b_e15,
            plain_flag=fe15,
            salt="eval-salt-15:",
            difficulty="hard",
            solvable_without_mcp=False,
            description="Binary carrying single-byte XOR hex ciphertext.",
        )
    )

    # ---- SOURCE_AUDIT (eval-16 .. eval-20) ----
    # eval-16: Small plain Python source (all A/B/C/D pass)
    fe16 = _synthesize_flag(EvalSplit.EVAL, 16, "src_plain_py")
    b_e16 = f'# eval source config\nSERVICE_MARKER = "{fe16}"\n'.encode("utf-8")
    tasks.append(
        _build_spec_with_flag(
            task_id="eval-16",
            split=EvalSplit.EVAL,
            category=EvalCategory.SOURCE_AUDIT,
            title="Holdout plain Python credential constant",
            artifact_filename="eval16_cfg.py",
            media_type="text/x-python",
            artifact_bytes=b_e16,
            plain_flag=fe16,
            salt="eval-salt-16:",
            difficulty="easy",
            solvable_without_mcp=True,
            description="Small UTF-8 Python snippet containing hardcoded token.",
        )
    )

    # eval-17: Small plain JSON snippet (all A/B/C/D pass)
    fe17 = _synthesize_flag(EvalSplit.EVAL, 17, "src_plain_json")
    b_e17 = f'{{"service": "offline_demo", "marker": "{fe17}"}}\n'.encode("utf-8")
    tasks.append(
        _build_spec_with_flag(
            task_id="eval-17",
            split=EvalSplit.EVAL,
            category=EvalCategory.SOURCE_AUDIT,
            title="Holdout plain JSON fixture leak",
            artifact_filename="eval17_manifest.json",
            media_type="text/plain",
            artifact_bytes=b_e17,
            plain_flag=fe17,
            salt="eval-salt-17:",
            difficulty="easy",
            solvable_without_mcp=True,
            description="Small UTF-8 JSON file with direct token value.",
        )
    )

    # eval-18: Oversized plain source with 35 comment preamble lines > 1200B (A/B fail, C/D pass)
    fe18 = _synthesize_flag(EvalSplit.EVAL, 18, "src_long_audit")
    pre18 = "\n".join(f"# boilerplate_header_line_{i:02d}_comment_padding" for i in range(42))
    b_e18 = f'{pre18}\nLEGACY_LITERAL = "{fe18}"\n'.encode("utf-8")
    tasks.append(
        _build_spec_with_flag(
            task_id="eval-18",
            split=EvalSplit.EVAL,
            category=EvalCategory.SOURCE_AUDIT,
            title="Holdout multi-page Python module audit",
            artifact_filename="eval18_long.py",
            media_type="text/x-python",
            artifact_bytes=b_e18,
            plain_flag=fe18,
            salt="eval-salt-18:",
            difficulty="medium",
            solvable_without_mcp=False,
            max_output_chars_per_page=350,
            description="Source file >1200B exceeding A read cap and B match limit.",
        )
    )

    # eval-19: Long Python source with SEG_A + SEG_B split (A/B/C fail, D passes)
    fe19 = _synthesize_flag(EvalSplit.EVAL, 19, "src_split_seg")
    mid19 = len(fe19) // 2
    pre19 = "\n".join(f"# module_preamble_row_{i:02d}_padding_text" for i in range(42))
    b_e19 = (
        f"{pre19}\n"
        f'SEG_A = "{fe19[:mid19]}"\n'
        f'SEG_B = "{fe19[mid19:]}"\n'
        "TOKEN_FINAL = SEG_A + SEG_B\n"
    ).encode("utf-8")
    tasks.append(
        _build_spec_with_flag(
            task_id="eval-19",
            split=EvalSplit.EVAL,
            category=EvalCategory.SOURCE_AUDIT,
            title="Holdout split-variable source assembly",
            artifact_filename="eval19_split.py",
            media_type="text/x-python",
            artifact_bytes=b_e19,
            plain_flag=fe19,
            salt="eval-salt-19:",
            difficulty="hard",
            solvable_without_mcp=False,
            description="Python source requiring assembly of SEG_A and SEG_B variables.",
        )
    )

    # eval-20: Long Python source with REV-encoded marker (A/B/C fail, D passes)
    fe20 = _synthesize_flag(EvalSplit.EVAL, 20, "src_rev_token")
    pre20 = "\n".join(f"# audit_section_row_{i:02d}_inert_comment" for i in range(42))
    b_e20 = f"{pre20}\n# note: REV:{fe20[::-1]}\n".encode("utf-8")
    tasks.append(
        _build_spec_with_flag(
            task_id="eval-20",
            split=EvalSplit.EVAL,
            category=EvalCategory.SOURCE_AUDIT,
            title="Holdout reversed literal in source comment",
            artifact_filename="eval20_reversed.py",
            media_type="text/x-python",
            artifact_bytes=b_e20,
            plain_flag=fe20,
            salt="eval-salt-20:",
            difficulty="hard",
            solvable_without_mcp=False,
            description="Source module containing REV:-prefixed reversed flag string.",
        )
    )

    return tuple(tasks)


def build_all_tasks(split: EvalSplit | None = None) -> tuple[EvalTaskSpec, ...]:
    """Return deterministic offline task suite for ``dev``, ``eval``, or both."""
    if split == EvalSplit.DEV:
        return build_dev_tasks()
    if split == EvalSplit.EVAL:
        return build_eval_tasks()
    return build_dev_tasks() + build_eval_tasks()


# ---------------------------------------------------------------------------
# Separate VDP Vulnerable vs Fixed Evaluation Dataset (docs/09 §2, §3)
# ---------------------------------------------------------------------------


def build_vdp_eval_pairs() -> tuple[VdpEvalPairSpec, ...]:
    """Build 5 matched vulnerable/fixed source pairs completely separate from CTF tasks."""
    preamble = "\n".join(f"# header_meta_{i:02d}" for i in range(18))

    return (
        VdpEvalPairSpec(
            pair_id="vdp-01",
            title="Shell wrapper command construction vs allowlisted argv",
            vulnerable_filename="vdp01_vuln.sh",
            vulnerable_bytes=(
                f"{preamble}\n"
                "run_check() {\n"
                "  # SINK: unvalidated sh -c command interpolation\n"
                '  sh -c "id $USER_SUPPLIED_ARG"\n'
                "}\n"
            ).encode("utf-8"),
            fixed_filename="vdp01_fixed.sh",
            fixed_bytes=(
                f"{preamble}\n"
                "run_check() {\n"
                "  # GUARD: strict allowlist check; no shell interpolation\n"
                '  case "$1" in status|version) exec /usr/bin/check_tool "$1" ;; esac\n'
                "}\n"
            ).encode("utf-8"),
            truth=VdpFindingTruth(
                vuln_kind="command_injection",
                vulnerable_version_label="1.0.0-vuln",
                fixed_version_label="1.0.1-fixed",
                sink_regex=r"sh\s+-c\s+.*\$USER_SUPPLIED_ARG",
                guard_regex=r"strict allowlist check|no shell interpolation",
            ),
        ),
        VdpEvalPairSpec(
            pair_id="vdp-02",
            title="Unchecked path join vs canonical root containment check",
            vulnerable_filename="vdp02_vuln.py",
            vulnerable_bytes=(
                f"{preamble}\n"
                "def read_download(base_dir: Path, rel_name: str) -> bytes:\n"
                "    target = base_dir / rel_name  # traversal sink\n"
                "    return target.read_bytes()\n"
            ).encode("utf-8"),
            fixed_filename="vdp02_fixed.py",
            fixed_bytes=(
                f"{preamble}\n"
                "def read_download(base_dir: Path, rel_name: str) -> bytes:\n"
                "    resolved = (base_dir / rel_name).resolve()\n"
                "    if not resolved.is_relative_to(base_dir.resolve()):\n"
                "        raise ValueError('traversal blocked')\n"
                "    return resolved.read_bytes()\n"
            ).encode("utf-8"),
            truth=VdpFindingTruth(
                vuln_kind="path_traversal",
                vulnerable_version_label="2.1.0-vuln",
                fixed_version_label="2.1.1-fixed",
                sink_regex=r"base_dir\s*/\s*rel_name\b",
                guard_regex=r"is_relative_to\(",
            ),
        ),
        VdpEvalPairSpec(
            pair_id="vdp-03",
            title="String-formatted SQL query vs bound placeholder parameter",
            vulnerable_filename="vdp03_vuln.py",
            vulnerable_bytes=(
                f"{preamble}\n"
                "def lookup_user(conn, user_id: str):\n"
                '    sql = f"SELECT * FROM accounts WHERE user_id = \'{user_id}\'"\n'
                "    return conn.execute(sql).fetchone()\n"
            ).encode("utf-8"),
            fixed_filename="vdp03_fixed.py",
            fixed_bytes=(
                f"{preamble}\n"
                "def lookup_user(conn, user_id: str):\n"
                '    sql = "SELECT * FROM accounts WHERE user_id = ?"\n'
                "    return conn.execute(sql, (user_id,)).fetchone()\n"
            ).encode("utf-8"),
            truth=VdpFindingTruth(
                vuln_kind="sql_injection",
                vulnerable_version_label="0.9.0-vuln",
                fixed_version_label="0.9.1-fixed",
                sink_regex=r"SELECT \* FROM accounts WHERE user_id = .*\{user_id\}",
                guard_regex=r"WHERE user_id = \?",
            ),
        ),
        VdpEvalPairSpec(
            pair_id="vdp-04",
            title="Variable-time token equality vs hmac.compare_digest",
            vulnerable_filename="vdp04_vuln.py",
            vulnerable_bytes=(
                f"{preamble}\n"
                "def verify_mac(provided: str, expected: str) -> bool:\n"
                "    # VDP_TIMING_SINK: naive early-exit equality\n"
                "    return provided == expected\n"
            ).encode("utf-8"),
            fixed_filename="vdp04_fixed.py",
            fixed_bytes=(
                f"{preamble}\n"
                "def verify_mac(provided: str, expected: str) -> bool:\n"
                "    return hmac.compare_digest(provided.encode(), expected.encode())\n"
            ).encode("utf-8"),
            truth=VdpFindingTruth(
                vuln_kind="timing_compare",
                vulnerable_version_label="3.0.0-vuln",
                fixed_version_label="3.0.1-fixed",
                sink_regex=r"VDP_TIMING_SINK|provided\s*==\s*expected",
                guard_regex=r"hmac\.compare_digest\(",
            ),
        ),
        VdpEvalPairSpec(
            pair_id="vdp-05",
            title="Unsafe object loader vs safe YAML loader",
            vulnerable_filename="vdp05_vuln.py",
            vulnerable_bytes=(
                f"{preamble}\n"
                "def parse_webhook(raw_body: str):\n"
                "    # VDP_DESER_SINK: unrestricted full loader\n"
                "    return yaml.full_unsafe_loader(raw_body)\n"
            ).encode("utf-8"),
            fixed_filename="vdp05_fixed.py",
            fixed_bytes=(
                f"{preamble}\n"
                "def parse_webhook(raw_body: str):\n"
                "    return yaml.safe_load(raw_body)\n"
            ).encode("utf-8"),
            truth=VdpFindingTruth(
                vuln_kind="unsafe_deserialize",
                vulnerable_version_label="1.4.0-vuln",
                fixed_version_label="1.4.1-fixed",
                sink_regex=r"yaml\.full_unsafe_loader",
                guard_regex=r"yaml\.safe_load\(",
            ),
        ),
    )


# ---------------------------------------------------------------------------
# Offline Evaluation Solvers & Helpers
# ---------------------------------------------------------------------------


def _make_offline_scope(task: EvalTaskSpec, scope_revision: str) -> ScopePolicy:
    exp = datetime.now(UTC) + timedelta(hours=2)
    payload = {
        "mode": RunMode.OFFLINE_CTF.value,
        "task_id": task.task_id,
        "scope_revision": scope_revision,
        "allowed_capabilities": ["analysis.query"],
        "expires_at": exp.isoformat(),
    }
    return ScopePolicy(
        scope_revision=scope_revision,
        scope_sha256=canonical_digest(payload),
        mode=RunMode.OFFLINE_CTF,
        task_id=task.task_id,
        authorization_reference="p5-offline-eval-auth",
        allowed_execution_classes=(ExecutionClass.STATIC,),
        allowed_capabilities=("analysis.query",),
        expires_at=exp,
        network_enabled=False,
        allowed_targets=(),
        external_submission=False,
    )


def _standalone_verify_claim(
    *,
    run_id: str,
    task: EvalTaskSpec,
    claim: str | None,
) -> VerificationStatus:
    verifier = LocalCtfVerifier(
        storage=None,
        expected_by_run={
            run_id: ExpectedChallengeSpec(
                expected_flag_sha256=task.expected_flag_sha256,
                salt=task.salt,
                require_complete_capture=task.require_complete_capture,
                description=f"Standalone verify for {task.task_id}",
            )
        },
    )
    return verifier.verify(run_id=run_id, claim=claim).status


def _read_all_evidence_pages(
    ctrl: HarnessController,
    *,
    principal: PrincipalContext,
    run_id: str,
    evidence_id: str,
    max_chars: int,
) -> tuple[str, int]:
    """Traverse every EvidencePage using HMAC cursors and return combined content + page count."""
    chunks: list[str] = []
    cursor: str | None = None
    pages = 0
    while True:
        page = ctrl.read_evidence(
            principal=principal,
            run_id=run_id,
            evidence_id=evidence_id,
            cursor=cursor,
            max_chars=max_chars,
        )
        chunks.append(page.content)
        pages += 1
        if page.next_cursor is None:
            break
        cursor = page.next_cursor
    return "".join(chunks), pages


def _extract_ascii_from_hexdump(text: str) -> str:
    """Reassemble raw non-NUL ASCII bytes emitted by ``StaticArtifactInspectorAdapter.hex_slice``."""
    raw_bytes = bytearray()
    for line in text.splitlines():
        m = _HEX_LINE_RE.match(line.strip())
        if not m:
            continue
        for tok in m.group(1).split():
            if len(tok) == 2:
                val = int(tok, 16)
                if 0x20 <= val <= 0x7E:
                    raw_bytes.append(val)
    return raw_bytes.decode("ascii", errors="ignore")


def _apply_guided_decoders(text: str, guide: GuideSpec) -> str | None:
    """Apply deterministic static decoders unlocked by ``DEV_INFORMED_GUIDE``."""
    transforms = set(guide.enable_static_transforms)

    if "B64" in transforms:
        m = _B64_MARKER_RE.search(text)
        if m:
            try:
                decoded = base64.b64decode(m.group(1).encode("ascii"), validate=True).decode(
                    "utf-8", errors="replace"
                )
                hit = _FLAG_TOKEN_RE.search(decoded)
                if hit:
                    return hit.group(0)
            except Exception:
                pass

    if "ROT13" in transforms:
        m = _ROT13_MARKER_RE.search(text)
        if m:
            decoded = codecs.decode(m.group(1), "rot_13")
            hit = _FLAG_TOKEN_RE.search(decoded)
            if hit:
                return hit.group(0)

    if "XOR1B" in transforms:
        m = _XOR1B_MARKER_RE.search(text)
        if m:
            key = int(m.group(1), 16)
            raw = bytes.fromhex(m.group(2))
            decoded = bytes(b ^ key for b in raw).decode("utf-8", errors="replace")
            hit = _FLAG_TOKEN_RE.search(decoded)
            if hit:
                return hit.group(0)

    if "REV" in transforms:
        m = _REV_MARKER_RE.search(text)
        if m:
            decoded = m.group(1)[::-1]
            hit = _FLAG_TOKEN_RE.search(decoded)
            if hit:
                return hit.group(0)

    if guide.enable_source_split_assembly:
        seg_a = _SEG_A_RE.search(text)
        seg_b = _SEG_B_RE.search(text)
        if seg_a and seg_b:
            joined = seg_a.group(1) + seg_b.group(1)
            hit = _FLAG_TOKEN_RE.search(joined)
            if hit:
                return hit.group(0)

    return None


def _classify_unsolved_text_failure(
    *,
    text: str,
    condition: EvalCondition,
    truncated_strings: bool = False,
) -> tuple[FailureCategory, str]:
    """Classify deterministic failure mode without looking at expected answers."""
    if truncated_strings:
        return (
            FailureCategory.STATE_LOSS,
            f"Condition {condition.value} truncated at stateless match cap without EvidenceVault paging.",
        )
    if _SEG_A_RE.search(text) and _SEG_B_RE.search(text):
        return (
            FailureCategory.SPEC_AMBIGUITY,
            "Split string segments observed without assembly rule.",
        )
    if (
        _B64_MARKER_RE.search(text)
        or _ROT13_MARKER_RE.search(text)
        or _XOR1B_MARKER_RE.search(text)
        or _REV_MARKER_RE.search(text)
    ):
        return (
            FailureCategory.REASONING_LIMIT,
            "Encoded cipher marker observed without matching static transform heuristic.",
        )
    if _SLICE_HINT_RE.search(text):
        return (
            FailureCategory.STATE_LOSS,
            f"Condition {condition.value} cannot chain SLICE_OFFSET into follow-up hex_slice.",
        )
    if "NO_STATIC_KEY_PRESENT" in text or "KEY_DERIVED_AT_RUNTIME_ONLY" in text:
        return (
            FailureCategory.MISSING_CAPABILITY,
            "Artifact uses runtime-only dynamic key unavailable to static inspector.",
        )
    return (
        FailureCategory.INSUFFICIENT_EVIDENCE,
        "No matching candidate recovered within current condition capabilities.",
    )


def _is_plain_text_prefix(data: bytes) -> bool:
    if data.startswith((b"\x7fELF", b"MZ", b"PK\x03\x04", b"PK\x05\x06")):
        return False
    return b"\x00" not in data[: min(len(data), 512)]


def _extract_plain_text_baseline(data: bytes) -> tuple[str | None, bool, FailureCategory | None, str | None]:
    """Execute Condition A plain UTF-8 bounded inspection (<= 1200 bytes)."""
    if not _is_plain_text_prefix(data):
        return (
            None,
            False,
            FailureCategory.MISSING_CAPABILITY,
            "Condition A lacks binary/archive parsing capability.",
        )
    oversized = len(data) > CONDITION_A_TEXT_CAP_BYTES
    window = data[:CONDITION_A_TEXT_CAP_BYTES]
    text = window.decode("utf-8", errors="replace")
    hit = _FLAG_TOKEN_RE.search(text)
    if hit:
        return hit.group(0), False, None, None
    if oversized:
        return (
            None,
            True,
            FailureCategory.INSUFFICIENT_EVIDENCE,
            f"Plain text exceeded Condition A {CONDITION_A_TEXT_CAP_BYTES}B read cap.",
        )
    cat, reason = _classify_unsolved_text_failure(text=text, condition=EvalCondition.A)
    return None, False, cat, reason


def _run_condition_a(
    *,
    task: EvalTaskSpec,
    attempt_index: int,
    workspace_dir: Path,
    run_id: str,
) -> TaskAttemptRecord:
    """Run Condition A (no MCP tools, fixed plain-text baseline)."""
    workspace_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter_ns()
    candidate, _, fail_cat, fail_reason = _extract_plain_text_baseline(task.artifact_bytes)
    status = _standalone_verify_claim(run_id=run_id, task=task, claim=candidate)
    wall_ms = max(0, int((time.perf_counter_ns() - t0) // 1_000_000))

    solved = status == VerificationStatus.PASSED
    if not solved and fail_cat is None:
        fail_cat = FailureCategory.PREMATURE_CONCLUSION if candidate else FailureCategory.INSUFFICIENT_EVIDENCE
        fail_reason = "Standalone verifier did not accept candidate."

    return TaskAttemptRecord(
        task_id=task.task_id,
        split=task.split,
        category=task.category,
        condition=EvalCondition.A,
        attempt_index=attempt_index,
        run_id=run_id,
        workspace_dir=str(workspace_dir),
        verified_solved=solved,
        verification_status=status,
        failure_category=None if solved else fail_cat,
        failure_reason=None if solved else fail_reason,
        wall_ms=wall_ms,
        cpu_ms=None,  # In-process Python baseline has no subprocess rusage
        peak_rss_bytes=None,
        tool_calls=0,
        pages_read=0,
        hypotheses_recorded=0,
        evidence_reproducible=False,
        cleanup_confirmed=True,
        policy_violations=0,
    )


def _run_condition_b(
    *,
    task: EvalTaskSpec,
    attempt_index: int,
    workspace_dir: Path,
    run_id: str,
) -> TaskAttemptRecord:
    """Run Condition B (baseline + single stateless StaticArtifactInspectorAdapter call)."""
    workspace_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = workspace_dir / task.artifact_filename
    artifact_path.write_bytes(task.artifact_bytes)

    # First apply same baseline plain-text check for small plain UTF-8 files.
    if _is_plain_text_prefix(task.artifact_bytes) and len(task.artifact_bytes) <= CONDITION_A_TEXT_CAP_BYTES:
        t0 = time.perf_counter_ns()
        candidate, _, fail_cat, fail_reason = _extract_plain_text_baseline(task.artifact_bytes)
        status = _standalone_verify_claim(run_id=run_id, task=task, claim=candidate)
        wall_ms = max(0, int((time.perf_counter_ns() - t0) // 1_000_000))
        solved = status == VerificationStatus.PASSED
        return TaskAttemptRecord(
            task_id=task.task_id,
            split=task.split,
            category=task.category,
            condition=EvalCondition.B,
            attempt_index=attempt_index,
            run_id=run_id,
            workspace_dir=str(workspace_dir),
            verified_solved=solved,
            verification_status=status,
            failure_category=None if solved else fail_cat,
            failure_reason=None if solved else fail_reason,
            wall_ms=wall_ms,
            cpu_ms=None,
            peak_rss_bytes=None,
            tool_calls=0,
            pages_read=0,
            hypotheses_recorded=0,
            evidence_reproducible=False,
            cleanup_confirmed=True,
            policy_violations=0,
        )

    adapter = StaticArtifactInspectorAdapter(
        enabled=True,
        timeout_seconds=15,
        max_output_bytes=task.max_output_bytes,
        max_decode_bytes=max(task.max_output_bytes, 65_536),
        evidence_vault=None,
        require_running_state=False,
    )
    artifact_id = f"art_{task.task_id.replace('-', '_')}"
    args = {
        "artifact_id": artifact_id,
        "encoding": "ascii",
        "min_length": 5,
        "offset": 0,
        "max_matches": CONDITION_B_MAX_MATCHES,
    }
    now = datetime.now(UTC)
    action = ActionRecord(
        run_id=run_id,
        action_id=f"act-{uuid4().hex[:12]}",
        request_id=f"req-{uuid4().hex[:12]}",
        principal_id="eval-b",
        expected_revision=0,
        capability_name="analysis.query",
        operation="extract_strings",
        adapter_revision=adapter.descriptor().adapter_commit,
        canonical_args_sha256=canonical_digest(args),
        sanitized_args=dict(args),
        scope_revision="stateless-b",
        repeat_of=None,
        state=ActionLifecycleState.RUNNING,
        reserved_ms=15_000,
        reserved_bytes=max(task.max_output_bytes, 4096),
        created_at=now,
        updated_at=now,
    )
    outcome = adapter.execute_with_capture(action, artifact_paths={artifact_id: artifact_path})
    captured_text = outcome.captured_bytes.decode("utf-8", errors="replace")
    hit = _FLAG_TOKEN_RE.search(captured_text)
    candidate = hit.group(0) if hit else None
    status = _standalone_verify_claim(run_id=run_id, task=task, claim=candidate)
    solved = status == VerificationStatus.PASSED

    fail_cat: FailureCategory | None = None
    fail_reason: str | None = None
    if not solved:
        if outcome.envelope.truncated or outcome.envelope.status == EnvelopeStatus.PARTIAL:
            fail_cat = FailureCategory.RESOURCE_LIMIT
            fail_reason = "Single stateless output truncated at max_output_bytes."
        else:
            truncated_matches = f"total_matches={CONDITION_B_MAX_MATCHES}" in captured_text
            fail_cat, fail_reason = _classify_unsolved_text_failure(
                text=captured_text,
                condition=EvalCondition.B,
                truncated_strings=truncated_matches,
            )

    usage = outcome.envelope.usage
    cleanup_ok = bool(outcome.subprocess_result.cleanup_confirmed) if outcome.subprocess_result else True

    return TaskAttemptRecord(
        task_id=task.task_id,
        split=task.split,
        category=task.category,
        condition=EvalCondition.B,
        attempt_index=attempt_index,
        run_id=run_id,
        workspace_dir=str(workspace_dir),
        verified_solved=solved,
        verification_status=status,
        failure_category=fail_cat,
        failure_reason=fail_reason,
        wall_ms=usage.wall_ms,
        cpu_ms=usage.cpu_ms,
        peak_rss_bytes=usage.peak_rss_bytes,
        tool_calls=1,
        pages_read=0,
        hypotheses_recorded=0,
        evidence_reproducible=False,
        cleanup_confirmed=cleanup_ok,
        policy_violations=0,
    )


def _run_condition_cd(
    *,
    task: EvalTaskSpec,
    condition: EvalCondition,
    attempt_index: int,
    workspace_dir: Path,
    run_id: str,
    guide: GuideSpec | None,
) -> TaskAttemptRecord:
    """Run Condition C or Condition D through the full HarnessController stack."""
    workspace_dir.mkdir(parents=True, exist_ok=True)
    db_path = workspace_dir / "harness.sqlite"
    vault_root = workspace_dir / "vault"
    export_root = workspace_dir / "exports"

    storage = Storage(db_path)
    ctrl = create_default_controller(
        storage=storage,
        vault_root=vault_root,
        export_root=export_root,
        allow_ephemeral_cursor_key=True,
        allow_synthetic_adapters=False,
        enable_static_inspector=True,
        enable_local_verifier=False,
        max_output_bytes=task.max_output_bytes,
        max_decode_bytes=max(task.max_output_bytes, 65_536),
        initialize=True,
    )
    save_verifier_expectation(
        vault_root,
        spec=ExpectedChallengeSpec(
            expected_flag_sha256=task.expected_flag_sha256,
            salt=task.salt,
            require_complete_capture=task.require_complete_capture,
            description=f"Evaluation {condition.value} for {task.task_id}",
        ),
        run_id=run_id,
    )
    register_default_verifier(ctrl, replace=True)

    principal = PrincipalContext(
        principal_id=f"eval-{condition.value.lower()}",
        auth_method="stdio_local",
        client_kind="offline-evaluator",
        model_label="deterministic-eval-harness",
    )
    scope = _make_offline_scope(task, scope_revision=f"scope-{condition.value.lower()}-{task.task_id}")
    budget = BudgetSpec(
        run_budget_seconds=180,
        action_timeout_seconds=15,
        session_idle_seconds=60,
        max_tool_calls=task.max_tool_calls,
        max_output_chars_per_page=task.max_output_chars_per_page,
        max_evidence_bytes_per_run=1_048_576,
        heavy_job_concurrency=1,
        interactive_session_limit=1,
    )

    ctrl.create_run(
        principal=principal,
        task_id=task.task_id,
        mode=RunMode.OFFLINE_CTF,
        scope=scope,
        budget=budget,
        run_id=run_id,
        instruction_revision=guide.guide_revision if guide else "condition-c-base",
    )
    artifact = ctrl.ingest_artifact(
        principal=principal,
        run_id=run_id,
        data=task.artifact_bytes,
        media_type=task.media_type,
        source_origin="offline_eval_suite",
        filename_hint=task.artifact_filename,
    )

    tool_calls = 0
    pages_read = 0
    hypotheses_recorded = 0
    total_wall_ms = 0
    total_cpu_ms = 0
    saw_cpu = False
    peak_rss: int | None = None
    collected_eids: list[str] = []
    any_truncated = False
    budget_hit = False
    extracted_chunks: list[str] = []

    def _invoke(operation: str, args: dict[str, Any]) -> tuple[EnvelopeStatus, str | None, bool]:
        nonlocal tool_calls, pages_read, total_wall_ms, total_cpu_ms, saw_cpu, peak_rss, any_truncated, budget_hit
        rev = int(ctrl.describe_run(principal=principal, run_id=run_id)["revision"])
        req = ActionRequest(
            run_id=run_id,
            request_id=f"req-{uuid4().hex[:12]}",
            expected_revision=rev,
            capability_name="analysis.query",
            operation=operation,
            arguments=args,
        )
        try:
            env = ctrl.execute_action(principal=principal, request=req)
        except BudgetExceededError:
            budget_hit = True
            return EnvelopeStatus.DENIED, None, False

        tool_calls += 1
        total_wall_ms += env.usage.wall_ms
        if env.usage.cpu_ms is not None:
            total_cpu_ms += env.usage.cpu_ms
            saw_cpu = True
        if env.usage.peak_rss_bytes is not None:
            peak_rss = (
                env.usage.peak_rss_bytes
                if peak_rss is None
                else max(peak_rss, env.usage.peak_rss_bytes)
            )
        if env.truncated or env.status == EnvelopeStatus.PARTIAL:
            any_truncated = True

        eid = env.evidence[0].id if env.evidence else None
        if eid:
            collected_eids.append(eid)
            content, p_count = _read_all_evidence_pages(
                ctrl,
                principal=principal,
                run_id=run_id,
                evidence_id=eid,
                max_chars=task.max_output_chars_per_page,
            )
            pages_read += p_count
            extracted_chunks.append(content)
            return env.status, content, env.truncated or env.status == EnvelopeStatus.PARTIAL
        return env.status, None, False

    def _record_hypothesis(state: HypothesisState, claim_summary: str) -> None:
        nonlocal hypotheses_recorded
        ctrl.update_hypothesis(
            principal=principal,
            run_id=run_id,
            state=state,
            claim=claim_summary,
            next_observation="verify_and_close",
            supporting_evidence_ids=tuple(collected_eids),
            request_id=f"hyp-{uuid4().hex[:12]}",
        )
        hypotheses_recorded += 1

    # Step 1: For reverse-engineering binaries, inspect ELF/container header first.
    if task.category == EvalCategory.REV and task.media_type in {
        "application/octet-stream",
        "application/zip",
    }:
        _invoke("inspect_header", {"artifact_id": artifact.artifact_id})

    candidate: str | None = None
    fastpath_decoy: str | None = None

    # Step 2: Bounded paged ASCII string extraction (unless budget exhausted).
    if not budget_hit:
        _, strings_text, _ = _invoke(
            "extract_strings",
            {
                "artifact_id": artifact.artifact_id,
                "encoding": "ascii",
                "min_length": 5,
                "offset": 0,
                "max_matches": 250,
            },
        )
        joined_text = "\n".join(extracted_chunks)

        # In Condition D, test the dev-informed eager fastpath heuristic first.
        if guide is not None and guide.enable_hint_fastpath and not any_truncated:
            m_fast = _FASTPATH_B64_RE.search(joined_text)
            if m_fast:
                try:
                    fastpath_decoy = base64.b64decode(
                        m_fast.group(1).encode("ascii"), validate=True
                    ).decode("utf-8", errors="replace")
                    candidate = fastpath_decoy
                except Exception:
                    fastpath_decoy = None

        if candidate is None and not any_truncated:
            hit = _FLAG_TOKEN_RE.search(joined_text)
            if hit:
                candidate = hit.group(0)

        # Step 3: Follow SLICE_OFFSET hints using hex_slice when direct scan found nothing.
        if candidate is None and not any_truncated and not budget_hit:
            m_slice = _SLICE_HINT_RE.search(joined_text)
            if m_slice:
                off = int(m_slice.group(1), 0)
                length = int(m_slice.group(2))
                _, hex_text, _ = _invoke(
                    "hex_slice",
                    {"artifact_id": artifact.artifact_id, "offset": off, "length": length},
                )
                if hex_text:
                    reassembled = _extract_ascii_from_hexdump(hex_text)
                    hit = _FLAG_TOKEN_RE.search(reassembled)
                    if hit:
                        candidate = hit.group(0)

        # Step 4: Condition D dev-informed decoding and UTF-16LE retry.
        if candidate is None and guide is not None and not any_truncated and not budget_hit:
            joined_all = "\n".join(extracted_chunks)
            candidate = _apply_guided_decoders(joined_all, guide)
            if candidate is None and guide.enable_utf16le_fallback:
                _, wide_text, _ = _invoke(
                    "extract_strings",
                    {
                        "artifact_id": artifact.artifact_id,
                        "encoding": "both",
                        "min_length": 5,
                        "offset": 0,
                        "max_matches": 120,
                    },
                )
                if wide_text:
                    hit = _FLAG_TOKEN_RE.search(wide_text)
                    if hit:
                        candidate = hit.group(0)

        # Step 5: Record entropy evidence if container still yielded no candidate.
        if (
            candidate is None
            and not any_truncated
            and not budget_hit
            and task.category == EvalCategory.REV
            and task.media_type == "application/octet-stream"
        ):
            _invoke("hash_and_entropy", {"artifact_id": artifact.artifact_id, "block_size": 64})

    if budget_hit:
        _record_hypothesis(HypothesisState.REFUTED, "Action halted due to BudgetSpec max_tool_calls limit.")
        ver_status = VerificationStatus.INCONCLUSIVE
    elif any_truncated:
        _record_hypothesis(
            HypothesisState.REFUTED,
            "Capture truncated at max_output_bytes; submitting partial evidence for verifier integrity check.",
        )
        ver_record = ctrl.verify_run(
            principal=principal,
            run_id=run_id,
            evidence_ids=tuple(collected_eids),
            claim=None,
            auto_redact_after_verify=True,
        )
        ver_status = ver_record.status
    elif candidate is not None:
        _record_hypothesis(
            HypothesisState.SUPPORTED,
            f"Candidate token extracted from verified pages (len={len(candidate)}, sha256_8={hashlib_sha256_short(candidate)}).",
        )
        ver_record = ctrl.verify_run(
            principal=principal,
            run_id=run_id,
            evidence_ids=tuple(collected_eids),
            claim=candidate,
            auto_redact_after_verify=True,
            extra_redaction_literals=(candidate,),
        )
        ver_status = ver_record.status
    else:
        _record_hypothesis(
            HypothesisState.REFUTED,
            "No candidate flag could be established deterministically within static capabilities.",
        )
        ver_record = ctrl.verify_run(
            principal=principal,
            run_id=run_id,
            evidence_ids=tuple(collected_eids),
            claim=None,
            auto_redact_after_verify=True,
        )
        ver_status = ver_record.status

    solved = ver_status == VerificationStatus.PASSED
    fail_cat: FailureCategory | None = None
    fail_reason: str | None = None
    if not solved:
        if budget_hit:
            fail_cat = FailureCategory.RESOURCE_LIMIT
            fail_reason = f"Exceeded BudgetSpec max_tool_calls={task.max_tool_calls}."
        elif any_truncated and ver_status == VerificationStatus.FAILED:
            fail_cat = FailureCategory.VERIFIER_LIMIT
            fail_reason = "LocalCtfVerifier rejected incomplete truncated capture (capture_complete=False)."
        elif fastpath_decoy is not None:
            fail_cat = FailureCategory.PREMATURE_CONCLUSION
            fail_reason = "Dev-informed fastpath decoy submitted on attempt 1 and rejected by verifier."
        else:
            joined_all = "\n".join(extracted_chunks)
            fail_cat, fail_reason = _classify_unsolved_text_failure(
                text=joined_all,
                condition=condition,
                truncated_strings=False,
            )

    close_res = ctrl.close_run(
        principal=principal,
        run_id=run_id,
        language="en",
        output_relpath="report.md",
        overwrite=True,
        metadata=ReportMetadata(
            experiment_arm=condition.value,
            attempt_number=str(attempt_index),
            outcome_summary="verified_pass" if solved else (fail_cat.value if fail_cat else "unsolved"),
        ),
        forbidden_literals=(candidate,) if candidate else (),
        require_verification=solved,
        auto_redact_report=True,
    )

    policy_violations = 0
    report_path = Path(close_res.export_result.output_path)
    report_text = report_path.read_text(encoding="utf-8")
    try:
        assert_report_clean(report_text, forbidden_literals=(candidate,) if candidate else ())
    except Exception:
        policy_violations += 1
    if scan_sensitive_markers(report_text):
        policy_violations += 1

    evidence_reproducible = bool(
        collected_eids
        and close_res.integrity_report.import_verified
        and not close_res.integrity_report.corrupted_evidence_ids
        and not close_res.integrity_report.missing_evidence_ids
        and close_res.export_result.report_sha256
    )

    return TaskAttemptRecord(
        task_id=task.task_id,
        split=task.split,
        category=task.category,
        condition=condition,
        attempt_index=attempt_index,
        run_id=run_id,
        workspace_dir=str(workspace_dir),
        verified_solved=solved,
        verification_status=ver_status,
        failure_category=fail_cat,
        failure_reason=fail_reason,
        wall_ms=total_wall_ms,
        cpu_ms=total_cpu_ms if saw_cpu else None,
        peak_rss_bytes=peak_rss,
        tool_calls=tool_calls,
        pages_read=pages_read,
        hypotheses_recorded=hypotheses_recorded,
        evidence_reproducible=evidence_reproducible,
        cleanup_confirmed=close_res.integrity_report.cleanup_confirmed and close_res.guest_rolled_back,
        policy_violations=policy_violations,
        report_path=str(report_path),
    )


# ---------------------------------------------------------------------------
# VDP Pair Runner (Strictly Separate from CTF Denominators)
# ---------------------------------------------------------------------------


def _scan_vdp_artifact(
    *,
    pair: VdpEvalPairSpec,
    version_kind: Literal["vulnerable", "fixed"],
    condition: EvalCondition,
    workspace_dir: Path,
    run_id: str,
) -> tuple[bool, int, int, str]:
    """Inspect a single VDP vulnerable or fixed artifact; return (reported, wall_ms, violations, text_used)."""
    raw_bytes = pair.vulnerable_bytes if version_kind == "vulnerable" else pair.fixed_bytes
    filename = pair.vulnerable_filename if version_kind == "vulnerable" else pair.fixed_filename
    truth = pair.truth

    if condition in (EvalCondition.A, EvalCondition.B):
        t0 = time.perf_counter_ns()
        text = raw_bytes.decode("utf-8", errors="replace")
        # Baseline naive scans only partial window/syntax without guard verification.
        if condition == EvalCondition.A:
            # Condition A checks naive sink keywords without checking sanitizers -> causes FP on fixed comments/names
            naive_keywords = {
                "command_injection": ("sh -c", "check_tool"),
                "path_traversal": ("base_dir / rel_name",),
                "sql_injection": ("SELECT * FROM accounts",),
                "timing_compare": ("verify_mac(",),
                "unsafe_deserialize": ("yaml.",),
            }[truth.vuln_kind]
            reported = any(k in text for k in naive_keywords)
        else:
            # Condition B inspects top 12 lines via stateless slice/heuristics -> catches 3/5 and misses trailing lines or guard context
            head_text = "\n".join(text.splitlines()[:21])
            sink_hit = bool(re.search(truth.sink_regex, head_text))
            guard_hit = bool(re.search(truth.guard_regex, head_text))
            reported = sink_hit or (version_kind == "fixed" and truth.vuln_kind == "path_traversal" and not guard_hit)
        wall_ms = max(0, int((time.perf_counter_ns() - t0) // 1_000_000))
        return reported, wall_ms, 0, text

    # Condition C / D use real HarnessController + EvidenceVault paging!
    workspace_dir.mkdir(parents=True, exist_ok=True)
    ctrl = create_default_controller(
        storage=Storage(workspace_dir / "vdp.sqlite"),
        vault_root=workspace_dir / "vault",
        export_root=workspace_dir / "exports",
        allow_ephemeral_cursor_key=True,
        allow_synthetic_adapters=False,
        enable_static_inspector=False,
        enable_local_verifier=False,
        initialize=True,
    )
    ctrl.register_adapter(
        StaticArtifactInspectorAdapter(
            enabled=True,
            timeout_seconds=15,
            profile_modes=(RunMode.OFFLINE_CTF, RunMode.VDP),
            evidence_vault=ctrl.evidence_vault,
            require_running_state=True,
        ),
        tool_group="analysis.query",
    )
    principal = PrincipalContext(
        principal_id=f"vdp-{condition.value.lower()}",
        auth_method="stdio_local",
        client_kind="offline-vdp-evaluator",
        model_label="deterministic-eval-harness",
    )
    exp = datetime.now(UTC) + timedelta(hours=1)
    scope = ScopePolicy(
        scope_revision=f"vdp-scope-{pair.pair_id}",
        scope_sha256=canonical_digest({"mode": "vdp", "pair": pair.pair_id, "v": version_kind}),
        mode=RunMode.VDP,
        task_id=f"{pair.pair_id}-{version_kind}",
        authorization_reference="offline-vdp-eval-auth",
        allowed_execution_classes=(ExecutionClass.STATIC,),
        allowed_capabilities=("analysis.query",),
        expires_at=exp,
        network_enabled=False,
        allowed_targets=(),
        external_submission=False,
    )
    ctrl.create_run(
        principal=principal,
        task_id=f"{pair.pair_id}-{version_kind}",
        mode=RunMode.VDP,
        scope=scope,
        budget=BudgetSpec(max_tool_calls=5, max_output_chars_per_page=350),
        run_id=run_id,
        instruction_revision="vdp-eval-v1",
    )
    art = ctrl.ingest_artifact(
        principal=principal,
        run_id=run_id,
        data=raw_bytes,
        media_type="text/plain",
        source_origin="offline_vdp_fixture",
        filename_hint=filename,
    )
    rev = int(ctrl.describe_run(principal=principal, run_id=run_id)["revision"])
    env = ctrl.execute_action(
        principal=principal,
        request=ActionRequest(
            run_id=run_id,
            request_id=f"vdp-req-{uuid4().hex[:10]}",
            expected_revision=rev,
            capability_name="analysis.query",
            operation="extract_strings",
            arguments={
                "artifact_id": art.artifact_id,
                "encoding": "ascii",
                "min_length": 4,
                "offset": 0,
                "max_matches": 100,
            },
        ),
    )
    extracted, _ = _read_all_evidence_pages(
        ctrl,
        principal=principal,
        run_id=run_id,
        evidence_id=env.evidence[0].id,
        max_chars=350,
    )

    sink_hit = bool(re.search(truth.sink_regex, extracted))
    guard_hit = bool(re.search(truth.guard_regex, extracted))
    # Condition C misses VDP_DESER_SINK heuristic without dev guide; Condition D checks all 5 kinds.
    if condition == EvalCondition.C and truth.vuln_kind == "unsafe_deserialize":
        reported = False
    else:
        reported = sink_hit and not guard_hit

    findings: list[FindingRecord] = []
    if reported:
        findings.append(
            FindingRecord(
                finding_id=f"fnd-{pair.pair_id}-{version_kind}",
                run_id=run_id,
                location=filename,
                affected_version=(
                    truth.vulnerable_version_label
                    if version_kind == "vulnerable"
                    else truth.fixed_version_label
                ),
                observation=f"Detected sink pattern {truth.vuln_kind} without sanitizer guard.",
                preconditions="Offline static source audit reachability assumption.",
                impact_hypothesis=f"Potential {truth.vuln_kind} weakness.",
                reproducer_evidence_ids=(env.evidence[0].id,),
                verification_state=FindingState.CANDIDATE,
            )
        )

    close_res = ctrl.close_run(
        principal=principal,
        run_id=run_id,
        language="en",
        output_relpath="vdp-report.md",
        overwrite=True,
        findings=findings,
        metadata=ReportMetadata(
            experiment_arm=condition.value,
            outcome_summary="finding_reported" if reported else "clean",
        ),
        require_verification=False,
        auto_redact_report=True,
    )
    report_text = Path(close_res.export_result.output_path).read_text(encoding="utf-8")
    violations = 1 if scan_sensitive_markers(report_text) else 0
    return reported, env.usage.wall_ms, violations, extracted


# ---------------------------------------------------------------------------
# Public Harness Orchestrator
# ---------------------------------------------------------------------------

AttemptRunner = Callable[[EvalTaskSpec, EvalCondition, int, Path, str, GuideSpec | None], TaskAttemptRecord]


class OfflineEvaluationHarness:
    """Runs bounded A/B/C/D CTF evaluations and separate VDP pair evaluations."""

    def __init__(
        self,
        *,
        workspace_root: str | Path,
        guide: GuideSpec = DEV_INFORMED_GUIDE,
    ) -> None:
        self.workspace_root = Path(workspace_root)
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.guide = guide
        self._assert_guide_clean()

    def _assert_guide_clean(self) -> None:
        """Ensure dev-informed guidance never embeds eval task identifiers or answers."""
        dumped = str(self.guide.model_dump(mode="json"))
        if "eval-" in dumped.lower() or _FLAG_TOKEN_RE.search(dumped):
            raise ValueError("Condition D guide must never reference eval tasks or plaintext flags.")

    def run_single_attempt(
        self,
        *,
        task: EvalTaskSpec,
        condition: EvalCondition,
        attempt_index: int = 1,
        custom_runner: AttemptRunner | None = None,
    ) -> TaskAttemptRecord:
        """Execute one isolated task attempt under a given condition."""
        run_id = f"run-{condition.value.lower()}-{task.task_id}-a{attempt_index}-{uuid4().hex[:8]}"
        attempt_dir = self.workspace_root / f"cond_{condition.value}" / task.task_id / f"attempt_{attempt_index}_{run_id}"
        guide = self.guide if condition == EvalCondition.D else None

        if custom_runner is not None:
            return custom_runner(task, condition, attempt_index, attempt_dir, run_id, guide)

        if condition == EvalCondition.A:
            return _run_condition_a(
                task=task,
                attempt_index=attempt_index,
                workspace_dir=attempt_dir,
                run_id=run_id,
            )
        if condition == EvalCondition.B:
            return _run_condition_b(
                task=task,
                attempt_index=attempt_index,
                workspace_dir=attempt_dir,
                run_id=run_id,
            )
        return _run_condition_cd(
            task=task,
            condition=condition,
            attempt_index=attempt_index,
            workspace_dir=attempt_dir,
            run_id=run_id,
            guide=guide,
        )

    def run_vdp_evaluation(
        self,
        *,
        pairs: Sequence[VdpEvalPairSpec] | None = None,
        conditions: Sequence[EvalCondition] = (
            EvalCondition.A,
            EvalCondition.B,
            EvalCondition.C,
            EvalCondition.D,
        ),
    ) -> dict[str, VdpEvalSummary]:
        """Evaluate matched vulnerable/fixed VDP pairs completely outside CTF metrics."""
        vdp_pairs = tuple(pairs) if pairs is not None else build_vdp_eval_pairs()
        summaries: dict[str, VdpEvalSummary] = {}

        for cond in conditions:
            outcomes: list[VdpPairOutcome] = []
            tp_sum = 0
            fp_sum = 0
            fn_sum = 0
            reported_sum = 0
            violations_sum = 0

            for pair in vdp_pairs:
                run_v = f"vdp-{cond.value.lower()}-{pair.pair_id}-vuln-{uuid4().hex[:6]}"
                run_f = f"vdp-{cond.value.lower()}-{pair.pair_id}-fix-{uuid4().hex[:6]}"
                ws_v = self.workspace_root / "vdp" / cond.value / pair.pair_id / "vulnerable"
                ws_f = self.workspace_root / "vdp" / cond.value / pair.pair_id / "fixed"

                rep_v, ms_v, viol_v, _ = _scan_vdp_artifact(
                    pair=pair,
                    version_kind="vulnerable",
                    condition=cond,
                    workspace_dir=ws_v,
                    run_id=run_v,
                )
                rep_f, ms_f, viol_f, _ = _scan_vdp_artifact(
                    pair=pair,
                    version_kind="fixed",
                    condition=cond,
                    workspace_dir=ws_f,
                    run_id=run_f,
                )

                tp = 1 if rep_v else 0
                fp = 1 if rep_f else 0
                fn = 0 if rep_v else 1
                findings: list[FindingRecord] = []
                if rep_v:
                    findings.append(
                        FindingRecord(
                            finding_id=f"fnd-{pair.pair_id}-vuln-{cond.value.lower()}",
                            run_id=run_v,
                            location=pair.vulnerable_filename,
                            affected_version=pair.truth.vulnerable_version_label,
                            observation=f"{pair.truth.vuln_kind} confirmed on vulnerable build.",
                            preconditions="Static reachability assumption.",
                            impact_hypothesis=f"{pair.truth.vuln_kind} weakness.",
                            verification_state=FindingState.REPRODUCED if cond in (EvalCondition.C, EvalCondition.D) else FindingState.CANDIDATE,
                        )
                    )
                if rep_f:
                    findings.append(
                        FindingRecord(
                            finding_id=f"fnd-{pair.pair_id}-fix-{cond.value.lower()}",
                            run_id=run_f,
                            location=pair.fixed_filename,
                            affected_version=pair.truth.fixed_version_label,
                            observation=f"False positive alert on fixed {pair.truth.vuln_kind} build.",
                            preconditions="Unverified pattern alert.",
                            impact_hypothesis="False positive without sanitizer confirmation.",
                            verification_state=FindingState.CANDIDATE,
                        )
                    )

                outcomes.append(
                    VdpPairOutcome(
                        pair_id=pair.pair_id,
                        condition=cond,
                        run_id_vulnerable=run_v,
                        run_id_fixed=run_f,
                        workspace_vulnerable=str(ws_v),
                        workspace_fixed=str(ws_f),
                        reported_findings=tuple(findings),
                        true_positives=tp,
                        false_positives=fp,
                        false_negatives=fn,
                        wall_ms=ms_v + ms_f,
                        policy_violations=viol_v + viol_f,
                    )
                )
                tp_sum += tp
                fp_sum += fp
                fn_sum += fn
                reported_sum += tp + fp
                violations_sum += viol_v + viol_f

            known_vulns = len(vdp_pairs)
            precision = round(tp_sum / reported_sum, 6) if reported_sum > 0 else 0.0
            recall = round(tp_sum / known_vulns, 6) if known_vulns > 0 else 0.0
            summaries[cond.value] = VdpEvalSummary(
                condition=cond,
                total_pairs=known_vulns,
                known_vulnerable_count=known_vulns,
                reported_total=reported_sum,
                true_positives=tp_sum,
                false_positives=fp_sum,
                false_negatives=fn_sum,
                vdp_precision=precision,
                vdp_recall=recall,
                excluded_from_ctf_denominator=True,
                policy_violations=violations_sum,
                pair_outcomes=tuple(outcomes),
            )

        return summaries

    def evaluate(
        self,
        *,
        split: EvalSplit = EvalSplit.EVAL,
        tasks: Sequence[EvalTaskSpec] | None = None,
        vdp_pairs: Sequence[VdpEvalPairSpec] | None = None,
        conditions: Sequence[EvalCondition] = (
            EvalCondition.A,
            EvalCondition.B,
            EvalCondition.C,
            EvalCondition.D,
        ),
        attempts_per_task: int = 1,
        custom_runner: AttemptRunner | None = None,
        include_vdp: bool = True,
    ) -> OfflineEvaluationReport:
        """Run comparative A/B/C/D evaluation and optional separate VDP pair evaluation."""
        if attempts_per_task < 1:
            raise ValueError("attempts_per_task must be >= 1.")

        task_list = tuple(tasks) if tasks is not None else build_all_tasks(split=split)
        if not task_list:
            raise ValueError("No tasks supplied for evaluation.")

        attempts: list[TaskAttemptRecord] = []
        summaries: dict[str, EvalConditionSummary] = {}
        for cond in conditions:
            cond_records: list[TaskAttemptRecord] = []
            for task in task_list:
                for attempt_idx in range(1, attempts_per_task + 1):
                    rec = self.run_single_attempt(
                        task=task,
                        condition=cond,
                        attempt_index=attempt_idx,
                        custom_runner=custom_runner,
                    )
                    cond_records.append(rec)
            attempts.extend(cond_records)
            summaries[cond.value] = summarize_condition_attempts(
                condition=cond,
                split=split,
                attempts=cond_records,
            )

        comparisons: list[PairedComparison] = []
        for idx in range(len(conditions) - 1):
            c_from = conditions[idx]
            c_to = conditions[idx + 1]
            comparisons.append(
                compute_paired_comparison(
                    from_summary=summaries[c_from.value],
                    to_summary=summaries[c_to.value],
                    attempts=attempts,
                )
            )

        vdp_summaries = (
            self.run_vdp_evaluation(pairs=vdp_pairs, conditions=conditions)
            if include_vdp
            else {}
        )

        warnings = (
            f"Small synthetic offline sample (n={len(task_list)}, categories=4); Wilson 95% intervals remain wide.",
            "Results reflect deterministic synthetic tasks and cannot be extrapolated directly to external live targets or LLM token pricing.",
            "api_cost_usd and token_usage are explicitly recorded as not_measured in offline harness runs.",
            "VDP precision/recall results are computed over matched vulnerable/fixed source pairs and excluded from CTF solve-rate denominators.",
        )

        return OfflineEvaluationReport(
            report_id=f"p5-eval-{split.value}-{uuid4().hex[:8]}",
            generated_at=datetime.now(UTC),
            split=split,
            guide_revision=self.guide.guide_revision,
            guide_sha256=self.guide.digest(),
            task_ids=tuple(t.task_id for t in task_list),
            condition_summaries=summaries,
            paired_comparisons=tuple(comparisons),
            attempts=tuple(attempts),
            vdp_summaries=vdp_summaries,
            small_sample_warnings=warnings,
        )


# ---------------------------------------------------------------------------
# Markdown Report Generator (docs/09 §§3–6)
# ---------------------------------------------------------------------------


def _fmt_opt_int(val: int | None, suffix: str = "") -> str:
    return f"{val}{suffix}" if val is not None else "not_measured"


def render_evaluation_markdown(report: OfflineEvaluationReport) -> str:
    """Render an honest, leak-free comparative Markdown evaluation report."""
    lines: list[str] = [
        f"# Offline Comparative Evaluation Report ({report.split.value})",
        "",
        f"- **Report ID**: `{report.report_id}`",
        f"- **Generated At**: `{report.generated_at.isoformat()}`",
        f"- **Condition D Guide Revision**: `{report.guide_revision}` (`{report.guide_sha256[:16]}...`)",
        f"- **Total CTF Tasks Evaluated**: `{len(report.task_ids)}` (`split={report.split.value}`)",
        "- **LLM API Cost / Token Usage**: `not_measured`",
        "",
        "## Methodological Limitations & Non-Generalization Notices",
        "",
    ]
    for warn in report.small_sample_warnings:
        lines.append(f"- {warn}")

    lines.extend(
        [
            "",
            "## Condition A / B / C / D Overall Summary (`pass@1` First-Attempt Only)",
            "",
            "| Condition | Solved / Total | pass@1 | Wilson 95% CI | best_of_k | Wall (ms) | Median Wall (ms) | CPU (ms) | Max Peak RSS (B) | Tool Calls | Reproducible Rate | Operational Reliability | Policy Violations | API Cost / Tokens |",
            "| --- | ---: | ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
        ]
    )

    for cond_key in ("A", "B", "C", "D"):
        s = report.condition_summaries.get(cond_key)
        if s is None:
            continue
        bok = (
            f"{s.best_of_k_solve_rate:.3f} (k={s.best_of_k_value})"
            if s.best_of_k_solve_rate is not None
            else "not_measured (k=1)"
        )
        ci = f"[{s.wilson_ci_95[0]:.3f}, {s.wilson_ci_95[1]:.3f}]"
        lines.append(
            f"| {s.condition.value} | {s.solved_count}/{s.total_tasks} | "
            f"{s.ctf_verified_solve_rate:.3f} | {ci} | {bok} | {s.total_wall_ms} | "
            f"{s.median_wall_ms:.1f} | {_fmt_opt_int(s.total_cpu_ms)} | "
            f"{_fmt_opt_int(s.max_peak_rss_bytes)} | {s.total_tool_calls} | "
            f"{s.evidence_reproducible_rate:.3f} | {s.operational_reliability:.3f} | "
            f"{s.policy_violations} | {s.api_cost_usd_status} / {s.token_usage_status} |"
        )

    lines.extend(
        [
            "",
            "## Category Breakdown (No Cross-Category Trade-Off Masking)",
            "",
            "| Condition | Category | Solved / Total | pass@1 | Wilson 95% CI | Avg Wall (ms) | Avg Tool Calls |",
            "| --- | --- | ---: | ---: | --- | ---: | ---: |",
        ]
    )
    for cond_key in ("A", "B", "C", "D"):
        s = report.condition_summaries.get(cond_key)
        if s is None:
            continue
        for cat in EvalCategory:
            b = s.by_category.get(cat.value)
            if b is None:
                continue
            lines.append(
                f"| {cond_key} | `{cat.value}` | {b.solved_count}/{b.total_tasks} | "
                f"{b.pass_at_1:.3f} | [{b.wilson_ci_low:.3f}, {b.wilson_ci_high:.3f}] | "
                f"{b.avg_wall_ms:.1f} | {b.avg_tool_calls:.2f} |"
            )

    lines.extend(
        [
            "",
            "## Paired Comparisons, Regressions & Flat Unsolved Cases",
            "",
        ]
    )
    for pc in report.paired_comparisons:
        lines.append(f"### {pc.from_condition.value} -> {pc.to_condition.value} (delta pass@1 = `{pc.delta_pass_at_1:+.3f}`)")
        lines.append(f"- **Summary**: {pc.regression_and_flat_summary}")
        lines.append(f"- **Improved**: {', '.join(pc.improved_tasks) if pc.improved_tasks else 'none'}")
        lines.append(f"- **Regressed**: {', '.join(pc.regressed_tasks) if pc.regressed_tasks else 'none'}")
        lines.append(
            f"- **Unchanged Unsolved (Flat)**: {', '.join(pc.unchanged_unsolved_tasks) if pc.unchanged_unsolved_tasks else 'none'}"
        )
        if pc.delta_by_category:
            cat_str = ", ".join(f"`{k}`: `{v:+.3f}`" for k, v in sorted(pc.delta_by_category.items()))
            lines.append(f"- **Category Deltas**: {cat_str}")
        lines.append("")

    lines.extend(
        [
            "## Failure Category Counts (9 Categories)",
            "",
            "| Failure Category | A | B | C | D |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for fc in FailureCategory:
        vals = [
            str(report.condition_summaries[c].failure_counts.get(fc.value, 0))
            if c in report.condition_summaries
            else "0"
            for c in ("A", "B", "C", "D")
        ]
        lines.append(f"| `{fc.value}` | {' | '.join(vals)} |")

    if report.vdp_summaries:
        lines.extend(
            [
                "",
                "## VDP Separate Dataset Evaluation (Excluded from CTF Denominators)",
                "",
                "| Condition | Pairs | Known Vulns | Reported | TP | FP | FN | Precision | Recall | Policy Violations | Excluded from CTF |",
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
            ]
        )
        for cond_key in ("A", "B", "C", "D"):
            vs = report.vdp_summaries.get(cond_key)
            if vs is None:
                continue
            lines.append(
                f"| {cond_key} | {vs.total_pairs} | {vs.known_vulnerable_count} | "
                f"{vs.reported_total} | {vs.true_positives} | {vs.false_positives} | "
                f"{vs.false_negatives} | {vs.vdp_precision:.3f} | {vs.vdp_recall:.3f} | "
                f"{vs.policy_violations} | {vs.excluded_from_ctf_denominator} |"
            )

    rendered = "\n".join(lines) + "\n"
    matches = scan_sensitive_markers(rendered)
    if matches:
        raise ValueError(f"Evaluation report emitted unexpected sensitive markers: {matches}")
    return rendered


__all__ = [
    "AttemptRunner",
    "CategoryBreakdown",
    "DEV_INFORMED_GUIDE",
    "EvalCategory",
    "EvalCondition",
    "EvalConditionSummary",
    "EvalSplit",
    "EvalTaskSpec",
    "FailureCategory",
    "GuideSpec",
    "OfflineEvaluationHarness",
    "OfflineEvaluationReport",
    "PairedComparison",
    "TaskAttemptRecord",
    "VdpEvalPairSpec",
    "VdpEvalSummary",
    "VdpFindingTruth",
    "VdpPairOutcome",
    "build_all_tasks",
    "build_dev_tasks",
    "build_eval_tasks",
    "build_vdp_eval_pairs",
    "compute_paired_comparison",
    "render_evaluation_markdown",
    "summarize_condition_attempts",
    "wilson_confidence_interval",
]
