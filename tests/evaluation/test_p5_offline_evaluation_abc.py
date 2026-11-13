"""Offline comparative A/B/C/D and separate VDP pair evaluation tests (P5)."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

from ctf_mcp.contracts import (
    EvidenceAccessDeniedError,
    EvidenceNotFoundError,
    PrincipalContext,
    VerificationStatus,
)
from ctf_mcp.controller import create_default_controller
from ctf_mcp.evidence.redaction import scan_sensitive_markers
from ctf_mcp.evaluation import (
    DEV_INFORMED_GUIDE,
    EvalCategory,
    EvalCondition,
    EvalSplit,
    EvalTaskSpec,
    FailureCategory,
    GuideSpec,
    OfflineEvaluationHarness,
    OfflineEvaluationReport,
    TaskAttemptRecord,
    build_all_tasks,
    build_dev_tasks,
    build_eval_tasks,
    build_vdp_eval_pairs,
    render_evaluation_markdown,
)
from ctf_mcp.storage import Storage

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def eval_workspace(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("p5_offline_eval")


@pytest.fixture(scope="module")
def eval_report(eval_workspace: Path) -> OfflineEvaluationReport:
    """Execute the full 20-task holdout A/B/C/D + 5 VDP pair evaluation once per module."""
    harness = OfflineEvaluationHarness(workspace_root=eval_workspace / "holdout_eval")
    return harness.evaluate(
        split=EvalSplit.EVAL,
        conditions=(
            EvalCondition.A,
            EvalCondition.B,
            EvalCondition.C,
            EvalCondition.D,
        ),
        attempts_per_task=1,
        include_vdp=True,
    )


def test_dev_and_eval_suites_strictly_disjoint_and_secret_free() -> None:
    dev_tasks = build_dev_tasks()
    eval_tasks = build_eval_tasks()
    all_tasks = build_all_tasks()

    assert len(dev_tasks) == 10
    assert len(eval_tasks) == 20
    assert len(all_tasks) == 30

    assert {t.category for t in dev_tasks} == set(EvalCategory)
    for cat in EvalCategory:
        assert sum(1 for t in eval_tasks if t.category == cat) == 5

    dev_ids = {t.task_id for t in dev_tasks}
    eval_ids = {t.task_id for t in eval_tasks}
    assert dev_ids.isdisjoint(eval_ids)

    dev_names = {t.artifact_filename for t in dev_tasks}
    eval_names = {t.artifact_filename for t in eval_tasks}
    assert dev_names.isdisjoint(eval_names)

    dev_sha = {t.artifact_sha256 for t in dev_tasks}
    eval_sha = {t.artifact_sha256 for t in eval_tasks}
    assert dev_sha.isdisjoint(eval_sha)

    dev_flags = {t.expected_flag_sha256 for t in dev_tasks}
    eval_flags = {t.expected_flag_sha256 for t in eval_tasks}
    assert dev_flags.isdisjoint(eval_flags)

    # Confirm plaintext flags are never persisted on EvalTaskSpec metadata or frozen dev guide.
    assert set(EvalTaskSpec.model_fields).isdisjoint({"expected_flag", "flag", "plaintext_flag"})
    for task in all_tasks:
        spec_meta = json.dumps(
            task.model_dump(mode="json", exclude={"artifact_bytes"}),
            ensure_ascii=False,
        )
        assert not re.search(r"CTF\{[^{}]+\}", spec_meta)
        assert scan_sensitive_markers(spec_meta) == ()

    guide_dump = json.dumps(DEV_INFORMED_GUIDE.model_dump(mode="json"), ensure_ascii=False)
    assert "eval-" not in guide_dump.lower()
    assert not re.search(r"CTF\{[^{}]+\}", guide_dump)


def test_eval_abcd_comparative_outcomes_regressions_and_flat_limits(
    eval_report: OfflineEvaluationReport,
) -> None:
    summaries = eval_report.condition_summaries
    assert set(summaries.keys()) == {"A", "B", "C", "D"}

    a = summaries["A"]
    b = summaries["B"]
    c = summaries["C"]
    d = summaries["D"]

    # Overall ordered gain verified end-to-end via real adapter + LocalCtfVerifier.
    assert a.total_tasks == 20
    assert b.total_tasks == 20
    assert c.total_tasks == 20
    assert d.total_tasks == 20
    assert a.solved_count < b.solved_count < c.solved_count < d.solved_count
    assert a.ctf_verified_solve_rate == pytest.approx(3 / 20)
    assert b.ctf_verified_solve_rate == pytest.approx(7 / 20)
    assert c.ctf_verified_solve_rate == pytest.approx(11 / 20)
    assert d.ctf_verified_solve_rate == pytest.approx(16 / 20)

    # Wilson 95% confidence intervals valid and bounded; no API cost/tokens fabricated.
    for s in (a, b, c, d):
        lo, hi = s.wilson_ci_95
        assert 0.0 <= lo <= s.ctf_verified_solve_rate <= hi <= 1.0
        assert s.api_cost_usd_status == "not_measured"
        assert s.token_usage_status == "not_measured"
        assert s.policy_violations == 0
        assert s.operational_reliability == 1.0
        assert set(s.failure_counts.keys()) == {fc.value for fc in FailureCategory}

    # Condition B/C/D record real subprocess usage; Condition C/D maintain evidence reproducibility.
    assert a.total_tool_calls == 0
    assert b.total_tool_calls > 0
    assert c.evidence_reproducible_rate == 1.0
    assert d.evidence_reproducible_rate == 1.0
    assert b.total_cpu_ms is not None and b.total_cpu_ms >= 0
    assert c.total_cpu_ms is not None and c.total_cpu_ms >= 0
    assert d.total_cpu_ms is not None and d.total_cpu_ms >= 0
    assert c.max_peak_rss_bytes is not None and c.max_peak_rss_bytes > 0
    assert d.max_peak_rss_bytes is not None and d.max_peak_rss_bytes > 0

    # Paired comparisons preserve explicit regressions and flat unsolvable tasks.
    comp_map = {(pc.from_condition, pc.to_condition): pc for pc in eval_report.paired_comparisons}
    comp_bc = comp_map[(EvalCondition.B, EvalCondition.C)]
    assert "eval-04" in comp_bc.regressed_tasks
    assert "eval-05" in comp_bc.unchanged_unsolved_tasks
    assert "eval-10" in comp_bc.unchanged_unsolved_tasks
    assert comp_bc.delta_by_category["rev"] == 0.0

    comp_cd = comp_map[(EvalCondition.C, EvalCondition.D)]
    assert "eval-08" in comp_cd.regressed_tasks
    # Forensics actively regresses from C (4/5 = 0.8) to D (3/5 = 0.6); not masked by overall gain.
    assert comp_cd.delta_by_category["forensics"] < 0.0
    assert c.by_category["forensics"].pass_at_1 == pytest.approx(0.8)
    assert d.by_category["forensics"].pass_at_1 == pytest.approx(0.6)
    assert "eval-04" in comp_cd.unchanged_unsolved_tasks
    assert "eval-05" in comp_cd.unchanged_unsolved_tasks
    assert "eval-10" in comp_cd.unchanged_unsolved_tasks

    # Verify explicit failure category attributions on C and D.
    attempt_map = {(att.condition, att.task_id): att for att in eval_report.attempts}
    assert attempt_map[(EvalCondition.C, "eval-04")].failure_category == FailureCategory.RESOURCE_LIMIT
    assert attempt_map[(EvalCondition.D, "eval-04")].failure_category == FailureCategory.RESOURCE_LIMIT
    assert attempt_map[(EvalCondition.C, "eval-05")].failure_category == FailureCategory.MISSING_CAPABILITY
    assert attempt_map[(EvalCondition.D, "eval-05")].failure_category == FailureCategory.MISSING_CAPABILITY
    assert attempt_map[(EvalCondition.C, "eval-10")].failure_category == FailureCategory.VERIFIER_LIMIT
    assert attempt_map[(EvalCondition.D, "eval-10")].failure_category == FailureCategory.VERIFIER_LIMIT
    assert attempt_map[(EvalCondition.D, "eval-08")].failure_category == FailureCategory.PREMATURE_CONCLUSION
    assert attempt_map[(EvalCondition.C, "eval-08")].verified_solved is True

    # Confirm all 4 categories in C/D tracked hypotheses & paged evidence reads.
    for att in eval_report.attempts:
        assert att.api_cost_usd is None
        assert att.token_usage is None
        if att.condition in (EvalCondition.C, EvalCondition.D):
            assert att.hypotheses_recorded >= 1
            assert att.report_path is not None and Path(att.report_path).exists()
            report_text = Path(att.report_path).read_text(encoding="utf-8")
            assert scan_sensitive_markers(report_text) == ()


def test_per_condition_workspace_and_evidence_isolation(
    eval_report: OfflineEvaluationReport,
) -> None:
    run_ids = [att.run_id for att in eval_report.attempts]
    workspaces = [att.workspace_dir for att in eval_report.attempts]
    assert len(run_ids) == len(set(run_ids)) == 80
    assert len(workspaces) == len(set(workspaces)) == 80

    # Pick a solved Condition C run and verify an independent principal cannot read its evidence.
    c_att = next(
        att
        for att in eval_report.attempts
        if att.condition == EvalCondition.C and att.task_id == "eval-02"
    )
    ws = Path(c_att.workspace_dir)
    ctrl = create_default_controller(
        storage=Storage(ws / "harness.sqlite"),
        vault_root=ws / "vault",
        export_root=ws / "exports",
        allow_ephemeral_cursor_key=True,
        initialize=False,
    )
    owner = PrincipalContext(
        principal_id="eval-c",
        auth_method="stdio_local",
        client_kind="offline-evaluator",
        model_label="deterministic-eval-harness",
    )
    intruder = PrincipalContext(
        principal_id="eval-d",
        auth_method="stdio_local",
        client_kind="offline-evaluator",
        model_label="deterministic-eval-harness",
    )
    details = ctrl.describe_run(principal=owner, run_id=c_att.run_id)
    assert len(details["actions"]) >= 2

    with pytest.raises((EvidenceAccessDeniedError, EvidenceNotFoundError, Exception)):
        ctrl.read_evidence(
            principal=intruder,
            run_id=c_att.run_id,
            evidence_id="ev-nonexistent",
        )


def test_pass_at_1_strictly_separated_from_best_of_k(tmp_path: Path) -> None:
    task = build_eval_tasks()[0]

    def _retry_succeeds_second_try(
        spec: EvalTaskSpec,
        cond: EvalCondition,
        attempt_index: int,
        ws_dir: Path,
        run_id: str,
        _guide: GuideSpec | None,
    ) -> TaskAttemptRecord:
        ws_dir.mkdir(parents=True, exist_ok=True)
        solved = attempt_index == 2
        return TaskAttemptRecord(
            task_id=spec.task_id,
            split=spec.split,
            category=spec.category,
            condition=cond,
            attempt_index=attempt_index,
            run_id=run_id,
            workspace_dir=str(ws_dir),
            verified_solved=solved,
            verification_status=(
                VerificationStatus.PASSED if solved else VerificationStatus.FAILED
            ),
            failure_category=None if solved else FailureCategory.PREMATURE_CONCLUSION,
            failure_reason=None if solved else "Attempt 1 failed intentionally.",
            wall_ms=5,
            cpu_ms=None,
            peak_rss_bytes=None,
            tool_calls=1,
            pages_read=0,
            hypotheses_recorded=0,
            evidence_reproducible=False,
            cleanup_confirmed=True,
            policy_violations=0,
        )

    harness = OfflineEvaluationHarness(workspace_root=tmp_path)
    report = harness.evaluate(
        split=EvalSplit.EVAL,
        tasks=(task,),
        conditions=(EvalCondition.C,),
        attempts_per_task=2,
        custom_runner=_retry_succeeds_second_try,
        include_vdp=False,
    )

    summary = report.condition_summaries["C"]
    # pass@1 stays strictly 0.0 (attempt 1 failed); best_of_k is reported separately as 1.0.
    assert summary.solved_count == 0
    assert summary.ctf_verified_solve_rate == 0.0
    assert summary.best_of_k_solve_rate == 1.0
    assert summary.best_of_k_value == 2


def test_vdp_pairs_strictly_excluded_from_ctf_denominators(
    eval_report: OfflineEvaluationReport,
) -> None:
    pairs = build_vdp_eval_pairs()
    assert len(pairs) == 5

    vdp = eval_report.vdp_summaries
    assert set(vdp.keys()) == {"A", "B", "C", "D"}
    assert all(not tid.startswith("vdp-") for tid in eval_report.task_ids)
    assert len(eval_report.task_ids) == 20

    for cond_key, summary in vdp.items():
        assert summary.excluded_from_ctf_denominator is True
        assert summary.total_pairs == 5
        assert summary.known_vulnerable_count == 5
        assert summary.policy_violations == 0
        assert eval_report.condition_summaries[cond_key].total_tasks == 20

    # Baseline A suffers false positives on patched code; C/D enforce guard checks (precision=1.0).
    assert vdp["A"].false_positives > 0
    assert vdp["A"].vdp_precision < 1.0
    assert vdp["C"].false_positives == 0
    assert vdp["C"].vdp_precision == 1.0
    assert vdp["C"].vdp_recall == pytest.approx(0.8)
    assert vdp["D"].false_positives == 0
    assert vdp["D"].vdp_precision == 1.0
    assert vdp["D"].vdp_recall == pytest.approx(1.0)


def test_markdown_report_and_dev_subset_execution(
    eval_report: OfflineEvaluationReport,
    eval_workspace: Path,
) -> None:
    md = render_evaluation_markdown(eval_report)
    assert "not_measured" in md
    assert "Small synthetic offline sample" in md
    assert "VDP Separate Dataset Evaluation (Excluded from CTF Denominators)" in md
    assert "Category Breakdown" in md
    for fc in FailureCategory:
        assert fc.value in md
    assert "eval-04" in md and "eval-08" in md
    assert scan_sensitive_markers(md) == ()
    assert not re.search(r"CTF\{[^{}]+\}", md)

    # Verify representative dev tasks under C vs D cleanly demonstrate what informed DEV_INFORMED_GUIDE.
    dev_by_id = {t.task_id: t for t in build_dev_tasks()}
    dev_subset = (
        dev_by_id["dev-05"],  # UTF-16LE -> D unlocks
        dev_by_id["dev-08"],  # Split source -> D unlocks
        dev_by_id["dev-09"],  # Runtime limit -> unsolved in C & D
        dev_by_id["dev-10"],  # Partial capture -> verifier_limit in C & D
    )
    dev_harness = OfflineEvaluationHarness(workspace_root=eval_workspace / "dev_subset")
    dev_report = dev_harness.evaluate(
        split=EvalSplit.DEV,
        tasks=dev_subset,
        conditions=(EvalCondition.C, EvalCondition.D),
        include_vdp=False,
    )
    dev_map = {(a.condition, a.task_id): a for a in dev_report.attempts}
    assert dev_map[(EvalCondition.C, "dev-05")].verified_solved is False
    assert dev_map[(EvalCondition.D, "dev-05")].verified_solved is True
    assert dev_map[(EvalCondition.C, "dev-08")].verified_solved is False
    assert dev_map[(EvalCondition.D, "dev-08")].verified_solved is True
    assert dev_map[(EvalCondition.D, "dev-09")].failure_category == FailureCategory.MISSING_CAPABILITY
    assert dev_map[(EvalCondition.D, "dev-10")].failure_category == FailureCategory.VERIFIER_LIMIT


def test_evaluation_module_ast_has_zero_forbidden_patterns() -> None:
    eval_path = REPO_ROOT / "src" / "ctf_mcp" / "evaluation.py"
    source = eval_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(eval_path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                raise AssertionError(f"Forbidden call {node.func.id}")
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "system"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
            ):
                raise AssertionError("Forbidden os.system call")
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    raise AssertionError("Forbidden shell=True")
