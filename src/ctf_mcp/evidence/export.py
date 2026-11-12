"""Run report generation, cleanup/import gating, and redaction verification.

Implements ``templates/run-report.ja.md`` / ``templates/run-report.md`` and
``docs/11`` section 3–4 (CTF-10, CTF-12):
- Blocks report export whenever cleanup is unconfirmed, active sessions/jobs
  or non-terminal actions remain, ``guest_health == 'cleanup_unconfirmed'``,
  or imported evidence cannot be verified in SQLite and the vault.
- Never runs automatic Git export.
- Scrubs or rejects sensitive markers (``SYNTHETIC_SECRET_...``,
  ``CTF_SENSITIVE_MARKER``, bearer/token credentials, and raw ``flag{...}``
  strings) before writing any report artifact.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from collections.abc import Sequence
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from ctf_mcp.contracts import (
    SHA256_PATTERN,
    TERMINAL_ACTION_STATES,
    BudgetSpec,
    ConfigurationError,
    ContractViolationError,
    EvidenceAccessDeniedError,
    EvidenceNotFoundError,
    FindingRecord,
    GuestBlockedError,
    GuestHealthState,
    PathSecurityError,
    RunManifest,
    StrictModel,
    canonical_json,
    sha256_bytes,
)
from ctf_mcp.evidence.redaction import redact_text, scan_sensitive_markers
from ctf_mcp.evidence.vault import EvidenceVault
from ctf_mcp.fs_guard import safe_read_bounded, safe_write_atomic
from ctf_mcp.storage import Storage

_TERMINAL_STATE_VALUES: frozenset[str] = frozenset(s.value for s in TERMINAL_ACTION_STATES)
_FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class ReportMetadata(StrictModel):
    """Optional supplementary fields for the investigation report template."""

    experiment_arm: str = "N/A"
    attempt_number: str = "1"
    human_assistance: str = "none"
    license_acceptance_ref: str = "pinned-local-dependencies"
    snapshot_ref: str = "unverified"
    outcome_summary: str = "inconclusive"
    regressions_notes: str = "none"
    retention_policy_ref: str = "private-per-run-no-auto-git"
    external_submission_status: str = "none"
    reasoning_settings: str = "not-recorded"


class ExportResult(StrictModel):
    """Result returned by ``RunReportExporter.export_run_report`` on verified export."""

    run_id: str = Field(min_length=1)
    language: Literal["ja", "en"]
    markdown: str = Field(min_length=1)
    report_sha256: str = Field(pattern=SHA256_PATTERN)
    output_path: str | None = None
    evidence_ids_referenced: tuple[str, ...] = ()
    redactions_applied: int = Field(ge=0)
    cleanup_confirmed: bool
    import_confirmed: bool
    exported_at: datetime


def assert_report_clean(
    markdown: str,
    *,
    forbidden_literals: Sequence[str] = (),
) -> None:
    """Fail closed if any sensitive marker, credential, or flag appears in ``markdown``.

    Raises ``ContractViolationError`` carrying only rule names (never raw secret text).
    """
    matched_rules = scan_sensitive_markers(markdown, extra_literals=forbidden_literals)
    if matched_rules:
        raise ContractViolationError(
            "Report export blocked: residual sensitive marker or raw flag pattern detected.",
            details={"matched_rules": list(matched_rules)},
        )


def _sanitize_cell(value: str, *, auto_redact: bool, extra_literals: Sequence[str]) -> tuple[str, int]:
    collapsed = value.replace("\r", " ").replace("\n", " ").replace("|", "\\|")
    if auto_redact:
        res = redact_text(collapsed, extra_literals=extra_literals)
        return res.redacted_text, res.redactions_applied
    return collapsed, 0


class RunReportExporter:
    """Generates and validates sanitized run reports aligned with ``templates/run-report*.md``."""

    def __init__(
        self,
        *,
        storage: Storage,
        vault: EvidenceVault | None = None,
        export_root: str | Path | None = None,
        automatic_git_export: bool = False,
    ) -> None:
        if automatic_git_export:
            raise ConfigurationError("automatic_git_export must remain False.")
        self.storage = storage
        self.vault = vault
        self.export_root = Path(export_root) if export_root is not None else None
        self.automatic_git_export = False

        if self.export_root is not None:
            if os.path.lexists(self.export_root):
                st = os.lstat(self.export_root)
                attrs = getattr(st, "st_file_attributes", 0)
                if stat.S_ISLNK(st.st_mode) or bool(attrs & _FILE_ATTRIBUTE_REPARSE_POINT):
                    raise PathSecurityError("Export root cannot be a symlink or reparse point.")
                if not stat.S_ISDIR(st.st_mode):
                    raise PathSecurityError("Export root must be a directory.")
            else:
                self.export_root.mkdir(parents=True, exist_ok=True)

    def _read_ctx(self, conn: sqlite3.Connection | None):
        if conn is not None:
            return nullcontext(conn)
        return self.storage.read_connection()

    def _verify_preconditions(
        self,
        conn: sqlite3.Connection,
        *,
        run_id: str,
        principal_id: str,
        cleanup_confirmed: bool,
        import_confirmed: bool,
        require_rolled_back: bool,
        expected_evidence_ids: Sequence[str],
    ) -> tuple[sqlite3.Row, list[sqlite3.Row], dict[str, list[sqlite3.Row]]]:
        run_row = conn.execute(
            "SELECT * FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if run_row is None:
            raise EvidenceNotFoundError(f"Run {run_id!r} not found.")
        if str(run_row["owner_principal_id"]) != principal_id:
            raise EvidenceAccessDeniedError(
                f"Principal {principal_id!r} is not authorized to export run {run_id!r}."
            )

        if not cleanup_confirmed:
            raise ContractViolationError(
                f"Export blocked for run {run_id!r}: cleanup has not been confirmed."
            )

        guest_health = str(run_row["guest_health"])
        if guest_health == GuestHealthState.CLEANUP_UNCONFIRMED.value:
            raise GuestBlockedError(
                f"Export blocked for run {run_id!r}: guest_health is cleanup_unconfirmed."
            )
        if require_rolled_back and guest_health != GuestHealthState.ROLLED_BACK.value:
            raise ContractViolationError(
                f"Export blocked for run {run_id!r}: guest rollback has not completed (guest_health={guest_health!r})."
            )
        if int(run_row["active_heavy_jobs"]) > 0 or int(run_row["active_sessions"]) > 0:
            raise ContractViolationError(
                f"Export blocked for run {run_id!r}: active jobs or sessions still remain."
            )

        action_rows = conn.execute(
            "SELECT * FROM actions WHERE run_id = ? ORDER BY created_at ASC, rowid ASC",
            (run_id,),
        ).fetchall()
        non_terminal = [
            str(r["action_id"])
            for r in action_rows
            if str(r["state"]) not in _TERMINAL_STATE_VALUES
        ]
        if non_terminal:
            raise ContractViolationError(
                f"Export blocked for run {run_id!r}: non-terminal actions remain ({non_terminal}).",
                details={"non_terminal_actions": non_terminal},
            )

        if not import_confirmed:
            raise ContractViolationError(
                f"Export blocked for run {run_id!r}: evidence import has not been confirmed."
            )

        ev_rows = conn.execute(
            "SELECT * FROM evidence_objects WHERE run_id = ? ORDER BY created_at ASC, rowid ASC",
            (run_id,),
        ).fetchall()
        ev_by_id = {str(r["evidence_id"]): r for r in ev_rows}

        for expected_id in expected_evidence_ids:
            if expected_id not in ev_by_id:
                other = conn.execute(
                    "SELECT run_id FROM evidence_objects WHERE evidence_id = ?",
                    (expected_id,),
                ).fetchone()
                if other is not None:
                    raise EvidenceAccessDeniedError(
                        f"Expected evidence {expected_id!r} belongs to another run."
                    )
                raise EvidenceNotFoundError(
                    f"Export blocked: expected imported evidence {expected_id!r} is missing."
                )

        views_by_ev: dict[str, list[sqlite3.Row]] = {}
        for eid in ev_by_id:
            v_rows = conn.execute(
                """
                SELECT * FROM evidence_views
                WHERE evidence_id = ?
                ORDER BY created_at ASC, rowid ASC
                """,
                (eid,),
            ).fetchall()
            views_by_ev[eid] = list(v_rows)
            if not v_rows:
                raise ContractViolationError(
                    f"Export blocked: evidence {eid!r} has no registered views."
                )
            if self.vault is not None:
                # Verify latest active view (or latest view if intentionally revoked) blob exists & matches SHA-256.
                active_views = [v for v in v_rows if v["revoked_at"] is None]
                target_view = active_views[-1] if active_views else v_rows[-1]
                try:
                    blob = safe_read_bounded(
                        self.vault.vault_root,
                        str(target_view["storage_relpath"]),
                        max_bytes=self.vault.max_evidence_bytes,
                        allow_truncate=False,
                    )
                except Exception as exc:
                    raise ContractViolationError(
                        f"Export blocked: imported evidence blob for {eid!r} is unreadable or missing: {exc}"
                    ) from exc
                if (
                    len(blob.data) != int(target_view["view_bytes"])
                    or sha256_bytes(blob.data) != str(target_view["view_sha256"])
                ):
                    raise ContractViolationError(
                        f"Export blocked: evidence blob for {eid!r} failed SHA-256 integrity verification."
                    )

        return run_row, list(action_rows), views_by_ev

    def export_run_report(
        self,
        *,
        run_id: str,
        principal_id: str,
        language: Literal["ja", "en"] = "ja",
        output_relpath: str | None = None,
        overwrite: bool = False,
        cleanup_confirmed: bool = True,
        import_confirmed: bool = True,
        require_rolled_back: bool = False,
        expected_evidence_ids: Sequence[str] = (),
        findings: Sequence[FindingRecord] = (),
        metadata: ReportMetadata | None = None,
        auto_redact: bool = True,
        forbidden_literals: Sequence[str] = (),
        include_evidence_excerpts: bool = False,
        excerpt_max_chars: int = 200,
        conn: sqlite3.Connection | None = None,
    ) -> ExportResult:
        """Render, redact/verify, and optionally write a run report to ``export_root``."""
        if language not in {"ja", "en"}:
            raise ConfigurationError(f"Unsupported report language: {language!r}.")
        if output_relpath is not None and self.export_root is None:
            raise ConfigurationError("output_relpath requires export_root to be configured.")
        if include_evidence_excerpts and self.vault is None:
            raise ConfigurationError("include_evidence_excerpts=True requires vault to be configured.")
        if excerpt_max_chars <= 0:
            raise ConfigurationError("excerpt_max_chars must be positive.")

        meta = metadata or ReportMetadata()
        redaction_count = 0

        def clean(text: str) -> str:
            nonlocal redaction_count
            cleaned, count = _sanitize_cell(
                text, auto_redact=auto_redact, extra_literals=forbidden_literals
            )
            redaction_count += count
            return cleaned

        with self._read_ctx(conn) as rc:
            run_row, action_rows, views_by_ev = self._verify_preconditions(
                rc,
                run_id=run_id,
                principal_id=principal_id,
                cleanup_confirmed=cleanup_confirmed,
                import_confirmed=import_confirmed,
                require_rolled_back=require_rolled_back,
                expected_evidence_ids=expected_evidence_ids,
            )

            scope_row = rc.execute(
                "SELECT * FROM scopes WHERE run_id = ? AND scope_revision = ?",
                (run_id, str(run_row["scope_revision"])),
            ).fetchone()
            hyp_rows = rc.execute(
                "SELECT * FROM hypotheses WHERE run_id = ? ORDER BY updated_at ASC, rowid ASC",
                (run_id,),
            ).fetchall()
            ev_rows = rc.execute(
                "SELECT * FROM evidence_objects WHERE run_id = ? ORDER BY created_at ASC, rowid ASC",
                (run_id,),
            ).fetchall()
            ver_rows = rc.execute(
                "SELECT * FROM verifications WHERE run_id = ? ORDER BY verified_at ASC, rowid ASC",
                (run_id,),
            ).fetchall()

            excerpts: dict[str, str] = {}
            if include_evidence_excerpts and self.vault is not None:
                for er in ev_rows:
                    eid = str(er["evidence_id"])
                    v_list = views_by_ev.get(eid, [])
                    if any(v["revoked_at"] is None for v in v_list):
                        page = self.vault.read_page(
                            run_id=run_id,
                            principal_id=principal_id,
                            evidence_id=eid,
                            max_chars=min(excerpt_max_chars, self.vault.max_page_chars),
                            conn=rc,
                        )
                        excerpts[eid] = page.content

        manifest_raw = json.loads(str(run_row["manifest_json"]))
        budget_raw = json.loads(str(run_row["budget_spec_json"]))
        manifest: RunManifest | None = None
        if isinstance(manifest_raw, dict) and "run_id" in manifest_raw:
            manifest = RunManifest.model_validate(manifest_raw)
        budget = (
            BudgetSpec.model_validate(budget_raw)
            if isinstance(budget_raw, dict) and budget_raw
            else (manifest.budget_spec if manifest else BudgetSpec())
        )

        scope_sha = (
            str(scope_row["scope_sha256"])
            if scope_row is not None
            else (manifest.scope_sha256 if manifest else "unknown")
        )
        scope_exp = (
            str(scope_row["expires_at"])
            if scope_row is not None and scope_row["expires_at"]
            else (
                manifest.scope_expires_at.isoformat()
                if manifest and manifest.scope_expires_at
                else "none"
            )
        )
        auth_ref = "recorded"
        if scope_row is not None:
            try:
                pol = json.loads(str(scope_row["policy_json"]))
                if isinstance(pol, dict) and pol.get("authorization_reference"):
                    auth_ref = str(pol["authorization_reference"])
            except json.JSONDecodeError:
                pass

        client_label = manifest.client_label if manifest else "not-recorded"
        instruction_rev = manifest.instruction_revision if manifest else "not-recorded"
        artifact_hashes = (
            canonical_json(manifest.artifact_hashes) if manifest else "{}"
        )
        adapter_revs = (
            canonical_json(manifest.adapter_revisions) if manifest else "{}"
        )

        # Map actions to their evidence objects
        ev_by_action: dict[str, list[sqlite3.Row]] = {}
        for er in ev_rows:
            ev_by_action.setdefault(str(er["action_id"]), []).append(er)

        ev_ids_referenced = tuple(str(er["evidence_id"]) for er in ev_rows)

        # Build hypothesis rows
        hyp_lines: list[str] = []
        if hyp_rows:
            for hr in hyp_rows:
                sup = json.loads(str(hr["supporting_evidence_json"]))
                con = json.loads(str(hr["contradicting_evidence_json"]))
                ev_refs = f"sup={sup}, con={con}"
                hyp_lines.append(
                    f"| {clean(str(hr['claim']))} | {clean(ev_refs)} | "
                    f"{clean(str(hr['state']))} | {clean(str(hr['next_observation']))} |"
                )
        else:
            empty_hyp = "| (none) | - | unknown | - |" if language == "en" else "| (なし) | - | 不明 | - |"
            hyp_lines.append(empty_hyp)

        # Build action & evidence rows
        action_lines: list[str] = []
        total_used_ms = 0
        has_derived_or_redacted = False
        has_truncation = False
        if action_rows:
            for ar in action_rows:
                aid = str(ar["action_id"])
                used_ms = int(ar["used_ms"])
                total_used_ms += used_ms
                status_label = str(ar["state"])
                if ar["envelope_json"]:
                    try:
                        env_obj: Any = json.loads(str(ar["envelope_json"]))
                        if isinstance(env_obj, dict) and env_obj.get("status"):
                            status_label = str(env_obj["status"])
                    except json.JSONDecodeError:
                        pass

                op_desc = f"{ar['capability_name']}.{ar['operation']} args={ar['sanitized_args_json']}"
                ev_parts: list[str] = []
                for er in ev_by_action.get(aid, ()):
                    eid = str(er["evidence_id"])
                    role = str(er["role"])
                    v_list = views_by_ev.get(eid, [])
                    active_v = [v for v in v_list if v["revoked_at"] is None]
                    chosen = active_v[-1] if active_v else v_list[-1]
                    v_rev = str(chosen["view_revision"])
                    v_sha = str(chosen["view_sha256"])
                    v_bytes = int(chosen["view_bytes"])
                    comp = bool(chosen["capture_complete"])
                    if role == "derived" or chosen["redaction_policy_rev"] is not None:
                        has_derived_or_redacted = True
                    if not comp:
                        has_truncation = True
                    om_note = (
                        f" truncated({clean(str(chosen['omission_reason']))})"
                        if not comp
                        else ""
                    )
                    red_note = (
                        f" policy={chosen['redaction_policy_rev']}"
                        if chosen["redaction_policy_rev"]
                        else ""
                    )
                    revoked_note = " [ALL_VIEWS_REVOKED]" if not active_v else ""
                    excerpt_note = f" excerpt={excerpts[eid]!r}" if eid in excerpts else ""
                    ev_parts.append(
                        f"{eid} ({role}/{v_rev}, sha256={v_sha}, 0..{v_bytes}B{red_note}{om_note}{revoked_note}{excerpt_note})"
                    )
                ev_text = "; ".join(ev_parts) if ev_parts else "-"
                budget_cell = f"used_ms={used_ms}, rem_ms={run_row['remaining_ms']}, rem_bytes={run_row['remaining_bytes']}"
                action_lines.append(
                    f"| {clean(aid)} | {clean(op_desc)} | {clean(status_label)} | {clean(ev_text)} | {clean(budget_cell)} |"
                )
        else:
            empty_act = (
                "| (none) | - | - | - | - |"
                if language == "en"
                else "| (なし) | - | - | - | - |"
            )
            action_lines.append(empty_act)

        # Findings and verifications
        finding_lines: list[str] = []
        for f in findings:
            finding_lines.append(
                f"  - [{f.finding_id}] state={f.verification_state.value}; loc={clean(f.location)} "
                f"ver={clean(f.affected_version)}; pre={clean(f.preconditions)}; "
                f"obs={clean(f.observation)}; impact={clean(f.impact_hypothesis)}; "
                f"repro={list(f.reproducer_evidence_ids)}; contra={list(f.contradictory_evidence_ids)}"
            )
        if not finding_lines:
            finding_lines.append("  - none recorded" if language == "en" else "  - 記録なし")

        ver_lines: list[str] = []
        for vr in ver_rows:
            checks = json.loads(str(vr["checks_json"]))
            limits = json.loads(str(vr["limitations_json"]))
            eids = json.loads(str(vr["evidence_ids_json"]))
            ver_lines.append(
                f"  - verifier={clean(str(vr['verifier_id']))}@{clean(str(vr['verifier_revision']))} "
                f"status={clean(str(vr['status']))} checks={clean(str(checks))} "
                f"limitations={clean(str(limits))} evidence={clean(str(eids))}"
            )
        if not ver_lines:
            ver_lines.append("  - none recorded" if language == "en" else "  - 記録なし")

        total_calls = max(0, budget.max_tool_calls - int(run_row["remaining_calls"]))
        used_ev_bytes = max(0, budget.max_evidence_bytes_per_run - int(run_row["remaining_bytes"]))
        guest_health = str(run_row["guest_health"])

        if language == "ja":
            lines = [
                "# 調査レポート",
                "",
                "実対象、flag、認証情報、生の対話記録は非公開証拠領域へ置き、Gitに書き出す場合は秘匿した参照を使います。",
                "",
                "## マニフェスト",
                f"- 調査／課題ID、所有者、モード、スコープ版・ハッシュ・期限、許可根拠：`run_id={clean(str(run_row['run_id']))}`, `task_id={clean(str(run_row['task_id']))}`, `owner={clean(principal_id)}`, `mode={clean(str(run_row['mode']))}`, `scope={clean(str(run_row['scope_revision']))}`, `sha256={scope_sha}`, `expires_at={clean(scope_exp)}`, `auth={clean(auth_ref)}`",
                f"- 実クライアント／モデル表示名、取得可能な推論設定：`{clean(client_label)}`, `{clean(meta.reasoning_settings)}`",
                f"- A／B／C／D条件、独立試行番号、人の補助：`arm={clean(meta.experiment_arm)}`, `attempt={clean(meta.attempt_number)}`, `human_assistance={clean(meta.human_assistance)}`",
                f"- 入力ハッシュ、ツール／アダプタのコミットとライセンス受入記録：`artifacts={clean(artifact_hashes)}`, `adapters={clean(adapter_revs)}`, `license={clean(meta.license_acceptance_ref)}`",
                f"- 手順／設定版、スナップショット、時間・呼出・資源予算：`instruction_rev={clean(instruction_rev)}`, `snapshot={clean(meta.snapshot_ref)}`, `budgets=(run_s={budget.run_budget_seconds}, action_s={budget.action_timeout_seconds}, calls={budget.max_tool_calls}, evidence_bytes={budget.max_evidence_bytes_per_run})`",
                "",
                "## 目的と仮説",
                "| 仮説 | 支持・反証の証拠ID | 状態 | 次に区別したい観測 |",
                "|---|---|---|---|",
                *hyp_lines,
                "",
                "## 操作と証拠",
                "| 操作ID | 型付き操作と秘匿した入力 | 結果状態 | 証拠ID・ハッシュ | 時間・残予算 |",
                "|---|---|---|---|---|",
                *action_lines,
                "",
                f"原文／派生、参照範囲、切捨て、秘匿・取得不能箇所：`derived_or_redacted={has_derived_or_redacted}`, `truncation_present={has_truncation}`, `evidence_count={len(ev_rows)}`。",
                "",
                "## 発見と独立検証",
                "- 位置・版、前提、観測、影響仮説、反証：",
                *finding_lines,
                "- 再現資料、検証器名・版、成功／失敗した検査：",
                *ver_lines,
                "- CTF：ローカル正答検証の結果のみ記載し、flag自体は本レポートへ書かない。",
                "- VDP：candidate / reproduced / report-ready / submitted / accepted の遷移証拠に従う。",
                "- 不確実性、根拠不足、確認者の限界：上記 verifier の limitations 参照。",
                "",
                "## 結果とコスト",
                f"- 検証済み結果／未解決／判断不能／基盤失敗：`{clean(meta.outcome_summary)}`",
                f"- 全所要時間、呼出数、資源最大値、直接取得できるトークン・費用：`wall_ms={total_used_ms}`, `tool_calls={total_calls}`, `evidence_bytes={used_ev_bytes}`",
                f"- 悪化、失敗分類、開発用に限定した改訂案：`{clean(meta.regressions_notes)}`",
                "- 条件を揃えた比較結果がなければ性能改善は主張しない。",
                "",
                "## 終了と書き出し",
                f"- セッション・プロセス終了、一時通信解除、復元と確認：`cleanup_confirmed={cleanup_confirmed}`, `guest_health={guest_health}`, `active_jobs={run_row['active_heavy_jobs']}`, `active_sessions={run_row['active_sessions']}`",
                f"- 証拠保存・削除規則、書き出し選定・秘匿確認、アクセス参照：`retention={clean(meta.retention_policy_ref)}`, `import_confirmed={import_confirmed}`, `auto_redact={auto_redact}`",
                f"- 外部提出状態：`{clean(meta.external_submission_status)}`",
            ]
        else:
            lines = [
                "# Investigation Report",
                "",
                "Keep real targets, flags, credentials, and raw transcripts in the private evidence system; use redacted references in repository exports.",
                "",
                "## Manifest",
                f"- Run/task ID, owner, mode, scope revision/hash/expiry and permission reference: `run_id={clean(str(run_row['run_id']))}`, `task_id={clean(str(run_row['task_id']))}`, `owner={clean(principal_id)}`, `mode={clean(str(run_row['mode']))}`, `scope={clean(str(run_row['scope_revision']))}`, `sha256={scope_sha}`, `expires_at={clean(scope_exp)}`, `auth={clean(auth_ref)}`",
                f"- Actual client/model label and observable reasoning settings: `{clean(client_label)}`, `{clean(meta.reasoning_settings)}`",
                f"- Arm A/B/C/D; independent attempt number; human assistance: `arm={clean(meta.experiment_arm)}`, `attempt={clean(meta.attempt_number)}`, `human_assistance={clean(meta.human_assistance)}`",
                f"- Input hashes, tool/adapter commits and license acceptance references: `artifacts={clean(artifact_hashes)}`, `adapters={clean(adapter_revs)}`, `license={clean(meta.license_acceptance_ref)}`",
                f"- Instruction/config revisions; snapshot; time/call/resource budgets: `instruction_rev={clean(instruction_rev)}`, `snapshot={clean(meta.snapshot_ref)}`, `budgets=(run_s={budget.run_budget_seconds}, action_s={budget.action_timeout_seconds}, calls={budget.max_tool_calls}, evidence_bytes={budget.max_evidence_bytes_per_run})`",
                "",
                "## Objective and hypotheses",
                "| Claim | Supporting / contradicting evidence IDs | State | Next discriminating observation |",
                "|---|---|---|---|",
                *hyp_lines,
                "",
                "## Actions and evidence",
                "| Action ID | Typed operation and sanitized inputs | Result status | Evidence IDs / hashes | Time / remaining budget |",
                "|---|---|---|---|---|",
                *action_lines,
                "",
                f"Raw vs derived, source ranges, truncation, and redactions: `derived_or_redacted={has_derived_or_redacted}`, `truncation_present={has_truncation}`, `evidence_count={len(ev_rows)}`.",
                "",
                "## Finding and independent verification",
                "- Location/version, preconditions, observed behavior, impact hypothesis, contrary evidence:",
                *finding_lines,
                "- Reproducer reference; verifier identity/version; exact checks passed/failed:",
                *ver_lines,
                "- CTF: local verification outcome only, never the flag in this report.",
                "- VDP: candidate / reproduced / report-ready / submitted / accepted transitions require recorded evidence.",
                "- Uncertainty, unsupported claims, and reviewer limitations: see verifier limitations above.",
                "",
                "## Outcome and cost",
                f"- Verified outcome / unsolved / inconclusive / infrastructure failure: `{clean(meta.outcome_summary)}`",
                f"- Total wall time, tool calls, resource peaks, tokens/cost if directly available: `wall_ms={total_used_ms}`, `tool_calls={total_calls}`, `evidence_bytes={used_ev_bytes}`",
                f"- Regressions, failure category and proposed development-only revision: `{clean(meta.regressions_notes)}`",
                "- No claim of performance gain unless backed by the matched comparison.",
                "",
                "## Cleanup and export",
                f"- Sessions/processes stopped; temporary egress revoked; snapshot restored and verified: `cleanup_confirmed={cleanup_confirmed}`, `guest_health={guest_health}`, `active_jobs={run_row['active_heavy_jobs']}`, `active_sessions={run_row['active_sessions']}`",
                f"- Evidence retention/deletion rule, export selection/redaction checks and access reference: `retention={clean(meta.retention_policy_ref)}`, `import_confirmed={import_confirmed}`, `auto_redact={auto_redact}`",
                f"- External submission status: `{clean(meta.external_submission_status)}`",
            ]

        rendered = "\n".join(lines) + "\n"
        if auto_redact:
            final_outcome = redact_text(rendered, extra_literals=forbidden_literals)
            rendered = final_outcome.redacted_text
            redaction_count += final_outcome.redactions_applied

        # Final fail-closed secrecy check before returning or writing to disk.
        assert_report_clean(rendered, forbidden_literals=forbidden_literals)

        written_path: str | None = None
        if output_relpath is not None:
            assert self.export_root is not None
            target = safe_write_atomic(
                self.export_root,
                output_relpath,
                rendered.encode("utf-8"),
                overwrite=overwrite,
                create_parents=True,
            )
            written_path = str(target)

        return ExportResult(
            run_id=run_id,
            language=language,
            markdown=rendered,
            report_sha256=sha256_bytes(rendered.encode("utf-8")),
            output_path=written_path,
            evidence_ids_referenced=ev_ids_referenced,
            redactions_applied=redaction_count,
            cleanup_confirmed=cleanup_confirmed,
            import_confirmed=import_confirmed,
            exported_at=datetime.now(UTC),
        )


__all__ = [
    "ExportResult",
    "ReportMetadata",
    "RunReportExporter",
    "assert_report_clean",
]
