# P12 PR-C：候補の既知問題・成立条件チェックポイント台帳受入記録 (2026-11-22)

- **対象ブランチ / 基準**: `feat/pr-c-candidate-checkpoints` (PR-B `342906c185bf5ee5932b9a0ef922120507b0d900` からの積み上げ、PR-A・PR-B は `origin/main` `35cba103c0d592366413e7c13d91a42f9c572467` へマージ済み)
- **検証範囲**: 運用中ホストのメイン作業ツリー・SQLite / EvidenceVault・稼働中 run・登録済み profile・Codex 設定には一切触れず、隔離 `git worktree` 上の抽象化した合成 fixture で検証。実対象コード・公開 GitHub API への自動通信・保守者トリアージ結果の判定は本記録に含めない。

## 1. 実装した機能と契約

- **`src/ctf_mcp/evidence/vdp_candidate_ledger.py` + `ctf_mcp.evidence`**:
  - `<vault_root>/_vdp/candidate_checkpoints.json` へファイルロック（`_vdp/candidate_checkpoints.json.lock`, `O_NOFOLLOW`）＋原子的書き込み＋`scan_sensitive_markers` 検査付きで候補台帳 `vdp-candidate-checkpoint/1` を永続化。`submissions.json` のロック／HTTPS URL 検査とも共通化。
  - **二段階ゲート (`pre_heavy_test` / `pre_submission`)**:
    - 外部検索は研究者・外部コネクタが実施して根拠をインポートする方式に固定（`external_search_performed_by_harness=False`）。
    - `KnownIssueReference` で参照種別（`issue` / `pull_request` / `fix_commit` / `advisory` / `release_note` / `other`）・`https://` URL（資格情報禁止）・対象版との関係・同一原因／同一影響に関する人間判断・根拠を記録。
    - **検索結果0件の誤断定防止**: `references_reviewed` が空のときは `zero_hits_observed=True` を要求し、`no_duplicate_claimed=False` 固定および `zero_hits_disclaimer="zero_search_results_does_not_prove_no_duplicate"` を強制付与（`zero_hits_observed=False` との不整合や `same_cause_and_impact` 参照があるのに `proceed_unconfirmed_candidate` を指定する矛盾はフェイルクローズ）。
    - **成立条件の必須記録 (`CandidatePreconditions`)**: `preconfig_created_by`（作成主体）、`attacker_controls`（攻撃者制御入力）、`real_world_prevalence`（`common` / `unverified` / `rare_special_setup`）、`observed_impact_cap`（観測影響上限）、`basis_refs` を記録。
    - **期限切れ再確認・恣意的昇格禁止**: `evaluate_candidate_gate` で `max_age_hours` 超過・`needs_recheck`・時刻逆転を検出して `stale_recheck_required=True`＋再確認プロンプトを返し、`status="confirmed_vulnerability"` や `auto_promoted_to_confirmed_vulnerability=True` はスキーマで拒否。
- **提出下書き連携・CLI・`run.describe` 指標**:
  - `VdpDraftSpec` に任意の `candidate_id` を追加（未指定の既存呼び出しは 100% 後方互換）。指定時は `pre_submission` ゲート合格（`pre_heavy_test` 実施済み＋有効・非ブロック）を必須とし、合格した下書きへ日英双方で「既知問題チェックポイントと成立条件」節・検索0件警告・`real_world_prevalence_unverified` 警告を転記。
  - `ctf-mcp-admin` に `record-vdp-candidate`、`check-vdp-candidate-gate`、`list-vdp-candidates` を追加し（CLI 専用）、`diagnose-mcp` の `cli_admin_only_commands` へ登録（MCP 公開ツールスキーマは維持）。
  - `run.describe` の `vdp` run に `vdp_candidate_checkpoints` と比較指標 `vdp_candidate_metrics`（`time_to_first_candidate_seconds`、ゲート漏れ・期限切れ・未検証普及度・根拠欠落件数、`auto_confirmed_vulnerability_count=0`、`maintainer_triage_preempted=False`）を表示。

## 2. 合成 fixture 受入検証 (`tests/integration/test_pr_c_candidate_checkpoints.py`)

1. **二段階ゲート通しフローと `export-vdp-draft`／`run.describe` 連携**:
   - `pre_heavy_test` のみ記録時点で `check-vdp-candidate-gate --gate pre_heavy_test` が 0、提出直前ゲート未達で `export-vdp-submission-draft` が拒否され、`pre_submission` 記録＋`ready_for_human_draft_review` 更新後に日英両方の下書きが出力され、参照表・成立条件・指標が出力されることを確認。
2. **検索結果0件の非断定保証**:
   - 0件時に `no_duplicate_claimed=False` と `zero_search_results_does_not_prove_no_duplicate` が維持されて下書きの未確認条件へ転記されること、および空参照での `zero_hits_observed=False` や `no_duplicate_claimed=True` が拒否されることを確認。
3. **重複／既修正ブロックと矛盾拒否**:
   - `same_cause_and_impact`＋対象版該当／修正済み参照で `proceed_unconfirmed_candidate` を指定すると拒否され、`blocked_already_fixed`／`blocked_likely_duplicate` 記録時は `status="blocked_known_issue"` となり両ゲートおよび下書き出力を停止することを確認。
4. **期限切れ再確認・ゲートスキップ・負例**:
   - `max_age_hours` 超過、`needs_recheck`、`pre_submission.checked_at < pre_heavy_test.checked_at` で `stale_recheck_required=True` と再確認プロンプトが返って下書き出力が止まり、再確認登録で解除されること、および `pre_heavy_test` 未実施の `pre_submission` 単体登録が `missing_items` に計上されることを確認。
   - 恣意的脆弱性確定・閉じた run・非 VDP run・他 run 証拠参照・秘密値・資格情報付き URL・symlink JSON・サイズ超過 JSON・ドラフト対象／コミット不一致がすべて拒否され、`candidate_id` の未指定下書き後方互換性と `diagnose-mcp` 健全性が保たれることを確認。

## 3. 未確認事項

1. 運用中リモートホストへの反映および実運用データを用いた再確認（PR マージ後、予定調査時間帯外に実施）。
2. 実保守者による報告受理／重複判定（判定待ちのため指標へ先取りしない）。

## 4. 反映・ロールバック手順

- **反映（予定調査時間帯外）**: `git status --porcelain` が空の状態で `git pull --ff-only origin main` を実行し、`ctf-mcp-admin record-vdp-candidate --help` と `ctf-mcp-admin diagnose-mcp --config <CONFIG_JSON>` で `healthy: true` を確認（本 PR は台帳・CLI・下書き連携の追加であり MCP 公開スキーマは変更なし）。
- **ロールバック**: 対象ホストで直前安定コミットへ `git checkout <PREVIOUS_COMMIT>` を実行して確認。
