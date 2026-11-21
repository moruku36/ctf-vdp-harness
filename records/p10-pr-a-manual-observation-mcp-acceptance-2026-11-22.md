# P10 PR-A：手動隔離観測の MCP 型付き取込 (`evidence.import_manual_observation`) 受入記録 (2026-11-22)

- **対象ブランチ / 基準コミット**: `feat/pr-a-manual-observation-mcp` (基準 `main`: `1da967b94cbbeb030eeff88fe7574ac7ce3a085a`)
- **検証方法**: 運用中メイン作業ツリー・既存 SQLite / EvidenceVault・稼働中 run・Codex 設定を一切変更せず、隔離 `git worktree`＋一時 `tmp_path` / `/tmp` 上の合成 VDP fixture で実施。
- **過去記録との区別**: P7〜P9 の実機受入結果をもって本変更の本番運用ホスト再受入とみなさない。実稼働ホストへの反映および本番クライアント再接続確認は未実施（下記「未確認事項」参照）。

## 1. 実装した機能・共通契約

- **MCP 公開面（VDP オープンかつ有効・期限内スコープ時のみ）**: `evidence.import_manual_observation`
  - 外部 URL 取得やローカル任意ファイル読取りは行わず、構造化メタデータ＋SHA-256 ハッシュ＋不透明な非公開証拠参照（`private_evidence_refs`）だけを受け取る。
  - MCP 取込（`strict_intake=True`, `intake_channel="mcp"`）の必須項目：固定ソース commit、固定イメージダイジェスト、テストコード SHA-256、実行者 (`executed_by`)、実行方法 (`execution_method`)、正常対照 (`positive_control`)＋防御/負対照 (`defense_check` または `negative_control`)、観測前後状態 (`before_state`, `after_state`)、未確認条件 (`unverified_conditions`)、後片付け確認 (`cleanup_confirmation`)、隔離宣言全項目 (`synthetic_data_only=True`, `external_egress_blocked=True`, `published_ports_none=True`)、不透明な非公開証拠参照 (`private_evidence_refs`)。
  - `request_id` による冪等リプレイと payload 競合時 `action_conflict`、および `expected_revision` 不一致拒否を備える。
- **CLI・MCP 共通検証・保存ロジック**: `ctf_mcp.evidence.manual_observation` + `HarnessController.import_manual_observation`
  - CLI `import-manual-observation` 側も共通ロジックと安全な JSON 読込み（`read_bounded_manual_json_file`: `O_NOFOLLOW` + `lstat`/`fstat` symlink 拒否 + 32 KiB 上限 + `..` 逸脱拒否）を適用しつつ、既存の CLI マニフェスト入力形式への後方互換を維持（`--strict` 指定時は MCP 同等必須検証）。
- **来歴分離と昇格拒否不変条件**:
  - 取り込んだ記録は常に `execution_provenance="manual_isolated_observation"`, `verification_tier="manual_isolated_observation_not_harness_verified"`, `promoted_to_vdp_product_test=False` を維持し、`unverified_conditions` 先頭に `not_executed_via_harness_vdp_test` を保持。
  - `run.verify(verifier_id="vdp.product_test")` へ渡しても `manual_observation_cannot_escalate_to_vdp_product_test`（`FAILED`）で拒否される。

## 2. 合成 E2E・負例セキュリティ検証範囲

`tests/integration/test_pr_a_manual_observation_mcp.py` および `tests/unit/test_p0_mcp_diagnostics.py` で以下を検証した：

1. **合成 VDP E2E (`fastmcp.Client`)**:
   - `tools/list` に `evidence.import_manual_observation` が公開され、トップレベルおよび全入れ子 `StrictModel` オブジェクト（`isolation_declared`, `controls`, `cleanup_confirmation`, `private_evidence_refs`）が `additionalProperties=False` を満たすこと。
   - MCP 経由取込、`evidence.read` による保存 JSON 検証、`run.describe` の `visible_mcp_tools` / `manual_observations` 反映、`request_id` 冪等リプレイ・競合拒否、`expected_revision` 競合拒否、`vdp.product_test` への昇格拒否、`export_vdp_submission_draft`（`automatic_submission=False`）連携。
2. **負例境界テスト**:
   - `offline_ctf` モード、クローズ済み VDP run、期限切れスコープ (`scope_expired`)、失効済みスコープ (`scope_revoked`)、他プリンシパル (`scope_denied`) での非表示・拒否（MCP・CLI 双方）。
   - 必須項目欠落、防御対照欠落、非隔離宣言（`external_egress_blocked=False` 等）、`..` 経路逸脱、ホスト絶対パス (`/etc/passwd`)、URL 混入 (`https://...`)、symlink 示唆 / CLI symlink JSON / CLI 32 KiB 超 JSON、ペイロード 32 KiB 超過、秘匿マーカー（エラー出力への非漏えい含む）、生 HTTP トランスクリプト・traceback 混入の拒否。
   - 既存 CLI レガシーマニフェストの後方互換維持（`--strict` なしで受理、`--strict` 指定時は必須項目検証で拒否）。
3. **診断チェック (`diagnose-mcp`)**:
   - 一時合成 VDP state に対し `diagnose-mcp` が `healthy: true`, `issues: []`, `surface_summary.vdp_manual_observation_mcp_exposed: true`, `tool_schemas["evidence.import_manual_observation"].additional_properties: false`, `nested_strict_objects_closed: true` を返し、`offline_ctf` では非公開となることを確認。

## 3. 未確認事項

1. 運用中リモートホストの基準作業ツリーへの反映・切替、および Windows Codex クライアント再接続後のライブ `tools/list` / `diagnose-nuc-mcp.ps1` 実機実行（予定されている調査セッションへの干渉を避けるため未実施）。
2. 実ターゲット（Weblate 製品コンテナ等）を使った実環境での追加確認（本 PR はハーネス機能拡張のため合成 fixture のみで受入）。

## 4. 運用ホストへの反映・クライアント再接続・ロールバック手順

- **反映（予定調査時間帯外に実施）**:
  1. 対象ホストのリポジトリで `git status --porcelain` がクリーンであることを確認し、`git pull --ff-only origin main` を実行。
  2. `ctf-mcp-admin diagnose-mcp --config <CONFIG_JSON> [--active-run <RUN_ID>]` で `healthy: true` と `surface_summary.vdp_manual_observation_mcp_exposed: true` を確認。
  3. 既存の Codex MCP セッションを終了し、**新しい Codex セッションを開始**してキャッシュ済み `tools/list` スキーマを再取得後、Windows 側から `scripts/diagnose-nuc-mcp.ps1` で `schema_match=true` を確認。
- **ロールバック**:
  1. 対象ホストで基準コミットへ戻す：`git checkout 1da967b94cbbeb030eeff88fe7574ac7ce3a085a`（または直前の安定コミット / `git switch main` 前の退避ブランチ）。
  2. 必要に応じて変更前の Codex `config.toml` バックアップを復元し、新しい Codex セッションを開始して `diagnose-mcp` / `diagnose-nuc-mcp.ps1` で復旧を確認。
