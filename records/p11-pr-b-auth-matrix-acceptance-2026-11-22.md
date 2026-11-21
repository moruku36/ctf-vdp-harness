# P11 PR-B：認可マトリクス（`vdp-auth-matrix`）および `vdp.test` オーバーレイ連携受入記録 (2026-11-22)

- **対象ブランチ / 基準**: `feat/pr-b-auth-matrix` (PR-A `c5fb842b363b28a3c55a9dd54e93724b403276a1` からの積み上げ、PR-A は `origin/main` `6d6b5bc2ae3d9b08b3a74254fdd7c71ea6cbdc52` へマージ済み)
- **検証範囲**: 運用中ホストのメイン作業ツリー・SQLite / EvidenceVault・稼働中 run・登録済み profile・Codex 設定には一切触れず、隔離 `git worktree` 上の抽象化した合成 Django/DRF 風 fixture（脆弱版／修正版）で検証。実対象コード・本番 Docker 環境での試験は本記録に含めない。

## 1. 実装した機能と契約

- **`src/ctf_mcp/vdp_auth_matrix.py` + `ctf-mcp-admin vdp-auth-matrix`**:
  - 人間定義の機械可読マトリクス `vdp-auth-matrix/1`（`policy_source_kind="human_documented_policy"` 必須）：`actor` / `resource` / `action` / `entrypoint` (`ui|api|webhook|async`)・明示的 allowlist・期待判定 (`allow|deny`)・`required_preconfiguration`・根拠 `expectation_basis`（`https://` URL または相対 `file:line`）・比較対象 `compared_fields`。
  - 各 `pair_group` で `allow`（正常対照）と `deny` の両方を必須とし、実行時に正常対照を先に実行して不成立なら `deny` 行を `baseline_blocked` へ倒し、防御成功や脆弱性確定へ誤分類しない。
  - 比較対象：`http_status`、`location_header`（伏字済み・最大300文字）、`json_keys`（ソート済みキー名のみ）、`synthetic_markers`（一致マーカー名のみ）、`db_state`・`git_revision`・`queue_enqueued`（前後差のみ）。応答本文・`Authorization`・Cookie・生トークンは `extract_bounded_observation` および `redact_structure` により保存しない。
  - 上限強制：組合せ数（最大64件・`limits.max_combinations`）、壁時計時間（最大30秒 -> `timed_out=True`, `skipped_limit`）、出力バイト上限（最大32 KiB -> `output_truncated=True`）。
  - `vdp-boundary-map` 連携：`--from-boundary-map` で `cross_path_diffs` / `test_coverage_gaps` を `status_policy="investigation_candidate_only"`・人手レビュー必須雛形へ変換（脆弱性自動確定なし）。
- **`vdp.test` / オーバーレイ・検証器連携**:
  - `emit_auth_matrix_evidence_marker` が `VDP_EVIDENCE_MARKER` を改行境界付きで出力（`local_git_http.py` の `emit_vdp_evidence_marker` も先頭テスト行で取りこぼさないよう改行開始へ改善）し、`VdpProductTestAdapter` が `execution_context["auth_matrix_summary"]` へ伏字保存して `VdpProductTestVerifier` で検証できることを確認。

## 2. 合成 Django/DRF 風 fixture 受入検証 (`tests/integration/test_pr_b_auth_matrix.py`)

1. **多層差分検証（脆弱版 vs 修正版）**:
   - 権限者許可 (`allow`: `200`/`202`) と非権限者拒否 (`deny`: `404`/`403`) の正常対比較。
   - **同一 HTTP status (`200`) で一部 JSON フィールド・合成マーカーだけ漏えいする例**: 脆弱版で `json_key_leak` + `synthetic_marker_leak` として `investigation_candidate` 記録、修正版で `defense_held`（正常系 `200` 維持）。
   - **`Location` ヘッダだけに制限識別子が漏れる例**: 脆弱版で `location_header_marker_leak` + `synthetic_marker_leak` を検出（直接アクセス拒否と両立）、修正版で `defense_held`。
   - **HTTP 403 でも裏で永続 DB・Git revision・タスクキュー投入が起きる例**: 脆弱版で `unexpected_db_mutation` + `unexpected_git_revision_change` + `unexpected_queue_enqueue` を検出、修正版で 0 副作用 `defense_held`。
   - **秘匿性・伏字確認**: 模擬応答ヘッダ／JSON 中のダミー Bearer トークン・Cookie・本文値が結果 JSON・`VDP_EVIDENCE_MARKER` のいずれにも含まれないことを確認。
2. **壊れた正常対照・上限・入力検証の負例**:
   - 正常対照失敗時に `baseline_blocked` となり防御成功・異常再現ヘルパが拒否されること、許可外アクタ／非人間ポリシー／根拠欠落（`..`・絶対パス・`http://`）／対照欠落／組合せ上限・時間上限 (`timed_out=True`)・出力上限 (`output_truncated=True`)・symlink JSON が拒否／打ち切りされることを確認。
3. **`vdp.test` + `register-vdp-overlay` + `VdpProductTestVerifier` 通し検証**:
   - `register-vdp-overlay --apply --confirm-apply` による登録と、疑似コンテナ内実 `pytest` オーバーレイ実行（`run_smoke` + `run_pytest`）で、脆弱モード `verdict="anomaly_observed"` (`auth_matrix_summary.investigation_candidates == 1`, `VdpProductTestVerifier` `PASSED` ＋資格・影響限界注記)・修正モード `verdict="hypothesis_falsified"` (`investigation_candidates == 0`, `defense_held == 1`) を確認。

## 3. 未確認事項

1. 実ターゲット製品コンテナを用いた実機動作確認（本 PR は合成 Django/DRF 風 fixture のみ）。
2. 運用中リモートホストへの反映（PR マージ後、予定調査時間帯外に実施）。

## 4. 反映・ロールバック手順

- **反映（予定調査時間帯外）**: `git status --porcelain` が空の状態で `git pull --ff-only origin main` を実行し、`ctf-mcp-admin vdp-auth-matrix --help` および `ctf-mcp-admin diagnose-mcp --config <CONFIG_JSON>` で `healthy: true` を確認（本 PR は CLI / オーバーレイライブラリ追加であり MCP 公開スキーマは変更なし）。
- **ロールバック**: 対象ホストで直前安定コミットへ `git checkout <PREVIOUS_COMMIT>` を実行して確認。
