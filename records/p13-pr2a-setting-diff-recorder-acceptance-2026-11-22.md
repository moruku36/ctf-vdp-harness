# P13 PR-2A：テスト設定と通常設定の差の自動記録 (`vdp_setting_diff.py`) 受入記録 (2026-11-22)

- **対象ブランチ / 基準**: `feat/pr2a-setting-diff-recorder` (PR-C `c66698cf2df2d3f144c96bde53dfd4064b562b5b` からの積み上げ、`origin/main` `af59e71c3b073f8a31cf89faf82ed499fe4659d2` 相当)
- **検証範囲**: 運用中ホストのメイン作業ツリー・SQLite / EvidenceVault・稼働中 run・登録済み profile・Codex 設定には一切触れず、隔離 `git worktree` 上の抽象化した合成設定マップ・合成オーバーレイおよび疑似 Docker `pytest` ランナーで検証。実対象製品コンテナや本番 Docker デーモンを用いた検証は本記録に含めない。

## 1. 実装した機能と契約

- **`src/ctf_mcp/vdp_setting_diff.py` + `src/ctf_mcp.vdp_fixtures` 再公開**:
  - `SettingDiffEntry`（`async_execution` / `service_transport` / `tls_network_policy` / `auth_middleware` / `storage_backend` / `other`）と `SettingDiffRecorder` を追加し、Layer 2 隔離規約（`gateway` / `runs` / `evidence` 非依存）を遵守。
  - Celery eager 設定、ループバック fixture（`127.0.0.1` / `localhost` / `::1`）、テスト用 CA バンドル・private IP allowlist・TLS 検証無効、`force_login`・CSRF/rate-limit 無効・`DEBUG=True`、SQLite/`:memory:`/locmem 一時ストレージ、登録時 `config_diffs` を自動検出し、URL 資格情報（`***:***@`）および Bearer/SYNTHETIC_SECRET/token 系秘密値を伏字化して `VDP_EVIDENCE_MARKER` を出力。
  - ループバック同期の段階完了（`sync_completed=True`）が確認された場合は `loopback_git_http_sync_confirmed`（`confirmed`）のみを付与し、実外部 VCS 転送との差（`loopback_fixture_vs_real_vcs_transport_unverified`）は `unverified` のまま保持（既定の `unverified` 上書きを `confirmed` で打ち消さない）。
- **`VdpProductTestAdapter` / `VdpProductTestVerifier` 連携**:
  - `_extract_evidence_markers` と `_build_execution_context_and_conclusion` で `setting_diffs` を抽出・正規化・伏字化し、`execution_context["setting_diffs"]` および `conclusion_status["confirmed_conditions"]` / `["unverified_conditions"]` へ統合。
  - `VdpProductTestVerifier.verify` は未確認設定差分の `condition_tag` を `VerificationRecord.limitations` へ転記し、`setting_diff_audit:recorded`（旧証跡には `setting_diff_audit:legacy_absent`）を記録。`claim="production_parity_confirmed"` 時に未確認差分または設定差分監査欠如があれば `VerificationStatus.FAILED`（`production_parity:unverified_setting_diff_present` / `production_parity:setting_diff_audit_missing`）でフェイルクローズ。

## 2. 合成受入テスト結果 (`test_vdp_setting_diff.py` / `test_vdp_setting_diff_verification.py`)

1. **ACC-F4-01 (`tests/unit/test_vdp_setting_diff.py`)**:
   - 全 5 カテゴリ＋`registration_config_diffs` 自動検出、段階別限定 `confirmed`（`loopback_git_http_sync_confirmed`）、URL パスワード・Bearer トークン・`SYNTHETIC_SECRET_*` の完全伏字化、`unverified` 優先保持、上限超過拒否、決定論的 JSON 出力を確認。
2. **ACC-F4-02 (`tests/integration/test_vdp_setting_diff_verification.py`)**:
   - 合成オーバーレイが発行した `SettingDiffRecorder().emit_marker()` が `execution_context["setting_diffs"]` と `VerificationRecord.limitations` へ伝播すること、`claim="production_parity_confirmed"` が未確認差分ありまたは監査欠如時に `FAILED` となること、および `setting_diffs` を持たない従来証跡が `setting_diff_audit:legacy_absent` で後方互換動作することを確認。

## 3. 未確認事項

1. 実ターゲット製品コンテナを用いた設定差分自動記録の実機動作確認。
2. PR-2B（限定差分・mutation 試験）の実装・検証（別 PR にて順次実施）。
3. 運用中リモートホストへの反映（PR マージ後、予定調査時間帯外に実施）。

## 4. 反映・ロールバック手順

- **反映（予定調査時間帯外）**: `git status --porcelain` が空の状態で `git pull --ff-only origin main` を実行し、`ctf-mcp-admin diagnose-mcp --config <CONFIG_JSON>` で `healthy: true` を確認（本 PR は内部設定差分モジュール・検証器強化であり MCP 公開ツールスキーマは変更なし）。
- **ロールバック**: 対象ホストで直前安定コミットへ `git checkout <PREVIOUS_COMMIT>` を実行して確認。
