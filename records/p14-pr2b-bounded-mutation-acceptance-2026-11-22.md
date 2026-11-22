# P14 PR-2B：限定差分・mutation 試験 (`vdp_mutation.py`) 受入記録 (2026-11-22)

- **対象ブランチ / 基準**: `feat/pr2b-bounded-mutation-testing` (PR-2A `0978c1422c01d4b56416675f7bcc716013d21b23` からの積み上げ、`origin/main` `822cf740101839dc6e66e736adad2984726d65f9` 相当)
- **検証範囲**: 運用中ホストのメイン作業ツリー・SQLite / EvidenceVault・稼働中 run・登録済み profile・Codex 設定には一切触れず、隔離 `git worktree` 上の抽象化した合成多入口 Python アプリ（`ui`/`api`/`webhook`）と疑似 Docker `pytest` ランナーで検証。実対象製品や外部ネットワーク通信を用いた試験は本記録に含めない。

## 1. 実装した機能と契約

- **`src/ctf_mcp/vdp_mutation.py`**:
  - **明示的ターゲット・上限制御 (`MutationPolicySpec` / `EntrypointPair`)**: `target_fields` は 1〜3 件、反復数 `max_iterations <= 256`、壁時計上限 `wall_time_cap_seconds <= 300`、反復単位タイムアウト `per_iteration_timeout_ms <= 2000`、縮小上限 `max_shrink_steps <= 64`、再現記録上限 `max_anomalies <= 3`、`allow_loopback_only=True`・`allow_external_egress=False` をフェイルクローズ強制。許可演算子は `boundary_length` / `encoding_normalization` / `scheme_or_path_variant` / `empty_null_type` / `whitespace_delimiter` のみ。
  - **決定論的シードと縮小器 (`BoundedMutationRunner`)**: 明示 `seed`（`uint64`）から完全再現可能な変異を生成し、最初に正常対照（`positive_control`）を検証して不成立時は即座に `baseline_failed` で終了。差分検出時は双方のエントリポイントを再評価しつつ決定論的縮小器で最小再現入力（`minimal_input`）と対照入力（`paired_control_input`）を抽出し、資格情報／秘密値を伏字化して出力サイズ上限内に収める。
  - **外部通信遮断 (`validate_loopback_only_value` + `LoopbackOnlyEgressGuard`)**: `127.0.0.1` / `::1` / `localhost` 以外の URL・socket `connect` / `connect_ex` / `create_connection` / `getaddrinfo` 呼び出しを `OutboundEgressBlockedError`（`network_isolation_violated`）で即座に遮断し `environment_failure` へ分類。
  - **PR-1 機能 1 連携**: `MutationPolicySpec.from_boundary_map_candidate` により `vdp-boundary-map` 候補から境界差分ペアの縮小ターゲットを生成可能。
- **`VdpProductTestAdapter` / `VdpProductTestVerifier` 連携**:
  - `VDP_PRODUCT_TEST_ARG_SCHEMA` に厳密入れ子型 `mutation_policy`（`additionalProperties: False`）を追加し、`network_mode == "none"` を必須化（非 `none` の場合は `network_mode_denied` で拒否）。
  - 実行結果の `mutation_summary` を `execution_context["mutation_summary"]` へ統合し、`egress_violation_detected` は `environment_failure` + `VerificationStatus.FAILED`（`network_isolation:violated`）、`positive_control_passed=False` は `baseline_failed` + `FAILED`、`anomaly_observed` は `vulnerability_qualification:separate_from_anomaly_observation` と `bounded_mutation:verified` を保持（自動的な脆弱性確定や外部送信は一切行わない）。

## 2. 合成受入テスト結果 (`test_vdp_mutation.py` / `test_vdp_mutation_synthetic_app.py`)

1. **ACC-F3-01..04 (`tests/unit/test_vdp_mutation.py`)**:
   - 同一 `seed=42` でバイト同一の変異反復・停止理由・縮小入力を再現、`>256` 反復／`>3` フィールド／`allow_external_egress=True` の事前回避、最小再現入力＋正常対照＋秘密伏字化、壊れたベースライン時の即 `baseline_failed`、外部 URL・`socket.connect`・`getaddrinfo` 遮断とループバック許可、`vdp-boundary-map` 候補変換を確認。
2. **多入口合成アプリ統合検証 (`tests/integration/test_vdp_mutation_synthetic_app.py`)**:
   - `vdp-boundary-map` → `register-vdp-overlay` (`dry-run`＋`--apply --confirm-apply`) → `SettingDiffRecorder` → `VdpProductTestAdapter` (`--network=none`) → `VdpProductTestVerifier` を一気通貫で実行し、脆弱版で `anomaly_observed`＋最小再現ケース取得＋`bounded_mutation:verified`、修正版で `hypothesis_falsified`、壊れた正常対照と外部 egress 試行でそれぞれ `baseline_failed` / `environment_failure`（いずれも `VerificationStatus.FAILED`）となることを確認。

## 3. 未確認事項

1. 実ターゲット製品コンテナおよび実 `vdp-weblate` 系プロファイルでの限定 mutation 試験（実作業は既存固定環境での承認済み試験範囲に限定）。
2. 運用中リモートホストへの反映（PR マージ後、予定調査時間帯外に実施）。

## 4. 反映・ロールバック手順

- **反映（予定調査時間帯外）**: `git status --porcelain` が空の状態で `git pull --ff-only origin main` を実行し、`ctf-mcp-admin diagnose-mcp --config <CONFIG_JSON>` で `healthy: true` を確認（既存の公開 MCP ツール一覧自体は増減せず、`vdp.test` 引数スキーマの任意フィールド `mutation_policy` を厳密拡張）。クライアント再接続時は新規 Codex セッションを起動。
- **ロールバック**: 対象ホストで直前安定コミットへ `git checkout <PREVIOUS_COMMIT>` を実行して新しい Codex セッションを起動。
