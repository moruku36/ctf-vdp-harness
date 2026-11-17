# VDP次段階実装計画（Stage 3 & 4 / PR-2仕様）

[English](vdp-next-stage-plan.md) | [ホーム](../README.ja.md) | [資料索引](README.ja.md)

本仕様書は、`ctf-vdp-harness`のVDP検証パイプラインにおける**Stage 3（Feature 3：隔離済み・上限付き差分／変異テスト）**および**Stage 4（Feature 4：テスト環境と本番設定の差分自動記録）**の設計・実装順序・工数見積もり・PR分割案を定義します。既存の`vdp.test`／`vdp.product_test`契約およびPR-1成果物を土台とし、既存のrun・証拠・オーバーレイSHA-256ピン留め・`--network=none`隔離境界を一切変更しません。

> [!IMPORTANT]
> **安全性と結論境界の原則**
> - **テストPASS／FAIL ≠ 脆弱性確定**：`anomaly_repro`のPASS、差分乖離の検出、アサーション失敗のいずれも、それ自体で脆弱性該当性や実害を確定しません。結果は`investigation_candidate`または`anomaly_observed`（`finding_qualification="separate_assessment_required_not_judged_from_pass_count"`）として記録します。
> - **オフライン・合成データ限定**：すべてのコンテナ実行は`--network=none`下で合成データとループバック（`127.0.0.1`）fixtureのみを対象とします。外部サービスへの送信・接続は厳禁です。
> - **既存状態の不変性**：既存のrun、SQLite状態、`EvidenceVault`のblob、登録済みプロファイルは変更せず、後方互換性を維持します。

---

## 1. 現行基盤とPR-1との依存関係

### 1.1 現行ランタイム契約（確認済みベースライン）

| 要素 | モジュール | 現行の役割と制約 |
|---|---|---|
| 製品テストアダプタ | `src/ctf_mcp/adapters/vdp_product_test.py` | `VdpProductTestAdapter`がピン留め済みDockerイメージ（`--network none`、CPU／メモリ／時間上限）内で`describe_profile`・`check_environment`・`run_smoke`・`run_pytest`を実行し、オーバーレイSHA-256検証（`_inspect_overlay_directory`）、秘匿化済み`VDP_EVIDENCE_MARKER`抽出、`vdp-product-test-evidence/1`生成を行う。 |
| 役割別判定器 | `src/ctf_mcp/adapters/vdp_product_test.py` | `_classify_verdict`が`positive_control`・`defense_check`・`anomaly_repro`・`env_check`（`VALID_SELECTOR_ROLES`）を厳密分離。アサーション失敗は`inconclusive`、正常系失敗は`baseline_failed`へ分類。 |
| ローカル検証器 | `src/ctf_mcp/verification/vdp_product_test.py` | `VdpProductTestVerifier`が`execution_provenance="harness_docker_isolated"`・`network_mode="none"`・cleanup確認・コミット／ダイジェスト一致を検証し、`conclusion_status.unverified_conditions`と`_MANDATORY_LIMITATIONS`を`VerificationRecord.limitations`へ転記する。 |
| ループバック・段階記録 | `src/ctf_mcp/vdp_fixtures/local_git_http.py` | `LocalGitHttpFixture`（`127.0.0.1`限定）、`StageComparisonRecorder`、`ScenarioStageRecord`、および`redact_sensitive_text`／`redact_structure`により、資格情報を漏らさず`update_scheduled`・`sync_completed`・`data_changed`を記録。 |

### 1.2 PR-1（Feature 1 & 2）への依存関係

PR-2はPR-1の公開契約を変更せず、出力を直接利用します：

1. **Feature 1（`src/ctf_mcp/vdp_boundary_map.py`）からの連携**：
   - `build_boundary_diff_map(...)`がAST解析により`ui`・`api`・`webhook`・`async`間の差分、`file:line`位置、既存テスト未カバー条件、`investigation_candidates`を出力。
   - **PR-2での利用**：Feature 3は無差別な全画面ファジングを行わず、`investigation_candidates`と抽出済み入力フィールド情報を起点に少数の`target_fields`と対比エントリポイントを選定します。
2. **Feature 2（`src/ctf_mcp/vdp_overlay_assistant.py`）からの連携**：
   - `generate_overlay_registration_plan(...)`および`preview_and_register_overlay(...)`がASTによるセレクタ検出、役割割り当て、SHA-256ピン留め、`--dry-run`プレビュー、`config_diffs`取得、`--apply --confirm-apply`でのフェイルクローズ登録を提供。
   - **PR-2での利用**：Feature 3で追加する変異／差分テスト用オーバーレイはFeature 2の安全な登録フロー経由でピン留めし、Feature 4はFeature 2が登録時に記録した`config_diffs`とコンテナ実行時の実設定差分を突合します。

---

## 2. Feature 3：隔離済み・上限付き差分／変異テスト

### 2.1 目的

`--network=none`コンテナ内で、単一または少数の入力フィールドに対して決定論的かつ上限付きの変異・差分テストを実行し、エントリポイント間（UI／API／Webhook／非同期処理など）の入力正規化・検証・スコープ境界の食い違いを検出し、異常時に最小再現入力と対照データを自動保存します。

### 2.2 アーキテクチャと安全境界

1. **対象フィールドの限定（`MutationTargetSpec`）**：
   - 1回の実行で変異対象にする`target_fields`を`1〜3`個に制限し、対比する`entrypoint_pair`（基準経路と候補経路）を明示指定。
   - 変異演算子（`MUTATION_OPERATORS`）は`boundary_length`・`encoding_normalization`・`scheme_or_path_variant`・`empty_null_type`・`whitespace_delimiter`に限定し、無制約な任意コード生成・送信を禁止。
2. **決定論的シードと厳格な上限**：
   - 整数`seed`（`uint64`）を必須指定または記録し、同一条件での100%再現性を保証。
   - `max_iterations`：既定`32`、ハード上限`256`（超過時は事前検証で拒否）。
   - `wall_time_cap_seconds`：既定`60`秒、上限は`min(plan.timeout_seconds, DEFAULT_VDP_TEST_TIMEOUT_SECONDS)`（`300`秒）。
   - `per_iteration_timeout_ms`：1反復あたりの上限（例：最大`2000ms`）を設け、単一入力の遅延による予算枯渇を防止。
   - `max_output_bytes`：`_encode_bounded_evidence_json`（`DEFAULT_VDP_TEST_MAX_OUTPUT_BYTES = 262_144`）を厳守。
3. **外部／本番サービス通信の厳禁**：
   - Docker実行時は常に`--network none`（`_validate_and_build_plan`および`VdpProductTestVerifier`で`network_mode="none"`を強制）。
   - コンテナ内の変異ランナー側でも非ループバックソケット接続・外部DNS解決を遮断するガードを組み込み、`127.0.0.1`／`::1`のローカルfixture（`LocalGitHttpFixture`等）以外へのアクセス試行を検知した時点で`environment_failure`（`network_isolation:violated`）として即座に中断。
4. **対照実行と最小再現入力の自動捕捉**：
   - **Step A（ベースライン関門）**：変異ループ前に`positive_control`対照入力を実行。不成立なら即座に`verdict="baseline_failed"`で終了。
   - **Step B（上限付き差分ループ）**：`max_iterations`および`wall_time_cap_seconds`の範囲内で、変異入力を候補経路・基準対照経路へ投入して応答／状態差分を比較。
   - **Step C（決定論的Shrinker）**：最初の乖離・異常検出時（または最大`3`種の異なる失敗クラスまで）、残り時間予算内で上限付きデルタデバッグ（`max_shrink_steps=24`）を実行し、最小再現入力（`minimal_repro_input`）を生成。
   - **Step D（伏字化済みペア証跡の出力）**：`redact_sensitive_text`／`redact_structure`適用後に`VDP_EVIDENCE_MARKER`を出力し、`mutation_summary`（`seed`・実行反復数・所要時間・停止理由）および`minimal_repro_case`（フィールド名・演算子・最小再現入力・対照入力・候補結果・対照結果・差分要約・縮小ステップ数）を証拠へ保存。
5. **判定規律**：
   - 正常系ベースラインが成立し最小再現入力で乖離が再現した場合のみ`verdict="anomaly_observed"`とし、ランナー例外やセットアップ失敗は`inconclusive`／`environment_failure`に隔離。
   - `finding_qualification`は常に`"separate_assessment_required_not_judged_from_pass_count"`とし、脆弱性確定へ自動昇格させない。

### 2.3 提案データ契約（`src/ctf_mcp/vdp_mutation.py`）

```text
MutationPolicySpec (StrictModel):
  seed: int (ge=0, le=2**63-1)
  max_iterations: int (ge=1, le=256, default=32)
  wall_time_cap_seconds: int (ge=5, le=300, default=60)
  max_shrink_steps: int (ge=0, le=64, default=24)
  target_fields: tuple[str, ...] (min_length=1, max_length=3)
  allowed_operators: tuple[MutationOperator, ...]
  allow_loopback_only: Literal[True] = True
```

---

## 3. Feature 4：テスト環境と本番設定の差分自動記録

### 3.1 目的

テスト用設定（同期eager実行、ループバックfixture、緩和されたTLS／許可リスト等）による挙動と本番相当設定の差異が暗黙のうちに見落とされるのを防ぐため、差分項目を自動抽出し、各項目に`"confirmed"`または`"unverified"`タグを付与して証拠および`VerificationRecord`へ確実に記録します。

### 3.2 記録対象カテゴリとタグ付け規則

各差分は型付きモデル`SettingDiffEntry`で表現します：

| カテゴリ | 典型的なテスト設定 | 本番想定ベースライン | 既定タグ | 条件タグの例 |
|---|---|---|---|---|
| `async_execution` | eager／インプロセス同期実行（`task_always_eager=True`、同期スタブ） | ブローカー経由の非同期ワーカー、シリアライズ、ワーカー権限 | `"unverified"`（実ワーカー確認時のみ昇格） | `celery_eager_test_settings_async_unverified` |
| `service_transport` | ループバックfixture（`127.0.0.1` `LocalGitHttpFixture`、モックHTTP） | 外部ネットワーク上の実VCS／Webhook／外部サービス | 遠隔通信は`"unverified"`、ローカルHTTPプロトコル確認済み範囲のみ`"confirmed"` | `loopback_fixture_vs_real_vcs_transport_unverified` |
| `tls_network_policy` | テスト用CA、プライベートIP／ループバック許可リスト上書き、`--network=none` | 本番TLS証明書検証、厳格な送信制御／SSRF IP拒否ポリシー | `"unverified"` | `test_ca_or_private_allowlist_vs_prod_tls_policy_unverified` |
| `auth_middleware` | テスト用`force_login`、CSRF／レート制限無効、`DEBUG=True` | 本番認証ミドルウェア、CSRF、リバースプロキシヘッダ | 回避時は`"unverified"`、実経路通過時は`"confirmed"` | `auth_middleware_parity_confirmed` / `auth_shortcut_unverified` |
| `storage_backend` | 一時SQLite／メモリキャッシュ | 本番RDBMS／Redisのロック・分離レベル | 並行性・ロック依存時は`"unverified"` | `ephemeral_db_concurrency_unverified` |

### 3.3 自動記録とVerifier伝搬フロー

1. **収集元（伏字化必須）**：
   - **登録時ベースライン**：Feature 2により`VdpTargetProfile`へ記録された`config_diffs`（テスト環境での既知オーバーライドと本番前提の宣言）。
   - **コンテナ内ランタイム検査**：`SettingDiffRecorder`が実行環境フラグ（eagerタスク設定、ループバックfixture URL、プライベート許可リスト環境変数、テストCA設定、`DEBUG`フラグ、DBエンジン種別）を収集し、プロファイルの本番ベースライン定義と比較。すべての値は`redact_sensitive_text`／`redact_structure`で伏字化。
   - **段階確認による限定的なconfirmed付与**：`StageComparisonRecorder`で`LocalGitHttpFixture`経由の`sync_completed=True`が確認できた場合は`loopback_git_http_sync_confirmed`のような狭義の項目のみ`"confirmed"`とし、実リモート通信・本番TLS・非同期ワーカーは引き続き`"unverified"`を明示。
2. **証拠ペイロードへの格納（`vdp-product-test-evidence/1`）**：
   - `_extract_evidence_markers`および`_build_execution_context_and_conclusion`で`setting_diffs: list[SettingDiffEntry]`を統合。
   - `verification_status == "unverified"`のエントリは`condition_tag`を自動的に`conclusion_status["unverified_conditions"]`へ追加し、`"confirmed"`エントリは`confirmed_conditions`へ追加。
   - `execution_context["setting_diffs"]`に伏字化済み差分一覧を`max_output_bytes`上限内で格納。
3. **Verifierによる自動検証と転記（`VdpProductTestVerifier.verify`）**：
   - 参照されたすべての`vdp.test`証拠から`execution_context.setting_diffs`を読み取り、`"unverified"`項目の条件タグを`_MANDATORY_LIMITATIONS`に加えて`VerificationRecord.limitations`へ自動転記（重複排除）。
   - 差分記録が存在する場合は`VerificationRecord.checks_performed`へ`setting_diff_audit:recorded`を記録（既存の後方互換証拠に対しては`setting_diff_audit:legacy_absent`として既存runを壊さない）。
   - `claim="production_parity_confirmed"`が指定された際に`"unverified"`項目が1件でも残っていれば`VerificationStatus.FAILED`（`production_parity:unverified_setting_diff_present`）としてフェイルクローズ。

---

## 4. 実装順序とマイルストーン別工数見積もり

### 4.1 マイルストーン一覧と依存関係

| マイルストーン | 内容 | 依存関係 | 工数見積 | 完了条件 |
|---|---|---|---|---|
| **M1: 設定差分コア（`vdp_setting_diff.py`）** | `SettingDiffEntry`・`SettingDiffRecorder`・伏字化連携・カテゴリ検出器・`VDP_EVIDENCE_MARKER`出力ヘルパー実装。 | 既存`local_git_http.py`の伏字化関数、PR-1 Feature 2の`config_diffs`形式 | **1.5〜2.0人日** | 合成設定辞書に対する単体テスト合格、秘密情報リーク0件、決定論的JSON生成。 |
| **M2: Adapter／Verifier連携** | `vdp_product_test.py`（マーカー統合・`execution_context`格納）と`verification/vdp_product_test.py`（`limitations`転記・`checks_performed`追加・本番同等性claim検証）を更新。 | M1 | **1.0〜1.5人日** | 既存`vdp-product-test-evidence/1`との後方互換維持、unverified差分残存時の`production_parity_confirmed`拒否を確認。 |
| **M3: 上限付き変異エンジン（`vdp_mutation.py`）** | `MutationPolicySpec`、許可済み変異演算子、決定論的RNG、対照実行、上限付きShrinker、ループバック限定通信ガード実装。 | M1、PR-1 Feature 1（`investigation_candidates`入力契約） | **2.5〜3.0人日** | `seed`による再現一致、反復・時間上限遵守、合成アプリでの最小再現入力＋対照ペア自動取得、外部ソケット遮断を確認。 |
| **M4: `vdp.test`操作・プロファイル統合** | `VdpProductTestAdapter`への`run_bounded_mutation`（または上限付き変異実行パラメータ）追加、`--network=none`・上限検証、Feature 2登録連携。 | M2、M3、PR-1 Feature 2 | **1.5〜2.0人日** | 不正seed・`>3`フィールド・`>256`反復・`network_mode != "none"`を事前拒否し、`EvidenceVaultPort`へ保存。 |
| **M5: 合成アプリ受入テスト・例・文書整備** | 合成マルチエントリポイントアプリでのE2E受入テスト、実行例、利用ガイド更新、リーク検査。 | M1〜M4 | **1.0〜1.5人日** | 合成fixtureでpytest 100%合格、実対象名／実知見リーク0件、PASS ≠ 脆弱性確定の検証完了。 |

**合計見積もり**：**7.5 〜 10.0人日**（レビュー性と安全性を高めるため、以下の2分割PR構成を推奨）。

---

## 5. PR-2分割計画

変更レビューと独立検証を容易にするため、PR-2を**PR-2A（Feature 4先行）**と**PR-2B（Feature 3後続）**に分割します：

### 5.1 PR-2A：Feature 4（設定差分自動記録 & Verifier連携）

- **推奨ブランチ**：`feat/pr2a-setting-diff-recorder`
- **変更・追加ファイル一覧**：
  - `src/ctf_mcp/vdp_setting_diff.py` *(新規)* — `SettingDiffEntry`、`SettingDiffRecorder`、5カテゴリの既定ルール、マーカー発行補助。
  - `src/ctf_mcp/vdp_fixtures/__init__.py` *(更新)* — `StageComparisonRecorder`と並べて再エクスポート。
  - `src/ctf_mcp/adapters/vdp_product_test.py` *(更新)* — `_extract_evidence_markers`と`_build_execution_context_and_conclusion`への`setting_diffs`統合。
  - `src/ctf_mcp/verification/vdp_product_test.py` *(更新)* — `VerificationRecord.limitations`への`"unverified"`自動転記、`setting_diff_audit:*`記録、`production_parity_confirmed`拒否条件追加。
  - `tests/unit/test_vdp_setting_diff.py` *(新規)* — 差分検出・伏字化・`"confirmed"`／`"unverified"`分類・後方互換の単体テスト。
  - `tests/integration/test_vdp_setting_diff_verification.py` *(新規)* — 合成証拠から`VdpProductTestVerifier`までの統合テスト。
  - `examples/vdp_setting_diff_example.py` *(新規)* — 合成アプリ設定を用いた実行例。

### 5.2 PR-2B：Feature 3（隔離済み・上限付き差分／変異テスト）

- **推奨ブランチ**：`feat/pr2b-bounded-mutation-testing`（PR-2A上へ積み上げ）
- **変更・追加ファイル一覧**：
  - `src/ctf_mcp/vdp_mutation.py` *(新規)* — `MutationPolicySpec`、許可済み変異演算子、シード固定ループ、対照実行、上限付きShrinker、ループバック限定通信ガード。
  - `src/ctf_mcp/adapters/vdp_product_test.py` *(更新)* — `run_bounded_mutation`操作（または上限付き変異実行計画の検証・`--network=none`強制）。
  - `src/ctf_mcp/verification/vdp_product_test.py` *(更新)* — 変異証跡のprovenance・ベースライン成立検証、`anomaly_observed`と脆弱性確定の分離維持。
  - `tests/unit/test_vdp_mutation.py` *(新規)* — シード再現性、反復／時間上限、Shrinker最小化、外部送信遮断の単体テスト。
  - `tests/integration/test_vdp_mutation_synthetic_app.py` *(新規)* — 合成マルチエントリポイントアプリ（UI／API／Webhook／非同期）でのFeature 1候補引き継ぎ・Feature 2ドライラン登録・Feature 4設定差分記録を跨ぐE2Eテスト。
  - `examples/vdp_mutation_example.py` *(新規)* — 合成アプリ向け実行例。
  - `docs/local-setup.md`・`docs/local-setup.ja.md` *(更新)* — 実装完了後の操作説明追記。

---

## 6. 合成アプリ限定・受入テスト計画

PR-2のすべての受入テストは`pytest`の`tmp_path`上に構築した一時的な合成Pythonアプリ／合成オーバーレイのみを使用し、実対象・非公開オーバーレイ・既存のrun／証拠には一切触れません：

| テストID | 対象 | 検証内容と合格条件 |
|---|---|---|
| **ACC-F3-01** | 合成マルチエントリポイントアプリ（`tmp_path`） | **決定論的シードと予算上限**：`seed=42, max_iterations=16, wall_time_cap_seconds=10`, `target_fields=("repo_url",)`で実行し、同一シード再実行で変異列と停止理由がバイト単位で一致すること。`max_iterations > 256`や`len(target_fields) > 3`が事前拒否されること。 |
| **ACC-F3-02** | `webhook`と`api`間で意図的な正規化差異を持つ合成アプリ | **最小再現入力＋対照ペア自動取得**：`positive_control`先行PASS後、変異により乖離を検出し、`max_shrink_steps`以内で縮小された`minimal_repro_input`と`paired_control_input`が証拠へ保存され、`verdict="anomaly_observed"`かつ`finding_qualification == "separate_assessment_required_not_judged_from_pass_count"`となること。 |
| **ACC-F3-03** | 正常系（`positive_control`）が失敗する合成アプリ | **ベースライン関門**：正常系失敗時は即座に`verdict="baseline_failed"`で停止し、`VdpProductTestVerifier`が`VerificationStatus.FAILED`を返すこと。 |
| **ACC-F3-04** | 外部HTTP／DNS接続を試みる合成変異ターゲット | **外部送信遮断と隔離保証**：非ループバック宛先または`network_mode != "none"`がフェイルクローズ（`network_mode_denied`／`network_isolation:violated`／`environment_failure`）で拒否され、`127.0.0.1`の`LocalGitHttpFixture`のみ許可されること。 |
| **ACC-F4-01** | eager実行・ループバックfixture・プライベート許可リストを含む合成設定 | **設定差分の自動記録とタグ付け**：3カテゴリすべてが`"unverified"`（`celery_eager_test_settings_async_unverified`、`loopback_fixture_vs_real_vcs_transport_unverified`、`test_ca_or_private_allowlist_vs_prod_tls_policy_unverified`）として記録され、URL内の資格情報が伏字化されること。 |
| **ACC-F4-02** | 合成証拠＋`VdpProductTestVerifier` | **Verifier伝搬と本番同等性ガード**：`"unverified"`タグが`VerificationRecord.limitations`へ自動転記されること。unverified差分が残る状態で`claim="production_parity_confirmed"`を渡すと`VerificationStatus.FAILED`になり、`setting_diffs`を持たない既存形式の証拠は`setting_diff_audit:legacy_absent`として後方互換維持されること。 |
| **ACC-HYG-01** | PR-2全ファイル＋テスト出力 | **機密・リーク検査**：実対象名0件、非公開オーバーレイ参照0件、生認証情報／トークン0件、自動`"confirmed_vulnerability"`判定0件を確認。 |
