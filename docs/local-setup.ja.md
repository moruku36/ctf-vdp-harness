# ローカルセットアップと運用

[English](local-setup.md) | 日本語 | [概要とクイックスタート](../README.ja.md) | [資料索引](README.ja.md)

オフラインの導入手順を補足する文書であり、実対象への調査許可ではありません。所有済みfixtureか、明示的に許可された対象だけを扱います。実行プロファイルや接続範囲を変える前に[セキュリティ](05-security.ja.md)と[契約](11-contracts-and-acceptance.ja.md)を確認してください。

## 導入と非公開状態

Python 3.12+で[PowerShellのクイックスタート](../README.ja.md#クイックスタートローカルオフラインmcp)を実行します。Windowsで`libyaml`のCビルドツールがなく、間接依存のPyYAMLビルドに必要な場合は、導入前に以下を設定します。

```powershell
$env:PYYAML_FORCE_LIBYAML = "0"
python -m pip install -e .
```

開発用の追加依存は`python -m pip install -e ".[dev]"`です。必要な検証を合意済みのテスト予算内で選び、導入や資料変更だけを理由に過去の全テストを実行しません。

DB・証拠vault・カーソルHMAC鍵は非公開で保持します。クイックスタートは`.local_state\harness.db`とGit除外済みの`.ctf_vault`を使います。除外設定だけに頼らず、ステージしたファイルも確認してください。再起動時も同じ鍵を安全に再利用します。明示的なローカル開発用の一時鍵オプションを選ばない限り、鍵がないサーバーは起動を拒否します。

新しいシェルから始めてください。既存の`CTF_MCP_CONFIG`、`CTF_MCP_PROFILE`、`CTF_MCP_ALLOW_DYNAMIC`、通信方式の上書き設定は動作を変えます。CLIは検証済み実行設定を`--config`または`CTF_MCP_CONFIG`で受け取ります。[offline-pilot.example.json](../configs/offline-pilot.example.json)は意図的に`executable: false`とした設計例で、実行設定としては拒否されます。

## 所有済み成果物の搬入とローカル検証

クイックスタートでrunを作成した後、返されたIDを`$runId`に設定し、同じ環境を使います。例のディレクトリ・ファイル名は自分が所有するfixtureに置き換え、無関係な非公開ファイルを搬入しないでください。

```powershell
ctf-mcp-admin ingest-artifact --run-id $runId --source-root C:\path\to\owned_fixtures --rel-path sample.bin
ctf-mcp-admin describe-run --run-id $runId
```

独立に確認した期待flagのダイジェストがある場合はローカルに登録します。

```powershell
ctf-mcp-admin register-expectation --run-id $runId --flag-sha256 "<64桁の小文字16進SHA-256>"
```

平文flagや秘密値はCLI引数に渡しません。ダイジェスト登録はローカル検証器の準備であり、それだけで発見の検証やVDP受入が完了するものではありません。既定のcreate-runスコープは静的検査（`analysis.query`、`artifact.inspect`）を許可し、追加機能には明示的なスコープ判断が必要です。

## MCPの通信方式

既定サーバーは静的インスペクタとローカル検証器を接続し、合成アダプタは有効にしません。同じ環境・run IDで起動します。

```powershell
ctf-mcp-server --transport stdio --active-run $runId
```

MCPクライアント側で、このコマンドを同じ環境変数付きで起動する必要があります。代わりにローカルの認証付きHTTPを使う場合は、強い非公開トークンを設定します。以下の文字列は置き換えるための仮値であり、認証情報ではありません。

```powershell
$env:CTF_MCP_AUTH_TOKEN = "<十分な強度の非公開Bearerトークン>"
ctf-mcp-server --transport streamable-http --host 127.0.0.1 --port 8000
```

HTTPには仮値でないトークンとクライアント認証が必要です。ローカルstdioはローカルプロセスの信頼境界に依存します。どちらのコマンドも、公開トンネル、OAuth、隔離ゲストのネットワーク、全ChatGPT／Codexクライアントとの接続を構築するものではありません。配置計画は[接続設計](04-connectivity.ja.md)、特定環境の過去の結果は[WSL2／Codex記録](../records/p0-p6-wsl2-codex-environment-acceptance.md)を参照してください。

## Windows Codex → Linux Dockerホスト（Intel NUC）MCP接続と診断

旧WSL2環境から所有者のIntel NUC等のLinux DockerホストへMCP実行環境を移した場合、Windows側`%USERPROFILE%\.codex\config.toml`にOpenSSH（`ssh.exe -T`）経由の`[mcp_servers.ctf_vdp_harness]`定義が必要です（単一引用符`'...'`内のバックスラッシュは二重化しない）。以下はプレースホルダ例であり、秘密鍵や接続先・認証情報をGitに転記しないでください。

```toml
[mcp_servers.ctf_vdp_harness]
command = 'C:\WINDOWS\System32\OpenSSH\ssh.exe'
args = [
  "-T",
  "-i", 'C:\Users\<USER>\.ssh\<KEY_FILE>',
  "-o", "BatchMode=yes",
  "-o", "StrictHostKeyChecking=yes",
  "-o", "IdentitiesOnly=yes",
  "-o", "ServerAliveInterval=30",
  "-o", "ServerAliveCountMax=3",
  "-o", "ConnectTimeout=10",
  "<NUC_USER>@<NUC_HOST>",
  "/home/<NUC_USER>/ctf-vdp-harness-runtime/launch-mcp-stdio.sh",
  "--config", "/home/<NUC_USER>/ctf-vdp-harness-runtime/config.vdp-weblate.json",
  "--allow-dynamic",
]
startup_timeout_sec = 30
tool_timeout_sec = 360
```

- **起動・設定検証・ツール定義更新**：設定追加後にCodexから`codex.exe mcp list`および`codex.exe mcp get ctf_vdp_harness`で登録を確認し、NUC側のコード更新や`config.toml`変更時は必ず新しいCodexセッションを開始してMCPツール定義（`tools/list`）を再取得します（`--strict-config`は`codex exec`等のルート起動時に有効）。
- **段階診断と切り分け**：
  - リモート（NUC）側：`ctf-mcp-admin diagnose-mcp --config <CONFIG_JSON> [--active-run <RUN_ID>] [--check-docker]`
  - Windows側（読み取り専用診断）：
    ```powershell
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\diagnose-nuc-mcp.ps1 `
      -SshTarget "<NUC_USER>@<NUC_HOST>" `
      -IdentityFile "C:\Users\<USER>\.ssh\<KEY_FILE>" `
      -RunId "<RUN_ID>" -CheckDocker
    ```
  - 診断結果コードで原因を分離します：`codex_config_missing`（設定欠落）／`codex_config_legacy_wsl`（旧`wsl.exe`設定残存）／`stdout_pollution`（`.bashrc`やMOTDのstdout出力汚染）／`transport_closed_on_initialize`・`transport_closed_on_tools_list`（起動時異常終了）／`schema_mismatch_or_extra_forbidden`（`additionalProperties: false`を含むクライアント・サーバー間のツール引数スキーマ不一致）。
- **反映・ツール定義再取得・復旧（ロールバック）**：予定調査時間帯外に NUC 側リポジトリを更新（`git pull --ff-only`）した後は、必ず新しい Codex セッションを開始してキャッシュ済み MCP `tools/list` スキーマを再取得し、`ctf-mcp-admin diagnose-mcp --config <CONFIG_JSON>` と `scripts/diagnose-nuc-mcp.ps1` で健全性と `schema_match=true` を確認してください。クライアント変更前には必ず `config.toml` をバックアップし、不調時は `git checkout <PREVIOUS_COMMIT>` で旧コミットへ戻したうえで新しい Codex セッションを起動します。

## 状態確認と復旧

```powershell
ctf-mcp-admin describe-run --run-id $runId
ctf-mcp-admin reconcile
```

`reconcile`は管理上の状態遷移であり、読み取り専用の稼働確認でも、操作の再実行許可でもありません。結果不明の操作は、まず証拠と予約を照合します。プロセスが消えたことだけを理由に再試行しません。

`recover-guest`は独立にcleanupを確認してから使います。`--cleanup-verified`と空でない`--note`は運用者による確認の申告であり、cleanupを実施・証明する機能ではありません。架空の確認メモで復旧ゲートを解除しないでください。[復旧契約](11-contracts-and-acceptance.ja.md)を参照してください。

`ctf-mcp-admin update-budget`は既存runの上限を変更できますが、合意済み予算を超える許可ではありません。コマンドのhelpを確認し、増額には適用前の再認可が必要です。

## 任意アダプタと評価

| 機能 | 境界 |
|---|---|
| `helper.transform` | 上限付きの決定論的変換。`--enable-transform-helper`か実行設定による登録が必要 |
| `session.control` | 型付きの限定対話操作。アダプタ登録・動的実行の有効化・対応スコープがすべて必要。任意shell／デバッガコマンドではない |
| `net.probe` | 対象限定HTTP。受入済みで有効なアダプタ、network実行クラス、有効なnetwork方針、`scoped_ctf`／`vdp`で認可された対象が必要 |
| `vdp.test` | 所有者のLinux Dockerホスト上で、ピン留め済みソースコミット・イメージダイジェスト・許可済みセレクタ／オーバーレイを検証し、`--network=none` または `--internal` ネットワーク分離付き `isolated_internal_services` で製品テスト（`describe_profile`、`check_environment`、`run_smoke`、`run_pytest`）を実行。`vdp`プロファイル・動的実行有効化・`vdp.test`スコープ・`ctf-vdp-product-test`または`--enable-vdp-product-test`がすべて必要 |
| `evidence.import_manual_observation` | ハーネス外の手動・隔離VDP観測を取り込む専用型付きMCPツール。オープンかつ有効・期限内スコープの `vdp` run でのみ公開され、外部URLやローカルファイルは取得せず、`vdp.product_test` へは昇格しない |

動的操作には`--allow-dynamic`／`CTF_MCP_ALLOW_DYNAMIC`または対応する実行設定が必要ですが、フラグだけではスコープを許可しません。基準の`offline_ctf`実行設定は動的実行とネットワークを禁止します。過去の明示的なローカルセッション記録は、基準を緩和したり実対象をprobeしたりする許可ではありません。ネットワークの対象・操作・期限の確認と、外部送信の認可は分けます。

### VDP製品テスト（`vdp.test`）とツール公開面の補足

- **実行ホスト前提と事前環境確認**: `vdp.test`（`VdpProductTestAdapter`）は、ローカルDocker CLIとピン留め済み製品スキャナDockerイメージ（`docker image inspect`）へ到達できる所有者のWSL2 Ubuntu／Linuxホスト上で動作します。テスト実行前に`vdp.test(operation="check_environment", ...)`または`ctf-mcp-admin check-vdp-env --profile-name ...`を使うと、プロファイル有効性・Dockerイメージダイジェスト・checkoutコミット・オーバーレイSHA-256を一括確認でき、問題がある箇所だけ原因と修正手順を返します。ホスト前提が欠けている場合は`BLOCKED_ENV`（`verdict="environment_failure"`, verifier `INCONCLUSIVE`）を明示返却します。
- **安全なプロファイル登録と参照**: ターゲットプロファイルは`ctf-mcp-admin register-vdp-profile --profile-name ... --profile-revision ...`で`<vault_root>/_vdp/profiles.json`へ登録・更新します。`--positive-selector`／`--defense-selector`／`--anomaly-repro-selector`／`--env-check-selector`（または`--selector-role SELECTOR=ROLE`）で役割を明示し、`--overlay-file REL_PATH=auto|SHA256`でオーバーレイをピン留めできます（ワイルドカード・CLIフラグ・裸ディレクトリは拒否）。`--dry-run`で既存プロファイルとの差分・セレクタ／役割・オーバーレイSHA-256・コミット・イメージダイジェスト・資源上限を一画面で確認してから新リビジョンとして登録でき、登録後にオーバーレイファイルが変更された場合は実行前に拒否します（`overlay_integrity_failed`）。実行中VDPランでは`run.describe`の`"vdp_profiles[].active_tests"`および`vdp.test(operation="describe_profile")`から、ホストパス（`host_dir`、`checkout_dir`）を除いた有効テストと役割・オーバーレイSHA-256・上限を参照できます。
- **新規テストオーバーレイの登録補助（`register-vdp-overlay`）**: 新しいオーバーレイディレクトリを安全に登録するには、`ctf-mcp-admin register-vdp-overlay --overlay-dir ... --profile-name ... --overlay-bundle ...`（および`--base-profile`またはピン留め済み`--image-ref`／`--image-digest`／`--source-commit`）を実行します。既定では非破壊のドライランとなり、通常ファイルのみのSHA-256計算、ASTによる`test_*`セレクタ抽出、接頭辞または`--selector-role SELECTOR=ROLE`による役割割り当て、`network_mode="none"`を維持した`--config-diff`記録、`check-vdp-env`相当の環境確認をまとめてプレビューします。`profiles.json`への永続化には`--apply --confirm-apply`の両方が必須で、既定で環境ヘルス確認不合格時は適用を拒否します（`--require-healthy-env`が既定有効、明示的な上書きのみ`--allow-unhealthy-env`）。また`profiles.json`の更新はファイルロック＋リビジョン／ダイジェストCAS（`_vdp/profiles.json.lock`）で直列化され、既存バンドル・既存役割・既存リビジョンの上書き、既存ターゲットプロファイルへの別`--base-profile`指定、既存オーバーレイ／セレクタの削除（`removed_overlays`／`removed_selectors`）はいずれもフェイルクローズで拒否されます（`examples/vdp_overlay_assistant_example.py`参照）。
- **人間定義の認可マトリクス検証とオーバーレイ連携（`vdp-auth-matrix`）**: `ctf-mcp-admin vdp-auth-matrix --from-boundary-map <MAP_JSON> [--output <CAND_JSON>]` で `vdp-boundary-map` 出力をレビュー可能な候補雛形（`status_policy='investigation_candidate_only'`）へ変換し、`ctf-mcp-admin vdp-auth-matrix --validate-matrix <MATRIX_JSON>` で許可リスト・`required_preconfiguration`・根拠（`https://` URL または `file:line`）・各 `pair_group` の `allow`/`deny` 対・件数/時間/出力上限（最大64件・30秒・32KiB）を検証できます。`vdp.test` オーバーレイからは `AuthMatrixRunner` と `emit_auth_matrix_evidence_marker` を用いて、HTTP ステータス・伏字済み `Location` ヘッダ・JSON キー・合成マーカー・永続 DB 状態・Git リビジョン・キュー投入有無の前後差を、応答本文や生トークンを保存せず比較します（正常対照失敗時は `baseline_blocked` として防御成立に数えません）。
- **静的権限境界差分マップ（`vdp-boundary-map`）**: テスト作成前の事前調査として、`ctf-mcp-admin vdp-boundary-map --feature <name> --source-dir <src> [--test-dir <tests>] [--baseline-kind ui|api|webhook|async] [--format json|markdown|text]`を実行すると、`ui`・`api`・`webhook`・`async`の各エントリポイントにおける権限チェック（`AllowAny`／`[]`等のオープン設定を識別）・入力検証・スコープ絞り込み（サーバ／認証コンテキスト由来とユーザ入力由来を区別）・更新シンク・静的判定不能（`unknown`）・既存テスト未カバー箇所を到達可能ASTのみから解析し、`file:line`付きで比較出力します。全出力項目は`status="investigation_candidate"`のみであり、`unknown`を含む比較でも一致扱いせず、脆弱性の自動確定も行いません（`examples/vdp_boundary_map_example.py`参照）。
- **セレクタの役割・判定の意味・検証の順序**: `vdp.test(operation="check_environment", ...)` → `vdp.test(operation="run_smoke", ...)` → `vdp.test(operation="run_pytest", ...)` → `run.verify(verifier_id="vdp.product_test", evidence_ids=[...])`の順に実行します。`VdpProductTestVerifier`は`execution_provenance="harness_docker_isolated"`を要求して外部手元ログやローカルHTTP 200の流用を拒否し、4つの役割（`positive_control`、`defense_check`、`anomaly_repro`、`env_check`）に基づいて判定を厳密分離します：
  - `positive_control`が通らなければ`baseline_failed`（`FAILED`）とし、防御成功や異常再現に数えません。
  - `defense_check`のPASSは`hypothesis_falsified`（その条件では境界が守られた）となります。
  - `anomaly_repro`のPASSは`anomaly_observed`（指定挙動を観測した）となり、`hypothesis_falsified`とは混同せず、脆弱性の成立や影響判定とも分離します（自動提出は行いません）。
  - アサーション失敗／セットアップ失敗は原因確認まで`inconclusive`（`VerificationStatus.INCONCLUSIVE`）とし、脆弱性の証拠に数えません。SKIP・収集0件・タイムアウト・環境エラーは防御成功にも異常再現にも数えません。
- **限定差分・mutation 試験（`ctf_mcp.vdp_mutation` ＋ `vdp.test` `mutation_policy`）**：`--network=none` コンテナ内オーバーレイから `BoundedMutationRunner` を利用するか、`vdp.test(operation="run_pytest", ...)` に厳密型の `mutation_policy` 引数を指定します（`examples/vdp_mutation_example.py` 参照）。`seed`・1〜3 対象フィールド・`EntrypointPair`（`MutationPolicySpec.from_boundary_map_candidate` で Feature 1 から連携可能）・反復 `<=256`・壁時計 `<=300` 秒・正常対照ゲート（`baseline_failed`）・決定論的最小再現入力縮小・`LoopbackOnlyEgressGuard`＋`network_mode="none"` 強制・`VdpProductTestVerifier` での `bounded_mutation:verified` 検査を行います。
- **テスト設定と通常設定の差の自動記録（`ctf_mcp.vdp_setting_diff`）**：オーバーレイテスト内で `SettingDiffRecorder` / `emit_setting_diff_evidence_marker`（`ctf_mcp.vdp_fixtures` から再公開、`examples/vdp_setting_diff_example.py` 参照）を呼び出すと、Celery eager・ループバック fixture URL・テスト CA／プライベート allowlist・認証ショートカット・一時 DB・登録時 `config_diffs` を資格情報伏字付きで自動検出し、`execution_context["setting_diffs"]` と `conclusion_status` へ記録します。`VdpProductTestVerifier` は未確認タグを `VerificationRecord.limitations` へ転記し、`setting_diff_audit:recorded`（従来証跡は `setting_diff_audit:legacy_absent`）を付与したうえで、未確認差分残存時または監査欠如時の `claim="production_parity_confirmed"` をフェイルクローズで `FAILED` 判定します。
- **ローカル段階検証fixtureと結論条件の証跡化**: 外部通信遮断（`--network=none`）環境で実際の同期まで検証するため、`ctf_mcp.vdp_fixtures`にループバック限定（`127.0.0.1`）のGit HTTP fixture（`LocalGitHttpFixture`）と段階比較レコーダ（`StageComparisonRecorder`）を備えており、`update_scheduled`（更新予約）・`sync_completed`（同期完了）・`data_changed`（データ変更）を別々に記録できます。証跡には伏字化済みの`execution_context`と`conclusion_status`（`confirmed_conditions`・`unverified_conditions`）および固定コミット・イメージダイジェスト・オーバーレイSHA-256が紐付き、未確認条件（合成データ、Celery eager設定による`celery_eager_test_settings_async_unverified`等）が`VerificationRecord.limitations`へ転記されます。
- **依存サービス（PostgreSQL等）を伴う限定内部ネットワーク試験（`isolated_internal_services`）**：既存の`network_mode="none"`と`VdpProductTestVerifier`の条件は緩めません。別コンテナのPostgreSQL等が必要な場合のみ、プロファイル登録時に`--network-mode isolated_internal_services --service-json <JSON> --runner-mode direct_pytest [--pytest-executable <PATH>] [--smoke-selector <SEL>]`を明示指定します。実行時は`docker network create --driver bridge --internal`で専用内部ネットワークを作成して`Internal==true`を検証し、サービス側`publish_ports=False`および`HostConfig.PortBindings`公開ポート0件を検査し、全サービスイメージダイジェスト固定・合算資源上限（CPU合計`<=4`、メモリ合計`<=8192MB`）・準備完了プローブ・異常終了を含む全コンテナ／DB／ネットワーク削除（`service_cleanup_confirmed`／`network_cleanup_confirmed`）を`VdpProductTestAdapter`と`VdpProductTestVerifier`が一体で検証します。
- **ハーネス外の手動・隔離観測の来歴取込（MCP `evidence.import_manual_observation` ＋ CLI `import-manual-observation`）**：例外的にハーネス外（手動隔離コンテナ等）で実施した検証は、日常のMCP経路から型付きツール `evidence.import_manual_observation`（オープンかつ有効・期限内スコープの `vdp` run のみ）で直接取り込むか、`ctf-mcp-admin import-manual-observation --run-id <RUN_ID> --manifest-json <JSON> [--test-file <PATH> ...] [--raw-log-file <LOG>] [--strict]` で取り込めます（検証・保存ロジックは共通）。MCP取込では、固定コミット／イメージダイジェスト・テストコードSHA-256・`executed_by`・`execution_method`・`positive_control`＋`defense_check`/`negative_control`・`before_state`/`after_state`・`unverified_conditions`・後片付け確認・不透明な`private_evidence_refs`を必須とし、外部URL・ホスト絶対パス・symlink・生HTTP/スタックトレース・秘密値・サイズ超過を拒否します。記録は常に`execution_provenance="manual_isolated_observation"`・`promoted_to_vdp_product_test=False`に固定され、`VdpProductTestVerifier`（`vdp.product_test`）へ渡しても`manual_observation_cannot_escalate_to_vdp_product_test`で拒否されます。
- **候補の既知問題・成立条件チェックポイント台帳（`record-vdp-candidate` / `check-vdp-candidate-gate` / `list-vdp-candidates`）**：重い製品テスト前（`pre_heavy_test`）と提出直前（`pre_submission`）の二段階で、研究者や外部コネクタが調べた公開 issue／PR／修正コミット参照、対象版との関係、同一原因／同一影響に関する人間判断、および必須の成立条件（`preconfig_created_by`・`attacker_controls`・`real_world_prevalence`・`observed_impact_cap`）を`<vault_root>/_vdp/candidate_checkpoints.json`へ記録します。ハーネス自体は外部検索を行わず（`external_search_performed_by_harness=False`）、検索結果0件を「重複なし」と自動断定しません（`zero_search_results_does_not_prove_no_duplicate`）。期限（`max_age_hours`）超過時は提出前に再確認を促し、候補の恣意的な脆弱性確定（`auto_promoted_to_confirmed_vulnerability=False`）を行わず、VDP `run.describe` 上で `vdp_candidate_checkpoints` と `vdp_candidate_metrics` を参照できます。
- **VDP提出用下書き出力と手動提出状態の記録（`export-vdp-draft` / `record-vdp-submission`）**：[汎用調査レポート雛形](../templates/run-report.ja.md)に加え、[VDP提出用下書き雛形](../templates/vdp-submission-draft.ja.md)（[English](../templates/vdp-submission-draft.md)）に沿った提出下書きを`ctf-mcp-admin export-vdp-draft --run-id <RUN_ID> --draft-json <JSON> [--language ja|en] [--output-relpath <REL>]`で生成できます。下書きJSONに`candidate_id`を指定した場合は提出直前ゲート（`pre_heavy_test`実施済み＋有効・非ブロックの`pre_submission`）通過を必須とし、既知問題・成立条件表を本文へ転記します。引き続きハーネス検証済み証拠と手動隔離観測の来歴を分離表示し、`assert_report_clean`で秘匿検査を実施し、自動提出は常に無効（`automatic_submission=False`）です。所有者が手動提出した後のみ、`ctf-mcp-admin record-vdp-submission --run-id <RUN_ID> --finding-id <ID> --status submitted|accepted --report-url https://... --recorded-by <ACTOR> [--report-ref <REF>] [--triage-status ...]`および`list-vdp-submissions`で`_vdp/submissions.json`へ状態記録できます。
- **ツール公開面と静的文字列抽出の既定上限**: `StaticArtifactInspectorAdapter`は`analysis.query`のみで登録され、`artifact.inspect`向けの既定アダプタが未接続のため、`artifact.inspect`はMCP一覧へ公開されません。`analysis.query(operation="extract_strings")`で`max_matches`を省略した場合は安全上限（`--max-matches 40`＋`--soft-byte-budget`）を自動適用し、`output_limit_exceeded`ではなく`status="ok"`, `truncated=True`, `recommended_max_matches`, `next_offset`を返却します（大きな`max_matches`を明示指定した場合は従来通り`partial`／`output_limit_exceeded`となります）。

ランタイムにはSQLite正本のrun状態、リクエスト冪等性、クラッシュ照合・fencing、セッションlease、限定搬入、ページ付き・秘匿化済み証拠、出力処理があります。これらの仕組みと受入の限界は[ハーネス設計](08-analysis-harness.ja.md)、[契約](11-contracts-and-acceptance.ja.md)、[日付付き記録](README.ja.md#受入記録)に記載しており、包括的な安全性認証ではありません。

[オフライン評価](09-evaluation.ja.md)は合成課題を使い、VDP precision／recallをCTF成績と分離します。課題分割、実測、悪化、外部API料金未計測は[P5記録](../records/p5-offline-evaluation-acceptance.md)を確認してください。設計に登場するGhidra、radare2、Workbench、CTFd、公開トンネルがすべてパッケージ導入時に導入・有効化されるわけではありません。
