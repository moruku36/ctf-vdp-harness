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
| `vdp.test` | 所有者のWSL2／Linux Dockerホスト上で、ピン留め済みソースコミット・イメージダイジェスト・許可済みセレクタ／オーバーレイ・`--network=none`を検証して製品テスト（`describe_profile`、`check_environment`、`run_smoke`、`run_pytest`）を実行。`vdp`プロファイル・動的実行有効化・`vdp.test`スコープ・`ctf-vdp-product-test`または`--enable-vdp-product-test`がすべて必要 |

動的操作には`--allow-dynamic`／`CTF_MCP_ALLOW_DYNAMIC`または対応する実行設定が必要ですが、フラグだけではスコープを許可しません。基準の`offline_ctf`実行設定は動的実行とネットワークを禁止します。過去の明示的なローカルセッション記録は、基準を緩和したり実対象をprobeしたりする許可ではありません。ネットワークの対象・操作・期限の確認と、外部送信の認可は分けます。

### VDP製品テスト（`vdp.test`）とツール公開面の補足

- **実行ホスト前提と事前環境確認**: `vdp.test`（`VdpProductTestAdapter`）は、ローカルDocker CLIとピン留め済み製品スキャナDockerイメージ（`docker image inspect`）へ到達できる所有者のWSL2 Ubuntu／Linuxホスト上で動作します。テスト実行前に`vdp.test(operation="check_environment", ...)`または`ctf-mcp-admin check-vdp-env --profile-name ...`を使うと、プロファイル有効性・Dockerイメージダイジェスト・checkoutコミット・オーバーレイSHA-256を一括確認でき、問題がある箇所だけ原因と修正手順を返します。ホスト前提が欠けている場合は`BLOCKED_ENV`（`verdict="environment_failure"`, verifier `INCONCLUSIVE`）を明示返却します。
- **安全なプロファイル登録と参照**: ターゲットプロファイルは`ctf-mcp-admin register-vdp-profile --profile-name ... --profile-revision ...`で`<vault_root>/_vdp/profiles.json`へ登録・更新します。`--positive-selector`／`--defense-selector`／`--anomaly-repro-selector`／`--env-check-selector`（または`--selector-role SELECTOR=ROLE`）で役割を明示し、`--overlay-file REL_PATH=auto|SHA256`でオーバーレイをピン留めできます（ワイルドカード・CLIフラグ・裸ディレクトリは拒否）。`--dry-run`で既存プロファイルとの差分・セレクタ／役割・オーバーレイSHA-256・コミット・イメージダイジェスト・資源上限を一画面で確認してから新リビジョンとして登録でき、登録後にオーバーレイファイルが変更された場合は実行前に拒否します（`overlay_integrity_failed`）。実行中VDPランでは`run.describe`の`"vdp_profiles[].active_tests"`および`vdp.test(operation="describe_profile")`から、ホストパス（`host_dir`、`checkout_dir`）を除いた有効テストと役割・オーバーレイSHA-256・上限を参照できます。
- **新規テストオーバーレイの登録補助（`register-vdp-overlay`）**: 新しいオーバーレイディレクトリを安全に登録するには、`ctf-mcp-admin register-vdp-overlay --overlay-dir ... --profile-name ... --overlay-bundle ...`（および`--base-profile`またはピン留め済み`--image-ref`／`--image-digest`／`--source-commit`）を実行します。既定では非破壊のドライランとなり、通常ファイルのみのSHA-256計算、ASTによる`test_*`セレクタ抽出、接頭辞または`--selector-role SELECTOR=ROLE`による役割割り当て、`network_mode="none"`を維持した`--config-diff`記録、`check-vdp-env`相当の環境確認をまとめてプレビューします。`profiles.json`への永続化には`--apply --confirm-apply`の両方が必須で、既存バンドル・既存役割・既存リビジョンの上書きは拒否されます（`examples/vdp_overlay_assistant_example.py`参照）。
- **静的権限境界差分マップ（`vdp-boundary-map`）**: テスト作成前の事前調査として、`ctf-mcp-admin vdp-boundary-map --feature <name> --source-dir <src> [--test-dir <tests>] [--baseline-kind ui|api|webhook|async] [--format json|markdown|text]`を実行すると、`ui`・`api`・`webhook`・`async`の各エントリポイントにおける権限チェック・入力検証・スコープ絞り込み・更新シンク・既存テスト未カバー箇所をAST解析し、`file:line`付きで比較出力します。全出力項目は`status="investigation_candidate"`のみであり、脆弱性の自動確定は行いません（`examples/vdp_boundary_map_example.py`参照）。
- **セレクタの役割・判定の意味・検証の順序**: `vdp.test(operation="check_environment", ...)` → `vdp.test(operation="run_smoke", ...)` → `vdp.test(operation="run_pytest", ...)` → `run.verify(verifier_id="vdp.product_test", evidence_ids=[...])`の順に実行します。`VdpProductTestVerifier`は`execution_provenance="harness_docker_isolated"`を要求して外部手元ログやローカルHTTP 200の流用を拒否し、4つの役割（`positive_control`、`defense_check`、`anomaly_repro`、`env_check`）に基づいて判定を厳密分離します：
  - `positive_control`が通らなければ`baseline_failed`（`FAILED`）とし、防御成功や異常再現に数えません。
  - `defense_check`のPASSは`hypothesis_falsified`（その条件では境界が守られた）となります。
  - `anomaly_repro`のPASSは`anomaly_observed`（指定挙動を観測した）となり、`hypothesis_falsified`とは混同せず、脆弱性の成立や影響判定とも分離します（自動提出は行いません）。
  - アサーション失敗／セットアップ失敗は原因確認まで`inconclusive`（`VerificationStatus.INCONCLUSIVE`）とし、脆弱性の証拠に数えません。SKIP・収集0件・タイムアウト・環境エラーは防御成功にも異常再現にも数えません。
- **ローカル段階検証fixtureと結論条件の証跡化**: 外部通信遮断（`--network=none`）環境で実際の同期まで検証するため、`ctf_mcp.vdp_fixtures`にループバック限定（`127.0.0.1`）のGit HTTP fixture（`LocalGitHttpFixture`）と段階比較レコーダ（`StageComparisonRecorder`）を備えており、`update_scheduled`（更新予約）・`sync_completed`（同期完了）・`data_changed`（データ変更）を別々に記録できます。証跡には伏字化済みの`execution_context`と`conclusion_status`（`confirmed_conditions`・`unverified_conditions`）および固定コミット・イメージダイジェスト・オーバーレイSHA-256が紐付き、未確認条件（合成データ、Celery eager設定による`celery_eager_test_settings_async_unverified`等）が`VerificationRecord.limitations`へ転記されます。
- **ツール公開面と静的文字列抽出の既定上限**: `StaticArtifactInspectorAdapter`は`analysis.query`のみで登録され、`artifact.inspect`向けの既定アダプタが未接続のため、`artifact.inspect`はMCP一覧へ公開されません。`analysis.query(operation="extract_strings")`で`max_matches`を省略した場合は安全上限（`--max-matches 40`＋`--soft-byte-budget`）を自動適用し、`output_limit_exceeded`ではなく`status="ok"`, `truncated=True`, `recommended_max_matches`, `next_offset`を返却します（大きな`max_matches`を明示指定した場合は従来通り`partial`／`output_limit_exceeded`となります）。

ランタイムにはSQLite正本のrun状態、リクエスト冪等性、クラッシュ照合・fencing、セッションlease、限定搬入、ページ付き・秘匿化済み証拠、出力処理があります。これらの仕組みと受入の限界は[ハーネス設計](08-analysis-harness.ja.md)、[契約](11-contracts-and-acceptance.ja.md)、[日付付き記録](README.ja.md#受入記録)に記載しており、包括的な安全性認証ではありません。

[オフライン評価](09-evaluation.ja.md)は合成課題を使い、VDP precision／recallをCTF成績と分離します。課題分割、実測、悪化、外部API料金未計測は[P5記録](../records/p5-offline-evaluation-acceptance.md)を確認してください。設計に登場するGhidra、radare2、Workbench、CTFd、公開トンネルがすべてパッケージ導入時に導入・有効化されるわけではありません。
