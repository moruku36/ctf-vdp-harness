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

動的操作には`--allow-dynamic`／`CTF_MCP_ALLOW_DYNAMIC`または対応する実行設定が必要ですが、フラグだけではスコープを許可しません。基準の`offline_ctf`実行設定は動的実行とネットワークを禁止します。過去の明示的なローカルセッション記録は、基準を緩和したり実対象をprobeしたりする許可ではありません。ネットワークの対象・操作・期限の確認と、外部送信の認可は分けます。

ランタイムにはSQLite正本のrun状態、リクエスト冪等性、クラッシュ照合・fencing、セッションlease、限定搬入、ページ付き・秘匿化済み証拠、出力処理があります。これらの仕組みと受入の限界は[ハーネス設計](08-analysis-harness.ja.md)、[契約](11-contracts-and-acceptance.ja.md)、[日付付き記録](README.ja.md#受入記録)に記載しており、包括的な安全性認証ではありません。

[オフライン評価](09-evaluation.ja.md)は合成課題を使い、VDP precision／recallをCTF成績と分離します。課題分割、実測、悪化、外部API料金未計測は[P5記録](../records/p5-offline-evaluation-acceptance.md)を確認してください。設計に登場するGhidra、radare2、Workbench、CTFd、公開トンネルがすべてパッケージ導入時に導入・有効化されるわけではありません。
