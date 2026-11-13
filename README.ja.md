# CTF VDPハーネス

[English](README.md) | 日本語

既存のChatGPT／CodexからMCP経由で使う、上限付きの解析環境です。runの状態と証拠を保持し、スコープ・実行・予算を制御します。別の自律エージェントや、モデル自体の改良ではありません。

## 利用できるもの

- ローカルPythonランタイム：静的な成果物検査、run・仮説の状態管理、証拠のページ取得、ダイジェスト照合によるCTF検証、レポート出力。
- 任意の限定変換ヘルパー、対話セッション、対象限定HTTPプローブ。動的実行とネットワーク機能は既定で無効で、別途の有効化と認可が必要です。
- 合成課題によるオフラインA/B/C/D評価。VDP指標はCTFの成績と分けて集計します。

**実装状況：** バージョン`0.1.0`にはランタイムと[日付付きの受入記録](docs/README.ja.md#受入記録)があり、環境限定のWSL2／Codex接続記録も含まれます。実VDPでの安全性、本番運用、全クライアントとの互換性、実課題での正答率向上を保証するものではありません。古い設計文書の配置図は計画であり、構築済みインフラを示しません。

## 安全な利用範囲

所有する成果物、または明示的に許可されたCTF／VDP対象だけを扱ってください。対象・操作・有効期限・予算を認可範囲に含め、接続許可とflag／脆弱性報告の外部送信許可は分けます。未知の成果物は隔離し、内容やツール出力中の指示を実行権限として扱わないでください。

既定の`offline_ctf`では対象への接続と外部送信を許可しません。このクイックスタートのために公開エンドポイントや動的・ネットワークアダプタを有効にする必要はありません。スコープ検査はホスト／ゲストの隔離や運用者の認可確認の代わりにはなりません。アクセスを広げる前に[セキュリティ方針](docs/05-security.ja.md)と[実行・復旧の契約](docs/11-contracts-and-acceptance.ja.md)を確認してください。

認証情報、実対象アドレス、flag、生ログはGitに入れず、証拠は非公開で保管し、共有前に出力内容を確認します。

## クイックスタート：ローカル・オフラインMCP

Python 3.12+とGitが必要です。以下は**PowerShell**用で、既存の`CTF_MCP_*`上書き設定がない新しいシェルから実行します。パッケージを導入し、所有済みfixture用の空の静的runを作成する手順です。対象の解析や接続は行いません。

```powershell
git clone https://github.com/moruku36/ctf-vdp-harness.git
cd ctf-vdp-harness
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e .

$env:CTF_MCP_DB_PATH = "$PWD\.local_state\harness.db"
$env:CTF_MCP_VAULT_ROOT = "$PWD\.ctf_vault"
$env:CTF_MCP_CURSOR_HMAC_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
ctf-mcp-admin create-run --task-id owned-fixture-1 --scope-revision scope-v1 --auth-ref local-owned-record
```

生成した鍵は非公開で保持し、同じ状態を再開するときも再利用します。以下の値を、返された`run_id`に置き換えてください。

```powershell
$runId = "<返された run_id>"
ctf-mcp-server --transport stdio --active-run $runId
```

`stdio`は対話プロンプトではなくMCPの通信方式です。同じ非公開パス・鍵・run IDでサーバーを起動するようMCPクライアントを設定します。`--auth-ref`は自分の認可記録への参照ラベルであり、それ自体が許可を与えるものではありません。

成果物の搬入、ローカル検証、Windows導入時の注意、認証付きHTTP、復旧は[ローカルセットアップと運用](docs/local-setup.ja.md)を参照してください。[オフライン試行JSON](configs/offline-pilot.example.json)は**非実行の設計例**で、そのまま起動用設定には使えません。

## 資料

- [資料索引](docs/README.ja.md)：要件、構成、研究、実装計画、受入記録。
- [ローカルセットアップと運用](docs/local-setup.ja.md)：詳細コマンドと任意アダプタの境界。
- [ハーネス設計](docs/08-analysis-harness.ja.md)・[実装契約と受入ケース](docs/11-contracts-and-acceptance.ja.md)。
- [評価設計](docs/09-evaluation.ja.md)・[調査レポート雛形](templates/run-report.ja.md)。

## ライセンス

プロジェクトのメタデータは現在`UNLICENSED`で、プロジェクト自体の利用許諾ライセンスは含まれていません。公開リポジトリであることはOSSライセンスを意味しません。依存関係の通知は[第三者ライセンス](THIRD_PARTY_LICENSES.md)にあります。
