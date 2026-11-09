# 03 MCP サーバー選定

English version: [03-mcp-selection.md](03-mcp-selection.md)


**2026-11-09の採用境界：** 以下の従来表は新たな互換性検証・コード監査ではない。[研究対応表](07-research-to-design.ja.md)で参考研究と依存採用を区別する。版・ライセンス・接続方式を固定し実試料を受入してから有効化。HexStrikeの不採用、REA・Burpの保留は維持。小さな分野別ツール一覧から始める。

## 1. 選定方針

- 既存資産（ゲスト配置済みの Workbench MCP と REA）を第一に位置づける。
- 追加候補は、GitHub 上の実在と一次・二次情報での裏付けが取れたものだけを載せる。確認できなかった項目は「未確認」と明記する。
- 本設計の原則（docs/01 N1）に反する「任意シェル実行が中核」のサーバーは、採用候補から外し、対照としてのみ記す。
- 最終更新の目安は、確認時点（2026-11-02）の二次情報に基づく目安であり、導入時に再確認する。

## 2. 選定表

### 2.1 既存資産

| 名称 | URL | ライセンス | 最終更新の目安 | トランスポート | ツールの粒度 | 任意シェル実行 | 主なカテゴリ | 位置づけ |
|---|---|---|---|---|---|---|---|---|---|
| OSS Vulnerability Workbench MCP | https://github.com/moruku36/oss-vulnerability-workbench-mcp | 自作（モルク自身のリポジトリ） | ゲスト配置済み | 未確認（ゲスト内で基本通信は確認済み） | 16 ツールの列挙を確認（ラボ記録）。実スキャナー実行は未検証 | なし（解析系ツール群） | コード監査・依存関係 | 土台として継続利用 |
| REA（Reverse Engineer Anything）6.7.0 | https://github.com/morluto/rea | 未確認 | ゲスト配置済み（オフライン資材の固定マニフェスト確認済み） | 未確認 | Ghidra 連携の解析支援 | 未確認 | rev | 既存資産として活用。ただし REA → Ghidra の解析能力は受入れ未完了（スコープ B） |

### 2.2 追加候補（採用を検討するもの）

| 名称 | URL | ライセンス | 最終更新の目安 | トランスポート | ツールの粒度 | 任意シェル実行 | 主なカテゴリ | 位置づけ |
|---|---|---|---|---|---|---|---|---|---|
| GhidraMCP（LaurieWired） | https://github.com/LaurieWired/GhidraMCP | Apache-2.0 | 活発（2026-10 時点で更新を確認した二次情報あり） | stdio ブリッジ／Streamable HTTP 選択可。Ghidra 拡張側はループバック HTTP | 関数一覧、デコンパイル、xref、リネーム等の細粒度解析ツール | なし（Ghidra 操作が中心。スクリプト実行系ツールの有無は導入時に確認） | rev | **第一候補**。導入済み Ghidra 12.1.4 に対応する |
| radare2-mcp（r2mcp、radareorg 公式） | https://github.com/radareorg/radare2-mcp | LGPL 系との二次情報あり（導入時に LICENSE 確認） | 活発（1.9.0 リリースを確認） | stdio／HTTP モード。HTTP 時は Bearer トークン認証に対応（リリース情報） | radare2 の解析機能をツール化。readonly モード、sandbox lock、ツール制限オプションあり | raw な r2 コマンド実行を任意で有効化できる設計がある。**既定で無効化できることを採用条件とする** | rev / pwn | radare2 系の本命。自作 core の radare2 ラッパーは作らず、こちらに寄せる |
| Burp MCP（PortSwigger 公式拡張） | https://github.com/PortSwigger/mcp-server | 未確認（二次情報に GPL-3.0 と Apache-2.0 の両説あり） | 未確認 | SSE（ループバック）＋ stdio プロキシ | Burp の操作ツール約 27（二次情報）。プロキシ履歴の参照、リクエスト送信等 | なし（Burp 操作が中心） | web | Web カテゴリの有力候補。前提として Burp Suite 本体（Community 可）の常駐が必要で、配置場所が判断ポイント |
| ghidra-mcp（bethington） | https://github.com/bethington/ghidra-mcp | Apache-2.0（二次情報） | 未確認（2025-08 作成、活発との二次情報） | GUI プラグイン＋ヘッドレスサーバー | 219 ツール（プロジェクト自己申告） | 未確認 | rev | Ghidra 系の代替候補。ツール数が欲しい場合に比較検討 |
| pyghidra-mcp（clearbluejar） | 未確認（導入時にリポジトリを特定する） | Apache-2.0（二次情報） | 未確認 | ヘッドレス特化 | プロジェクト横断の解析、セマンティック検索等（二次情報） | 未確認 | rev | GUI のないゲスト運用と相性が良い候補。まず出所の特定と精査から |

### 2.3 参考・対照（採用しないもの）

| 名称 | URL | 概要 | 採用しない理由 |
|---|---|---|---|
| HexStrike AI（0x4m4） | https://github.com/0x4m4/hexstrike-ai | MIT。150 以上のセキュリティツールを束ねる MCP サーバー（FastMCP ブリッジ＋Flask API）。カテゴリ構成は network / web / binary / cloud / CTF・forensics 等 | ツールは個別ラッパーだが、内部実装が `shell=True` のサブプロセス実行であること、上流版にサーバー認証がないことが分析レポートで指摘されている。本設計の原則（N1・N6）と衝突するため、そのままでは採用しない。ツール目録とカテゴリ構成の参考資料として扱う |
| CTF-Solver（foxibu） | https://github.com/foxibu/CTF-Solver | Kali ツール 55 以上を HTTP（ポート 5000）で公開する MCP Kali Server 系。7 カテゴリ対応を掲げる。ライセンス未確認 | Kali Server 系は任意コマンド実行を含む設計であり、原則（N1）と衝突する。参考のみ |
| MCP-Kali-Server（Wh0am123） | https://github.com/Wh0am123/MCP-Kali-Server | Kali のターミナルコマンド実行そのものを API ブリッジするサーバー | 任意シェル実行が中核であり、原則（N1）に反する。対照例としてのみ記載 |
| mcp-ctf-server（zemi-gh） | 未確認（MCP サーバーディレクトリ Glama への掲載で実在を確認） | stdio 型。crypto / forensics / stego / traffic 等のカテゴリ別ツールと、Python スニペット実行サンドボックスを含む | 出所（GitHub URL）とライセンスが未確認であり、Python 任意実行を含む。導入前に出所の特定と精査が必須の参考候補 |

## 3. 選定の根拠（要点）

1. **Ghidra 系は導入済み資産との一致を優先した。** ゲストには Ghidra 12.1.4 が配置済みであり、GhidraMCP はそのバージョンに対応する拡張＋ブリッジ構成で、実績も厚い。GUI を開かない運用が主になる場合は、ヘッドレス特化の pyghidra-mcp を比較対象に残す。
2. **radare2 系は公式実装を採る。** radare2-mcp は radareorg 公式で、readonly モードやツール制限、HTTP 時のトークン認証など、本設計の原則と噛み合う制御を持っている。Gemini 資料が自作を想定していた radare2 ラッパー群は、原則として本家に寄せ、自作範囲を縮小する。
3. **「全部入り」サーバーは原則との衝突で見送った。** HexStrike AI のような統合型は一見便利だが、任意実行に近い実装と認証の欠如が確認されており、公開経路を持つ本設計には載せない。必要なツールはカテゴリ別に、細粒度のサーバーと自作 core で組み立てる。
4. **Web カテゴリは Burp 公式を軸にしつつ、配置を保留した。** Burp 本体は GUI アプリケーションであり、ヘッドレスのゲスト内常駐が適切かは未検証である。Windows 側に置く案も含め、docs/06 の判断ポイントとする。軽量な HTTP 検査は ctf-mcp core 側の httpx ラッパーで先行して賄う。
5. **crypto / encoding は OSS が薄く、自作 core の主担当とした。** 既存の CTF 特化サーバーは任意実行を含むものが多く、決定論的ヘルパーだけを抜き出した実装が見つからなかったためである。

## 4. 導入時の再確認リスト

- 各リポジトリの LICENSE ファイルと最新リリースを導入時点で確認する（本書のライセンス・更新情報は目安）。
- ツール一覧を棚卸しし、許可リスト（docs/05）に載せるものだけを有効化する。特に「raw コマンド実行」「スクリプト実行」に相当するツールは既定で無効化する。
- 依存関係とビルド手順を確認し、ゲストへの搬入はオフライン資材化（従来の ISO 経路）で完結させる。
