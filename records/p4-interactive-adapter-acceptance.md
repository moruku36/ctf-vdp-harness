# MVP P4 + CTF-09 受入記録: 対話デバッグアダプタ (`session.control`)・変換ヘルパー (`helper.transform`)・Scoped Network 防御 (`net.probe`)

- 担当: `p4-impl`
- ブランチ: `feat/p4-interactive-and-ctf09` (親コミット: `121039d` / `main`)
- 日時: 2026-11-13
- 対象範囲: MVP P4 (`docs/08-analysis-harness.ja.md` §5〜§7, `docs/10-implementation-plan.ja.md` P4, `docs/11-contracts-and-acceptance.ja.md` §1, §4, §5, §7 `CTF-09`)

---

## 1. 変更内容・実装サマリー

既存の保護対象ファイル（`docs/`, `schemas/`, `configs/`, `examples/`, `templates/`, `THIRD_PARTY_LICENSES.md`, `pyproject.toml`, `README.md`, `README.ja.md`, `src/ctf_mcp/evaluation.py`, `tests/evaluation/`）は一切変更せず、以下を新規実装・統合した。

### 新規作成モジュール（すべて Python 標準ライブラリのみ、`shell=False`、Layer 2 横方向 import ゼロ）
- [`src/ctf_mcp/adapters/transform_helper.py`](../src/ctf_mcp/adapters/transform_helper.py)
  - `DeterministicTransformAdapter(BaseAdapter)` / `create_transform_helper_descriptor()`
  - 識別子: `adapter_id="ctf-helper-transform"`, `name="helper.transform"`, `adapter_commit="p4-transform-helper-1"`, `ExecutionClass.STATIC`, `profile_modes=(RunMode.OFFLINE_CTF, RunMode.SCOPED_CTF, RunMode.VDP)`, `required_scope={"modes": ["offline_ctf", "scoped_ctf", "vdp"]}`。
  - 列挙 8 操作: `base64_encode`, `base64_decode`, `hex_encode`, `hex_decode`, `xor_bytes`, `rot_caesar`, `url_decode`, `zlib_decompress`。
  - セキュリティ・上限境界: 非シンボリックリンク通常ファイル検査、入力上限 `65,536 B` (`MAX_TRANSFORM_INPUT_BYTES`)、解凍・出力上限 `65,536 B` (`MAX_TRANSFORM_DECODE_BYTES`) による zlib bomb 遮断、JSON 出力上限 `262,144 B` (`MAX_TRANSFORM_STDOUT_BYTES`)、XOR 鍵上限 `256 B` (`MAX_XOR_KEY_BYTES`)、実サブプロセス `peak_rss_bytes`/`cpu_ms`/`wall_ms` 計測および `EvidenceVault` ページ取得連携。
- [`src/ctf_mcp/adapters/interactive_session.py`](../src/ctf_mcp/adapters/interactive_session.py)
  - `InteractiveDebugSessionAdapter(BaseAdapter)` / `create_interactive_session_descriptor()`
  - 識別子: `adapter_id="ctf-interactive-session"`, `name="session.control"`, `adapter_commit="p4-interactive-session-1"`, `ExecutionClass.DYNAMIC`, `profile_modes=(RunMode.OFFLINE_CTF, RunMode.SCOPED_CTF)`, `required_scope={"modes": ["offline_ctf", "scoped_ctf"]}`。
  - 動的実行プロファイル分離: デフォルト静的プロファイル（`allow_dynamic=False` / 未登録時）では MCP `tools/list` に表示せず、直接呼出でも拒否する。
  - 型付き 4 操作のみ許可: `open`, `inspect`, `step`, `close`（生コマンド文字列・`eval`/`exec`・追加未定義引数・任意操作名をスキーマ・Gateway・Adapter の多層で拒否）。
  - OS プロセス・セッション状態管理: 各操作を `SubprocessRunner(shell=False)` で隔離実行し、`timeout` / `cancel_event` で孫プロセスを含めて終了（`is_os_process_alive == False`）、`close`・15分 (900秒) アイドル失効・Supervisor 再起動 `lost` 化と連動してチェックポイントファイルを確実削除する。
- [`src/ctf_mcp/gateway/network_guard.py`](../src/ctf_mcp/gateway/network_guard.py)
  - `ScopedNetworkPolicyGuard` / `AllowedTargetRule` / `PinnedNetworkTarget`
  - `ScopePolicy` (`network_enabled=True`, `allowed_targets`) に基づき、`http`/`https` のみ許可、IDNA/大文字小文字/末尾ドット/既定ポート/パス接頭辞/HTTP メソッドを検証し、userinfo 埋め込み URL (`user@host`) を無条件拒否する。
  - 注入可能な DNS リゾルバ（既定 `socket.getaddrinfo`）の**全返却 IP**を検査し、未許可の loopback (`127.0.0.0/8`, `::1`), RFC1918 private, link-local / cloud metadata (`169.254.0.0/16`, `fe80::/10`, `fd00:ec2::254`), IPv6 ULA (`fc00::/7`), IPv4-mapped IPv6 (`::ffff:...`) を拒否する。
  - 接続先を検査済み IP へピン留め（`PinnedNetworkTarget`）しつつ元ホストの `Host` ヘッダを維持し、HTTP `3xx` リダイレクト自動追従を禁止してホップごと (`MAX_REDIRECT_HOPS`) に遷移先 URL・DNS 解決・スコープを再検査する。
- [`src/ctf_mcp/adapters/scoped_http_probe.py`](../src/ctf_mcp/adapters/scoped_http_probe.py)
  - `ScopedHttpProbeAdapter(BaseAdapter)` / `create_scoped_http_probe_descriptor()`
  - 識別子: `adapter_id="ctf-scoped-http-probe"`, `name="net.probe"`, `adapter_commit="p4-scoped-http-probe-1"`, `ExecutionClass.NETWORK`, `profile_modes=(RunMode.SCOPED_CTF, RunMode.VDP)`, `required_scope={"modes": ["scoped_ctf", "vdp"], "network_enabled": True}`, 操作 `('request', 'get', 'head')`。
  - 事前検証・IP ピン留め情報をワーカープロセス (`SubprocessRunner(shell=False)`) に渡し、取得ボディを上限付きで `EvidenceVault` へ保存して `usage` (`wall_ms`, `output_bytes`, `peak_rss_bytes`, `cpu_ms`) と `provenance` を返す。

### Layer 2/3/4 統合更新
- [`src/ctf_mcp/adapters/__init__.py`](../src/ctf_mcp/adapters/__init__.py) & [`src/ctf_mcp/gateway/__init__.py`](../src/ctf_mcp/gateway/__init__.py): P4 / CTF-09 公開シンボルをエクスポート（`adapters` ⇔ `gateway` 間の直接 import ゼロを維持）。
- [`src/ctf_mcp/contracts.py`](../src/ctf_mcp/contracts.py): P4 / CTF-09 に伴う契約型補助を更新。
- [`src/ctf_mcp/controller.py`](../src/ctf_mcp/controller.py):
  - `session.control` の `LeaseManager` 連携（`open` で `acquire_lease_in_tx` による `interactive_session_limit=1` 制限、`inspect`/`step` で `touch_lease`、実行前後の `expire_idle_leases` による 900 秒アイドル失効、`close` で `close_lease`、起動 `initialize()` 時の `lost` 化と `register_adapter()` / `close_run()` / 失効時のセッションファイル確実削除）。
  - `net.probe` 用の `_load_live_scope_policy`（`scopes.revoked_at` による即時 `scope_revoked` 拒否）・preflight IP ピン留め連携・TX2 決済前の再失効検査、および `register_default_adapters` / `create_default_controller` へのオプトイン登録 (`include_transform_helper`, `include_interactive_session`, `include_scoped_http_probe`) 統合。
  - `_execute_adapter_outside_tx` に検証済み `raw_arguments` の任意受渡しを追加（SQLite `actions.sanitized_args_json`・監査ログの秘匿化/短縮を維持したまま長大ペイロードを `helper.transform` 等へ渡すため）。
- [`src/ctf_mcp/server.py`](../src/ctf_mcp/server.py):
  - `SUPPORTED_TOOL_NAMES` に `"session.control"`, `"net.probe"` を追加し、`@self.mcp.tool` として登録。
  - 動的専用・ネットワーク専用プロファイル分離（未登録時または `offline_ctf` 既定 `allow_dynamic=False` / `network_enabled=False` 時は `tools/list` 非表示、直接呼出時も `status="denied"`, `error.code="tool_denied"` / `"scope_revoked"` で拒否）を維持。

### 新規統合テスト
- [`tests/integration/test_p4_interactive_session_and_transform.py`](../tests/integration/test_p4_interactive_session_and_transform.py)（4 件）
- [`tests/integration/test_ctf09_local_network_scope_rebinding.py`](../tests/integration/test_ctf09_local_network_scope_rebinding.py)（3 件）

---

## 2. 署名済み Capability Descriptor 固定値・依存根拠

| ツール名 | `adapter_id` | `adapter_commit` | `dependency_lock_sha256` (`pyproject.toml`) | `descriptor_sha256` |
|---|---|---|---|---|
| `helper.transform` | `ctf-helper-transform` | `p4-transform-helper-1` | `85b597a81479e0c5e809bc170fac1a31c4ac4fe8fdfdfae0c5c5699e764366c9` | `d29037c62508cf945cc55085cc456353adfecc38b7977e3c751d4703f53746b8` |
| `session.control` | `ctf-interactive-session` | `p4-interactive-session-1` | `85b597a81479e0c5e809bc170fac1a31c4ac4fe8fdfdfae0c5c5699e764366c9` | `d921b1bfdbbdca08b998cd0509846e64472dc396494570295b486d069945d467` |
| `net.probe` | `ctf-scoped-http-probe` | `p4-scoped-http-probe-1` | `85b597a81479e0c5e809bc170fac1a31c4ac4fe8fdfdfae0c5c5699e764366c9` | `7f3dbd394ad9bd9c81b7876b4fd52cd5c55aafb5766352b16a1df7ae0f6c7d91` |

- サードパーティ依存追加なし（`pyproject.toml` および `THIRD_PARTY_LICENSES.md` 無変更、ワーカーおよびガード実装は Python `3.15.2` 標準ライブラリのみを使用）。

---

## 3. 検証・実測結果

### 全数テスト実行（最終コード・テスト編集後）
- OS / Python: `win32` / Python `3.15.2` (`.ctf-vdp-harness-venv`, `pytest==9.2.0`)
- 実行コマンド:
  ```powershell
  $env:PYTHONPATH = "$PWD\src"
  C:\Users\kenta\.gemini\antigravity\scratch\.ctf-vdp-harness-venv\Scripts\python.exe -m pytest -v
  ```
- 実行結果: **`92 passed, 1 warning in 46.90s`**（既存ベースライン 85 件 ＋ 新規 P4/CTF-09 テスト 7 件すべて PASS、`0 failed`, `0 skipped`；warning 1 件は外部 `beartype` の `AsyncKeyValue` protocol に係る既知 `DeprecationWarning`）。

### AST・レイヤ分離検査（`src/ctf_mcp/**/*.py` 全 41 ファイル）
- AST 禁止構文スキャン（`shell=True`, `os.system`, `eval`, `exec`）: **0 件**
- Layer 2 横方向 import スキャン（`adapters`, `gateway`, `runs`, `evidence`, `verification` 間の相互 import）: **0 件**

### 実サブプロセス資源実測サマリー（`SCOPED_CTF` ローカル実行）

| ツール / 操作 | 状態 | `wall_ms` | `cpu_ms` | `peak_rss_bytes` | `output_bytes` |
|---|---|---:|---:|---:|---:|
| `helper.transform` (`zlib_decompress`) | `ok` | `92 ms` | `46 ms` | `14,561,280 B` | `362 B` |
| `session.control` (`open`, ELF64) | `ok` | `92 ms` | `78 ms` | `16,924,672 B` | `598 B` |
| `session.control` (`step`, `step_count=2`) | `ok` | `90 ms` | `62 ms` | `17,448,960 B` | `561 B` |
| `session.control` (`close`) | `ok` | `97 ms` | `62 ms` | `15,659,008 B` | `155 B` |
| `net.probe` (`get`, local `127.0.0.1`) | `ok` | `128 ms` | `109 ms` | `18,382,848 B` | `547 B` |

### 主要受入観点 (`docs/10` P4・`docs/11` §5/§7 `CTF-09`)
1. **`helper.transform`**: 8 操作全疎通、4,000 文字超結果の `evidence.read` ページング再結合、256 KiB zlib bomb 遮断、64 KiB 超入力拒否を確認。
2. **`session.control` プロファイル分離・ライフサイクル**: 既定 `offline_ctf` (`allow_dynamic=False`) での `tools/list` 非表示・直接実行拒否 (`tool_denied`)、`allow_dynamic=True` 下の `open`→`inspect`→`step`→`close`、1 セッション同時上限 (`budget_exceeded`)、900 秒アイドル失効 (`session_expired`)、再起動後 `lost` 化＋ファイル削除 (`session_lost`)、timeout/cancel での孫プロセス含む OS 終了 (`is_os_process_alive == False`)、不正コマンド/フラグ注入拒否を確認。
3. **`CTF-09` (`net.probe` & `ScopedNetworkPolicyGuard`)**: 許可済みローカルターゲットへの `GET`/`HEAD` と IP ピン留め、`169.254.169.254` / `[::1]` / `[::ffff:127.0.0.1]` / 別ホスト・ポートへの HTTP `302` リダイレクト遮断、DNS rebinding（1回目許可 IP → 2回目禁止 IP）での実接続ゼロ遮断、userinfo URL 拒否、実行中 `revoke_scope` 後の即時拒否、`offline_ctf` 分離を確認。

---

## 4. 既知制約・留意点

- 本フェーズのネットワーク検証はローカル `http.server` フィクスチャおよび注入可能 DNS リゾルバを用いた `CTF-09` 受入試験であり、実外部 VDP ターゲットへの疎通は本ブランチ検証範囲外である。
- `peak_rss_bytes` / `cpu_ms` は Windows 環境 (`win32`, タイマ粒度約 15.6 ms) における実測値である。
