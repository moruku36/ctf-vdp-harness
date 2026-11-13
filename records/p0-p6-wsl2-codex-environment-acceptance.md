# P0 / P6 受入記録: WSL2 Ubuntu ネイティブ実行環境構築 + Windows Codex MCP 接続（案A）

- 実施日: 2026-11-13
- ブランチ: `feat/p0-p6-wsl2-codex-runtime`
- 対象リポジトリ: `ctf-vdp-harness`

## 1. P0 ホスト / WSL2 / ツール版インベントリ

### Windows 側ホスト環境
- OS: Windows 11 (`Windows-11-10.0.26300-SP0`)
- Python（開発仮想環境 `.ctf-vdp-harness-venv`）: `3.15.2`
- 主要 Python 依存（`importlib.metadata` 実測）:
  - `fastmcp`: `4.1.8`
  - `mcp`: `2.3.0`
  - `pydantic`: `2.14.3`
  - `jsonschema`: `4.26.0`
  - `pytest`: `9.2.0`
- Codex MCP 設定ファイル: `C:\Users\kenta\.codex\config.toml`（元ファイルは `C:\Users\kenta\.codex\config.toml.before-ctf-vdp-harness.bak` に退避済み）

### WSL2 Ubuntu ネイティブ環境
- WSL ディストリビューション / 状態: `Ubuntu` (`Running`, WSL Version `2`, 実行ユーザ `moruku36`)
- OS / カーネル: `Ubuntu 26.04.1 LTS` / `Linux moruku36-win 6.18.58.1-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Tue Oct 27 00:24:11 UTC 2026 x86_64 GNU/Linux`
- ネイティブ解析・ビルドツール:
  - `python3`: `Python 3.14.4`
  - `gdb`: `GNU gdb (Ubuntu 17.1-2ubuntu1) 17.1`
  - `gcc`: `gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0`
  - `objdump`: `GNU objdump (GNU Binutils for Ubuntu) 2.46`
  - `readelf`: `GNU readelf (GNU Binutils for Ubuntu) 2.46`
  - `strace`: `strace -- version 6.19`
  - `ltrace`: `ltrace 0.7.91`
- WSL2 側仮想環境 `/home/moruku36/ctf-vdp-harness/.venv`:
  - `PYYAML_FORCE_LIBYAML=0 .venv/bin/pip install -e ".[dev]"` で導入（`fastmcp==4.1.8`, `mcp==2.3.0`, `pydantic==2.14.3`, `jsonschema==4.26.0`, `pytest==9.2.0`）

## 2. コード拡張（P6 設定自動配線 + POSIX GDB/Binutils 読み取り専用メタデータ）

既存 99 件テストの後方互換と fail-closed 境界を維持したまま以下を拡張:

1. [`src/ctf_mcp/controller.py`](file:///C:/Users/kenta/.gemini/antigravity/scratch/ctf-vdp-harness/src/ctf_mcp/controller.py) (`create_default_controller`):
   - `config.execution.adapters_enabled` に `"helper.transform"` / `"ctf-helper-transform"` が含まれる場合は `include_transform_helper=True` を自動有効化。
   - `"session.control"` / `"ctf-interactive-session"` が含まれる場合は `include_interactive_session=True`、かつ `allow_dynamic is None` なら `allow_dynamic=True` を自動有効化（`allow_dynamic=False` 明示時は fail-closed で拒否を優先）。
   - `"net.probe"` / `"ctf-scoped-http-probe"` が含まれる場合は `include_scoped_http_probe=True` を自動有効化。
   - `config=None` かつ明示指定なし時は従来どおりすべて無効 (`False`)・`allow_dynamic=False` を維持。
2. [`src/ctf_mcp/server.py`](file:///C:/Users/kenta/.gemini/antigravity/scratch/ctf-vdp-harness/src/ctf_mcp/server.py) (`build_server_from_env`, `main`):
   - `CTF_MCP_ALLOW_DYNAMIC` (`1`/`true` vs `0`/`false`、不正値は `ConfigurationError`) の厳格パースと `--allow-dynamic` / `--enable-transform-helper` / `--enable-interactive-session` オプションを接続。
3. [`src/ctf_mcp/cli.py`](file:///C:/Users/kenta/.gemini/antigravity/scratch/ctf-vdp-harness/src/ctf_mcp/cli.py) (`server_main`, `admin_main`):
   - `ctf-mcp-server` に `--allow-dynamic` / `--enable-transform-helper` / `--enable-interactive-session` を追加。
   - `ctf-mcp-admin` でも `--config`（ネットワーク設定含む）と `--allowed-capabilities` (`helper.transform`, `session.control`, `net.probe`) および `CTF_MCP_ALLOW_DYNAMIC` を整合サポート。
4. [`src/ctf_mcp/adapters/interactive_session.py`](file:///C:/Users/kenta/.gemini/antigravity/scratch/ctf-vdp-harness/src/ctf_mcp/adapters/interactive_session.py):
   - POSIX 上で `shutil.which("gdb")` が存在し対象が `ELF32`/`ELF64` の場合、`open` / `inspect` (`summary`, `registers`) / `step` 出力に固定引数リスト (`shell=False`, `stdin=DEVNULL`, `timeout=2.0s`) の非対話・読み取り専用 `gdb --nx --nh --batch` + `readelf` + `objdump` メタデータ（`native_inspection`: 実シンボル・逆アセンブリ・エントリ確認、vault 実パス非開示サニタイズ済み）を付加。
   - ユーザ由来の任意 GDB コマンド文字列はスキーマ（`additionalProperties: False`）で完全拒否し、Windows 環境や `gdb` 不在環境では従来の決定論フォールバックを完全維持。
5. [`tests/integration/test_p6_config_adapter_autowire.py`](file:///C:/Users/kenta/.gemini/antigravity/scratch/ctf-vdp-harness/tests/integration/test_p6_config_adapter_autowire.py):
   - 上記自動配線・既定無効境界・環境変数/CLI・POSIX GDB ヘルパおよびフォールバックを検証する 4 テストケースを追加。

## 3. WSL2 ネイティブランタイム構築実績 (`/home/moruku36/ctf-vdp-harness-runtime`)

- リポジトリ同期先: `/home/moruku36/ctf-vdp-harness`（`feat/p0-p6-wsl2-codex-runtime`）
- ランタイム設定・状態格納:
  - `/home/moruku36/ctf-vdp-harness-runtime/.env`（権限 `0o600`、`CTF_MCP_CURSOR_HMAC_KEY` はランダム 64-hex 生成値をローカル保存し、リポジトリ・記録には一切非記載）
    - `CTF_MCP_DB_PATH=/home/moruku36/ctf-vdp-harness-runtime/state/harness.db`
    - `CTF_MCP_VAULT_ROOT=/home/moruku36/ctf-vdp-harness-runtime/vault`
    - `CTF_MCP_PROFILE=offline_ctf`
    - `CTF_MCP_TRANSPORT=stdio`
    - `CTF_MCP_ALLOW_DYNAMIC=1`
  - `/home/moruku36/ctf-vdp-harness-runtime/config.wsl-debug.json`:
    - `HarnessConfig` スキーマ検証済み（`profile: "offline_ctf"`, `execution.dynamic_execution: false`, `execution.adapters_enabled: ["ctf-static-inspector", "ctf-helper-transform", "ctf-interactive-session"]`）。
  - デバッグ対象 ELF64:
    - ソース: `/home/moruku36/ctf-vdp-harness-runtime/samples/debug_target.c`（所有合成課題 `wsl-elf-debug-01`、XOR エンコード済みダミートークン検証バイナリ）
    - コンパイル: `gcc -g -O0` → `/home/moruku36/ctf-vdp-harness-runtime/samples/debug_target.elf`（`ELF 64-bit LSB pie executable, x86-64, ..., with debug_info, not stripped`, `18600` bytes, `sha256: fce354cf7c57667affaa6a4119521ddce2f44073d3e3612c04ce63025c31616f`）
  - Run 作成・搬入・検証期待値登録:
    - `run_id`: `run-wsl-debug-01` (`task_id`: `wsl-elf-debug-01`, `mode`: `offline_ctf`, `scope_revision`: `scope-wsl-debug-v1`, `allowed_capabilities`: `analysis.query,helper.transform,session.control`, `allowed_execution_classes`: `static,dynamic`)
    - 搬入済み `artifact_id`: `art_9b523c5b6abe4aa2`
    - `register-expectation`: `--flag-sha256` による SHA-256 ダイジェストのみを `/home/moruku36/ctf-vdp-harness-runtime/vault/_verifier/expectations.json` に登録（平文フラグは検証期待値ファイルに非保存）
  - `stdio` 起動ラッパー: `/home/moruku36/ctf-vdp-harness-runtime/launch-mcp-stdio.sh`（権限 `0o755`、LF 改行）

## 4. P6 Codex ↔ WSL2 `stdio` 実疎通結果

`C:\Users\kenta\.codex\config.toml` の `[mcp_servers.ctf_vdp_harness]` を `tomllib.loads` で検証した上で、Windows 側 FastMCP Python クライアント (`StdioTransport(command='C:\\Windows\\System32\\wsl.exe', args=['-d', 'Ubuntu', '-u', 'moruku36', '--', '/home/moruku36/ctf-vdp-harness-runtime/launch-mcp-stdio.sh'])`) から実疎通を実施:

1. `tools/list`（8 ツール露出を確認）:
   - `['analysis.query', 'evidence.read', 'helper.transform', 'hypothesis.update', 'run.close', 'run.describe', 'run.verify', 'session.control']`
2. `run.describe("run-wsl-debug-01")`:
   - `task_id="wsl-elf-debug-01"`, `mode="offline_ctf"`, `guest_health="ready"`, `active_sessions=0`, `artifacts=["art_9b523c5b6abe4aa2"]` を確認。
3. `analysis.query(operation="inspect_header")` + `evidence.read`:
   - `format="elf64"`, `entry_point="0x10c0"` のページング読み出し成功。
4. `helper.transform(operation="xor_bytes")` + `evidence.read`:
   - 入力 `3c363b3d21` ^ キー `5a` → `output_utf8="flag{"` を確認。
5. `session.control` (`open` → `inspect(summary)` → `inspect(registers)` → `step(step_count=1)` → `close`):
   - `open` 出力の `native_inspection` で `tools.gdb=True`, `entry_point_verified="0x10c0"`, 実シンボル（`kXorKey@0x0000000000002020`, `frame_dummy`, `deregister_tm_clones` 等）および `_start` 逆アセンブリ（`0x10c0 <_start>: endbr64` 等）を確認。
   - `inspect(view="summary")`, `inspect(view="registers")` でも `native_inspection.tools.gdb=True` を確認。
   - `step(step_count=1)` で `previous_pc="0x10c0"` → `current_pc="0x10c2"` へ遷移し、更新後 PC の逆アセンブリ付与を確認。
   - `close` 後に `run.describe("run-wsl-debug-01")` で `active_sessions=0`, `active_heavy_jobs=0`, `guest_health="ready"`, `closed_leases=1` を確認（`run-wsl-debug-01` 自体は Codex からの即時利用のためオープン状態のまま維持）。
6. クライアント終了後の残存プロセス確認:
   - WSL2 上で `ps -ef` を確認し、`ctf-mcp-server` / `interactive_session.py` / `gdb` / `launch-mcp-stdio.sh` 等の残存プロセスが 0 件であることを確認。

## 5. テスト・品質スキャン実績

- Windows 側全件テスト (`pytest -v`): `103 passed`（既存 99 件 + 新規 P6 統合テスト 4 件）
- WSL2 Ubuntu Linux 側全件テスト (`pytest -v`): `103 passed`（実 POSIX + `gdb`/`readelf`/`objdump` 存在環境含む）
- AST 禁止構文スキャン (`eval` / `exec` / `os.system` / `shell=True` under `src/ctf_mcp`): **0 件**
- Layer 2 横方向 import スキャン (`gateway` / `runs` / `evidence` / `verification` / `adapters` 間): **0 件**
- 変更禁止領域 (`docs/`, `schemas/`, `configs/`, `examples/`, `templates/`, `THIRD_PARTY_LICENSES.md`): 差分なし

## 6. Codex 運用・再起動・元に戻す（Rollback）手順

### 日常運用（新しい課題を WSL2 側へ追加する場合）
1. `/home/moruku36/ctf-vdp-harness-runtime/samples/` 等に新しい対象バイナリを配置する。
2. WSL2 側で `.env` を読み込んだうえで `.venv/bin/ctf-mcp-admin` により新規 `run_id` 作成・`ingest-artifact`・（必要に応じて `register-expectation --flag-sha256 ...`）を実行する:
   ```bash
   set -a && source /home/moruku36/ctf-vdp-harness-runtime/.env && set +a
   /home/moruku36/ctf-vdp-harness/.venv/bin/ctf-mcp-admin create-run \
     --config /home/moruku36/ctf-vdp-harness-runtime/config.wsl-debug.json \
     --run-id <new-run-id> \
     --allowed-capabilities analysis.query,helper.transform,session.control \
     --allowed-execution-classes static,dynamic
   ```
3. 既定の `--active-run` を切り替える場合は `/home/moruku36/ctf-vdp-harness-runtime/launch-mcp-stdio.sh` の `--active-run` 引数を書き換える（または Codex からツール引数 `run_id` を明示指定する）。

### コード更新・MCP サーバ再起動手順
1. Windows 側で変更を入れた場合、`/home/moruku36/ctf-vdp-harness` へ最新ブランチ／差分を同期し、`PYTHONPATH=src .venv/bin/pytest -v` で回帰がないことを確認する。
2. Codex クライアント（IDE / CLI）を再起動または MCP サーバ再接続を行うと、`wsl.exe` が最新の `launch-mcp-stdio.sh` を自動再起動する（`stdio` 接続のため常駐デーモン不要）。
3. 異常終了等で `reconciliation_required` が残った場合は WSL2 側で `ctf-mcp-admin reconcile` / `recover-guest` を実行する。

### 元に戻す（Rollback）手順
1. Windows 側 Codex 設定をバックアップから復元する:
   ```powershell
   Copy-Item -Path "$env:USERPROFILE\.codex\config.toml.before-ctf-vdp-harness.bak" -Destination "$env:USERPROFILE\.codex\config.toml" -Force
   ```
2. 必要に応じて WSL2 側のランタイム・クローンディレクトリを削除する（作業リポジトリ自体は未破壊）:
   ```bash
   wsl -d Ubuntu -u moruku36 -- rm -rf /home/moruku36/ctf-vdp-harness-runtime /home/moruku36/ctf-vdp-harness
   ```
