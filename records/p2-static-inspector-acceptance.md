# MVP P2 受入記録: 静的解析アダプタ (`ctf-static-inspector`)

- 担当: `p2-adapter`
- ブランチ: `feat/p2-static-inspector` (親コミット: `692af25`)
- 日時: 2026-11-13
- 対象フェーズ: MVP P2 (`docs/10-implementation-plan.ja.md`, `docs/11-contracts-and-acceptance.ja.md`)

---

## 1. 変更内容

既存設計ドキュメント・テンプレート群（`docs/`, `schemas/`, `configs/`, `examples/`, `templates/`）は一切改変せず、以下を追加・最小改修した。

### 新規作成
- [`src/ctf_mcp/adapters/static_inspector.py`](../src/ctf_mcp/adapters/static_inspector.py)
  - `StaticArtifactInspectorAdapter(BaseAdapter)` (`adapter_id="ctf-static-inspector"`, `name="analysis.query"`, `ExecutionClass.STATIC` のみ)。
  - 独立ワーカー（`if __name__ == "__main__": _worker_main()`）は Python 標準ライブラリ（`argparse`, `collections`, `hashlib`, `json`, `math`, `os`, `re`, `stat`, `struct`, `sys`, `zipfile` 等）のみを使用し、`SubprocessRunner` 経由（`[sys.executable, str(_SCRIPT_PATH), ...]`, `shell=False`, `PYTHONPATH` 非継承の `build_minimal_env()`）で起動する。
  - 公開型付き 4 操作 (`STATIC_INSPECTOR_OPERATIONS`):
    1. `inspect_header`: マジックバイト、ELF32 / ELF64（セクション名プレビュー・エントリポイント）、PE/COFF（セクション・RVA）、ZIP（暗号化エントリ検出＋展開前エントリ数/総展開サイズ/膨張比上限検査）、UTF-8 テキスト構造判定。
    2. `extract_strings`: ASCII / UTF-16LE（偶数・奇数バイト境界両対応）印字可能文字列のストリーミング抽出（`encoding`, `min_length`, `offset`, `max_matches` 有界引数）。4,000 文字超ページングおよび `max_output_bytes` 超過を発生可能。
    3. `hex_slice`: 有界 `offset` / `length`（`max_decode_bytes` 上限連動）の 16 バイト正規化 hex + ASCII ダンプ。
    4. `hash_and_entropy`: SHA-256、識別用 SHA-1、全体およびブロック別 Shannon エントロピー、静的 PEM / Base64 指標カウント。
  - 非公開・禁止操作の明示除外: `FORBIDDEN_OR_UNACCEPTED_OPERATIONS = ("raw_disasm", "carve_execute", "dynamic_trace", "remote_fetch")` を定義し `CapabilityDescriptor.operations` から完全除外したうえで、Catalog / Scope / Adapter / ワーカー CLI の多層で拒否する。
  - `ResultEnvelope.summary` はメタデータ（`adapter_id`, `operation`, `outcome`, `output_bytes`, `capture_complete`, `cleanup_confirmed`）のみを返し、生出力・機微マーカー・プロンプトインジェクション文言を含めない（`CTF-12`）。
- [`tests/integration/test_p2_static_inspector.py`](../tests/integration/test_p2_static_inspector.py)
  - P2 受入・統合テスト 8 件（FastMCP `Client` + `HarnessController` 実サブプロセス実行、4 操作実測、`CTF-01/03/05/07/11/12`、AST 禁止パターン検査、Win32 `K32GetProcessMemoryInfo` による実測資源計測）。
- `records/p2-static-inspector-acceptance.md`（本受入記録）

### 既存 P1 統合修正（最小限）
- [`src/ctf_mcp/adapters/__init__.py`](../src/ctf_mcp/adapters/__init__.py): P2 定数・`StaticArtifactInspectorAdapter`・`create_static_inspector_descriptor`・`get_dependency_lock_sha256` をエクスポート。
- [`src/ctf_mcp/adapters/base.py`](../src/ctf_mcp/adapters/base.py): `BaseAdapter._resolve_source_artifact_hashes()` および `execute_with_capture(..., source_artifact_hashes=...)` を追加し、`EvidenceManifest.source_artifact_hashes` に実入力 artifact の SHA-256 を記録可能に改修（既存の `source_artifact_hashes` 非指定・空パス経路と完全互換）。
- [`src/ctf_mcp/adapters/synthetic.py`](../src/ctf_mcp/adapters/synthetic.py): `create_synthetic_descriptor` の `required_scope` キー `"profiles"` を `gateway/scope.py` と整合する `"modes"` へ統一。
- [`src/ctf_mcp/controller.py`](../src/ctf_mcp/controller.py):
  - `_infer_tool_group` の存在しない属性参照 `descriptor.execution_class` を `set(descriptor.execution_classes) != {ExecutionClass.STATIC}` へ修正。
  - `_resolve_run_artifact_context` を追加して入力 artifact の実体パスと SHA-256 を取得し、`inspect.signature` 互換チェック付きで `_execute_adapter_outside_tx` へ伝播。
  - デフォルト起動用ファクトリ `register_default_adapters()` / `create_default_controller()` を追加（`allow_synthetic_adapters=False` のまま `StaticArtifactInspectorAdapter` のみ有効登録可能）。
- [`src/ctf_mcp/server.py`](../src/ctf_mcp/server.py): `build_server_from_env()` が `create_default_controller()` 経由で `StaticArtifactInspectorAdapter` を標準登録するよう調整（`allow_synthetic_adapters=False` 維持）。

---

## 2. 固定版・ピン留め識別子・ライセンス根拠

| 項目 | 固定値 / 根拠 |
|---|---|
| `adapter_id` | `ctf-static-inspector` |
| `capability_name` | `analysis.query` |
| `adapter_commit` | `ctf-static-inspector-v1.0.0-692af25`（プレースホルダ接頭辞不使用） |
| `dependency_lock_sha256` | `aa77f6d8bb12dda29d557712cba6e1f370c7e4ec1fb73231ed2d4b74a64c1ef8`（[`pyproject.toml`](../pyproject.toml) の SHA-256） |
| `descriptor_sha256` | `682152c95ef52766119bf036d2e6c89b4cb3bc3f1dc9ca0faa298ea3b28814df` |
| `required_scope` | `{"modes": ["offline_ctf"]}` |
| `profile_modes` | `(RunMode.OFFLINE_CTF,)` |
| `execution_classes` | `(ExecutionClass.STATIC,)` |
| サードパーティ依存追加 | **なし**（ワーカー部は Python `3.15.2` 標準ライブラリのみ使用 / PSF-2.0、[`pyproject.toml`](../pyproject.toml) と [`THIRD_PARTY_LICENSES.md`](../THIRD_PARTY_LICENSES.md) 変更なし・既知分布 80 件 / Copyleft 0 / Unknown 0 を維持） |

---

## 3. 実測テスト結果・資源消費（実サブプロセス実行）

### テスト環境・コマンド
- OS / Python: `win32` / Python `3.15.2` (`.ctf-vdp-harness-venv`, `pytest==9.2.0`)
- コマンド:
  ```powershell
  $env:PYTHONPATH = "$PWD\src"
  C:\Users\kenta\.gemini\antigravity\scratch\.ctf-vdp-harness-venv\Scripts\python.exe -m pytest -v -s
  ```
- 実行結果: **`65 passed, 1 warning in 18.89s`**
  - 既存 P0/P1 テスト: 57/57 PASSED
  - 新規 P2 統合/受入テスト: 8/8 PASSED
  - warning 1 件は外部 `beartype` の `AsyncKeyValue` protocol に係る既知 `DeprecationWarning`

### サブプロセス実測資源値 (`test_p2_resource_telemetry_measurement`)

`build_minimal_env()`（`PYTHONPATH` 非継承）下で実ワーカーを起動し、標準出力バイト数・経過時間・Win32 `K32GetProcessMemoryInfo` (`PeakWorkingSetSize`) を計測した実測値：

| 操作 (`operation`) | 実測出力 (`output_bytes`) | 実測壁時計時間 (`wall_ms`) | 実測ピーク RSS (`peak_rss_bytes`) |
|---|---:|---:|---:|
| `inspect_header` (ELF64) | `436 B` | `94 ms` | `5,214,208 B` (約 4.97 MiB) |
| `extract_strings` (ASCII, 500 matches) | `25,592 B` | `99 ms` | `5,210,112 B` (約 4.97 MiB) |
| `hex_slice` (128 B slice) | `730 B` | `92 ms` | `5,214,208 B` (約 4.97 MiB) |
| `hash_and_entropy` (block=256) | `11,910 B` | `102 ms` | `5,222,400 B` (約 4.98 MiB) |

### 受入観点別検証状況
- **4 操作実実行 + SHA-256 連携**: ELF32 / ELF64 / PE32+ / 暗号化有無含 ZIP / UTF-8 テキストに対し `status="ok"`・`EvidenceRef` 発行・`EvidenceManifest.source_artifact_hashes` 一致を確認。
- **`CTF-03` ページング**: 4,000 文字超の `extract_strings` 出力を `evidence.read` で複数ページ取得・結合し、`sha256_bytes` が `view_sha256` と一致。
- **`CTF-05` 上限停止・ZIP bomb 拒否**: `max_output_bytes=65536` 超過時に事前停止し `status="partial"`, `truncated=True`, `capture_complete=False`, `error.code="output_limit_exceeded"`。ZIP bomb は Layer 1 取込 (`BoundsExceededError`) と Layer 2 `StaticArtifactInspectorAdapter`（展開前中央ディレクトリ検査 `status="tool_error"`）の双方で拒否。
- **`CTF-11` / `CTF-07` 異常・停止**: 破損 ELF / 破損 PE / 範囲外 `offset` / 破損 ZIP はすべて `status="tool_error"` (`tool_execution_failed`)。`cancel_event` による `CANCELLED` および 4 MiB エントロピー計算時の `reserved_ms=50` タイムアウト `TIMEOUT` でいずれも `cleanup_confirmed=True` 確認。
- **`CTF-01` 権限・改ざん拒否**: `raw_disasm` / `dynamic_trace`（`status="denied"`）、`carve_execute` / `remote_fetch` を含む全禁止操作のワーカー直起動拒否（`returncode=2`）、禁止引数（`file_path`, `command`）拒否、SQLite `descriptor_sha256` 改ざん時の失敗安全拒否、`enabled=False` / `session.control` の `tools/list` 非表示＋直接呼出 `denied` を確認。
- **`CTF-12` 非漏洩**: 合成フラグ・機微マーカー・プロンプトインジェクション文言を含む試料でも `ResultEnvelope.summary`・`audit_events`・エクスポート済み日本語レポートに 0 件であることを確認。
- **AST 安全性・レイヤ隔離**: `static_inspector.py` に `shell=True`, `os.system`, `eval`, `exec` が 0 件、トップレベル import は標準ライブラリのみ、`ctf_mcp.{gateway,runs,evidence}` への水平インポート 0 件を確認。

---

## 4. 既知制約・限界

1. **暗号化 ZIP の取込制約**: `gateway/intake.py` の Layer 1 アーカイブ検査は圧縮エントリ検査時に `zf.open(...)` を呼ぶため、暗号化フラグ付き ZIP は取込段階で `RuntimeError` によりブロックされる（`StaticArtifactInspectorAdapter` 単体では中央ディレクトリのみで暗号化フラグを安全に検出し未展開でメタ報告可能）。
2. **プラットフォーム別 RSS 計測範囲**: 本記録のサブプロセス `peak_rss_bytes` は Windows `K32GetProcessMemoryInfo` に基づく受入ハーネス計測値であり、本番 `UsageMetrics` / `RunReportExporter` への常時自動記録は P3 範囲。
3. **解析対象範囲**: MVP P2 は標準ライブラリによる静的構造判定・文字列抽出・hex スライス・ハッシュ/エントロピー算出に限定され、逆アセンブリ (`raw_disasm`)・動的トレース (`dynamic_trace`)・外部通信 (`remote_fetch`)・バイナリ実行 (`carve_execute`) は未実装かつ禁止。

---

## 5. 再現・ロールバック手順

### 再現手順
```powershell
cd C:\Users\kenta\.gemini\antigravity\scratch\ctf-vdp-harness
git checkout feat/p2-static-inspector
$env:PYTHONPATH = "$PWD\src"
C:\Users\kenta\.gemini\antigravity\scratch\.ctf-vdp-harness-venv\Scripts\python.exe -m pytest -v
```

### ロールバック手順
- ブランチ単位で無効化する場合:
  ```powershell
  git checkout main
  ```
- 特定実行時の緊急無効化（`analysis.query` のみ停止）:
  `HarnessController.set_capability_enabled("analysis.query", False)` または `create_default_controller(..., static_inspector_enabled=False)` を指定する（既存の `allow_synthetic_adapters=False` と他のコアツールはそのまま維持される）。
