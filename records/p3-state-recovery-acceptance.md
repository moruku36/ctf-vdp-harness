# MVP P3 受入記録: 状態管理・障害復旧・上位層統合・CLI・5合成試料E2E

- 担当: `p3-mvp` (Wave P3-B+C)
- ブランチ: `feat/p3-mvp-complete` (親コミット: `d223900` / `main`)
- 日時: 2026-11-13
- 対象フェーズ: MVP P3（`docs/10-implementation-plan.ja.md`, `docs/11-contracts-and-acceptance.ja.md` §7, `docs/09-evaluation.ja.md` §2）

---

## 1. 変更内容・有効化機能・依存版・ライセンス根拠

既存の設計文書・テンプレート・ライセンス台帳（`docs/`, `schemas/`, `configs/`, `examples/`, `templates/`, `THIRD_PARTY_LICENSES.md`）は一切改変せず、P0〜P3-A 基盤の上に MVP P3 完結に必要な統合実装・CLI・統合テスト・受入記録を追加した。

### 主要実装変更
- [`src/ctf_mcp/controller.py`](../src/ctf_mcp/controller.py)（Layer 3 復旧・リース・閉鎖順序・テレメトリ統合）
  - `initialize()` にデフォルト `is_process_alive=is_os_process_alive` を用いた非終端アクション実 OS プロセス照合、起動時 `AuditEvent` 記録、および補完テーブル初期化（`action_slots`, `hypothesis_requests`）を統合。
  - `execute_action()` でアダプタ種別ごとの `heavy_job_slot` / `interactive_session_slot` を予約・精算と連動させ、`SubprocessResult` の実測 `process_start_id`・`peak_rss_bytes`・`cpu_ms` を `ActionRecord` / `UsageMetrics` へ記録・伝播。
  - 公開 API を追加：`resolve_reconciled_action`, `commit_worker_result`, `acquire_lease`, `touch_lease`, `expire_idle_leases`, `close_lease`, `recover_guest_ready`, `register_scope`, `save_verifier_expectation`, `load_verifier_expectations`, `register_default_verifier`。
  - `describe_run()` に `session_leases` 一覧および `reconciliation_required` アクション要約（`fencing_token`, `error_code` 含む）を統合。
  - `close_run()` 実行順序を契約準拠へ修正：
    1. 事前整合検査（`evaluate_close_integrity_in_tx`）
    2. メモリ内レポート生成・非漏洩検査・`peak_rss_bytes`/`cpu_ms` 集計検証（`RunReportExporter.prepare_run_report`）
    3. `vm_rollback_hook` 実行および `mark_guest_rolled_back_in_tx`（失敗時はファイルをディスクへ残さず `GuestBlockedError` 等を送出）
    4. 最終整合検査後に `RunReportExporter.write_verified_report` で確定書出し＋ `close_run_in_tx`
  - `update_hypothesis()` に `request_id` 指定時の SQLite 永続冪等性チェック（再送キャッシュ・異引数 `ActionConflictError`）を追加。
- [`src/ctf_mcp/server.py`](../src/ctf_mcp/server.py)（Layer 4 MCP 境界・標準配線）
  - `run.close` MCP ツールから AI クライアント自己申告バイパス引数（`import_completed`, `child_processes_confirmed_stopped`）を削除し、`_derive_host_close_checks` によるホスト実測状態・SQLite 整合検査導出へ置換。
  - `build_server_from_env()` が `StaticArtifactInspectorAdapter` ＋ `LocalCtfVerifier` を標準配線し（`allow_synthetic_adapters=False` 厳守）、有効な `HarnessConfig` 指定・`hypothesis.update` の `request_id` 伝播に対応。
- [`src/ctf_mcp/cli.py`](../src/ctf_mcp/cli.py) / [`pyproject.toml`](../pyproject.toml)（MVP 運用 CLI 導線）
  - `ctf-mcp-server`（`server_main`：`StaticArtifactInspectorAdapter` + `LocalCtfVerifier` 標準起動）および `ctf-mcp-admin`（`admin_main`：`create-run`, `register-scope`, `ingest-artifact`, `register-expectation`, `reconcile`, `recover-guest`, `describe-run`、`shell=False`・秘密値非出力）を新規作成。
  - `pyproject.toml` に `[project.scripts]` エントリポイントのみ追記。
- [`src/ctf_mcp/verification/ctf_local.py`](../src/ctf_mcp/verification/ctf_local.py)（最小統合修正）
  - `require_complete_capture=True` かつ未完了証拠（`capture_complete=False`）のみで `expected_flag_sha256` が照合された場合（`claim` 直接一致なし）に誤って `PASSED` を返さず `expected_flag_sha256:rejected_incomplete_capture` として拒否するよう 10 行修正。
- [`README.md`](../README.md) / [`README.ja.md`](../README.ja.md)
  - 既存の設計文書テキストを改変せず、末尾にのみ MVP（P1〜P3）実装状態、セットアップ手順（`PYYAML_FORCE_LIBYAML=0` 注記）、テスト手順、CLI 起動方法を追記。
- 統合テスト新規追加
  - [`tests/integration/test_p3_recovery_fencing_e2e.py`](../tests/integration/test_p3_recovery_fencing_e2e.py)（6件：`CTF-02/04/06/07/08/10` MCP + 実サブプロセス統合検証）
  - [`tests/integration/test_p3_five_fixtures_mvp_e2e.py`](../tests/integration/test_p3_five_fixtures_mvp_e2e.py)（6件：`docs/09` §2 の合成試料 5 件一気通貫検証＋`CTF-09` オフライン境界＋`CTF-12`＋CLI 統合検証）

### 固定依存版・ライセンス根拠
- `pyproject.toml` の依存パッケージおよび固定バージョン（`fastmcp==3.2.4`, `mcp==1.27.0`, `pydantic==2.13.0`, `pyyaml==6.0.3` 等）は**一切変更していない**。
- `THIRD_PARTY_LICENSES.md`（既知分布 80 件 / Copyleft 0 / Unknown 0）も無変更のまま維持している。

---

## 2. 統合用所有合成試料 5 件の実測結果・資源計測 (`docs/09` §2)

以下は性能・正答率比較の評価結果ではなく、`docs/09` §2「統合用所有合成試料 5 件」に対する `StaticArtifactInspectorAdapter` ＋ `LocalCtfVerifier` ＋ `FastMCP Client` ＋ `RunReportExporter` の結合疎通・安全性実測記録である。

### 実測環境
- OS / Python: `win32` / Python `3.15.2` (`.ctf-vdp-harness-venv`, `pytest==9.2.0`)
- 実行コマンド:
  ```powershell
  $env:PYTHONPATH = "$PWD\src"
  C:\Users\kenta\.gemini\antigravity\scratch\.ctf-vdp-harness-venv\Scripts\python.exe -m pytest -v -s tests/integration/test_p3_five_fixtures_mvp_e2e.py
  ```

### 5 合成試料・資源実測サマリー

| 試料区分 | 実行内容 | 実測結果 | 実測資源 (`wall_ms` / `cpu_ms` / `peak_rss_bytes` / `output_bytes`) |
|---|---|---|---|
| **試料1: 正常入力** | 所有 ELF64 バイナリ＋UTF-8 テキスト搬入 → 4型付き静的解析 → `hypothesis.update` (`unknown`→`supported`) → `run.verify` (`ctf.local_digest`) → `run.close` (バイパス引数なし) | `status="ok"`、`PASSED`（平文 flag 非出力）、レポート書出し＆`guest_rolled_back=True` | `inspect_header`: 129 ms / 46 ms / 15,130,624 B (14.43 MiB) / 436 B<br>`hex_slice`: 96 ms / 78 ms / 15,106,048 B (14.41 MiB) / 404 B<br>`hash_and_entropy`: 128 ms / 78 ms / 15,286,272 B (14.58 MiB) / 1,618 B<br>`extract_strings`: 97 ms / 62 ms / 15,155,200 B (14.45 MiB) / 207 B |
| **試料2: 不正入力** | `../outside_secret.txt` パストラバーサル、シンボリックリンク脱出、250,000 B ZIP bomb、破損 ELF/ZIP、`raw_disasm`/`dynamic_trace`、`session.control`、禁止引数 `file_path` | すべて失敗安全で拒否：`PathSecurityError`、`BoundsExceededError`、直接/MCP 解析 `tool_error`、未許可操作・隠しツール `denied`/エラー | 展開前拒否により数 ms〜数十 ms で即時終了・出力有界 |
| **試料3: 長出力** | 4,000 文字超（12,632 文字）`extract_strings` の `evidence.read` 複数ページ取得＋SHA-256 結合検証、`max_output_bytes=65,536` 超過の `partial` 取得＋`LocalCtfVerifier` 検証 | ページ結合 `sha256_bytes == view_sha256` 一致；超過時は `status="partial"`, `capture_complete=False` で `LocalCtfVerifier` が `PASSED` を拒否（`inconclusive`/`failed`） | 超過停止 (`extract_strings`): 90 ms / 46 ms / 15,151,104 B (14.45 MiB) / 65,536 B |
| **試料4: 時間超過・取消** | 孫プロセス付き実サブプロセスの 0.8s timeout、2 MiB ハッシュ計算中の `cancel_event` 即時取消、`cleanup_unconfirmed` 閉塞 → `recover_guest_ready` 復帰後再実行 | OS 残存 PID **0**（`is_os_process_alive == False`）、`CANCELLED` + `cleanup_confirmed=True`、閉塞中は action `denied` (`guest_blocked`) ＆ `close_run` `GuestBlockedError`、復帰後正常化 | 復帰後 `inspect_header`: 124 ms / 78 ms / 15,192,064 B (14.49 MiB) / 175 B |
| **試料5: 復旧・境界・非漏洩** | 再起動クラッシュ照合（`initialize()`）、単調 `fencing_token` 増分、旧 worker `FencingError` 拒否、`session_leases` `lost` 化、`configs/offline-pilot.example.json` 拒否、`network_enabled=True` 拒否、HTTP 未認証拒否、合成マーカー/注入文入出力検査 | 再起動照合・fencing・lease `lost` すべて契約通り動作、`CTF-09` オフライン境界拒否、`CTF-12` マーカー 0 件流出（`summary` / `audit_events` / レポート） | `extract_strings` (毒入り試料): 100 ms / 78 ms / 15,118,336 B (14.42 MiB) / 380 B |

---

## 3. `CTF-01`〜`CTF-12` 契約・受入対応表 (`docs/11` §7)

| ID | 検証内容 | 検証テスト（抜粋） | 結果 |
|---|---|---|---|
| **CTF-01** | scope 欠損・期限切れ・未登録/隠しツール (`session.control`)・未許可操作 (`raw_disasm`) 直接呼出の事前拒否 | `test_ctf01_scope_and_catalog.py`, `test_p2_ctf01_*`, `test_p3_fixture2_*` | PASS |
| **CTF-02** | `request_id` 同引数リプレイ（サブプロセス再実行 0・予算非消費）、異引数 `ActionConflictError`、`repeat_of`、`hypothesis.update` 永続冪等性 | `test_ctf02_mcp_replay_zero_subprocess_conflict_repeat_of_and_hypothesis_restart` | PASS |
| **CTF-03** | 4,000 文字超 UTF-8 / binary ページ取得・EOF 厳密性・結合 SHA-256 == `view_sha256` | `test_ctf03_04_evidence_paging_and_access.py`, `test_p3_fixture3_*` | PASS |
| **CTF-04** | 別 `run_id` / 別 principal カーソル拒否、`redact_evidence(..., revoke_prior_views=True)` 後旧カーソル失効＋新秘匿ビュー参照 | `test_ctf04_cross_run_cursor_rejected_and_redaction_revokes_old_cursor` | PASS |
| **CTF-05** | `max_output_bytes` 超過停止、`archive bomb` 展開前拒否、トラバーサル/symlink ブロック | `test_ctf05_intake.py`, `test_p3_fixture2_*`, `test_p3_fixture3_*` | PASS |
| **CTF-06** | 実 OS プロセス (`is_os_process_alive`) 照合付き再起動復旧（生存維持／死亡→`reconciliation_required`）、`usage_unknown` 予約保持＋スロット解放 | `test_ctf06_real_os_process_crash_reconciliation_on_initialize` | PASS |
| **CTF-07** | 孫プロセス付き実サブプロセス timeout/cancel で OS 残存 PID 0、`cleanup_unconfirmed` 閉塞 → `recover_guest_ready` 復帰 | `test_ctf07_timeout_cancel_zero_survivors_and_cleanup_unconfirmed_recovery`, `test_p3_fixture4_*` | PASS |
| **CTF-08** | 再起動跨ぎ単調 `fencing_token`、旧 worker `commit_worker_result` `FencingError` 拒否、`session_leases` `lost` 化・900s アイドル失効・`describe_run` 可視化 | `test_ctf08_fencing_and_session_leases_lost_and_idle_expiry` | PASS |
| **CTF-09** | オフライン境界検証（`network_enabled=False`, `external_submission=False`, `allowed_targets=()`, 非実行設定例 `executable=false` 拒否, HTTP bearer fail-closed） | `test_p3_fixture5_recovery_offline_boundary_and_ctf12_secrecy`, `test_e2e_offline_vertical_slice.py` | PASS（オフライン境界範囲） |
| **CTF-10** | `run.close` クライアントバイパス引数廃止、`vm_rollback_hook=False` / import 未完時の閉鎖阻止・不確定レポート未生成・証拠保護 | `test_ctf10_mcp_rejects_client_bypass_flags_and_preserves_evidence_on_rollback_failure` | PASS |
| **CTF-11** | 破損 ELF/PE/ZIP や未了取得に対する `tool_error` 厳守・偽陽性 `PASSED`/`ok` ブロック、`allow_synthetic_adapters=False` | `test_ctf11_errors.py`, `test_p3_fixture2_*`, `test_p3_fixture3_*` | PASS |
| **CTF-12** | 合成 flag/secret/sensitive マーカーおよびプロンプト注入文を含む入力で権限不変・`summary`/`audit_events`/CLI/日英レポート露出 0 件 | `test_p2_ctf12_*`, `test_p3_fixture1_*`, `test_p3_fixture5_*`, `test_p3_cli_*` | PASS |

---

## 4. 既知制約・限界

1. **検証対象の範囲**: 本記録は所有合成試料 5 件および契約・統合テスト 85 件の受入検証であり、20 件規模のオフライン試行評価（P5）や AI ソルバ性能・優位性評価は未実施である。
2. **対話セッション／実外部対象（P4/P6/P7）未実施**: `acquire_lease` / `touch_lease` / `expire_idle_leases` / `close_lease` および再起動 `lost` 化の状態機械は実装・検証済みだが、実対話デバッガアダプタ（P4）、隔離 vNIC 経由の実クライアント接続（P6）、ローカル/許可外部 HTTP ターゲットのリダイレクト・DNS・IPv6 試験（P7）は次フェーズ範囲である。
3. **プラットフォーム固有の資源計測精度**: 実測 `peak_rss_bytes` / `cpu_ms` は Windows (`K32GetProcessMemoryInfo`, `GetProcessTimes`) で計測した実測値であり、Windows タイマ分解能（約 15.6 ms 単位）による離散化を含む。Linux 環境 (`getrusage`) での連続実測は未実施。
4. **暗号化 ZIP・PyYAML 環境注記**: Layer 1 搬入検査はパスワード保護 ZIP を安全のため拒否する。Windows + Python 3.15 環境でソースから導入する際は、Cython/libyaml ビルド回避のため `PYYAML_FORCE_LIBYAML=0` が必要な場合がある（実行時設定は標準 JSON を推奨）。

---

## 5. 全数テスト・安全性検証サマリー & 再現・ロールバック手順

### 全数検証結果
- `pytest` 全数実行: **`85 passed, 1 warning in 31.21s`**（既存 73 件 ＋ 新規 P3-B+C テスト 12 件すべて合格、skip 0 / fail 0。warning 1 件は `beartype` における外部 `key_value` protocol に係る既知 `DeprecationWarning`）
- `src/**/*.py` AST 構文スキャン（`shell=True`, `os.system`, `eval`, `exec`）: **0 件**

### 再現手順
```powershell
cd C:\Users\kenta\.gemini\antigravity\scratch\ctf-vdp-harness
$env:PYTHONPATH = "$PWD\src"
C:\Users\kenta\.gemini\antigravity\scratch\.ctf-vdp-harness-venv\Scripts\python.exe -m pytest -v
```

### ロールバック手順・影響
- ブランチ単位で P3-B+C 統合変更を取り消す場合:
  ```powershell
  git checkout main
  ```
- ロールバック時の DB/運用影響:
  - `main` (`d223900`) に戻る場合、`ctf-mcp-server` / `ctf-mcp-admin` スクリプト定義、`controller.py` / `server.py` の統合 API、および `ctf_local.py` の 10 行修正が取り消される。
  - SQLite 上で作成済みの `hypothesis_requests` テーブルは追加の読み書きを行わない限り既存テーブルおよび `main` の動作と干渉せず安全に無視される。
  - 一時運用上のフェイルセーフ停止が必要な場合は `HarnessController.set_capability_enabled("analysis.query", False)` を用いる。
