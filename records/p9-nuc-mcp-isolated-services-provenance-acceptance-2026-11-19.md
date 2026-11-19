# P9 Windows→NUC MCP・内部サービス隔離試験・手動来歴・VDP提出下書き受入記録 (2026-11-19)

- **作業ブランチ / 基準コミット**: `feat/nuc-mcp-isolated-services-provenance-draft` (基準 `main`: `9ee60b3666498e18e11cb0412b23819b8c4ee9bc`)
- **構成**: Windows Codex CLI → OpenSSH (`<NUC_USER>@<NUC_HOST>`) → Intel NUC Linux Dockerホスト (`weblate-oss-scanner:2026.11.2`, `sha256:f3556156645159fee3e3c08eda2f742661dfed1ee92b90bfa0b7dc713862948d`, Weblate固定コミット `3562388dd005298e3d2c06562987dd3e07be1c89`)
- **履歴との区別（重要）**:
  - 過去のWSL2環境での受入記録（[P7](p7-vdp-weblate-product-test-acceptance.md)・[P8](p8-vdp-daily-workflow-acceptance-2026-11-14.md)・W-01/W-02）は旧環境の結果であり、本記録をもってNUCでのW-01/W-02再受入とはみなさない。
  - 2026-11-19に所有者がハーネス外で実施したG-01観察（HackerOne #4216840提出済み）および既存の提出済み／既知事項（#4213086、Weblate issue #22886）は既存事実として扱い、`vdp.product_test` による自動検証へ混同・昇格させない。
  - 既存の `run-vdp-weblate-01`（`revision=68`, `guest_health="ready"`, OPEN）および運用プロファイルは一切変更せず、P0は使い捨てrun `run-vdp-nuc-p0-accept-20261119`、P1/P2は一時ワークスペース `/tmp/ctf-vdp-p1-accept-20261119`（受入後に完全削除）で検証した。

## 1. P0：Windows Codex → Intel NUC MCP接続と診断

- **原因切り分け結果**:
  - Windows側 `%USERPROFILE%\.codex\config.toml` に `[mcp_servers.ctf_vdp_harness]` セクション自体が未登録だったことが主因と判明（ハーネス本体の不具合ではなくクライアント設定欠落）。
  - バックアップ取得（`config.toml.before-nuc-mcp-20261119.bak`）後に `C:\WINDOWS\System32\OpenSSH\ssh.exe -T -i C:\Users\<USER>\.ssh\<KEY_FILE> ... <NUC_USER>@<NUC_HOST> /home/<NUC_USER>/ctf-vdp-harness-runtime/launch-mcp-stdio.sh --config ... --allow-dynamic` を登録。
- **診断コマンド実測**:
  - `codex.exe mcp list` / `codex.exe mcp get ctf_vdp_harness --json`: `enabled=true`, `startup_timeout_sec=30.0`, `tool_timeout_sec=360.0`。
  - `powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/diagnose-nuc-mcp.ps1 -SshTarget <NUC_USER>@<NUC_HOST> -IdentityFile C:\Users\<USER>\.ssh\<KEY_FILE> -RunId run-vdp-weblate-01 -CheckDocker`: 終了コード `0`、`codex_config.status="configured"`、`ssh_clean_stdout.ok=true`、`remote_diagnose.healthy=true`、`mcp_handshake.schema_match=true`（10ツール、`additional_properties=false` 一致）、`lingering_server_processes=[]`、`issues=[]`。
- **Windows Codex CLI実機ライブ呼び出し（`codex.exe exec --strict-config --skip-git-repo-check --ephemeral -s read-only`）**:
  - `run.describe("run-vdp-weblate-01")`: 読み取り専用で `revision=68`, `mode="vdp"`, `guest_health="ready"`, 10ツール公開を確認。
  - `vdp.test(operation="check_environment", target_profile="weblate-2026.11.2")`（使い捨て `run-vdp-nuc-p0-accept-20261119`）: `status="ok"`。
  - `vdp.test(operation="run_pytest")`（許可済み `weblate/trans/tests/test_search.py::BulkEditTest::test_replacement_processes_each_selected_translation_once`, `network_mode="none"`）: `status="ok"`, `verdict="baseline_passed"`, `exit=0, collected=1, passed=1, cleanup=True`, `evidence="ev-264501328e7444c697a63c93ae5532b7"`, `wall_ms=42591`。
  - 後処理：`run-vdp-nuc-p0-accept-20261119` をクローズ（`guest_health="rolled_back"`, `revision=5`）、`run-vdp-weblate-01` が `revision=68` / `ready` / OPEN のまま無傷であること、および `ctf-mcp-server` 残留プロセス0件・`ctf-vdp-*` コンテナ0件を確認。

## 2. P1-A：内部依存DB（PostgreSQL 18）を伴う `isolated_internal_services` 実機検証

- 従来の `network_mode="none"` と検証器契約は一切緩めず、使い捨て `/tmp` 環境に `weblate-2026.11.2-pg-g01`（`network_mode="isolated_internal_services"`, `runner_mode="direct_pytest"`, 独立PostgreSQL 18コンテナ `db:5432`, `publish_ports=false`, CPU合計 `2+1<=4`, メモリ合計 `3072+1024<=8192MB`）を `register-vdp-profile` で登録し実行。
- **`check_environment` / `run_smoke`**:
  - `check_environment`: `status="ok"`。
  - `run_smoke` (`TestG01InternalPostgres::test_external_postgres_smoke`, `ev-347032ca165341f09a054807c2584115`): `status="ok"`, `verdict="smoke_passed"`（テストコンテナ内の `127.0.0.1:5432` は接続拒否であり、専用 `--internal` ネットワーク越しに `db:5432` へ接続・SQL応答することを確認）。
- **G-01相当合成テスト＋外部egress遮断（`run_pytest`, `ev-a6c583dcdf8c46c890639029a4ef5fac`）**:
  - 隔離ネットワーク `ctf-vdp-net-act-729a4671-0a7cbc29`: `internal_flag_verified=true`, `external_egress_blocked=true`, `published_ports_count=0`, `published_ports_verified_none=true`。
  - `positive_control`: 公開コンポーネントの画面(`200`)・Gitエクスポート(`200`)成功。
  - `defense_check`: `--internal` ネットワークからの外部IP (`1.1.1.1:443`) TCP接続が `OSError` で拒否されること、および非公開親リポジトリへの匿名直接Gitアクセスが `401`・画面/APIが `404` であることを確認。
  - `anomaly_repro`: 公開リンク子の匿名Git `info/refs` 要求が `301` を返し、非公開親のプロジェクト／コンポーネント識別子を `Location` に含むこと（リダイレクト先直接アクセスは `401` で内容・認証情報は未開示）を確認。
  - 判定・検証：`verdict="anomaly_observed"`、`service_cleanup_confirmed=true`、`network_cleanup_confirmed=true`、`VdpProductTestVerifier` が `status="passed"` を返却（`network_isolation:internal_services_verified`, `published_ports:none_verified`, `service_image_pins:verified`, `service_and_network_cleanup:confirmed`）。
- **異常終了（5秒タイムアウト）時の後片付け確認**:
  - 30秒スリープ対象を `timeout_seconds=5` で実行 → `status="timeout"`, `verdict="timeout"`, `container_cleanup_confirmed=true`, `service_cleanup_confirmed=true`, `network_cleanup_confirmed=true`、ホスト上 `docker ps -aq --filter name=ctf-vdp-` および `docker network ls -q --filter name=ctf-vdp-net-` がともに空であることを確認。

## 3. P1-B：ハーネス外・手動隔離観測の来歴取込

- `ctf-mcp-admin import-manual-observation` により手動テストスクリプトSHA-256（`manual_g01_obs.py`）・固定版・対照試験・未確認条件・後片付け確認を取り込み（`ev-ee6b15126e004740adf0d2439b167c45`）。
- `run.describe` 上で `execution_provenance="manual_isolated_observation"`, `promoted_to_vdp_product_test=false` を確認し、同証拠を `VdpProductTestVerifier`（`vdp.product_test`）へ渡すと `status="failed"`（`manual_observation_cannot_escalate_to_vdp_product_test`）で昇格拒否されることを確認。

## 4. P2：VDP提出用下書き出力と手動提出状態の記録

- `ctf-mcp-admin export-vdp-draft` により日英（`ja` / `en`）の下書きを生成し、再現手順・成功／失敗対照・影響の限界・未確認条件・AI利用開示・ハーネス検証済み証拠 (`ev-347032ca...`, `ev-a6c583dc...`) と手動隔離観測 (`ev-ee6b1512...`) の分離表示、および `automatic_submission=false`・`state="report-ready"` を確認。
- 運用者手動提出後の想定記録として `ctf-mcp-admin record-vdp-submission`（プレースホルダHTTPS URL `https://example.invalid/reports/0000000`）と `list-vdp-submissions` を実行し、`state="submitted"`, `automatic_submission=false` が `_vdp/submissions.json` へ保存されることを確認（実サイトへの自動提出機能は実装せず）。

## 5. 自動テストスイートと未確認事項

- 新規追加テスト（`tests/unit/test_p0_mcp_diagnostics.py`、`tests/integration/test_p1_isolated_services_vdp.py`、`tests/integration/test_p1_manual_observation_provenance.py`、`tests/integration/test_p2_vdp_submission_draft.py`）を含む全回帰テストは最終編集後のNUC実行で確認（件数・結果は最終実行ログ参照）。
- **未確認事項**:
  1. W-01 / W-02 の NUC 実機上での再実行（過去のWSL2記録 P7/P8 を流用しない）。
  2. 既提出 HackerOne #4216840 / #4213086 の外部トリアージ受理・重複判定。
  3. Hosted環境・本番実サイトや実Async Celeryワーカー構成での挙動（対象外）。
  4. `network_mode="isolated_internal_services"` における PostgreSQL 以外のサービス（Valkey/Redis 等）の実コンテナ起動（ユニット／モック検証のみ）。
