# P5 オフライン比較評価（A / B / C / D & VDP 別集合）受入記録

- **日付**: 2026-11-13
- **ブランチ / 対象作業ツリー**: `feat/p5-offline-evaluation` (`ctf-vdp-harness-p5`)
- **根拠仕様**: `docs/09-evaluation.ja.md` §§1–6 / `docs/10-implementation-plan.ja.md` (P5)
- **主要成果物**:
  - `src/ctf_mcp/evaluation.py`（Layer 3 評価オーケストレータ。標準ライブラリ + `contracts`, `controller`, `adapters/static_inspector`, `evidence`, `storage`, `verification/ctf_local` のみ使用）
  - `tests/evaluation/__init__.py`
  - `tests/evaluation/test_p5_offline_evaluation_abc.py`
  - `README.md` / `README.ja.md`（末尾追記のみ）

---

## 1. 受入基準との適合性チェック

| 契約要件（`docs/09` / `docs/10`） | 実装・検証状況 | 根拠箇所 / 実測値 |
| --- | --- | --- |
| 条件 A / B / C / D 同一環境比較 | **適合** | `OfflineEvaluationHarness.evaluate` で A（MCP なし）・B（単発 stateless `StaticArtifactInspectorAdapter`）・C（`HarnessController` フル運用）・D（`dev` 凍結ガイド適用 C）を実ランタイムで比較 |
| `dev`（10件）と `eval`（20件）の厳密分離 | **適合** | `task_id` / ファイル名 / `artifact_sha256` / `expected_flag_sha256` 重複 0。`DEV_INFORMED_GUIDE`（`dev-guide-v1`, sha256 `f9dff2e865d2797c...`）に `eval-` 記述・平文 flag 混入 0 |
| 全4分野（`rev`, `forensics`, `crypto_transform`, `source_audit`）網羅 | **適合** | `dev` 全4分野（3/3/2/2 = 10件）、`eval` 各分野 5 件ずつ計 20 件 |
| `pass@1` 初回試行限定 & `best_of_k` 分離 | **適合** | `summarize_condition_attempts` は `attempt_index == 1` のみで `ctf_verified_solve_rate` を算出。複数回試行時のみ別フィールド `best_of_k_solve_rate` 出力（`test_pass_at_1_strictly_separated_from_best_of_k` で検証） |
| 条件・試行ごとの独立 `run_id` / 隔離ワークスペース | **適合** | `eval` 全 80 試行（20件×4条件）で 80 個の固有 `run_id` / `workspace_dir` / SQLite / `vault_root` を生成し証拠流用を遮断（`test_per_condition_workspace_and_evidence_isolation`） |
| VDP 脆弱版 / 修正版ペアの CTF 分母からの完全分離 | **適合** | `build_vdp_eval_pairs()`（5 ペア・10 試料）を `VdpEvalSummary` に独立集計（`excluded_from_ctf_denominator = True`）。CTF 側 `total_tasks=20` に一切混入しない |
| 横ばい・悪化（regression）・限界ケースの隠蔽なし記録 | **適合** | `B→C` の予算枯渇悪化（`eval-04`: `resource_limit`）、`C→D` の過適合誤提出悪化（`eval-08`: `premature_conclusion` / `forensics` -0.200）、解決不能 2 件（`eval-05`, `eval-10`）を明示記録 |
| 実 API 料金の捏造禁止・未計測項目の明示 | **適合** | `api_cost_usd` / `token_usage` / Condition A の subprocess CPU・RSS は `not_measured` として出力 |
| 平文 flag 非保持・マーカー漏洩 0・保護ファイル無改変 | **適合** | `EvalTaskSpec` は `expected_flag_sha256`（+ `salt`）のみ保持。全レポート・Markdown で `scan_sensitive_markers(...) == ()`、AST 禁止構文 0 件 |

---

## 2. ホールドアウト `eval`（20件、4分野×5件）実測結果

計測実行 ID: `p5-eval-eval-0b560bf4`（`OfflineEvaluationHarness.evaluate(split=EvalSplit.EVAL, attempts_per_task=1, include_vdp=True)`）

### 2.1 条件 A / B / C / D 全体サマリー（`pass@1` 初回試行のみ）

| Condition | Solved / Total | pass@1 | Wilson 95% CI | best_of_k | Wall (ms) | Median Wall (ms) | Subprocess CPU (ms) | Max Peak RSS (B) | Tool Calls | Reproducible Rate | Operational Reliability | Policy Violations | API Cost / Tokens |
| --- | ---: | ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| **A** | 3/20 | 0.150 | [0.052, 0.360] | not_measured (k=1) | 0 | 0.0 | not_measured | not_measured | 0 | 0.000 | 1.000 | 0 | not_measured / not_measured |
| **B** | 7/20 | 0.350 | [0.181, 0.567] | not_measured (k=1) | 1676 | 98.0 | 1292 | 15,228,928 | 17 | 0.000 | 1.000 | 0 | not_measured / not_measured |
| **C** | 11/20 | 0.550 | [0.342, 0.742] | not_measured (k=1) | 2677 | 99.0 | 1926 | 15,228,928 | 28 | 1.000 | 1.000 | 0 | not_measured / not_measured |
| **D** | 16/20 | 0.800 | [0.584, 0.919] | not_measured (k=1) | 2716 | 97.5 | 2020 | 15,265,792 | 28 | 1.000 | 1.000 | 0 | not_measured / not_measured |

> [!NOTE]
> `eval` の全体標本数は `n=20`（各分野 `n=5`）と小さいため、Wilson 95% 信頼区間は非常に広く、本結果をもって実戦ターゲット・未知バイナリへの汎化や LLM API 推論費用削減を一般化主張することはできません。

### 2.2 分野別内訳（他分野の改善による悪化の隠蔽なし）

| Condition | `rev` (n=5) | `forensics` (n=5) | `crypto_transform` (n=5) | `source_audit` (n=5) |
| --- | ---: | ---: | ---: | ---: |
| **A** | 0/5 (0.000) | 1/5 (0.200) | 0/5 (0.000) | 2/5 (0.400) |
| **B** | 2/5 (0.400) | 2/5 (0.400) | 1/5 (0.200) | 2/5 (0.400) |
| **C** | 2/5 (0.400) | **4/5 (0.800)** | 2/5 (0.400) | 3/5 (0.600) |
| **D** | 3/5 (0.600) | **3/5 (0.600)** [-0.200] | 5/5 (1.000) | 5/5 (1.000) |

### 2.3 条件間ペア比較・悪化・横ばいサマリー

| 遷移 | delta pass@1 | Improved | Regressed (悪化) | Flat Unsolved (横ばい未解決) | 特記すべき分野別動向 |
| --- | ---: | --- | --- | --- | --- |
| **A → B** | `+0.200` | `eval-01`, `eval-04`, `eval-09`, `eval-11` (4件) | なし | 13件 (`eval-02`, `eval-03`, `eval-05`, `eval-07`, `eval-08`, `eval-10`, `eval-12`, `eval-13`, `eval-14`, `eval-15`, `eval-18`, `eval-19`, `eval-20`) | `source_audit` 横ばい (`+0.000`) |
| **B → C** | `+0.200` | `eval-02`, `eval-07`, `eval-08`, `eval-12`, `eval-18` (5件) | **`eval-04`** (1件: `resource_limit`) | 8件 (`eval-03`, `eval-05`, `eval-10`, `eval-13`, `eval-14`, `eval-15`, `eval-19`, `eval-20`) | `rev` 横ばい (`+0.000`: ヘッダ事前点検が `max_tool_calls=1` 予算に抵触し B の 1-shot 成功より悪化) |
| **C → D** | `+0.250` | `eval-03`, `eval-13`, `eval-14`, `eval-15`, `eval-19`, `eval-20` (6件) | **`eval-08`** (1件: `premature_conclusion`) | 3件 (`eval-04`, `eval-05`, `eval-10`) | **`forensics` が `-0.200` 悪化**（`dev` 由来 fastpath ヒューリスティックがデコイ `HINT_B64_FASTPATH` を優先誤提出し `pass@1` 失敗） |

### 2.4 失敗分類集計（`docs/09` §5 規定 9 分類）

| Failure Category | A | B | C | D | 主な該当事象（`eval`） |
| --- | ---: | ---: | ---: | ---: | --- |
| `intake_scope` | 0 | 0 | 0 | 0 | — |
| `missing_capability` | 14 | 1 | 1 | 1 | A: ELF/ZIP/バイナリ解析不能 14件。全条件共通: `eval-05`（動的実行依存の暗号化ペイロード） |
| `spec_ambiguity` | 0 | 0 | 1 | 0 | C: `eval-19`（分割代入 `SEG_A` + `SEG_B` 結合規則なし） |
| `state_loss` | 0 | 8 | 0 | 0 | B: `max_matches=10` 打ち切り・`SLICE_OFFSET -> hex_slice` 継続不可 |
| `insufficient_evidence` | 3 | 1 | 1 | 0 | A: 1200B 超ソース/バイナリ、B/C: `eval-03`（UTF-16LE 専用で ASCII 抽出が空） |
| `premature_conclusion` | 0 | 0 | 0 | 1 | D: `eval-08`（`dev` 学習過適合による decoy fastpath 誤提出） |
| `verifier_limit` | 0 | 0 | 1 | 1 | C/D: `eval-10`（`max_output_bytes=1600` 超過 `capture_complete=False` を `LocalCtfVerifier` が仕様通り拒否） |
| `resource_limit` | 0 | 0 | 1 | 1 | C/D: `eval-04`（`BudgetSpec(max_tool_calls=1)` による 2 手目遮断） |
| `reasoning_limit` | 0 | 3 | 4 | 0 | B/C: `B64`, `ROT13`, `XOR1B`, `REV` 静的変換規則なし |

---

## 3. 開発用 `dev` 集合（10件）実測サマリー

計測実行 ID: `p5-eval-dev-e98fd1c6`（条件 D 凍結ガイド `dev-guide-v1` の根拠集合。VDP は未実行）

| Condition | Solved / Total | pass@1 | Wilson 95% CI | Wall (ms) | CPU (ms) | Tool Calls | Reproducible | Failures / Flat Notes |
| --- | ---: | ---: | --- | ---: | ---: | ---: | ---: | --- |
| **A** | 1/10 | 0.100 | [0.018, 0.404] | 0 | not_measured | 0 | 0.000 | `dev-01` のみ成功 (`missing_capability=8`, `insufficient_evidence=1`) |
| **B** | 2/10 | 0.200 | [0.057, 0.510] | 902 | 699 | 9 | 0.000 | `dev-02` 追加成功 (`state_loss=4`, `reasoning_limit=2`, `insufficient_evidence=1`, `missing_capability=1`) |
| **C** | 4/10 | 0.400 | [0.168, 0.687] | 1502 | 1149 | 16 | 1.000 | `dev-03`, `dev-04` 追加成功 (`reasoning_limit=2`, `spec_ambiguity=1`, `insufficient_evidence=1`, `missing_capability=1`, `verifier_limit=1`) |
| **D** | 8/10 | 0.800 | [0.490, 0.943] | 1611 | 1165 | 17 | 1.000 | `dev-05`〜`08` 追加成功。**`dev-09` (`missing_capability`), `dev-10` (`verifier_limit`) は全条件未解決** |

---

## 4. VDP 別集合評価（脆弱版 vs 修正版 5ペア・CTF 分母から完全分離）

- 対象: `vdp-01`（Command Injection）、`vdp-02`（Path Traversal）、`vdp-03`（SQL Injection）、`vdp-04`（Timing Compare）、`vdp-05`（Unsafe Deserialize）各脆弱版・修正版計 10 試料。
- 条件 C / D は `RunMode.VDP` + 独立ワークスペース + `HarnessController` + `EvidenceVault` ページ読取 + `RunReportExporter` を実行。

| Condition | Pairs | Known Vulns | Reported | TP | FP | FN | Precision | Recall | Policy Violations | Excluded from CTF |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| **A** | 5 | 5 | 10 | 5 | 5 | 0 | 0.500 | 1.000 | 0 | **True** |
| **B** | 5 | 5 | 6 | 5 | 1 | 0 | 0.833 | 1.000 | 0 | **True** |
| **C** | 5 | 5 | 4 | 4 | 0 | 1 | 1.000 | 0.800 | 0 | **True** |
| **D** | 5 | 5 | 5 | 5 | 0 | 0 | 1.000 | 1.000 | 0 | **True** |

---

## 5. 既知限界と非汎化注記

1. **小標本と合成バイナリ範囲**: 全課題が標準ライブラリで決定論的生成されたオフライン合成 ELF64 / ZIP / ソース試料であり、難読化済み商用バイナリや動的実行（P4 `session.control` / `net.probe` 対象）は本オフライン静的分析条件の対象外（`eval-05` 等で明示的に未解決記録）。
2. **外部モデル費用の未計測**: 本評価はオフライン再現性検証のため決定論的ベースライン・手続きソルバを使用しており、外部 LLM の `api_cost_usd` と `token_usage` は常に `not_measured` です。
3. **過適合リスクの実証**: `eval-08` における `C → D` の `forensics` 分野悪化が示すとおり、`dev` 失敗分析から抽出した高速ヒューリスティックは、異なるデコイ構造を持つ新規課題において `pass@1` を低下させ得ます。

---

## 6. 再現手順（Windows PowerShell）

作業ツリー `C:\Users\kenta\.gemini\antigravity\scratch\ctf-vdp-harness-p5`（ブランチ `feat/p5-offline-evaluation`）上で実行：

```powershell
$env:PYTHONPATH = "$PWD\src"

# P5 評価テストスイートのみ実行（観測結果: tests/evaluation/ 7 passed in 44.31s）
C:\Users\kenta\.gemini\antigravity\scratch\.ctf-vdp-harness-venv\Scripts\python.exe -m pytest tests/evaluation/ -v

# 全テストスイート実行（既存 85 件 + 新規 P5 7 件）
C:\Users\kenta\.gemini\antigravity\scratch\.ctf-vdp-harness-venv\Scripts\python.exe -m pytest -v
```
