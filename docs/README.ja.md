# 資料索引

[English](README.md) | 日本語 | [プロジェクト概要](../README.ja.md)

まず[ローカルセットアップと運用](local-setup.ja.md)を参照してください。番号付き文書は設計と当時の環境前提を保存したもので、現在の構築済み環境一覧ではありません。実装と計画はソースおよび日付付き受入記録で区別します。今回の資料整理で新たなランタイム受入結果は追加していません。

## 設計と契約

| 文書 | 内容 |
|---|---|
| [01 要件](01-requirements.ja.md) | 制約と既存環境の記録 |
| [02 物理構成](02-architecture.ja.md) | 計画上のホスト／ゲスト配置 |
| [03 MCP選定](03-mcp-selection.ja.md) | 既存資産、候補、採用条件 |
| [04 接続](04-connectivity.ja.md) | 隔離セグメントと接続経路 |
| [05 セキュリティ](05-security.ja.md) | 認可、隔離、スコープ、非公開データ |
| [06 従来の計画](06-roadmap.ja.md) | 意思決定の履歴と未確認事項 |
| [07 研究から設計へ](07-research-to-design.ja.md) | 一次資料、採用する仕組み、適用限界 |
| [08 ハーネス設計](08-analysis-harness.ja.md) | 構成、セッション、証拠、復旧 |
| [09 評価](09-evaluation.ja.md) | 比較条件、未使用課題、導入判定 |
| [10 実装計画](10-implementation-plan.ja.md) | 作業単位と受入基準 |
| [11 実装契約と受入](11-contracts-and-acceptance.ja.md) | 実行判定、証拠の所有、再送・復旧 |

研究の対応表ではEnIGMA、D-CIPHER、CTFusion、SKILL-SIF、選定MCP／HexStrikeの参考点を扱います。これらのシステムを採用依存関係としたり、他のベンチマーク結果をこのハーネスの成果としたりするものではありません。

## 受入記録

記録されたコミット・環境での過去の報告です。今回の資料変更で再実行した検証ではありません。記録は現在日本語で、英語索引からも同じ文書を参照します。

- [P2 静的インスペクタ](../records/p2-static-inspector-acceptance.md)
- [P3 状態管理と復旧](../records/p3-state-recovery-acceptance.md)
- [P4 対話アダプタとローカルネットワークfixture](../records/p4-interactive-adapter-acceptance.md)
- [P5 合成課題のオフライン評価](../records/p5-offline-evaluation-acceptance.md)
- [P0／P6 WSL2環境とCodex接続](../records/p0-p6-wsl2-codex-environment-acceptance.md)
- [P7 VDP Weblate製品テストアダプタ](../records/p7-vdp-weblate-product-test-acceptance.md)
- [P8 VDP日次運用・W-02ライブ受入記録](../records/p8-vdp-daily-workflow-acceptance-2026-11-14.md)

P5はA（MCPなし）、B（単発の静的検査）、C（状態を保持するハーネス）、D（開発課題由来の凍結ガイドを加えたC）を、開発用10件・重複しない合成ホールドアウト20件で比較します。初回`pass@1`と`best_of_k`を区別し、VDPの脆弱版／修正版ペアをCTFの分母から分離し、悪化やAPI料金未計測も記録します。実モデルや実対象での性能向上を示すものではありません。

## 雛形と連携

- [調査レポート雛形](../templates/run-report.ja.md)：実クライアント・モデル・推論設定、スコープ、予算、再現可能な証拠を記録。
- [証拠schemaの説明](../schemas/README.ja.md)・[合成証拠の例](../examples/evidence-page.synthetic.json)。
- [オフライン試行設定](../configs/offline-pilot.example.json)：全アダプタ無効の非実行設計例。起動用設定ではありません。
- [第三者ライセンス](../THIRD_PARTY_LICENSES.md)：依存関係の通知であり、このプロジェクトのライセンスではありません。
- [任意の三ハーネス受け渡し契約](https://github.com/moruku36/ai-agent-scientist/blob/main/docs/11-harness-boundaries.ja.md)：参照型の境界です。各repoは単独で使え、権限や非公開状態を共有しません。
