# Documentation

English | [日本語](README.ja.md) | [Project overview](../README.md)

Start with [local setup and operation](local-setup.md). The numbered documents preserve the design and its recorded lab assumptions; they are not a current deployment inventory. Use source and dated acceptance records to distinguish implementation from proposals. This documentation cleanup adds no runtime acceptance result.

## Design and contracts

| Document | Read it for |
|---|---|
| [01 Requirements](01-requirements.md) | Constraints and recorded lab premises |
| [02 Physical architecture](02-architecture.md) | Intended host/guest placement |
| [03 MCP selection](03-mcp-selection.md) | Existing assets, candidates and adoption constraints |
| [04 Connectivity](04-connectivity.md) | Isolated segment and client transport options |
| [05 Security](05-security.md) | Authorization, isolation, scope and private data |
| [06 Earlier roadmap](06-roadmap.md) | Decision history and pending confirmations |
| [07 Research to design](07-research-to-design.md) | Primary sources, extracted mechanisms and limitations |
| [08 Analysis harness](08-analysis-harness.md) | Modules, sessions, evidence and recovery |
| [09 Evaluation](09-evaluation.md) | Baselines, held-out tasks and release gates |
| [10 Implementation plan](10-implementation-plan.md) | Work packages and acceptance criteria |
| [11 Contracts and acceptance](11-contracts-and-acceptance.md) | Action admission, evidence ownership and retry/recovery |

The research map covers EnIGMA, D-CIPHER, CTFusion, SKILL-SIF and selective MCP/HexStrike references. It does not make those systems adopted dependencies or transfer their benchmark results to this harness.

## Acceptance records

These are historical reports for their recorded commits and environments, not checks rerun by this documentation change. Records are currently in Japanese and shared by both documentation indexes.

- [P2 Static inspector](../records/p2-static-inspector-acceptance.md)
- [P3 State and recovery](../records/p3-state-recovery-acceptance.md)
- [P4 Interactive adapter and local network fixtures](../records/p4-interactive-adapter-acceptance.md)
- [P5 Offline synthetic evaluation](../records/p5-offline-evaluation-acceptance.md)
- [P0/P6 WSL2 environment and Codex connection](../records/p0-p6-wsl2-codex-environment-acceptance.md)

The P5 evaluation compares A (no MCP), B (one stateless inspection), C (stateful harness) and D (C with frozen development guidance), using 10 development and 20 disjoint synthetic holdout tasks. It separates first-attempt `pass@1` from `best_of_k`, keeps VDP vulnerable/fixed pairs outside CTF denominators, and reports regressions and unmeasured API costs. It does not establish real-model or live-target performance gains.

## Templates and integration

- [Run report template](../templates/run-report.md) — record actual client/model/reasoning settings, scope, budget and reproducible evidence.
- [Evidence schema notes](../schemas/README.md) · [Synthetic evidence example](../examples/evidence-page.synthetic.json).
- [Offline pilot profile](../configs/offline-pilot.example.json) — non-executable design example, all adapters disabled; not a live configuration.
- [Third-party licenses](../THIRD_PARTY_LICENSES.md) — dependency notices, not a license for this project.
- [Optional three-harness handoff contract](https://github.com/moruku36/ai-agent-scientist/blob/main/docs/11-harness-boundaries.md) — reference-only boundaries; repositories stay independently usable and do not share authority or private state.
