# 07 Research to Design

[日本語](07-research-to-design.ja.md) | [Home](../README.md)

Reviewed 2026-11-09. The mechanisms below inform this project's design; they are not measurements of the user's model or a dependency installation list. The application choices in the last column are this project's proposals.

## Evidence and extraction

| Primary source | What it supports | What we borrow | Boundary |
|---|---|---|---|
| [EnIGMA, v3](https://arxiv.org/html/2409.16165v3), [code](https://github.com/SWE-agent/SWE-agent/tree/v0.7) | The study examines interactive agent-computer interfaces, including GDB and pwntools sessions, output handling, demonstrations, and guidelines in CTF tasks. Effects vary across categories. | Bounded persistent sessions; short observations with retrievable originals; small, task-specific usage examples. | Neither evidence that every debugger improves every category nor proof for the current model. Implementing radare2/Ghidra support here is our integration choice. |
| [D-CIPHER, v2](https://arxiv.org/abs/2502.10931), [code](https://github.com/NYU-LLM-CTF/nyuctf_agents) | Studies a planner and heterogeneous executors with collaborative feedback in offensive-security benchmarks. | Explicit decomposition, a hypothesis board, and action/observation feedback. | Start with one existing AI taking sequential roles. Multi-agent execution is optional future work requiring its own comparison and budget. |
| [CTFusion, v2](https://arxiv.org/html/2605.11504v2), [code](https://github.com/kaist-hacking/CTFusion) | Uses MCP for CTFd platform operations and evaluation, including isolated trial records and submission handling; distinguishes live and static evaluation conditions. | Separate platform adapter; isolate trial state; local verification and duplicate handling. | CTFd integration is not a collection of analysis tools. Live/static differences do not by themselves prove contamination. Initial pilot has no live competition submissions. |
| [SKILL-SIF study, v1](https://arxiv.org/html/2610.25705v1) | Evaluates security guidance on known Linux-kernel vulnerability cases and refines procedures using observed failures. | Classify missed evidence, premature stopping, and unsupported conclusions; revise a small skill set offline, then freeze it for held-out evaluation. | Guided kernel localization differs from open-ended CTF and VDP discovery. This is instruction refinement, not weight training, and does not establish general false-positive rates. |
| [HexStrike AI](https://github.com/0x4m4/hexstrike-ai) | An OSS MCP-oriented security-tool integration catalogue; tool counts and capability descriptions are upstream claims. | Category coverage and candidate discovery. | Keep the earlier decision not to adopt it wholesale. No new code audit establishes that broad command execution or authentication is suitable. Tool count is not a performance metric. |
| [Incident-Arena, v1](https://arxiv.org/html/2610.00648v1) | A different task domain: incident remediation evaluated with checks of outcomes and operational properties. | Separate the acting AI from deterministic outcome checks; verify cleanup and recovery as well as a claimed success. | It is not evidence of CTF/VDP discovery gains. Our challenge verifiers and VDP reproduction criteria must be defined independently. |
| [Apiiro analysis](https://apiiro.com/blog/coding-agents-leaking-secrets-github-dont-ask-again) | Describes risks from agent-related repository artifacts carrying sensitive information. | Review exported reports, transcripts, and derived memory for sensitive content; separate raw evidence from audit summaries. | A vendor report is contextual risk evidence, not an independently measured leak rate for this environment. No secret search or scanning was performed in this design update. |

## OSS adoption is a separate decision

The existing [selection table](03-mcp-selection.md) remains the adoption record. Upstream identities were revisited, but runtime compatibility, source audit, licensing at a pinned revision, and acceptance are still required.

| Capability | Candidate / disposition |
|---|---|
| Source/dependency observations | Existing `moruku36/oss-vulnerability-workbench-mcp`; first verify real analysis on a controlled fixture. Basic tools/list success is insufficient. |
| Binary structure, functions, decompilation | [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP), subject to installed-Ghidra compatibility and narrow-tool acceptance. REA remains pending separately. |
| Binary inspection | [radareorg/radare2-mcp](https://github.com/radareorg/radare2-mcp); do not expose unrestricted r2 commands. |
| Web analysis workspace | [PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server), optional after Burp placement/licensing and request controls are resolved. |
| Interactive debugging / connection state | Bounded adapter around already accepted guest tooling, inspired by EnIGMA. New work; not currently available. |
| Encoding, metadata, embedded-content summaries | Existing OSS first; small helpers only where no accepted adapter covers the need. Extraction limits and subprocess constraints apply. |

Prefer the smallest capability set that completes a measured task. Pin repository commit, license/SPDX evidence, dependencies, supported transport, descriptor hash, tool permissions, and fixture results in a future adapter acceptance record. A release/version named in an older document is a recorded environment observation, not a claim about the latest compatible upstream version.

## Source-informed design choices

The following are **our synthesis**, not a tested combination from one paper:

1. Keep the user's existing AI as the planner; use a compact catalog and inspectable observations.
2. Give each run scoped capabilities, recoverable hypotheses, and evidence references.
3. Introduce stateful tools only where stateless calls lose useful context.
4. Use independent verification; do not accept the AI's confidence as the result.
5. Revise skills using development failures, never held-out answers or private flags.
6. Expand categories only after matched-budget comparisons justify them.

[Architecture](08-analysis-harness.md) specifies the resulting system, and [evaluation](09-evaluation.md) specifies what would count as improvement.
