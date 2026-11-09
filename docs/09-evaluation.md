# 09 Evaluation and Release Criteria

[日本語](09-evaluation.ja.md) | [Home](../README.md)

This is an experiment plan, not reported results. Do not equate MCP connectivity, a larger tool catalog, or an AI's confidence with improved security analysis.

## 1. Comparison conditions

| Arm | Condition | Question |
|---|---|---|
| A | Current AI/workflow and its normal existing tools; frozen baseline inventory | How does the user solve tasks today? |
| B | Same AI + selected bounded OSS tools through MCP | Do the added capabilities help? |
| C | B + run state, persistent sessions where relevant, evidence paging, hypothesis board | Does the harness beyond tool access help? |
| D | C + a frozen revision of failure-informed task guides | Does instruction refinement add value? |

A and B have different tool availability by design; record that difference. B→C isolates harness state/interface effects, C→D isolates revised guidance. If an upstream tool or base model changes, restart or label a separate experiment rather than attributing the difference to the harness.

Match actual model/reasoning setting, client mode, task inputs, time/tool-call/token budgets where observable, start conditions, and permitted network access. Record unavailable metrics as unavailable; do not infer API token cost from a subscription UI. Human hints are logged and compared separately. Fresh conversations, fresh run IDs, isolated workspaces, and restored VM snapshots prevent cross-arm evidence reuse.

## 2. Task sets

Start with 5 owned synthetic fixtures for integration (not a performance result), covering valid input, malformed input, long output, timeout/cancel, and recovery. Then use a proposed development set of 10 licensed/local tasks and a disjoint pilot holdout of 20. Fix the actual list, category balance, version/hashes and inclusion rules before running; small samples are exploratory.

Include reverse engineering, forensics/encoding, source analysis, and a locally hosted web task where feasible. Do not force every category onto the current guest or count skipped unsupported tasks as solved. Public challenge answers may already be in model training; report that limitation. Prefer newly authored variants and private local fixtures when lawful and practical. No unrestricted web search for solutions in either arm.

VDP-style evaluation uses a **separate controlled set**, with known vulnerable and matched non-vulnerable/fixed versions and a reviewer-defined ground truth. Do not mix this denominator with CTF scores. Real VDP work, if later allowed, is observational and reported separately; vendor response time and acceptance are external outcomes.

## 3. Metrics

| Metric | Definition |
|---|---|
| CTF verified solve rate | Tasks with a correct local verifier result within budget / all predeclared eligible tasks. No self-reported success. |
| First-attempt result | One independent run per task/arm. Report separately from success over multiple attempts; never label best-of-k as pass@1. |
| Time and resource use | Time to verified solve, total wall time, tool calls, CPU/peak RSS/disk, and observable token/API cost; failures consume budget too. |
| Evidence quality | Referenced originals exist, versions and preconditions are recorded, and a fresh reviewer can reproduce the claimed result. |
| VDP-style precision | Independently confirmed findings / all reported findings, using predeclared deduplication and ground truth. |
| VDP-style recall | Detected known cases / eligible known cases in the controlled set only. Unknown real-world negatives cannot establish recall. |
| Operational reliability | Tool-error/timeout counts, lost sessions, inaccessible evidence, duplicate actions, successful cleanup and restore. |
| Policy violations | Out-of-scope execution, unauthorized egress, cross-run access, or sensitive export; severity and reproduction retained privately. |

Report unsupported findings, inconclusive cases, and false negatives rather than dropping them. Timeouts and infrastructure failures remain visible in the main task count; additionally give an infrastructure-qualified view if needed. For repeated trials, publish the number of repetitions, seeds where controllable, and outcome distribution.

Use paired task outcomes (improved/regressed/unchanged) and uncertainty intervals when sample size permits. Twenty tasks do not justify a general claim about all CTFs or VDP. Preserve category results: a gain in reverse engineering may coexist with regression elsewhere.

## 4. Verification and control acceptance

Before testing performance, exercise:
- Scope expiry/change, denied tools, malformed schemas, path traversal/symlinks, oversized/archive inputs, and unauthorized evidence IDs.
- DNS/redirect/alternate-address restrictions in a local test network; never use the home LAN as a probing fixture.
- Timeout/cancel/disconnect/restart, orphan process cleanup, resource exhaustion, and rollback.
- Prompt-like text in tool output remaining untrusted data; no resulting permission or export change.
- Sensitive fixture markers withheld from audit logs and redacted exports; original retrieval remains access-controlled.

Use synthetic markers, not real credentials. Acceptance tests belong to implementation, not this documentation-only update.

## 5. Failure-informed revisions

For each development failure, record: intake/scope issue, missing capability, interface ambiguity, lost state, missing evidence, premature conclusion, verifier failure, resource failure, or model reasoning limitation. Change one dimension at a time when practical.

Revise only concise operational guidance and adapter behavior supported by those failures. Freeze instruction/adapter revisions before holdout. Do not insert holdout answers, flags, or raw private session content into skills or memory. Once inspected for tuning, a holdout becomes development data; use a new untouched set for later claims.

## 6. Release decisions

These are proposed pilot gates:
1. **Integration:** every declared contract/control fixture passes; no critical scope or data leak failure remains.
2. **Offline pilot:** all runs are reproducible from manifests and evidence, cleanup succeeds, and A/B/C outcomes plus regressions are documented.
3. **Useful enhancement:** independent solve/reproduction evidence improves within the fixed budget without unexplained regressions. If uncertain or flat, keep the simpler accepted profile and report no proven gain.
4. **Network/VDP:** separate scope, rate-limit, authentication, and request-control acceptance passes on local targets before an authorized real target is enabled.
5. **Broader claims:** require a larger held-out set and repeated matched runs; no numerical improvement is promised in advance.

A small controlled pilot can justify continued engineering; it does not establish bounty eligibility, zero false positives, or general model superiority. [Run report](../templates/run-report.md) records the minimum evidence.

## Detailed implementation contract

[11 Contracts and acceptance](11-contracts-and-acceptance.md) specifies action replay, reservations, evidence pages, recovery/cleanup and CTF-01–12. This delivery is design-only; runtime fixtures remain unexecuted.
