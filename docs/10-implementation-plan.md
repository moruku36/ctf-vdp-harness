# 10 Implementation Plan for the Existing AI

[日本語](10-implementation-plan.ja.md) | [Home](../README.md)

The implementing AI remains the user's chosen ChatGPT/Codex. Follow this order; deliver a small working vertical slice before adding categories. This document authorizes no deployment or environment change by itself.

## Work packages

| Package | Deliverable | Acceptance / dependency |
|---|---|---|
| P0 — Inventory and baseline | Record actual host/guest resources, VM snapshot, client/transport capabilities, existing tool catalog, license/revision evidence and current workflow A. | Distinguish observed state from planned state. J1 preference, J2 vNIC decision, and J3 expansion direction are already settled. J4 Burp and J5 REA stay deferred; the offline slice does not depend on them. |
| P1 — Contracts and offline intake | Run manifest, scope validator, artifact IDs/hashes, result envelope, private evidence paging, sanitized audit summaries. | Reject missing/expired scope, unauthorized IDs, escaped paths and oversized input. Match the report template. No egress, platform submission, or active debugger. |
| P2 — One accepted analyzer | Use the lightest useful existing Workbench/helper capability first. Pin an upstream commit and enable only the accepted typed operations. | A controlled input produces a reproducible observation and evidence reference; long output remains retrievable. Real execution is tested, not merely tools/list. |
| P3 — Run state and recovery | Hypothesis board, action history, budgets, cancellation, process cleanup, restart behavior and evidence export. | Intake → observation → revised hypothesis → independent verifier → report → restore works on the synthetic fixture set. No missing evidence or secret markers in exported logs. |
| P4 — Interactive adapter | One bounded debugger or connection adapter where task evidence justifies it. | Typed operations only; scope-bound target/artifact, lease expiry, disconnect handling and orphan cleanup. Separate dynamic-execution profile. |
| P5 — Offline comparison | A/B/C comparison under docs/09; add D only after development-guidance revision. | Report all tasks, failures and regressions. A flat result is valid; do not claim a gain without evidence. |
| P6 — Actual client route | Secure MCP Tunnel first; otherwise the existing authenticated HTTPS fallback. Reconcile the isolated vNIC and lab acceptance records before enabling it. | End-to-end authentication, tool filtering, evidence paging, reconnect and deny cases succeed in each actual client. No guest/home-LAN reachability or report-service exposure. |
| P7 — Scoped CTF / VDP | Program-specific scope records, constrained request capability and local vulnerable/fixed test fixtures. | Local request-budget, redirect/DNS, exclusion and expiry checks pass. Live target access depends on the actual permission/rules, not this roadmap. Burp is optional, not a prerequisite. |
| P8 — Optional platform / expansion | CTFd adapter, further categories, resource expansion or multi-agent comparison only when justified. | Separate adoption records and experiments. No automatic external submission in the initial implementation. |

P1–P5 can progress on local paths without waiting for J4/J5. P6/P7 have infrastructure and target-scope dependencies and are not implied completed by an offline pilot. The currently documented no-vNIC guest cannot be reached by ordinary SSH into the guest; first use the existing console/offline intake, or accept the approved isolated bridge before a gateway route.

## Planned runtime layout

The following is a proposal. Only documentation, templates and a non-executable configuration example exist in this update.

```text
src/ctf_mcp/
  gateway/       # principal, scope, catalog, budget, audit
  runs/          # manifests, hypotheses, action state, leases
  adapters/      # narrow wrappers around accepted OSS
  evidence/      # import validation, provenance, paging, export
  verification/  # registered local outcome checks
  server.py      # MCP registration; no general exec endpoint
tests/
  contracts/     # typed requests/results and authorization
  integration/   # owned fixtures, cancellation and recovery
  evaluation/    # frozen task manifest and comparison runner
```

Retain Python 3.12+/uv/FastMCP as the earlier proposal, subject to pinned-version compatibility acceptance. Reuse existing implementations when they meet the contracts. Do not build a new agent runtime, a full pentest distribution, or a generic shell wrapper to fill a minor gap. Provide only small task guides; do not copy large upstream prompts or bundle code without license review.

## Required implementation handoff

For each package, submit a reviewable change with:
- What changed, pinned dependencies/license evidence, and enabled tools.
- Inputs, fixture results, error/cancel behavior, resource measurements and remaining limitations.
- Reproduction instructions and migration/rollback effects.
- Any actual user decision needed, scoped to the unresolved step; never reopen settled J1–J3 preferences as blanket approval requests.

Check real upstream tool descriptors before mapping proposed names to implementations. Keep runtime secrets outside Git; config examples contain no working endpoint or credential. The [example profile](../configs/offline-pilot.example.json) is intentionally disabled and not a supported launcher configuration.

## Definition of the first usable version

An existing AI can use **one accepted offline analysis capability**, access its original evidence in bounded pages, update a recoverable hypothesis record, obtain an independent local verification result, and produce a reproducible report. Timeouts and disconnects leave no untracked process. The report explicitly says whether any performance gain has been measured.

More tools, live target access, Burp, REA, and competition submission can follow without blocking that first version.

## Detailed implementation contract

[11 Contracts and acceptance](11-contracts-and-acceptance.md) specifies action replay, reservations, evidence pages, recovery/cleanup and CTF-01–12. This delivery is design-only; runtime fixtures remain unexecuted.
