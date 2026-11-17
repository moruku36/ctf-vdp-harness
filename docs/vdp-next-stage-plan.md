# VDP Next-Stage Implementation Plan (Stages 3 & 4 / PR-2 Specification)

[日本語](vdp-next-stage-plan.ja.md) | [Home](../README.md) | [Documentation index](README.md)

This specification defines **Stage 3 (Feature 3: Isolated Bounded Differential/Mutation Testing)** and **Stage 4 (Feature 4: Test vs. Production Setting Diff Auto-Recorder)** for the `ctf-vdp-harness` VDP verification pipeline. It builds on the existing `vdp.test` / `vdp.product_test` contracts and PR-1 deliverables while preserving all existing runs, evidence, SHA-256 overlay pins, and `--network=none` isolation guarantees.

> [!IMPORTANT]
> **Safety & Conclusion Boundaries**
> - **Test PASS/FAIL != Confirmed Vulnerability**: A passing `anomaly_repro` check, a differential divergence, or an assertion failure never establishes vulnerability eligibility or real-world impact by itself. Findings remain `investigation_candidate` or `anomaly_observed` with `finding_qualification="separate_assessment_required_not_judged_from_pass_count"`.
> - **Offline & Synthetic Only**: All container runs execute under `--network=none` against synthetic data and loopback (`127.0.0.1`) fixtures. Outbound/external service calls are strictly prohibited.
> - **Existing State Untouched**: Existing runs, SQLite state, `EvidenceVault` blobs, and registered profiles must remain untouched and backward-compatible.

---

## 1. Current Baseline & PR-1 Dependencies

### 1.1 Existing Runtime Contracts (Verified Baseline)

| Component | Module | Current Role & Constraints |
|---|---|---|
| Product test adapter | `src/ctf_mcp/adapters/vdp_product_test.py` | `VdpProductTestAdapter` executes `describe_profile`, `check_environment`, `run_smoke`, and `run_pytest` inside pinned Docker images (`--network none`, fixed CPUs/memory/timeout), verifies SHA-256 overlay files (`_inspect_overlay_directory`), extracts redacted `VDP_EVIDENCE_MARKER` lines, and emits `vdp-product-test-evidence/1`. |
| Role-aware verdict classifier | `src/ctf_mcp/adapters/vdp_product_test.py` | `_classify_verdict` separates `positive_control`, `defense_check`, `anomaly_repro`, and `env_check` (`VALID_SELECTOR_ROLES`). Failed assertions map to `inconclusive`; broken baselines map to `baseline_failed`. |
| Local verifier | `src/ctf_mcp/verification/vdp_product_test.py` | `VdpProductTestVerifier` enforces `execution_provenance="harness_docker_isolated"`, `network_mode="none"`, cleanup confirmation, pinned commit/digest parity, and propagates `conclusion_status.unverified_conditions` plus `_MANDATORY_LIMITATIONS` into `VerificationRecord.limitations`. |
| Loopback & stage recorder | `src/ctf_mcp/vdp_fixtures/local_git_http.py` | `LocalGitHttpFixture` (`127.0.0.1` only), `StageComparisonRecorder`, `ScenarioStageRecord`, and `redact_sensitive_text` / `redact_structure` record `update_scheduled`, `sync_completed`, and `data_changed` without leaking credentials. |

### 1.2 PR-1 Dependencies (Features 1 & 2)

PR-2 consumes PR-1 outputs directly without modifying PR-1's public contracts:

1. **From Feature 1 (`src/ctf_mcp/vdp_boundary_map.py`)**:
   - `build_boundary_diff_map(...)` emits AST-extracted cross-entrypoint (`ui`, `api`, `webhook`, `async`) differences, `file:line` locations, untested conditions, and `investigation_candidates`.
   - **PR-2 use**: Feature 3 uses `investigation_candidates` and extracted input-validation/scoping fields to pick bounded `target_fields` and paired differential entrypoints instead of blind full-surface fuzzing.
2. **From Feature 2 (`src/ctf_mcp/vdp_overlay_assistant.py`)**:
   - `generate_overlay_registration_plan(...)` and `preview_and_register_overlay(...)` perform AST selector discovery, role mapping, SHA-256 pinning, `--dry-run` preview, `config_diffs` capture, and fail-closed `--apply --confirm-apply` registration.
   - **PR-2 use**: Feature 3 registers any new mutation/differential test overlays through Feature 2's fail-closed registration flow; Feature 4 reconciles runtime setting diffs with Feature 2's registration-time `config_diffs`.

---

## 2. Feature 3: Isolated Bounded Differential/Mutation Testing

### 2.1 Purpose

Detect input-normalization, validation, or scoping discrepancies on a single field or small field tuple across entrypoints (e.g., UI vs. API vs. webhook vs. async task) using deterministic, bounded mutations inside a `--network=none` container, automatically minimizing any reproducing input alongside a paired control.

### 2.2 Architecture & Guardrails

1. **Bounded Target Selection (`MutationTargetSpec`)**:
   - Explicitly allowlists `target_fields` (`minItems=1`, `maxItems=3` per run) and `entrypoint_pair` (e.g., baseline path vs. candidate path from Feature 1).
   - Mutator families are strictly allowlisted (`MUTATION_OPERATORS`): `boundary_length`, `encoding_normalization`, `scheme_or_path_variant`, `empty_null_type`, `whitespace_delimiter`. Arbitrary code injection or unconstrained payload generation is disallowed.
2. **Deterministic Seed & Hard Caps**:
   - Every run requires (or deterministically derives and records) an explicit integer `seed` (`uint64`) so any anomaly is 100% replayable.
   - `max_iterations`: default `32`, hard schema cap `256` (fail-closed if exceeded).
   - `wall_time_cap_seconds`: default `60`, hard cap bounded by `min(plan.timeout_seconds, DEFAULT_VDP_TEST_TIMEOUT_SECONDS)` (`300s`).
   - `per_iteration_timeout_ms`: bounded (e.g., `2000ms` max) to prevent single-input stalls from starving the budget.
   - `max_output_bytes`: enforced via `_encode_bounded_evidence_json` (`DEFAULT_VDP_TEST_MAX_OUTPUT_BYTES = 262_144`).
3. **Strict Prohibition Against Outbound / External Service Calls**:
   - Container always launches with `--network none` (`network_mode="none"` enforced in `_validate_and_build_plan` and `VdpProductTestVerifier`).
   - In-container mutation harness installs a fail-closed egress guard (blocking non-loopback sockets/DNS resolution; only `127.0.0.1` / `::1` loopback fixtures such as `LocalGitHttpFixture` are permitted).
   - Any detected outbound socket attempt, DNS lookup outside loopback, or non-loopback URL in `target_fields` aborts the iteration as `environment_failure` (`network_isolation:violated`) and never records an anomaly pass.
4. **Paired Control & Automatic Minimal Reproducing Input Capture**:
   - **Step A — Baseline Gate**: Run the unmodified `positive_control` pair first. If baseline fails, abort immediately with `verdict="baseline_failed"`.
   - **Step B — Bounded Differential Loop**: For `i in 0..max_iterations-1` (until wall-time cap), run the mutated input against the candidate path and its paired control input against the reference path (or expected defense invariant).
   - **Step C — Deterministic Shrinker (Delta Debugging)**: On the first anomaly/divergence (or up to `max_anomalies=3` distinct failure classes), run a bounded binary/token shrinker (`max_shrink_steps=24`, sharing the remaining wall-time cap) to produce a minimal reproducing input (`minimal_repro_input`).
   - **Step D — Redacted Paired Evidence Emission**: Emit a redacted `VDP_EVIDENCE_MARKER` containing:
     - `mutation_summary`: `seed`, `iterations_executed`, `wall_ms`, `stop_reason` (`completed`, `anomaly_found`, `wall_time_cap`, `baseline_failed`, `egress_blocked`).
     - `minimal_repro_case`: `field_name`, `operator`, `minimal_input` (redacted & bounded `<= 1024` chars), `paired_control_input`, `candidate_outcome`, `control_outcome`, `differential_summary`, `shrink_steps`.
5. **Verdict & Qualification Discipline**:
   - Divergences map to `verdict="anomaly_observed"` only when `positive_control` passes and the divergence is reproducible with the minimal input; setup/runner exceptions map to `inconclusive` or `environment_failure`.
   - `finding_qualification` stays `"separate_assessment_required_not_judged_from_pass_count"` and never promotes to a confirmed vulnerability automatically.

### 2.3 Proposed Data Contract (`src/ctf_mcp/vdp_mutation.py`)

```text
MutationPolicySpec (StrictModel):
  seed: int (ge=0, le=2**63-1)
  max_iterations: int (ge=1, le=256, default=32)
  wall_time_cap_seconds: int (ge=5, le=300, default=60)
  max_shrink_steps: int (ge=0, le=64, default=24)
  target_fields: tuple[str, ...] (min_length=1, max_length=3)
  allowed_operators: tuple[MutationOperator, ...]
  allow_loopback_only: Literal[True] = True
```

---

## 3. Feature 4: Test vs. Production Setting Diff Auto-Recorder

### 3.1 Purpose

Prevent test-environment shortcuts (eager task execution, loopback fixtures, relaxed TLS/allowlists) from being mistaken for production parity by automatically recording every environment/config difference with an explicit `"confirmed"` or `"unverified"` tag in both evidence receipts and `VerificationRecord`.

### 3.2 Setting Categories & Tagging Rules

Each recorded entry uses a typed `SettingDiffEntry` model:

| Category | Typical Test Setting | Typical Production Baseline | Default Status Tag | Example Condition Tag |
|---|---|---|---|---|
| `async_execution` | Eager / inline task execution (`task_always_eager=True`, synchronous stub) | Brokered async worker queue, serialization, worker permissions | `"unverified"` (unless real worker confirmed) | `celery_eager_test_settings_async_unverified` |
| `service_transport` | Loopback fixture (`127.0.0.1` `LocalGitHttpFixture`, mock HTTP) | Real remote VCS / webhook / service endpoint over external network | `"unverified"` for remote transport; `"confirmed"` only for local protocol steps verified via fixture | `loopback_fixture_vs_real_vcs_transport_unverified` |
| `tls_network_policy` | Test CA bundle, private IP/loopback allowlist override, `--network=none` | Production TLS CA verification, strict egress/SSRF IP deny policy | `"unverified"` | `test_ca_or_private_allowlist_vs_prod_tls_policy_unverified` |
| `auth_middleware` | Test client `force_login`, disabled CSRF/rate-limit, `DEBUG=True` | Production auth middleware, CSRF, reverse-proxy headers | `"unverified"` if bypassed; `"confirmed"` if real middleware path exercised | `auth_middleware_parity_confirmed` / `auth_shortcut_unverified` |
| `storage_backend` | Ephemeral SQLite / local memory cache | Production RDBMS / Redis locking & isolation | `"unverified"` when concurrency/locking matters | `ephemeral_db_concurrency_unverified` |

### 3.3 Auto-Recording & Verifier Propagation Flow

1. **Collection Sources (Redacted)**:
   - **Registration-time baseline**: `config_diffs` captured in `VdpTargetProfile` (via Feature 2) declaring known test-harness overrides vs. production baseline expectations.
   - **Runtime introspection inside container**: Helper `SettingDiffRecorder` inspects sanitized runtime flags (e.g., eager task mode, loopback fixture URLs, private-allowlist env vars, test CA overrides, `DEBUG` flag, DB engine kind) and compares against the profile's production-baseline descriptor. All values pass through `redact_sensitive_text` / `redact_structure` before emission.
   - **Stage-aware promotion**: If `StageComparisonRecorder` confirms a sub-stage (e.g., `sync_completed=True` over `LocalGitHttpFixture`), only that narrow sub-condition is tagged `"confirmed"` (`loopback_git_http_sync_confirmed`), while real remote transport/TLS/async worker remain explicitly `"unverified"`.
2. **Evidence Embedding (`vdp-product-test-evidence/1`)**:
   - `_extract_evidence_markers` and `_build_execution_context_and_conclusion` accept `setting_diffs: list[SettingDiffEntry]`.
   - Every `SettingDiffEntry` with `verification_status == "unverified"` automatically appends its `condition_tag` to `conclusion_status["unverified_conditions"]`; entries with `"confirmed"` append to `conclusion_status["confirmed_conditions"]`.
   - `execution_context["setting_diffs"]` stores the redacted diff table cleanly within `max_output_bytes`.
3. **Verifier Enforcement (`VdpProductTestVerifier.verify`)**:
   - Reads `execution_context.setting_diffs` from all referenced `vdp.test` payloads.
   - Propagates every `"unverified"` condition tag into `VerificationRecord.limitations` (deduplicated, preserving `_MANDATORY_LIMITATIONS`).
   - Appends `setting_diff_audit:recorded` to `VerificationRecord.checks_performed` when diffs are present (or `setting_diff_audit:legacy_absent` for historical evidence schemas so existing runs remain valid and readable).
   - If a `claim` asserts production parity (e.g., `claim="production_parity_confirmed"`) while any `setting_diffs` entry is `"unverified"`, `VdpProductTestVerifier` returns `VerificationStatus.FAILED` with `checks_performed` including `production_parity:unverified_setting_diff_present`.

---

## 4. Concrete Implementation Order & Effort Estimates

### 4.1 Milestones & Dependencies

| Milestone | Scope | Depends On | Effort Estimate | Exit Criteria |
|---|---|---|---|---|
| **M1: Setting Diff Core (`vdp_setting_diff.py`)** | `SettingDiffEntry`, `SettingDiffRecorder`, redaction integration, category detectors, `VDP_EVIDENCE_MARKER` serializer. | Existing `local_git_http.py` redactors; PR-1 Feature 2 `config_diffs` format | **1.5–2.0 eng-days** | Unit tests pass on synthetic settings dicts; zero credential leaks; deterministic JSON output. |
| **M2: Adapter & Verifier Integration** | Merge `setting_diffs` in `vdp_product_test.py` (`_extract_evidence_markers`, `_build_execution_context_and_conclusion`) & `verification/vdp_product_test.py` (`VerificationRecord.limitations` + `checks_performed`). | M1 | **1.0–1.5 eng-days** | Backward-compatible with existing `vdp-product-test-evidence/1` receipts; `production_parity_confirmed` claim fails closed on unverified diffs. |
| **M3: Bounded Mutation Engine (`vdp_mutation.py`)** | `MutationPolicySpec`, allowlisted mutator operators, deterministic RNG, paired control runner, bounded delta-debug shrinker, in-process egress guard. | M1; PR-1 Feature 1 (`investigation_candidates` input schema) | **2.5–3.0 eng-days** | Deterministic replay by `seed`; strict iteration & wall-time caps; automatic minimal repro + paired control on synthetic apps; outbound socket attempts blocked. |
| **M4: `vdp.test` Operation & Profile Wiring** | Optional `run_bounded_mutation` operation (or overlay-driven bounded runner) in `VdpProductTestAdapter`, schema validation, `--network=none` enforcement, PR-1 Feature 2 registration integration. | M2, M3, PR-1 Feature 2 | **1.5–2.0 eng-days** | Preflight rejects invalid seeds, `>3` fields, `>256` iterations, or `network_mode != "none"`; evidence stored via `EvidenceVaultPort`. |
| **M5: Synthetic E2E Acceptance, Examples & Docs** | Synthetic multi-entrypoint test app acceptance suite, runnable examples, `README*.md` / `docs/local-setup*.md` updates, leak scan. | M1–M4 | **1.0–1.5 eng-days** | 100% pytest pass on synthetic fixtures; 0 real VDP targets/findings; PASS != confirmed vulnerability verified. |

**Total Estimated Effort**: **7.5 – 10.0 engineering days** (recommended split into two reviewable PRs below).

---

## 5. PR-2 Split Plan

To keep diffs small, auditable, and independently verifiable, split PR-2 into **PR-2A (Feature 4)** followed by **PR-2B (Feature 3)**:

### 5.1 PR-2A: Feature 4 — Test vs. Production Setting Diff Auto-Recorder

- **Target Branch**: `feat/pr2a-setting-diff-recorder`
- **File List**:
  - `src/ctf_mcp/vdp_setting_diff.py` *(new)* — `SettingDiffEntry`, `SettingDiffRecorder`, default category rules (`async_execution`, `service_transport`, `tls_network_policy`, `auth_middleware`, `storage_backend`), marker helper.
  - `src/ctf_mcp/vdp_fixtures/__init__.py` *(modify)* — re-export setting diff helpers alongside `StageComparisonRecorder`.
  - `src/ctf_mcp/adapters/vdp_product_test.py` *(modify)* — extract `setting_diffs` in `_extract_evidence_markers`, attach to `execution_context`, merge into `confirmed_conditions` / `unverified_conditions`.
  - `src/ctf_mcp/verification/vdp_product_test.py` *(modify)* — propagate unverified setting diffs into `VerificationRecord.limitations`, add `setting_diff_audit:*` check, enforce fail-closed `production_parity_confirmed` claim check.
  - `tests/unit/test_vdp_setting_diff.py` *(new)* — unit tests for diff detection, redaction, `"confirmed"` vs `"unverified"` tagging, and backward compatibility.
  - `tests/integration/test_vdp_setting_diff_verification.py` *(new)* — end-to-end synthetic evidence -> `VdpProductTestVerifier` limitation propagation tests.
  - `examples/vdp_setting_diff_example.py` *(new)* — runnable synthetic example.

### 5.2 PR-2B: Feature 3 — Isolated Bounded Differential/Mutation Testing

- **Target Branch**: `feat/pr2b-bounded-mutation-testing` (stacked on PR-2A)
- **File List**:
  - `src/ctf_mcp/vdp_mutation.py` *(new)* — `MutationPolicySpec`, allowlisted mutators, deterministic seeded engine, paired control runner, bounded delta-debugging shrinker, loopback-only egress guard.
  - `src/ctf_mcp/adapters/vdp_product_test.py` *(modify)* — add `run_bounded_mutation` (or bounded mutation parameters validated in `_validate_and_build_plan` under `--network=none` and `DEFAULT_VDP_TEST_TIMEOUT_SECONDS`).
  - `src/ctf_mcp/verification/vdp_product_test.py` *(modify)* — validate mutation evidence provenance, baseline pass requirement, and keep `anomaly_observed` distinct from vulnerability confirmation.
  - `tests/unit/test_vdp_mutation.py` *(new)* — deterministic seed replay, iteration/wall-time cap, shrinker minimization, and egress-block tests on synthetic targets.
  - `tests/integration/test_vdp_mutation_synthetic_app.py` *(new)* — synthetic multi-entrypoint app (UI/API/webhook/async) differential + Feature 1 candidate handoff + Feature 2 overlay dry-run/apply + Feature 4 setting diff audit.
  - `examples/vdp_mutation_example.py` *(new)* — runnable synthetic example.
  - `docs/local-setup.md` & `docs/local-setup.ja.md` *(modify)* — document new options after implementation lands.

---

## 6. Synthetic-Only Acceptance Test Plan

All PR-2 acceptance tests MUST construct ephemeral synthetic Python apps/overlays under `pytest`'s `tmp_path` (never touching real targets, private overlays, or existing runs/evidence):

| Test ID | Target | Scenario & Assertions |
|---|---|---|
| **ACC-F3-01** | Synthetic multi-entrypoint app (`tmp_path`) | **Deterministic Seed & Budget Caps**: Run mutation with `seed=42, max_iterations=16, wall_time_cap_seconds=10` on `target_fields=("repo_url",)`. Re-run with identical `seed=42` and assert byte-identical mutation sequence and stop reason. Verify `max_iterations > 256` or `len(target_fields) > 3` is rejected preflight. |
| **ACC-F3-02** | Synthetic app with deliberate normalization mismatch on `webhook` vs `api` | **Minimal Repro + Paired Control Capture**: Confirm `positive_control` passes first; confirm mutation detects divergence, shrinks payload within `max_shrink_steps`, captures both `minimal_repro_input` and `paired_control_input`, maps verdict to `anomaly_observed`, and keeps `finding_qualification == "separate_assessment_required_not_judged_from_pass_count"`. |
| **ACC-F3-03** | Synthetic app with broken positive control | **Baseline Guard**: When `positive_control` fails, mutation aborts immediately with `verdict="baseline_failed"` and `VdpProductTestVerifier` returns `VerificationStatus.FAILED`. |
| **ACC-F3-04** | Synthetic mutator attempting outbound HTTP/DNS | **Egress & Isolation Enforcement**: Non-loopback host or `network_mode != "none"` is rejected fail-closed (`network_mode_denied` / `network_isolation:violated` / `environment_failure`). Loopback `127.0.0.1` (`LocalGitHttpFixture`) succeeds. |
| **ACC-F4-01** | Synthetic test profile with eager tasks, loopback fixture, and private allowlist | **Setting Diff Auto-Record & Tagging**: Verify `SettingDiffRecorder` records all three categories tagged `"unverified"` (`celery_eager_test_settings_async_unverified`, `loopback_fixture_vs_real_vcs_transport_unverified`, `test_ca_or_private_allowlist_vs_prod_tls_policy_unverified`) and redacts any embedded URL credentials. |
| **ACC-F4-02** | Synthetic evidence + `VdpProductTestVerifier` | **Verifier Propagation & Parity Guard**: Verify `"unverified"` tags appear in `VerificationRecord.limitations`; verify `claim="production_parity_confirmed"` returns `VerificationStatus.FAILED` when any unverified diff exists; verify historical evidence without `setting_diffs` still passes legacy checks (`setting_diff_audit:legacy_absent`). |
| **ACC-HYG-01** | All PR-2 files + test outputs | **Confidentiality & Leak Scan**: Assert zero real target names, zero private overlay references, zero raw credentials/tokens, and zero automated `"confirmed_vulnerability"` claims. |
