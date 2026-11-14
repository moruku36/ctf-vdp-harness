# P8 VDP Daily-Workflow & W-02 Live Acceptance Record (2026-11-14)

- **Run ID**: `run-vdp-weblate-01` (remains `OPEN`, `guest_health=ready`, `revision=36`, `scope_revision=scope-vdp-weblate-v2`)
- **Base Git Commit**: `d91a4c6fba38d5e972014c363cc1b9902293fb1d` (with P7/P8 working-tree updates loaded via editable install)
- **Server Profile / Client Revision**: `vdp` (`instruction_revision=p6-wsl2-vdp-v1`)
- **Pinned Target Profile**: `weblate-2026.11.2` (`profile_revision=weblate-2026.11.2-r2`)
  - **Source Commit**: `3562388dd005298e3d2c06562987dd3e07be1c89`
  - **Image Ref**: `weblate-oss-scanner:2026.11.2`
  - **Image Digest**: `sha256:f3556156645159fee3e3c08eda2f742661dfed1ee92b90bfa0b7dc713862948d`
  - **Network Mode**: `none` (`synthetic_data_only=true`, `async_behavior_unverified=true`)
  - **Registered Overlays**:
    - `w01-2026-11-13` (`test_w01.py`, `sha256:fa288bdf5c5354661fd47ab9695314b0fa490fdc42c0b7ed76a5990ac234768f`)
    - `w02-2026-11-14` (`test_w02.py`, `sha256:4d6d15f52d17318110bf908d5e6665bd35af9fe6dc0c1b1d06edb4f8a05b3f04`)

## 1. Profile Registration, Discovery & Tool Surface

- Registered `weblate-2026.11.2` (`profile_revision=weblate-2026.11.2-r2`, 10 allowlisted selectors, 2 overlays) into `<vault_root>/_vdp/profiles.json` via `ctf-mcp-admin register-vdp-profile`.
- `run.describe(run_id="run-vdp-weblate-01")`:
  - `visible_mcp_tools` (10): `["analysis.query", "evidence.read", "helper.transform", "hypothesis.update", "net.probe", "run.close", "run.describe", "run.verify", "session.control", "vdp.test"]`.
  - `artifact.inspect` is intentionally omitted because `StaticArtifactInspectorAdapter` binds to `tool_group="analysis.query"` and no default adapter binds to `artifact.inspect`.
  - `vdp_profiles` exposes sanitized profile metadata (`has_host_dir=false`, `has_checkout_dir=false`).
- `vdp.test(operation="describe_profile", target_profile="weblate-2026.11.2")`:
  - `status="ok"`, `evidence_id="ev-c2850a61cc1149fb8af5d9c2de8143d7"`, `profile_revision="weblate-2026.11.2-r2"`, omitting host paths (`has_host_dir=false`, `has_checkout_dir=false`).

## 2. Boundary Denials & Safe Static Extraction Default

- Denied / conflict checks on `run-vdp-weblate-01`:
  - Unallowlisted selector -> `status="denied"`, `error.code="selector_not_allowlisted"`
  - Mismatched `source_commit` -> `status="denied"`, `error.code="source_commit_mismatch"`
  - Mismatched `image_digest` -> `status="denied"`, `error.code="image_digest_mismatch"`
  - Stale `expected_revision` (31 vs 32) -> `action_conflict`
- Default `analysis.query(operation="extract_strings")` on `art_5c7265043d7249eb` (omitting `max_matches`):
  - `status="ok"`, `truncated=true`, `error=null`, `output_bytes=1922`, `evidence_id="ev-4130d21b0afe42f7b3927a02704ebeb0"`
  - Metadata footer/summary: `matches_truncated=True`, `reason=max_matches`, `recommended_max_matches=40`, `next_offset=0x000003e1` (42 lines).

## 3. Live Containerized Smoke, W-02 Product Tests & Verification

1. **Official Smoke (`vdp.test`, `operation="run_smoke"`, `request_id="p8-live-smoke-01"`)**:
   - `evidence_id="ev-d75d7947c8d54258bc9a5fddf6ada923"`, `execution_provenance="harness_docker_isolated"`, `profile_revision="weblate-2026.11.2-r2"`, `exit_code=0`, `collected=251`, `passed=251`, `failed=0`, `skipped=0`, `wall_ms=115486`, `verdict="smoke_passed"`, `container_cleanup_confirmed=true`, `process_cleanup_confirmed=true`.
2. **Crash / Concurrency Reconciliation Recovery Drill**:
   - Initial W-02 upstream attempt (`act-2496a8383f0049a9a89f722cb59da2f0`) entered `reconciliation_required` after an overlapping MCP server startup reconciliation (`stale_fencing_token`). After verifying zero lingering `ctf-vdp-*` containers, `ctf-mcp-admin reconcile --action-id act-2496a8383f0049a9a89f722cb59da2f0 --target-state failed --error-code worker_interrupted` cleared `active_heavy_jobs` back to `0`.
3. **W-02 Upstream Tests (`vdp.test`, `operation="run_pytest"`, `request_id="p8-live-w02-upstream-02"`)**:
   - Selectors:
     - `weblate/api/tests.py::MemoryAPITest::test_delete_removes_only_authorized_scope_from_compacted_entry` (positive & negative control)
     - `weblate/api/tests.py::MemoryAPITest::test_delete_workspace_scope_requires_source_project_permission` (negative control)
   - `evidence_id="ev-45bd3598b0dc4ed1bf6f0106de4428ff"`, `execution_provenance="harness_docker_isolated"`, `baseline_evidence_ref="ev-d75d7947c8d54258bc9a5fddf6ada923"`, `exit_code=0`, `collected=2`, `passed=2`, `failed=0`, `skipped=0`, `positive_passed=1`, `negative_passed=2`, `wall_ms=61083`, `verdict="hypothesis_falsified"`, `container_cleanup_confirmed=true`, `process_cleanup_confirmed=true`.
4. **W-02 Overlay Test (`vdp.test`, `operation="run_pytest"`, `request_id="p8-live-w02-overlay-01"`)**:
   - Overlay bundle: `w02-2026-11-14` (`test_w02.py` SHA-256 `4d6d15f52d17318110bf908d5e6665bd35af9fe6dc0c1b1d06edb4f8a05b3f04`)
   - Selector: `/src/vdp-test-overlay/test_w02.py::TestMemoryCrossProjectScope::test_delete_preserves_foreign_project_scope`
   - `evidence_id="ev-e7c31e4147dc458fb244999c6c9553da"`, `execution_provenance="harness_docker_isolated"`, `baseline_evidence_ref="ev-d75d7947c8d54258bc9a5fddf6ada923"`, `exit_code=0`, `collected=1`, `passed=1`, `failed=0`, `skipped=0`, `positive_passed=1`, `negative_passed=1`, `wall_ms=56028`, `verdict="hypothesis_falsified"`, `container_cleanup_confirmed=true`, `process_cleanup_confirmed=true`.
5. **Deterministic Verifier (`run.verify`, `verifier_id="vdp.product_test"`)**:
   - `verification_id="ver-ee19885d147a4d47b9c378b277aa4c60"`, `status="passed"`
   - `evidence_ids`: `["ev-d75d7947c8d54258bc9a5fddf6ada923", "ev-45bd3598b0dc4ed1bf6f0106de4428ff", "ev-e7c31e4147dc458fb244999c6c9553da"]`
   - `checks_performed`: `["evidence_integrity:verified", "smoke_receipt:verified", "provenance_pin:matched", "positive_baseline:passed", "outcome_state:hypothesis_falsified"]`
   - `limitations`: `["synthetic_data_only", "network_isolated", "celery_eager_test_settings_async_unverified"]`

## 4. Isolated `run.close` & Automated Test Suite

- Tested `run.close` cleanly on an isolated temporary disposable run (`run-p8-close-check`), reaching `guest_health="rolled_back"` and recording `closed_at="2026-11-14T00:25:25.485769+00:00"` while keeping `run-vdp-weblate-01` **OPEN** and `ready` (`active_heavy_jobs=0`, `active_sessions=0`, `remaining_calls=476`).
- Automated test suite: `.venv/bin/pytest -q` passed (`115 passed`).
- **Scope Limitation**: W-02 permission deviation was **not reproduced** under pinned commit `3562388dd005298e3d2c06562987dd3e07be1c89`, synthetic fixtures, `--network=none`, and Celery eager test settings, and is **not** treated as a new vulnerability. Asynchronous production Celery execution remains unverified.
