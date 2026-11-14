# P7 Acceptance Record — Bounded VDP Product Test Execution (Weblate 2026.11.2)

- **Date**: 2026-11-13
- **Execution Host**: Owner WSL2 Ubuntu (`moruku36`, Docker group `986`, local Docker daemon + `/home/moruku36/vdp-weblate-2026.11.2` + `/home/moruku36/vdp-test-overlay/w01-2026-11-13`)
- **Run ID**: `run-vdp-weblate-01` (`mode=vdp`, `scope_revision=scope-vdp-weblate-v2`)
- **Pinned Source Commit**: `3562388dd005298e3d2c06562987dd3e07be1c89`
- **Pinned Scanner Image**: `weblate-oss-scanner:2026.11.2` (`sha256:f3556156645159fee3e3c08eda2f742661dfed1ee92b90bfa0b7dc713862948d`)
- **Approved Synthetic Overlay**: `w01-2026-11-13/test_w01.py` (`sha256:fa288bdf5c5354661fd47ab9695314b0fa490fdc42c0b7ed76a5990ac234768f`)

## 1. Automated Unit/Contract/Integration Test Suite

- **Command**: `.venv/bin/pytest -q` (in `/home/moruku36/ctf-vdp-harness`)
- **Result**: `111 passed in 41.29s` (including all 5 integration tests in `tests/integration/test_p7_vdp_product_test.py` and existing Layer 2 isolation, budget, state-recovery, `net.probe`, `session.control`, and `analysis.query` tests).

## 2. Live Weblate Docker Acceptance Comparison (MCP `vdp.test` + `vdp.product_test`)

| Leg | Harness MCP Request / Operation | Harness Evidence ID | Harness Outcome & Counts | Manual Baseline Log (`2026-11-13-evening`) | Match |
| --- | --- | --- | --- | --- | --- |
| Smoke (60s cap check) | `vdp.test` `run_smoke` (`action_timeout_seconds=60`) | `ev-275eb395d8aa42c8951c5b79cdd491de` | `status=timeout`, `verdict=timeout`, `collected=129`, `wall_ms=60265`, cleanup confirmed (`verifier=inconclusive`) | `smoke.log` requires ~76s total | Expected timeout at 60s; cleanup verified |
| Smoke (300s cap) | `vdp.test` `run_smoke` (`action_timeout_seconds=300`) | `ev-8399b05e2d86427aaebb1cb77a049cc1` | `status=ok`, `verdict=smoke_passed`, `exit=0`, `collected=251` (`[129, 122]`), `passed=251`, `failed=0`, `skipped=0`, `negative_exit4_check=true`, `wall_ms=110618` | `smoke.log`: `129 passed` + `122 passed` + exit-4 nonexistent-file check | Exact match |
| Baseline existing tests (3) | `vdp.test` `run_pytest` (`BulkEditTest` + `EditPropagateTest`) | `ev-6aa57d9f9d7e4fad9a9e9917306c5716` | `status=ok`, `verdict=hypothesis_falsified`, `exit=0`, `collected=3`, `passed=3` (`pos=1, neg=2`), `wall_ms=57669` | `baseline.log`: `3 passed in 44.94s` | Exact match |
| W-01 core real-code (2) | `vdp.test` `run_pytest` (`overlay_bundle="w01-2026-11-13"`) | `ev-d730c7812ac54406bd1cb33f364674f2` | `status=ok`, `verdict=hypothesis_falsified`, `exit=0`, `collected=2`, `passed=2` (`pos=1, neg=1`), `wall_ms=54020` | `w01.log`: `2 passed in 40.53s` | Exact match |
| W-01 HTTP POST (2) | `vdp.test` `run_pytest` (`overlay_bundle="w01-2026-11-13"`) | `ev-c4416f6b7e6048fd82c21fdd948296c6` | `status=ok`, `verdict=hypothesis_falsified`, `exit=0`, `collected=2`, `passed=2` (`pos=1, neg=1`), `wall_ms=54784` | `w01-http.log`: `2 passed in 42.86s` | Exact match |
| Deterministic Verifier | `run.verify` (`verifier_id="vdp.product_test"`) | Verification `ver-1b95ec61acfe4f7f89b77f7314b380a0` | `status=passed` (`evidence_integrity:verified`, `smoke_receipt:verified`, `provenance_pin:matched`, `positive_baseline:passed`, `outcome_state:hypothesis_falsified`) | Manual conclusion: W-01 did not reproduce under fixed commit + synthetic data + Celery eager settings | Exact match |

## 3. Cleanliness & Post-Run State

- Container isolation enforced (`--network none`, `--cpus 2`, `--memory 6144m`, read-only overlay bind mount only).
- Post-run `docker ps -a --filter name=ctf-vdp-` returned zero containers.
- `run-vdp-weblate-01` left open and healthy for continued operator/Codex use (`revision=27`, `guest_health=ready`, `active_heavy_jobs=0`, `active_sessions=0`, `remaining_calls=485`, `visible_mcp_tools` includes `analysis.query`, `net.probe`, `session.control`, `vdp.test`, `evidence.read`, `run.verify`, `run.describe`, `run.close`).
- W-01 permission deviation was **not reproduced** under pinned commit `3562388dd005298e3d2c06562987dd3e07be1c89`, synthetic test fixtures, and Celery eager test settings, and is **not** treated as a new vulnerability. Asynchronous production Celery execution remains unverified.
