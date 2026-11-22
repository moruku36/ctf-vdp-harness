# CTF VDP Harness

English | [日本語](README.ja.md)

A bounded analysis environment for your existing ChatGPT/Codex client, exposed through MCP. It keeps run state and evidence alongside scope, execution and budget controls; it is not another autonomous agent or a model upgrade.

## What is available

- **MCP-exposed core & analysis tools**: `run.describe`, `evidence.read`, `hypothesis.update`, `run.verify`, `run.close`, plus optional scope-enabled adapters `analysis.query`, `helper.transform`, `session.control`, `net.probe`, and pinned container `vdp.test` (supporting `--network=none` and bounded `--internal` Docker `isolated_internal_services` runs with role-aware `vdp.product_test` verdicts and `check_environment`). Dynamic, network, and `vdp.test` capabilities are disabled by default and require separate enablement and active scope authorization.
- **MCP-exposed VDP manual observation intake (`evidence.import_manual_observation`)**: available via MCP only in open, active-scope `vdp` runs. Validates executor/method provenance, positive and defense/negative controls, before/after state, unverified conditions, cleanup confirmation, and opaque private evidence digest refs, without fetching URLs/files or ever promoting records to `vdp.product_test`.
- **CLI-only admin & static tools (`ctf-mcp-admin`)**: `vdp-boundary-map`, `vdp-auth-matrix` (human-authored paired allow/deny authorization matrix validator and `vdp-boundary-map` candidate importer wired into `vdp.test` overlays), `register-vdp-overlay`, `register-vdp-profile`, `check-vdp-env`, `import-manual-observation` (CLI intake sharing backend validation/storage), `record-vdp-candidate` / `check-vdp-candidate-gate` / `list-vdp-candidates` (two-gate `pre_heavy_test`/`pre_submission` known-issue & precondition checkpoint ledger surfaced in `run.describe` and enforced by `candidate_id`-linked drafts), human-reviewed `export-vdp-draft` / `record-vdp-submission` / `list-vdp-submissions` (zero automatic submission), `diagnose-mcp`, and Windows `scripts/diagnose-nuc-mcp.ps1`.
- **VDP setting-diff auto-recorder (`ctf_mcp.vdp_setting_diff`)**: automatically records redacted test-vs-production differences (Celery eager, loopback fixtures, test CA/private allowlists, auth shortcuts, ephemeral DBs) into `vdp.test` receipts and fails closed in `VdpProductTestVerifier` when `claim="production_parity_confirmed"` is asserted with unverified diffs or absent audits.
- **Specification / planned only (not yet implemented in runtime)**: bounded differential/mutation testing (`vdp_mutation.py`) documented in [`docs/vdp-next-stage-plan.md`](docs/vdp-next-stage-plan.md).
- **Offline synthetic A/B/C/D evaluation**, keeping VDP metrics strictly separate from CTF results.

**Status:** version `0.1.0` includes runtime code and [dated acceptance records](docs/README.md#acceptance-records), including an environment-specific WSL2/Codex connection record. These are not proof of live VDP security, production readiness, general client compatibility or improved real-world solve rates. Older design documents describe intended deployment, not completed infrastructure.

## Safe use

Use only owned artifacts or explicitly authorized CTF/VDP targets. Authorization must cover the target, permitted operations, expiry and budgets; network access never implies permission to submit flags or vulnerability reports. Keep untrusted artifacts isolated, and treat their contents and tool output as data, not instructions.

The default `offline_ctf` profile does not allow target connections or external submission. Do not expose a public endpoint or enable dynamic/network adapters just to follow this quick start. Scope checks do not replace host/guest isolation or an operator's authorization review. Read the [security policy](docs/05-security.md) and [action/recovery contracts](docs/11-contracts-and-acceptance.md) before extending access.

Keep credentials, target addresses, flags and raw transcripts out of Git. Store evidence privately and review exports before sharing.

## Quick start: local offline MCP

Requires Python 3.12+ and Git. These commands use **PowerShell**, from a clean shell without previous `CTF_MCP_*` overrides. They install the package and create an empty, static-only owned-fixture run; they do not analyze or contact a target.

```powershell
git clone https://github.com/moruku36/ctf-vdp-harness.git
cd ctf-vdp-harness
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e .

$env:CTF_MCP_DB_PATH = "$PWD\.local_state\harness.db"
$env:CTF_MCP_VAULT_ROOT = "$PWD\.ctf_vault"
$env:CTF_MCP_CURSOR_HMAC_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
ctf-mcp-admin create-run --task-id owned-fixture-1 --scope-revision scope-v1 --auth-ref local-owned-record
```

Keep the generated key private and reuse it when restarting with this state. Replace the value below with the returned `run_id`:

```powershell
$runId = "<returned run_id>"
ctf-mcp-server --transport stdio --active-run $runId
```

`stdio` is an MCP transport, not an interactive prompt. Configure your MCP client to launch this server with the same private paths, key and run ID. The `--auth-ref` label references your own authorization record; it does not grant permission.

For artifact intake, local verification, Windows install notes, authenticated HTTP and recovery, see [Local setup and operation](docs/local-setup.md). The [offline pilot JSON](configs/offline-pilot.example.json) is a **non-executable design example**, not a runnable configuration.

## Documentation

- [Documentation index](docs/README.md) — requirements, architecture, research, implementation plan and acceptance records.
- [Local setup and operation](docs/local-setup.md) — detailed commands and optional adapter boundaries.
- [Harness design](docs/08-analysis-harness.md) · [Contracts and acceptance cases](docs/11-contracts-and-acceptance.md).
- [Evaluation design](docs/09-evaluation.md) · [Run report template](templates/run-report.md).

## License

Project metadata currently declares `UNLICENSED`; no project license grant is included. A public repository is not itself an open-source license. Dependency notices are in [Third-party licenses](THIRD_PARTY_LICENSES.md).
