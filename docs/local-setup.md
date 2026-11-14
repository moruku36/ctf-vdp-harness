# Local setup and operation

English | [日本語](local-setup.ja.md) | [Overview and quick start](../README.md) | [Documentation index](README.md)

This guide expands the offline quick start, not authorization for a live investigation. Use only owned fixtures or explicitly authorized targets. See [Security](05-security.md) and [Contracts](11-contracts-and-acceptance.md) before changing execution profiles or connectivity.

## Installation and private state

Use Python 3.12+ and the [PowerShell quick start](../README.md#quick-start-local-offline-mcp). On Windows without the required `libyaml` C build tools, set this before installation if the transitive PyYAML build needs it:

```powershell
$env:PYYAML_FORCE_LIBYAML = "0"
python -m pip install -e .
```

For development, the optional extra is `python -m pip install -e ".[dev]"`. Select relevant checks within the agreed test budget; installing or editing documentation is not a reason to run every historical test.

Keep the database, evidence vault and cursor HMAC key private. The quick start uses `.local_state\harness.db` and the ignored `.ctf_vault` directory. Ignore rules are not a substitute for reviewing staged files. Preserve the key securely across server restarts; the server fails closed if it is missing unless the explicit local-development ephemeral-key option is selected.

Start in a clean shell: existing `CTF_MCP_CONFIG`, `CTF_MCP_PROFILE`, `CTF_MCP_ALLOW_DYNAMIC` or transport overrides can change behavior. The CLI accepts `--config` or the `CTF_MCP_CONFIG` fallback for a validated executable configuration; [offline-pilot.example.json](../configs/offline-pilot.example.json) deliberately has `executable: false` and is rejected as live configuration.

## Owned artifact intake and local verification

After creating the quick-start run, set `$runId` to its returned ID and keep the same environment. Replace the example directory and filename with an owned fixture; do not ingest unrelated private files.

```powershell
ctf-mcp-admin ingest-artifact --run-id $runId --source-root C:\path\to\owned_fixtures --rel-path sample.bin
ctf-mcp-admin describe-run --run-id $runId
```

If an independently known expected flag digest is available, register it locally:

```powershell
ctf-mcp-admin register-expectation --run-id $runId --flag-sha256 "<64 lowercase hex SHA-256>"
```

Do not pass plaintext flags or secrets as CLI arguments. Digest registration supports the local verifier; it does not itself verify a finding or establish VDP acceptance. The default create-run scope permits static inspection (`analysis.query`, `artifact.inspect`); additional capabilities require an explicit scope decision.

## MCP transports

The default server wires the static inspector and local verifier, without synthetic adapters. With the same environment and run ID:

```powershell
ctf-mcp-server --transport stdio --active-run $runId
```

An MCP client must launch this command with the same environment. For a local authenticated HTTP endpoint instead, supply a strong private token; the text below is a placeholder to replace, not a credential:

```powershell
$env:CTF_MCP_AUTH_TOKEN = "<strong private bearer token>"
ctf-mcp-server --transport streamable-http --host 127.0.0.1 --port 8000
```

HTTP requires a non-placeholder token; clients must authenticate. Local stdio relies on the local process trust boundary. Neither command establishes a public tunnel, OAuth flow, isolated guest network or working connection for every ChatGPT/Codex client. See [Connectivity](04-connectivity.md) for the deployment design and the [WSL2/Codex record](../records/p0-p6-wsl2-codex-environment-acceptance.md) for that environment's historical result.

## State inspection and recovery

```powershell
ctf-mcp-admin describe-run --run-id $runId
ctf-mcp-admin reconcile
```

`reconcile` is an administrative state transition, not a read-only health check or permission to replay an action. Resolve uncertain actions against their evidence and reservations first. Never retry unknown outcomes simply because a process disappeared.

Use `recover-guest` only after independently verifying cleanup. Its `--cleanup-verified` flag and nonempty `--note` are an operator assertion, not a command that performs or proves cleanup. Do not clear a recovery gate with an invented note. See [Recovery contracts](11-contracts-and-acceptance.md#4-recovery-and-cleanup-are-outcomes).

`ctf-mcp-admin update-budget` can adjust an existing run's limits; it is not permission to exceed the operator's agreed budget. Consult the command's help and reauthorize any increase before applying it.

## Optional adapters and evaluation

| Surface | Boundary |
|---|---|
| `helper.transform` | Bounded deterministic transforms; opt-in registration with `--enable-transform-helper` or executable config |
| `session.control` | Bounded typed interactive operations; adapter registration, dynamic opt-in and matching scope are all required; not arbitrary shell/debugger commands |
| `net.probe` | Scoped HTTP adapter; requires an accepted enabled adapter, network execution class, enabled network policy and authorized targets in `scoped_ctf` / `vdp` |
| `vdp.test` | Bounded VDP product-test execution (`describe_profile`, `run_smoke`, `run_pytest`) against pinned source commit, scanner image digest, allowlisted selectors/overlays and `--network=none` on an operator WSL2/Linux Docker host; requires `vdp` profile, dynamic opt-in, `vdp.test` scope, and `ctf-vdp-product-test` / `--enable-vdp-product-test` |

Dynamic operations require `--allow-dynamic` / `CTF_MCP_ALLOW_DYNAMIC` or the corresponding executable config. A flag alone does not grant scope. The baseline `offline_ctf` executable config forbids dynamic execution and network access. Historical opt-in local session records are not permission to relax that baseline or probe live targets. Network target/method/expiry checks and external submission authorization remain separate.

### VDP product tests (`vdp.test`) and tool surface notes

- **Execution host premise**: `vdp.test` (`VdpProductTestAdapter`) runs on an operator WSL2 Ubuntu/Linux host where `ctf-mcp-server` has local Docker CLI access and pinned product scanner images (`docker image inspect`). Missing host prerequisites return `BLOCKED_ENV` (`verdict="environment_failure"`, verifier `INCONCLUSIVE`).
- **Profile registration & discovery**: Register or update pinned target profiles in `<vault_root>/_vdp/profiles.json` via `ctf-mcp-admin register-vdp-profile --profile-name ... --profile-revision ...` (rejects wildcards, flags and bare directories). Inside an open VDP run, `run.describe` (`"vdp_profiles"`) and `vdp.test(operation="describe_profile")` expose allowlisted selectors, overlay SHA-256 digests and limits without host filesystem paths (`host_dir`, `checkout_dir`).
- **Execution & verification**: Run `vdp.test(operation="run_smoke", ...)` -> `vdp.test(operation="run_pytest", ...)` -> `run.verify(verifier_id="vdp.product_test", evidence_ids=[...])`. `VdpProductTestVerifier` enforces `execution_provenance="harness_docker_isolated"` (rejecting external receipts and local HTTP 200 probes) and separates `smoke_passed`, `hypothesis_falsified`, `deviation_reproduced`, `baseline_failed`, `not_executed`, `skipped`, `timeout` and `environment_failure`. Containerized Django tests use synthetic data and Celery eager test settings (`async_behavior_unverified: true`).
- **Tool surface & static extraction default**: `artifact.inspect` is omitted by default because `StaticArtifactInspectorAdapter` binds under `analysis.query` and no default adapter binds to `artifact.inspect`. When `max_matches` is omitted on `analysis.query(operation="extract_strings")`, the worker applies a safe default cap (`--max-matches 40` + `--soft-byte-budget`) returning `status="ok"`, `truncated=True`, `recommended_max_matches`, and `next_offset` without triggering `output_limit_exceeded` (explicit large `max_matches` still enforces `partial` / `output_limit_exceeded`).

The runtime includes SQLite-owned run state, request idempotency, crash reconciliation/fencing, session leases, bounded artifact intake, paged/redacted evidence and export. These mechanisms and their acceptance limits are described in the [harness design](08-analysis-harness.md), [contracts](11-contracts-and-acceptance.md) and [dated records](README.md#acceptance-records), not a blanket security certification.

[Offline evaluation](09-evaluation.md) uses synthetic tasks and separates VDP precision/recall from CTF results. See the [P5 record](../records/p5-offline-evaluation-acceptance.md) for task splits, measured results, regressions and unmeasured external API costs. Ghidra, radare2, Workbench, CTFd and public tunnels mentioned in design documents are not all installed or enabled by package installation.
