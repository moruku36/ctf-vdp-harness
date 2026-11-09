# 11 Action, Evidence and Recovery Contracts

[日本語](11-contracts-and-acceptance.ja.md) | [Home](../README.md)

Status: design only. This is the implementation handoff for P1–P3, not a deployed gateway or new permission for a target. It resolves details left open in [08](08-analysis-harness.md). Use docs/10 for implementation order; older infrastructure phases are historical.

## 1. Capability is more than a tool name

An accepted capability binds adapter commit, dependency lock, descriptor hash, operation enum, argument schema, execution class, required scope and measured limits. Execution classes are `static`, `dynamic`, `network` and `submission`; an operation may require more than one. Labels such as `read_only` are not sufficient: opening a debugger executes target code, and fetching an apparently read-only URL can have remote effects.

The public request has artifact/session/endpoint IDs and typed arguments, never a raw shell/debugger command. Resolve IDs against the current run; clients do not provide guest or host paths. Existing analyzer functionality is reused only after its actual descriptors and behavior pass acceptance. An upstream name or version table does not prove installed-version compatibility.

The first profile allows one accepted static observation, evidence paging, hypothesis updates and local verification. It excludes debugger launch, target connections and external submission. In later profiles, a connection needs both an accepted network capability and current destination/operation authorization.

## 2. Action admission and replay

Each action carries `run_id`, `action_id`, `request_id`, `expected_revision`, capability/adapter revision, canonical argument digest, scope revision and budget reservation. The gateway authenticates the principal, validates the current scope/expiry and resolves every input before reservation. The guest independently verifies the scoped request; it cannot expand the operation.

The deduplication key is `(principal, run_id, request_id)`. Same key and digest returns the existing action. Same key with changed arguments is a conflict. An intentional repeat uses a new request ID and an explicit `repeat_of`; a polling request does not create another action. Do not promise exactly-once side effects across a process crash or a remote target.

| State | Permitted next state | Transition owner |
|---|---|---|
| proposed | denied, reserved | Gateway policy/registry |
| reserved | running, cancelled, expired | Registry plus supervisor acknowledgement |
| running | completed, partial, timeout, cancelled, failed, reconciliation_required | Supervisor receipt verified by registry |
| reconciliation_required | running or a documented terminal state | Registry after process/artifact reconciliation |
| terminal | none | New attempt requires a new identity; original evidence is immutable |

Result-envelope status and lifecycle state are different: `completed` with a successful tool receipt maps to `ok`, and `failed` maps to `tool_error`. `denied` maps to `denied`; `expired` before launch maps to `denied` with an expiry reason. `reconciliation_required` has no successful terminal result. `partial`, `timeout` and `cancelled` remain explicit. An empty finding list cannot substitute for a failed analyzer.

Reserve maximum action time/output and an available worker slot atomically. A short remaining run budget lowers the executable action allowance before dispatch or rejects it. Charge retries and partial output; unknown usage retains its reservation. Model/client costs, when observable, are a separate accounting boundary from analyzer time.

## 3. Evidence must survive paging, redaction and rollback

The evidence service owns a manifest of run/principal, source artifact hashes, adapter/version, sanitized argument digest, capture time, byte length, media type, completeness, raw/derived role and parent evidence IDs. SHA-256 covers the exact stored bytes. A summary or redacted copy is a new derived object with its own hash; never attach the original hash to altered text.

The [evidence-page schema](../schemas/evidence-page.schema.json) makes the page shape explicit. Cursors bind run, principal, evidence hash, view/redaction revision and next offset. They are opaque authenticated server tokens or server-held references, not client-editable file offsets and not access credentials. Access is checked on every page, including after revocation.

`offset_bytes` and `next_offset_bytes` address the selected stored view, not the original when redacted. Text pages end at UTF-8 boundaries; use base64 for binary data. Cap both response characters and decoded bytes. Repeated cursors return the same page for the same immutable object. Invalid/out-of-range/tampered cursors produce explicit errors, not a successful empty page. End of the captured object has `next_cursor=null`; `capture_complete=false` still means the original output was cut off, even if pagination reached EOF.

Streaming capture is bounded before buffering: per-stream, per-action and per-run quotas; archive depth, entry count, decompressed bytes and expansion ratio. Once the quota is reached, stop capture/producer under the accepted policy, preserve a partial object and record the exact reason. Do not retain unbounded output and truncate only the AI-facing string.

The importer accepts opaque object IDs, checks size/type/hash and uses a dedicated unprivileged host identity. No general shared folder, archive extraction path or arbitrary host destination. Workspace confinement must use race-resistant file handling; prefix checks or resolve-then-open alone do not establish protection against symlink replacement. Static parsing remains inside the disposable guest.

## 4. Recovery and cleanup are outcomes

Persist intent/reservation before launching; supervisor acknowledgement includes host/supervisor instance, process-start identity and a monotonically increasing fencing token. Heartbeat loss is not process death. A replacement worker cannot accept late writes from the old token. On restart, reconcile every nonterminal action before admitting overlapping work.

Cancel/timeout must stop descendants, verify their termination, settle known usage, preserve allowed partial evidence and revoke the action's temporary access. If cleanup cannot be confirmed, mark `cleanup_unconfirmed`, retain conservative reservations and prevent new actions in that guest. Do not describe a best-effort kill request as successful cleanup.

Close the investigation by freezing allowed evidence/report references first, verifying the host import, then restoring the guest. A successful VM rollback does not prove evidence export succeeded; failed export remains visible. Persistent logical state survives in the registry, while debugger memory and open connections are marked lost after restart.

## 5. Network scope at the connection boundary

Later network profiles validate scheme, normalized host, resolved addresses, port, path/method and exclusions. Resolve and connect through the enforcing proxy/adapter; checking one DNS answer then allowing the tool to resolve again leaves a rebinding gap. Validate every redirect and newly opened connection, including alternate IPv4/IPv6 representations. A userinfo URL, redirect or proxy must not turn an allowed target into a management endpoint. Apply a reviewed normalization policy rather than ambiguous string-prefix matching.

Scope expiry/revocation stops new requests and terminates active sessions according to the current policy, not merely at the next prompt. Platform download, target access and submission are separately authorized operations. No actual network probe is part of this design change.

## 6. Integration with the other harnesses

The [three-harness contract](https://github.com/moruku36/ai-agent-scientist/blob/main/docs/11-harness-boundaries.md) is an optional reference-only request/receipt boundary. Scientist may fund an investigation, but CTF retains its own scope checks. Pin the accepted external schema commit/hash locally before implementation; do not fetch mutable remote schemas at runtime.

Only reviewed, permitted development lessons can be exported toward Sleep. Raw flags, private target evidence, final task answers and program secrets cannot become reusable memory. No integration grants another component direct writes into the private evidence vault, scope database or guest control plane.

## 7. Required fixtures for the implementing AI

All are **planned, not executed**. These acceptance requirements are not evidence of improved solve rates.

| ID | Stimulus | Required result |
|---|---|---|
| CTF-01 | Missing/expired scope or direct call of hidden tool | Denied before launch or reservation consumption |
| CTF-02 | Duplicate request; then same ID with changed args | First replay returns prior action; second conflicts |
| CTF-03 | Long UTF-8/binary output plus paged reads | Reassembly matches captured hash; exact EOF and completeness |
| CTF-04 | Redaction changes; cursor from another run/principal | Old view cannot bypass current access; cross-run read denied |
| CTF-05 | Output flood, archive bomb, symlink/path race | Bounded capture/intake; explicit failure; no host-path escape |
| CTF-06 | Crash at reserve/launch/result boundaries | Reconciliation; no untracked duplicate action |
| CTF-07 | Timeout/cancel with child process and no heartbeat | Descendants checked; unconfirmed cleanup blocks reuse |
| CTF-08 | Supervisor restart and old worker completion | Stale fencing token rejected; debugger session marked lost |
| CTF-09 | Local redirect/DNS-change/IPv6 scope fixture | Rechecked actual connection denied outside scope |
| CTF-10 | Host import fails immediately before VM rollback | No successful export claim; recovery protects remaining evidence |
| CTF-11 | Analyzer error with empty result | `tool_error`, never “no vulnerabilities” |
| CTF-12 | Synthetic output requests permissions or reveals marker | No authority change; private marker excluded from audit/export |

Each implementation PR reports code/schema/dependency revisions, actual fixture outcomes, resource peaks, reproduction steps, known limits and migration/rollback. Preserve J1–J3; defer J4/J5. First deliver P1–P3 on local controlled fixtures, then evaluate whether interactive state earns its cost.
