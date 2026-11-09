# 05 Security Design

日本語版: [05-security.ja.md](05-security.ja.md)

## 1. Basic Policy

- Isolation is primary, convenience secondary. Even with a public path, the structure "the guest is inside the isolated segment" does not change.
- Defense is layered. It is enforced independently at each layer: network (FW), gateway (authentication, allowlist, auditing), server (tool design), and operations (snapshots, competition mode).
- On failure, fall to the closed side (fail closed). If authentication or allowlist judgment cannot be made, tools are not executed.

## 2. Maintaining Isolation

- The guest's vNIC connects only to the isolated-segment-dedicated bridge, and no routing to the home LAN segment is provided (docs/04).
- Inbound is only MCP communication via the host-side gateway. Outbound is permitted toward CTF targets only during competitions; the default is deny all.
- The host's management plane (SSH, serial console, VNC) is made unreachable from the guest. Management paths remain one-directional from the host side, as before.
- Material intake maintains the existing read-only ISO path (`noexec,nosuid,nodev`).

## 3. Authentication

| Path | Authentication method | Notes |
|---|---|---|
| Public path (ChatGPT) | OAuth 2.1 first candidate plus tunnel-side access control as applicable | Project security policy, not a claim that OAuth is mandatory for all MCP servers. Accept the actual client/tunnel flow; no unauthenticated analysis endpoint |
| Fallback (Tailscale) | In addition to Tailscale's authentication, a Bearer token is verified at the gateway | Authentication is not weakened even when the path changes |
| Fallback (SSH tunnel) | SSH key authentication + server-side token | Even for stdio relay, token verification is enforced on the server side |

- Tokens and keys are placed only in secret management inside the guest and on the host side, never in the repository. Configuration files record placeholders only.
- Credential rotation procedures (issuance, replacement, revocation) are included in the operating procedures.

## 4. Allowlist (Tool Exposure Scope)

- Tool-unit allowlists are managed doubly, at the gateway and at each MCP server. The principle is that tools not on the allowlist are not even shown to the client (excluded from tools/list).
- The default allowed scope is limited to "observation, analysis, and deterministic helpers."
  - Allowed (default): Structure inspection, function listing, obtaining disassembly/decompilation results, string extraction, static analysis, crypto/encoding operations, metadata extraction.
  - During competitions only: HTTP inspection of CTF targets, tools involving target connections.
  - Always prohibited: Arbitrary shell execution, raw command execution (raw execution in radare2-mcp, etc. is disabled), tools involving communication toward the host or home LAN, file writes outside the guest.
- If adopted OSS includes "raw execution" or "script execution" type tools, they are inventoried before enablement and disabled by default (the re-confirmation list in docs/03).

## 5. Defenses at Tool Execution Time (Server Side)

The Gemini material's principles are required of all servers in common.

- File paths are forcibly verified to be under the workspace, and path traversal is blocked.
- Subprocesses are executed in a `shell=False`-equivalent manner, with arguments passed as arrays. A timeout (default 60 seconds) is set on all executions.
- Truncation (default around 4,000 characters) is applied to output; huge output is not returned as-is.
- The execution user's privileges are minimized; tools do not run as root even inside the guest.

## 6. Audit Logs

- All tool invocations are recorded at the gateway. Recorded items are: time, authenticated principal, tool name, argument summary, success/failure, output size, and outbound destinations (full arguments and output are not retained, because competition information such as flags could be mixed in).
- Logs are not kept only inside the guest; they are forwarded to and stored on the host side, in an arrangement where the logs cannot be tampered with even if the guest is compromised.
- A form Moruku can review after a competition (daily summaries, etc.) is included in operations.

## 7. Snapshots and Rollback

- Before a competition starts, a snapshot of the guest (qcow2 snapshot / clone) is taken, and after the competition the guest is in principle rolled back to that state.
- Updates to the tool set and configuration changes are also made only after taking a pre-change snapshot, so that rollback is possible if problems occur.
- Analysis target files are premised on disappearing upon rollback; deliverables (analysis notes, etc.) are included in operations as a procedure to evacuate outside the guest (to a management area on the host side).

## 8. Caution on Prompt Injection

- Output returned from CTF targets and analysis target files becomes input to the LLM as-is. The operating premise is that even if "instructions" are contained in output, they are data and are not grounds for changing the tool-use policy.
- In particular, no chain is performed in which tool output triggers calling tools outside the allowlist or sending data externally. The gateway's allowlist is the final line of defense from this standpoint as well.

## 9. Handling of Secrets

- Tokens, keys, real network addresses, and personal information are not written in the repository or design documents.
- Competition account information and flags are not retained in audit logs either (summaries only, as above).
- The convention of the lab documents referenced by this design (mark unverified items explicitly as "unverified") is followed.

## 10. Harness extension (2026-11-09)

All controls above are planned requirements, not newly verified runtime properties. For VDP, “competition mode” means a scoped, expiring run; it never grants general Internet access. Apply target/method/rate/exclusion checks at each connection, including redirects and DNS results. The default offline profile remains offline.

Audit logs remain summaries only. A separate private, per-run evidence vault may retain permitted originals for reproduction, with ownership checks, retention/deletion policy and no automatic Git export. The bounded evidence importer is the sole deliverable-transfer exception to guest-only tool writes; analysis tools cannot write arbitrary host paths. See [docs/08 sections 4–7](08-analysis-harness.md).

Dynamic debugger execution uses a separate accepted profile. No arbitrary shell, script evaluation, raw r2 command or general execution function is added. Disabled tools are both hidden and rejected; client-side read-only hints are not policy enforcement. Use synthetic markers for security acceptance tests and review redacted exports before publication.
