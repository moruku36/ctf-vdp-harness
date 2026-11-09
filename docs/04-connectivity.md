# 04 Connectivity Design

[日本語](04-connectivity.ja.md) | [Home](../README.md)

Updated 2026-11-09. This is a planned route, not evidence of installation. The historical guest has no vNIC and is reachable only through the host serial console and loopback VNC.

## 1. Current decision and product evidence

The 2026-11-02 record is authoritative: **add exactly one isolated-segment vNIC (J2)**; prioritize Secure MCP Tunnel when usable (J1); measure before deciding expansion scale (J3). The vsock alternative is not the selected implementation. Reconcile the lab's earlier no-NIC acceptance record before commissioning the changed isolation model.

Official [ChatGPT custom MCP documentation](https://developers.openai.com/api/docs/guides/custom-mcp-server) describes read/write tools, streaming HTTP/SSE, authentication choices and a Secure MCP Tunnel option. Thus a public URL and mandatory OAuth for every server are not universal product requirements. This project's analysis gateway nevertheless requires authenticated access. Actual account/workspace availability and end-to-end acceptance remain unverified.

The [official Codex MCP guide](https://learn.chatgpt.com/docs/extend/mcp?surface=cli) describes stdio and Streamable HTTP. Local configuration is not automatically a ChatGPT web plugin connection. Test the actual client rather than treating all ChatGPT/Codex surfaces as interchangeable.

## 2. Routes

| Route | Purpose / disposition |
|---|---|
| E: Secure MCP Tunnel → host gateway → isolated guest segment | First connection candidate, subject to actual account, authentication and runtime acceptance. Does not grant broader tools or egress. |
| A: Authenticated HTTPS tunnel → host gateway → isolated guest segment | Fallback if E is unavailable. Existing Cloudflare Tunnel + Access + MCP authentication proposal retained. Compatibility of layered authentication must be tested by the actual MCP client. |
| D: Local client → Tailscale → host gateway → isolated guest segment | Local development/fallback after the host-to-guest route is commissioned. Tailnet membership is not granted to a cloud client by implication. |
| C: Local stdio relay via authenticated host management path | Optional development route. No ordinary SSH-to-guest path exists in the recorded no-vNIC state. Use an accepted relay/console workflow, or the approved isolated segment; do not claim this already works. |
| B: Host proxy / virtio-vsock without vNIC | Historical alternative only; not selected under J2. |

First accept the smallest offline analysis path. Remote reachability is a separate milestone; a local tools/list result is not proof that ChatGPT can use the analyzers.

## 3. Isolated segment

Add one guest vNIC on a dedicated host bridge separated from the home LAN. The host gateway reaches only accepted guest MCP ports. The guest has no general Internet route or access to host management services. Target traffic is relayed/controlled by the gateway or host firewall, with explicit per-run policy.

| Direction | Policy |
|---|---|
| Gateway → accepted guest MCP ports | Allow only the selected service identity/path |
| Other inbound → guest | Deny |
| Guest → home LAN, host management, metadata services | Deny; no management reachability through target aliases |
| Guest/relay → authorized CTF/VDP target | Default deny; scoped profile only, within destination/time/rate budgets |
| Guest → arbitrary Internet / arbitrary DNS | Deny |
| Maintenance acquisition | Separate controlled maintenance procedure outside task runs; no implicit target permission |

Firewall and application checks are independent. Validate resolved addresses and every redirect/new connection; proxy/browser/adapter bypass paths must obey the same scope. Record sanitized destinations/times. Concrete addresses and credentials belong outside the repository.

## 4. External connection boundary

The host, not the guest, terminates the client-facing route. Keep the existing read-only report MCP service, management console and other services outside this endpoint. A tunnel must not become a general port forward.

For the HTTPS fallback, keep host-originated tunnel establishment and no newly opened public inbound router/host ports. The previous OAuth-first gateway policy remains; a bare unauthenticated server is not a fallback. Validate token audience/expiry, principal-to-run binding, authentication failures, catalog filtering, evidence access and reconnect. Do not confuse Cloudflare browser login with usable MCP authentication.

For Secure MCP Tunnel, accept actual client binding and authenticated identity, not simply process startup. Adopt only when it provides the required access controls in this environment. Do not weaken server-side scope enforcement on any local/tunnel path.

## 5. Materials, target access and rollback

Keep the existing read-only ISO intake with `noexec,nosuid,nodev`. Optional CTFd download is a later acquisition/staging capability: content must still pass intake validation and the offline transfer process; it does not directly mount network downloads into the analysis workspace.

Competition mode becomes a scoped run profile for authorized CTF or VDP work. An authorized target definition, expiry and operation budget replace an unrestricted “network on” switch. Before a run: snapshot, scope and tool checks. After: stop sessions, revoke temporary egress, preserve permitted evidence through the bounded importer and restore the guest. Network permission does not authorize external flag or vulnerability-report submission.

[Security](05-security.md) | [Logical harness](08-analysis-harness.md) | [Implementation plan](10-implementation-plan.md)
