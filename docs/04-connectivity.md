# 04 Connectivity Path Design

日本語版: [04-connectivity.ja.md](04-connectivity.ja.md)

## 1. The Core Problem

The current analysis guest has no virtual NIC. The only access paths are the host's serial console and loopback-only VNC, and it cannot be reached over the network from either ChatGPT or Windows.

Meanwhile, ChatGPT connects from OpenAI's cloud side. Within the range of secondary information, the custom MCP connector is said to require a "public HTTPS endpoint (Streamable HTTP, or SSE) + OAuth authentication," and a local stdio server cannot be registered directly (direct confirmation in OpenAI's official documentation is not yet complete = unverified. The verification method is in docs/06).

In other words, this design must squarely address the following two changes.

1. Newly establishing a network reachability path to the guest (or a host-side termination point acting on its behalf).
2. Controlling that path in a way that does not expose the home LAN and does not break the intent of isolation.

## 2. Comparison of Options

| Option | Path | Reachable from ChatGPT | Isolation preserved | Implementation cost | Notes |
|---|---|---|---|---|---|
| A. Public HTTPS (Tunnel) + isolated-segment vNIC | ChatGPT → Cloudflare Tunnel → host GW → isolated segment → guest | Yes (assumed to satisfy the connector specification) | Premised on adding a vNIC. Preservable depending on FW design | Medium | **Recommended (main line)**. The Tunnel is established by outbound connections from the host, so no public ports are opened on the host |
| B. No vNIC + host proxy (vsock relay) | ChatGPT → Tunnel → host GW → virtio-vsock → in-guest server | Yes (the public termination is the same as A) | Most faithful (the guest is given no IP network) | High | The in-guest server side needs vsock support or a relay (socat, etc.). Relaying stdio-type servers works well, but aggregating HTTP-type and multiple servers requires ingenuity on the gateway side |
| C. stdio via SSH tunnel | Local client → SSH → stdio server started inside the guest | No (because ChatGPT is on the cloud side) | Can be established via the host management path even without a vNIC | Low | The method the Gemini material assumed. Effective as a development/verification path dedicated to local clients on Windows (Codex, etc.) |
| D. Via Tailscale | Local client → tailnet → NUC host GW → guest | No (the OpenAI cloud does not participate in the tailnet) | The host already participates in Tailscale, so new setup cost is small | Low | The main choice for the fallback path. Not a substitute for ChatGPT |
| E. OpenAI Secure MCP Tunnel | ChatGPT → OpenAI's tunnel mechanism → local side | Unverified | May avoid having a public endpoint | Unverified | Secondary information exists that this is an official private connectivity method. Whether it can be used in Moruku's Daybreak environment is unverified, so it is not relied on until confirmed |

## 3. Recommended Option

**The main line is A, with C and D used together for verification and fallback.** B is kept as the alternative if the decision becomes "absolutely do not add a vNIC." If E is confirmed usable, it could replace the public part of A.

The reason for staged introduction is that the public path (A) only becomes safe once authentication, allowlists, and the firewall are all in place. First, verify connectivity and behavior of the tool set from local clients via C and D, and open A only after the controls are solidified (docs/06).

## 4. Details of the Recommended Option (A)

### 4.1 Guest-Side Network Addition

- Add exactly one vNIC to the guest and connect it to a host bridge dedicated to the isolated segment. This bridge is separated from the home LAN segment and is given no routing.
- As a rule, the only party the guest can communicate with is the gateway on the host. Communication toward CTF targets is basically relayed and controlled on the gateway side (or by the host's FW), and the guest is not given direct reachability to the Internet by default.

### 4.2 Firewall Policy (default: deny all)

| Direction | Source → Destination | Policy |
|---|---|---|
| inbound | Gateway → guest's MCP ports | Allow (only this path) |
| inbound | Everything else → guest | Deny |
| lateral | Guest → home LAN segment | **Deny all** (create no reachability path) |
| lateral | Guest → host's management plane (SSH, console, etc.) | Deny |
| outbound | Guest / relay → CTF targets (organizer-provided endpoints) | Allow only during competitions. Log destinations and times |
| outbound | Guest → general Internet | Deny by default. If needed for tool acquisition, etc., operate with temporary allowance limited to maintenance windows outside competitions |

- DNS is also subject to control, closing paths by which the guest communicates externally via arbitrary name resolution (resolution is relayed on the host side, or allowed only during competitions).
- Concrete values such as addresses are decided in the design/implementation phase and are not written in this document.

### 4.3 Public Side (Host → ChatGPT)

- Cloudflare Tunnel (cloudflared) runs on the NUC host and relays from the public HTTPS endpoint to the host's gateway over an outbound connection. No inbound public ports are opened on the router or the host.
- Authentication is two-layered. In addition to access control on the Tunnel side (Cloudflare Access, etc.), the gateway verifies MCP authentication (OAuth 2.1, or Bearer tokens). Because the authentication method required by the ChatGPT-side connector is unverified, finalization comes after specification confirmation (docs/06).
- Only the gateway's MCP endpoint is published; the management console and other host services are not published over the same path.

## 5. Fallback Paths (C and D)

- From local clients on Windows (Codex, etc.), a path connecting to the host's gateway via Tailscale is provided. Because the host already participates in Tailscale, no additional publication is needed.
- stdio-type MCP servers (radare2-mcp, the GhidraMCP bridge, etc.) can also be used via the method of relaying stdio over an SSH tunnel (C). This path is the simplest during development and debugging.
- On the fallback paths as well, authentication and allowlists are enforced identically on the gateway/server side. Controls are not weakened depending on the path.

## 6. Reaching CTF Targets

In many CTFs, it is necessary to actively connect to instances provided by the organizer (endpoint host and port). Outbound is therefore essential, but it is not made unlimited egress.

- "Competition mode," which Moruku enables at the start of a competition and disables at the end, is the unit of operation.
- Destinations are recorded in the audit log so they can be reviewed after the competition.
- Access to organizer sites, such as downloading challenge files, is placed under the same controls.

## 7. Material Intake Path (unchanged)

Intake of challenge files and similar materials maintains the existing read-only ISO path. Even after a network path exists, intake of analysis targets is not shifted to the network. This preserves the current operating principle that "analysis targets are always brought in offline."
