# 06 Phase Plan and Decision Points

日本語版: [06-roadmap.ja.md](06-roadmap.ja.md)

## 1. Phase Plan

Publication is done last. First verify over local paths, and open the public path only after the controls (authentication, allowlist, FW) are solidified.

| Phase | Content | Completion criteria |
|---|---|---|
| Phase 0: Decisions and confirmations | Confirm the actual client route and only the decisions needed by the current slice | J1–J3 preferences recorded; J4/J5 may remain deferred for an offline slice |
| Phase 1: Offline baseline and intake | Use the existing console/read-only ISO path for one controlled observation. Do not assume SSH into the no-vNIC guest. | Scope, artifact and evidence fixtures; actual client route follows accepted isolated networking |
| Phase 2: Implementation of ctf-mcp core | Implement the in-house gap-fillers (crypto / encoding, lightweight observation tools, shared foundation). Bring them into the guest offline, according to the placement method (whether a container platform exists, U4) | Core's tools can be called over the Phase 1 paths, and truncation, path validation, and timeouts are effective |
| Phase 3: Isolated network construction | Implement the approved single isolated vNIC, bridge, gateway and firewall; update lab acceptance records. vsock B is not selected | Isolation and gateway policies are verified in a controlled fixture network |
| Phase 4: Public path and ChatGPT connection | Secure MCP Tunnel first; authenticated HTTPS fallback if unavailable. Accept the actual ChatGPT/Codex route | Only accepted tools and run evidence are reachable; auth/deny/reconnect cases pass |
| Phase 5: Operations | Make competition mode (pre-start snapshot, egress enablement, post-end rollback and disablement), audit log review, and tool/allowlist review part of regular operations | One full competition can be run through with these procedures |

Resource expansion (J3): after seeing the Phase 1 verification results (measured shortfalls against the current specifications), the scale is finalized and it is carried out by Phase 3.

## 2. Decision Register (original options; status follows below)

| # | Decision item | Options / issues | Affected phase |
|---|---|---|---|
| J1 | Publication path method | Cloudflare Tunnel (publishing HTTPS outbound from the host) or OpenAI Secure MCP Tunnel (if confirmed usable). The Tunnel method requires a Cloudflare account and possibly a custom domain | Phase 4 |
| J2 | Whether the guest may get a vNIC | The current isolation model was premised on "no virtual NIC" for Scope A acceptance. Add exactly one, limited to the isolated segment, or lean toward option B, the vsock relay with no vNIC? If adding, also decide how the acceptance records (lab documents) side is handled | Phase 3 |
| J3 | Whether to expand resources, and the scale | The current 2 vCPU / 4 GiB / 20 GiB is expected to be insufficient. The draft proposal is 4 vCPU / 8–16 GiB / 60–100 GiB. Because the host (NUC)'s total resources and other services' usage are unverified, confirming the ceiling comes first | Phase 1–3 |
| J4 | Burp MCP placement | Keep Burp Suite resident inside the guest, place it on the Windows side, or pass on adoption itself? The Windows-side placement needs to be reconciled with the policy "the MCP execution location is not placed on Windows" (Burp is an interactive analysis tool and differs in nature from the tool sets blocked by security software) | Phase 1–2 |
| J5 | Handling of REA | The REA → Ghidra analysis capability has not completed acceptance (Scope B). Use it ahead for CTF purposes, or complete acceptance first and then incorporate it? | Phase 1 |

### Decision Record (2026-11-02, Moruku)

- **Basic policy**: Keep in-house development to a minimum (finalized). The main line is a combination of OSS.
- **J1 Publication method**: Prioritize the more secure option (decided). First confirm whether OpenAI Secure MCP Tunnel is usable (C3); if usable, adopt it. If not usable, use Cloudflare Tunnel + Access + MCP authentication.
- **J2 vNIC addition**: **Add it (decided)**. This decision was made after confirming that a vNIC can be added by logical configuration only and requires no physical equipment. With this, the connectivity path is finalized with option A (docs/04) as the main line, and the vsock relay option (B) is not adopted. Reconciling and updating the lab-side acceptance records (Scope A is premised on "no NIC") is included in the implementation phase's work.
- **J3 Resource expansion**: Proceed in the direction of expanding (decided). Check the current VM and host usage (C5) and carve out free capacity for the KVM guest side. Rebuilding the guest is also among the options. The concrete scale is finalized after measurement.
- **J4 Burp placement / J5 Handling of REA**: On hold (Moruku still considering). To be decided again later.

## 3. Items Requiring Confirmation, and How

| # | Item to confirm | Confirmation method |
|---|---|---|
| C1 | General MCP product support checked 2026-11-09; exact integration still pending | Official sources in docs/08; exercise the chosen transport and authentication with the actual client |
| C2 | Actual account/workspace availability of custom MCP tools | Check the current account flow and restrictions. Official general read/write support does not prove this account's entitlement; Daybreak is not a plan identifier |
| C3 | Whether OpenAI Secure MCP Tunnel can be used in Moruku's environment | Check the official documentation and whether a tunnel option exists in the actual settings screen |
| C4 | Whether the current guest has a container platform (Docker, etc.) | Check inside the guest via the host's serial console (possible with the existing management path) |
| C5 | The host (NUC)'s total resources and current usage | Check on the host (within the scope of existing operational information) |
| C6 | Whether AI / automation tools may be used under the rules of the CTF competition being entered | Check the official rules for each competition. This confirmation is needed for every competition and cannot be substituted by design |

## 4. Risks and Reservations

- Depending on the results for the ChatGPT-side specifications (C1, C2), the public path design may change. In particular, if it turns out that "write-type tools are not allowed," the tool exposure scope needs redesign toward read-only and analysis types (even in that case, the Phase 1–3 assets remain useful on the fallback paths).
- The vNIC addition must be reconciled with the lab-side acceptance records (Scope A premises). Updating the records on the home-ai-engineering-lab side, not only the design documents, is included in the work.
- The state of the OSS candidates (licenses, updates, tool contents) is premised on re-confirmation at introduction time (docs/03).

## 5. Research-based harness plan (2026-11-09)

The logical implementation sequence is now [P0–P8 in docs/10](10-implementation-plan.md): baseline → offline contracts/evidence → one analyzer → state/recovery → selective sessions → matched evaluation → client route → scoped network/VDP → optional expansion. This refines the earlier infrastructure phases; their dependencies still apply. No phase is marked executed by this update.

J1/J2/J3 decisions above are preserved verbatim and need no renewed blanket confirmation. J4/J5 remain on hold and are not blockers for the initial offline vertical slice. The old Cloudflare-first ordering is superseded by the recorded Secure MCP Tunnel preference. No unconditional public endpoint is required. General official product support is now sourced; account-specific availability, resources, actual vNIC installation and tool acceptance remain unverified.

Performance acceptance is defined in [docs/09](09-evaluation.md), rather than inferred from the number of installed tools. VDP target rules and reproducibility are separate from CTF exact-answer verification. This remains a design-only change.
