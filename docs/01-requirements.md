# 01 Requirements, Premises, and Unverified Items

日本語版: [01-requirements.ja.md](01-requirements.ja.md)

## 1. Purpose

Build, in an isolated environment in the home lab, a set of MCP tools that ChatGPT (Daybreak-series models) can call during CTF competitions. This document defines the requirements and premises. The scope covers design only; implementation is work for later phases.

## 2. Functional Requirements

| # | Requirement |
|---|---|
| F1 | MCP tools can be called from ChatGPT (used on the Windows side) |
| F2 | Binary analysis is possible (structure inspection, function listing, disassembly/decompilation, string extraction, ROP gadget search) |
| F3 | Source code static analysis (semgrep, etc.) and HTTP endpoint inspection are possible |
| F4 | Cryptographic and encoding operations are possible (various conversions, hash identification, single-byte XOR brute force, etc.) |
| F5 | Forensics assistance is possible (metadata extraction, embedded file detection) |
| F6 | Communication with CTF targets (connection endpoints provided by the organizer) is possible from inside the guest |
| F7 | The same tool set can also be used from local clients on the Windows side (Codex, etc.) (fallback path) |
| F8 | Materials such as challenge files can be brought into the guest via the existing read-only ISO path |

## 3. Non-Functional Requirements (Design Principles)

These carry over the design principles of the Gemini advance-research material (master prompt).

| # | Principle | Reason |
|---|---|---|
| N1 | As a rule, do not implement or adopt an arbitrary shell-command execution tool (such as `exec_shell`) | It easily triggers refusals by the model's guardrails, and is also less safe |
| N2 | Define all tools at a fine granularity as "observation, static analysis, and deterministic helpers," with explicit input/output schemas | Improves analysis accuracy and prevents tool misuse |
| N3 | Provide output truncation on all tools (`max_lines` / `max_chars`, default around 4,000 characters) and return structured responses (JSON) | Protects the context window |
| N4 | For tools that accept file paths, forcibly verify that the path is under the workspace, and block path traversal | Limits the access scope within the guest |
| N5 | Execute subprocesses in a `shell=False`-equivalent manner, and set a timeout on all commands (default 60 seconds, configurable) | Prevents command injection and runaway execution |
| N6 | Require authentication (Bearer / OAuth) on HTTP-based transports | Defense premised on a public path |
| N7 | Tools can be enabled/disabled per category. Network-emitting tools are enabled only during competitions | Reduces the attack surface in normal times |

## 4. Premises (Confirmed Facts)

The current home lab configuration is based on the documents in the home-ai-engineering-lab repository (README, `docs/security-analysis-vm.md`, updated 2026-10-20).

- The host is an Intel NUC (Ubuntu Server) running a set of Docker Compose services and an independent QEMU/KVM security-analysis guest.
- The analysis guest's current specifications are 2 vCPU / 4 GiB RAM / 20 GiB qcow2.
- The guest has no virtual NIC and is completely separated from the network. Access is only via the host's serial console (UNIX socket) and loopback-only VNC.
- Material intake is via read-only ISO (mounted in the guest with `noexec,nosuid,nodev`).
- Inside the guest, the OSS Vulnerability Workbench MCP (in-house, moruku36/oss-vulnerability-workbench-mcp) and REA 6.7.0 + Ghidra 12.1.4 have been placed offline.
- The Workbench's basic MCP communication (tool listing, etc.) has been verified. However, actually running real scanners or diagnosing real targets is unverified.
- The REA → Ghidra analysis capability has not completed acceptance (Scope B not accepted). Scope A (foundation and basic operations) has been conditionally accepted, but its premise is the "no virtual NIC" configuration.
- The host can be accessed via Tailscale. An existing mcp-server (for read-only reports) also runs on the host.
- On Windows, security software reacts and security tool sets effectively cannot run (a placement constraint based on Moruku's actual experience).

## 5. Constraints

- The MCP execution location is limited to the home lab side, not Windows.
- The guest's isolation is maintained. Even when adding paths, no reachability path toward the home LAN side is created.
- Secrets (tokens, keys, real network addresses, etc.) are not written in the repository or design documents.
- Adopted OSS is limited to items whose existence and license have been confirmed (docs/03).

## 6. Unverified Items

The following could not be confirmed as of this design and are not asserted. Verification methods are given in docs/06.

| # | Unverified item | Impact |
|---|---|---|
| U1 | The exact specification of ChatGPT's custom MCP connector (whether public HTTPS + Streamable HTTP + OAuth is mandatory). Secondary information is broadly consistent, but direct confirmation in OpenAI's official documentation is not yet complete | Finalizing the publication path method |
| U2 | Whether connectors can be added under Moruku's plan (Daybreak series), and whether write-type (action) tools are permitted. Secondary information contains both claims: "Plus/Pro are read-only only" and "writing is possible in developer mode" | Design of the tool exposure scope |
| U3 | Whether OpenAI's Secure MCP Tunnel can be used in Moruku's environment | Whether the alternative publication method works |
| U4 | Whether a container platform such as Docker is already installed in the current guest | How ctf-mcp core is placed |
| U5 | The host (NUC)'s total resources and free capacity (the ceiling for guest expansion) | Scale of the expansion proposal |
| U6 | Details of REA's transport type, license, etc. | How it is incorporated into the connectivity design |
| U7 | Whether AI and automation tools may be used under each CTF competition's rules | Operational feasibility (checked per competition) |
