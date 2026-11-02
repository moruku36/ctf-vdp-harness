# ctf-mcp

日本語版: [README.ja.md](README.ja.md)

This repository holds the overall design for letting ChatGPT (Daybreak-series models) safely use CTF-oriented MCP tools running in an isolated VM in the home lab.

## 1. Introduction

Moruku solves CTF challenges with ChatGPT's Daybreak-series models (security-specialized, used on the Windows side). This project is a design repository for building the set of MCP (Model Context Protocol) tools that this ChatGPT can call. This round is design only; no code is implemented.

The approach is to "gather existing OSS MCP servers, evaluate them, and limit in-house development to filling the gaps." As design material for the in-house gap-filling components, we carry over the master prompt (tool specifications and design principles) that was researched in advance with Gemini.

## 2. Overview

The MCP execution location is not Windows. Because security software on Windows reacts and prevents the tool set from running, execution happens in a QEMU/KVM security-analysis guest inside the home lab (Intel NUC).

The path is: "ChatGPT on Windows → (public HTTPS) → gateway on the NUC host → (isolated segment) → MCP servers inside the analysis guest → CTF targets." There is one major change of premise here: the current analysis guest has no virtual NIC and is completely separated from the network, so as-is it cannot be reached from ChatGPT. Designing the connectivity path is the core of this project (details in docs/04).

## 3. Components

- **Existing assets (first candidates)**: The OSS Vulnerability Workbench MCP (in-house) and REA 6.7.0 + Ghidra 12.1.4, already placed inside the guest. The Workbench's basic MCP communication has been verified; the REA → Ghidra analysis capability has not yet completed acceptance.
- **Additional OSS MCP servers**: GhidraMCP (version-matched to the installed Ghidra), the official radare2-mcp, the official Burp Suite MCP extension, and others, selected after confirming they exist (docs/03).
- **In-house gap-filler "ctf-mcp core"**: A FastMCP-based server that covers crypto / encoding helpers and shared foundations such as output truncation, which OSS does not cover (docs/02).
- **Gateway**: Placed on the NUC host, it single-handedly handles authentication, allowlists, and audit logging. It is the key to not giving the guest side any exposed surface.

## 4. Connectivity Path

ChatGPT's custom MCP connector is assumed to require a public HTTPS endpoint (Streamable HTTP) and OAuth authentication (this is marked "unverified" because confirmation in OpenAI's official documentation itself is not yet complete; the verification method is stated in docs/06).

The recommendation is to publish from the host via Cloudflare Tunnel, and to add exactly one vNIC, dedicated to the isolated segment, to the guest. This is premised on a firewall where inbound traffic is only via the host-side gateway, outbound traffic is permitted only toward CTF targets, and the home LAN side is unreachable. In addition, a fallback path is provided for using the tools from local clients on the Windows side (such as Codex) via Tailscale.

## 5. Intended Usage

During a competition, tools inside the analysis guest are called from the ChatGPT conversation to perform binary structure inspection, disassembly, cryptographic operations, HTTP inspection, and similar tasks. Tools are limited to "observation, analysis, and deterministic helpers"; as a rule, no arbitrary shell-command execution tool is provided. This is for safety, and also to avoid refusals by the model's guardrails.

Intake of materials (challenge files) continues to use the existing read-only ISO path. After a competition, the guest is rolled back to a snapshot, and network-emitting tools are kept disabled in normal times.

## 6. Caveats

- With the current guest (2 vCPU / 4 GiB / 20 GiB), keeping the Kali tool set + Ghidra + multiple MCP servers resident is expected to run short on resources. Expansion is a decision point (docs/06).
- Adding a vNIC is a change to the current isolation model (no virtual NIC). Because the conditional acceptance of Scope A is premised on "no NIC," whether to add one requires Moruku's decision.
- Output returned from CTF targets becomes input to the LLM as-is. The operating premise is that tool output is always treated as "data" and instructions contained in output are not followed.
- Whether AI and automation tools may be used differs by competition rules. The rules of each competition must be checked before participating.

## 7. Open Items

Points requiring Moruku's decision or confirmation are collected in docs/06. The main decisions were made on 2026-11-02: keep in-house development to a minimum; for the publication method, prioritize security (first check whether Secure MCP Tunnel is usable); the vNIC addition to the guest will be carried out; resource expansion will be done based on observed usage. What remains is the Burp MCP placement and the handling of REA (both on hold), and confirmation of the connector specification on the ChatGPT side.

## Document Structure

- [docs/01-requirements.md](docs/01-requirements.md) — Requirements, premises, and unverified items
- [docs/02-architecture.md](docs/02-architecture.md) — Overall architecture and the ctf-mcp core design
- [docs/03-mcp-selection.md](docs/03-mcp-selection.md) — MCP server selection table and rationale
- [docs/04-connectivity.md](docs/04-connectivity.md) — Connectivity path design (option comparison and recommendation)
- [docs/05-security.md](docs/05-security.md) — Security design
- [docs/06-roadmap.md](docs/06-roadmap.md) — Phase plan and decision points

## About Licensing and Secrets

This repository contains no secrets (tokens, keys, real network addresses, etc.). Credentials are kept in secret management on the host side, and the policy is to place only configuration examples (placeholders) in the repository.
