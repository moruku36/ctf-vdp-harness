# 03 MCP Server Selection

日本語版: [03-mcp-selection.ja.md](03-mcp-selection.ja.md)


**2026-11-09 adoption boundary:** The historical table below is not a fresh compatibility or source-code audit. [Research mapping](07-research-to-design.md) distinguishes design inspiration from dependencies. Pin licenses/revisions/transports and accept real fixtures before enabling adapters. HexStrike's exclusion remains; REA and Burp decisions remain pending. Start with a small category-specific catalog.

## 1. Selection Policy

- Existing assets (the Workbench MCP and REA already placed in the guest) are positioned first.
- Additional candidates are included only if their existence on GitHub and corroboration from primary/secondary sources have been obtained. Items that could not be confirmed are explicitly marked "Unverified."
- Servers whose core is "arbitrary shell execution," contrary to this design's principles (docs/01 N1), are excluded from adoption candidates and noted only for contrast.
- The "last updated" estimates are based on secondary information as of the confirmation date (2026-11-02) and are re-checked at introduction time.

## 2. Selection Table

### 2.1 Existing Assets

| Name | URL | License | Last-updated estimate | Transport | Tool granularity | Arbitrary shell execution | Main categories | Positioning |
|---|---|---|---|---|---|---|---|---|
| OSS Vulnerability Workbench MCP | https://github.com/moruku36/oss-vulnerability-workbench-mcp | In-house (Moruku's own repository) | Placed in guest | Unverified (basic communication verified inside the guest) | Listing of 16 tools confirmed (lab records). Running real scanners is unverified | None (analysis-type tool set) | Code audit, dependencies | Continue using as the foundation |
| REA (Reverse Engineer Anything) 6.7.0 | https://github.com/morluto/rea | Unverified | Placed in guest (fixed manifest of offline materials confirmed) | Unverified | Analysis support integrated with Ghidra | Unverified | rev | Use as an existing asset. However, the REA → Ghidra analysis capability has not completed acceptance (Scope B) |

### 2.2 Additional Candidates (under consideration for adoption)

| Name | URL | License | Last-updated estimate | Transport | Tool granularity | Arbitrary shell execution | Main categories | Positioning |
|---|---|---|---|---|---|---|---|---|
| GhidraMCP (LaurieWired) | https://github.com/LaurieWired/GhidraMCP | Apache-2.0 | Active (secondary information confirming updates as of 2026-10) | Choice of stdio bridge / Streamable HTTP. The Ghidra extension side uses loopback HTTP | Fine-grained analysis tools such as function listing, decompilation, xrefs, renaming | None (centered on Ghidra operations. Whether script-execution-type tools exist is to be checked at introduction) | rev | **First candidate**; installed Ghidra 12.1.4 compatibility remains to be accepted at a pinned revision |
| radare2-mcp (r2mcp, official radareorg) | https://github.com/radareorg/radare2-mcp | Secondary information says LGPL family (check LICENSE at introduction) | Active (release 1.9.0 confirmed) | stdio / HTTP mode. Over HTTP, Bearer token authentication is supported (release information) | Turns radare2's analysis functions into tools. Has a readonly mode, sandbox lock, and tool-restriction options | Designed so that raw r2 command execution can optionally be enabled. **A condition of adoption is that it can be disabled by default** | rev / pwn | The main choice for the radare2 family. The in-house core's radare2 wrapper will not be built; delegate to this |
| Burp MCP (official PortSwigger extension) | https://github.com/PortSwigger/mcp-server | Unverified (secondary information contains both GPL-3.0 and Apache-2.0 claims) | Unverified | SSE (loopback) + stdio proxy | About 27 Burp operation tools (secondary information). Proxy history reference, request sending, etc. | None (centered on Burp operations) | web | A strong candidate for the web category. Premised on the Burp Suite core (Community is acceptable) being resident; the placement location is a decision point |
| ghidra-mcp (bethington) | https://github.com/bethington/ghidra-mcp | Apache-2.0 (secondary information) | Unverified (created 2025-08; secondary information says active) | GUI plugin + headless server | 219 tools (project's self-report) | Unverified | rev | An alternative candidate in the Ghidra family. Compare if a large tool count is wanted |
| pyghidra-mcp (clearbluejar) | Unverified (identify the repository at introduction) | Apache-2.0 (secondary information) | Unverified | Headless-specialized | Cross-project analysis, semantic search, etc. (secondary information) | Unverified | rev | A candidate that fits GUI-less guest operation well. Start with identifying the source and scrutinizing it |

### 2.3 Reference / Contrast (not adopted)

| Name | URL | Summary | Reason for not adopting |
|---|---|---|---|
| HexStrike AI (0x4m4) | https://github.com/0x4m4/hexstrike-ai | MIT. An MCP server bundling 150+ security tools (FastMCP bridge + Flask API). Category structure includes network / web / binary / cloud / CTF & forensics, etc. | Although the tools are individual wrappers, analysis reports point out that the internal implementation executes subprocesses with `shell=True` and that the upstream version has no server authentication. This conflicts with this design's principles (N1, N6), so it is not adopted as-is. Treated as reference material for the tool catalog and category structure |
| CTF-Solver (foxibu) | https://github.com/foxibu/CTF-Solver | An MCP Kali Server family item exposing 55+ Kali tools over HTTP (port 5000). Claims support for 7 categories. License unverified | The Kali Server family is designed to include arbitrary command execution, which conflicts with the principles (N1). Reference only |
| MCP-Kali-Server (Wh0am123) | https://github.com/Wh0am123/MCP-Kali-Server | A server that API-bridges execution of Kali terminal commands themselves | Arbitrary shell execution is its core, contrary to the principles (N1). Noted only as a contrast example |
| mcp-ctf-server (zemi-gh) | Unverified (existence confirmed via listing in the MCP server directory Glama) | stdio type. Includes category-specific tools for crypto / forensics / stego / traffic, etc., and a Python snippet execution sandbox | Its source (GitHub URL) and license are unverified, and it includes arbitrary Python execution. A reference candidate for which identifying the source and scrutiny are mandatory before introduction |

## 3. Selection Rationale (Key Points)

1. **GhidraMCP is a compatibility candidate, not an accepted integration.** Test its pinned extension/bridge against the installed Ghidra version and actual headless/GUI workflow. Compare an alternative only if that acceptance fails.
2. **radare2-mcp is the preferred candidate, not a deployed dependency.** Reuse a pinned upstream adapter only after typed-operation, raw-command disablement and authentication fixtures pass; do not build a duplicate wrapper by default.
3. **Broad all-in-one adoption remains excluded.** Earlier third-party reports motivated the decision. This update performs no pinned source audit and does not assert that the current upstream still has the same authentication or shell behavior.
4. **The web category is centered on the official Burp offering, with placement on hold.** The Burp core is a GUI application, and whether resident operation inside a headless guest is appropriate is unverified. It is made a decision point in docs/06, including the option of placing it on the Windows side. Lightweight HTTP inspection is covered in the meantime by the httpx wrapper on the ctf-mcp core side.
5. **crypto / encoding is thin in OSS, so it became the in-house core's main scope.** Existing CTF-specialized servers often include arbitrary execution, and no implementation extracting only deterministic helpers was found.

## 4. Re-Confirmation List for Introduction Time

- Check each repository's LICENSE file and latest release at introduction time (the license and update information in this document is an estimate).
- Inventory the tool lists and enable only those placed on the allowlist (docs/05). In particular, tools corresponding to "raw command execution" and "script execution" are disabled by default.
- Confirm dependencies and build procedures, and complete delivery into the guest by offline materialization (the existing ISO path).
