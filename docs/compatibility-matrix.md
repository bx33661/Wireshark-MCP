# Compatibility Matrix

This document outlines verified operating systems, MCP clients, Wireshark/TShark versions, and transport protocols supported by Wireshark MCP 3.0.

## Status Definitions

To maintain rigorous engineering honesty, compatibility is categorized into three explicit tiers:
- **CI / Locally Verified (实际验证)**: Covered by reproducible end-to-end automated tests in CI or verified local suites executing real binaries, sockets, or processes.
- **Config Supported (配置支持)**: Client configuration generators, file formats, and CLI flags are programmatically validated via automated installer unit tests (`tests/test_installer.py`).
- **Expected Compatible (预期兼容)**: Conforms to published specifications (e.g. MCP 2024-11-05 / 2026-07-28, standard JSON-RPC, standard POSIX/Win32 pipes) without direct automated app-level GUI regression in the repository.

---

## Protocol & Specification Support

| Specification / Standard | Tier | Notes |
| :--- | :--- | :--- |
| **MCP Protocol `2026-07-28`** | **Locally Verified** | Uses the stateless per-request envelope, advertises exactly `2026-07-28` through `server/discover`, and verifies discovery, tool listing, successful calls, and protocol-level `isError` on failed calls without session IDs. |
| **MCP Python SDK `2.x`** | **CI Verified** | Built on top of `mcp>=2.1.1,<3`. |
| **Transport: `stdio`** | **CI / Locally Verified** | Default transport. Verified via subprocess pipe handshake in `test_real_stdio_subprocess_handshake`. |
| **Transport: `Streamable HTTP`** | **Locally Verified** | Bound to loopback (`127.0.0.1`) by default. Verified via real subprocess listener and Starlette TestClient in `test_server.py`. |
| **Transport: `HTTP + SSE`** | **Expected Compatible** | Maintained for legacy compatibility with MCP 1.x endpoints. Bound to loopback by default. |

---

## Client Integration Matrix

| Client Environment | Transport | Integration Method | Compatibility Tier |
| :--- | :--- | :--- | :--- |
| **Claude Desktop** | `stdio` | `claude_desktop_config.json` via `wireshark-mcp install --client claude-desktop` | Config Supported (Installer Tested) |
| **Claude Code** | `stdio` | Project / Global MCP registration (`claude mcp add`) | Config Supported (CLI Validated) |
| **Cursor** | `stdio` | `.cursor/mcp.json` via `wireshark-mcp install --client cursor` | Config Supported (Installer Tested) |
| **Windsurf / Cascade** | `stdio` | `mcp_config.json` via `wireshark-mcp install --client windsurf` | Config Supported (Installer Tested) |
| **Codex CLI** | `stdio` | `config.toml` via `wireshark-mcp install --client codex` | Config Supported (Installer Tested) |
| **Generic MCP 2.x Clients** | `stdio` / `HTTP` | Standard discovery, listing, and invocation | Expected Compatible (Spec Conformance) |

---

## Wireshark / TShark Engine Matrix

Wireshark MCP interacts directly with the local system installation of `tshark`, `capinfos`, `mergecap`, `editcap`, `dumpcap`, and `text2pcap`.

| Engine Version | Platform | Compatibility Tier | Notes |
| :--- | :--- | :--- | :--- |
| **Wireshark 4.6.x** | macOS | **Locally Verified** | Tested against 4.6.6 with 5 synthetic pcap fixtures in `test_real_pcap.py`. |
| **Wireshark 4.6.x** | Windows Server | **CI Verified** | Pinned to 4.6.8 via Chocolatey in Windows GitHub Actions runner. |
| **Wireshark 4.2.x** | Ubuntu Linux | **CI Verified** | Tested in Ubuntu GitHub Actions runner (`apt-get install -y tshark`). |
| **Wireshark 4.0.x** | Linux / Windows | **Expected Compatible** | Core packet extraction and aggregation supported; field aliases mapped. |
| **Wireshark 3.6.x** | Ubuntu 22.04 LTS | **Expected Compatible (Floor)** | Minimum supported version floor for basic display filters. |
| **< 3.6.0** | All | **Unsupported** | Lacks required dissector fields and modern JSON export options. |

---

## Operating System Matrix

| Operating System | Architecture | Verification Tier | Notes |
| :--- | :--- | :--- | :--- |
| **macOS 14+ (Sonoma, Sequoia)** | Apple Silicon (`arm64`) | **Locally Verified** | Homebrew `wireshark 4.6.6` + Python 3.13 verified across 461 tests. |
| **Ubuntu / Debian** (22.04+, 24.04+) | `x86_64` | **CI Verified** | Verified in GitHub Actions with system `tshark`. |
| **Windows 10 / 11 / Server** | `x86_64` | **CI Verified** | Verified in GitHub Actions with Chocolatey `wireshark`. |
| **Fedora / RHEL / Rocky** | `x86_64`, `aarch64` | **Expected Compatible** | Standard `dnf install wireshark-cli` supported. |

---

## Result Contract & Error Behavior

1. **Protocol Error Synchronization**:
   When any tool encounters a fatal execution error or permission failure (`success: false`), the MCP envelope sets `CallToolResult.isError = true`. Clients inspecting protocol status reliably identify failures without parsing string bodies.
2. **Type Invariance Under Character Ceilings**:
   When tool outputs exceed configured character budgets (`MAX_RESULT_CHARS`), structured types (`list`, `dict`) retain their object types:
   - Lists are truncated by item count (Top-K) and annotated with `pagination: {"has_more": true, "returned": K, "total": N}`.
   - Dictionaries preserve top-level keys and trim internal collection lists.
   - Text fields are truncated with explicit `truncated: true` and `[Showing K/N lines]` indicators.
3. **Evidence Anchors**:
   Security and threat tools report findings adhering to the candidate signal contract: every candidate signal provides frame numbers, stream indexes, display filters, and sample values for reproducible investigation.
