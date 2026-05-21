<div align="center">
<!-- mcp-name: io.github.bx33661/wireshark-mcp -->

<img src="Logo.png" width="150" alt="Wireshark MCP" style="margin-top: 20px; margin-bottom: 20px;">

<h1>Wireshark MCP</h1>

**Give your AI assistant a packet analyzer.**

*Drop a `.pcap` file, ask questions in plain English — get answers backed by real `tshark` data.*

<p style="margin-top: 15px;">
  <a href="https://github.com/bx33661/Wireshark-MCP/actions/workflows/ci.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/bx33661/Wireshark-MCP/ci.yml?style=flat-square&logo=github&label=CI" alt="CI">
  </a>
  <a href="https://github.com/bx33661/Wireshark-MCP/releases/latest">
    <img src="https://img.shields.io/github/v/release/bx33661/Wireshark-MCP?style=flat-square&logo=github&color=24292f" alt="GitHub Release">
  </a>
  <a href="https://pypi.org/project/wireshark-mcp/">
    <img src="https://img.shields.io/pypi/v/wireshark-mcp?style=flat-square&logo=pypi&color=0066cc" alt="PyPI">
  </a>
  <a href="https://pypi.org/project/wireshark-mcp/">
    <img src="https://img.shields.io/pypi/pyversions/wireshark-mcp?style=flat-square&logo=python" alt="Python">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square" alt="MIT License">
  </a>
</p>

<p>
  <a href="README.md"><b>English</b></a> •
  <a href="README_zh.md"><b>中文</b></a> •
  <a href="CHANGELOG.md"><b>Changelog</b></a> •
  <a href="CONTRIBUTING.md"><b>Contributing</b></a>
</p>
</div>

---

## What is this?

An [MCP server](https://modelcontextprotocol.io/introduction) that wraps `tshark` (and optional Wireshark suite tools) into a structured analysis interface. Works with Claude Desktop, Claude Code, Cursor, VS Code, and [18+ other MCP clients](docs/manual-configuration.md).

```
You:    "Find all DNS queries going to suspicious domains in this capture."
Claude: [calls wireshark_extract_dns_queries → wireshark_check_threats]
        "Found 3 queries to domains flagged by URLhaus: ..."
```

---

## Install

**Prerequisites:** Python 3.10+ and [Wireshark](https://www.wireshark.org/) with `tshark` on PATH.

```sh
pip install wireshark-mcp
wireshark-mcp install   # auto-configures all detected MCP clients
```

Restart your AI client — done.

Run `wireshark-mcp doctor` if anything looks off. See [docs/manual-configuration.md](docs/manual-configuration.md) for manual setup or platform-specific notes.

---

## Quick Start

Point your AI client at a `.pcap` file and try:

```
Analyze capture.pcap using the Wireshark MCP tools.
Start with wireshark_open_file, then run wireshark_security_audit.
Write findings to report.md.
```

---

## Tools

40+ tools organized into categories:

| Category | Highlights | Count |
|----------|-----------|:-----:|
| **Agentic Workflows** | `wireshark_security_audit`, `wireshark_quick_analysis`, `wireshark_open_file` | 4 |
| **Packet Analysis** | Packet list, details, bytes, context, stream follow, search | 7 |
| **Data Extraction** | HTTP requests, DNS queries, TLS handshakes, field extraction | 6 |
| **Statistics** | Protocol hierarchy, endpoints, conversations, I/O graph, expert info | 6 |
| **Security** | Threat intel, credential scan, port scan, DNS tunnel, DoS detection | 6 |
| **Protocol Deep Dive** | TCP health, ARP spoofing, SMTP, DHCP | 5 |
| **File Ops & Capture** | Live capture, merge, filter-save, file info | 5 |
| **Suite Utilities** | editcap trim/split/dedup, text2pcap import | 5 |
| **Decode & Visualize** | Payload decode, traffic plot, protocol tree | 3 |

The server starts with only `tshark` required. Optional tools (`capinfos`, `mergecap`, `editcap`, `dumpcap`, `text2pcap`) are auto-detected and enable extra features when present.

---

## Documentation

| Topic | Link |
|-------|------|
| Platform setup (macOS/Linux/Windows) | [docs/platform-validation.md](docs/platform-validation.md) |
| Manual client configuration | [docs/manual-configuration.md](docs/manual-configuration.md) |
| Prompt templates | [docs/prompt-engineering.md](docs/prompt-engineering.md) |
| Release checklist | [docs/release-checklist.md](docs/release-checklist.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |
| Security policy | [SECURITY.md](SECURITY.md) |

---

## Development

```sh
pip install -e ".[dev]"
pytest tests/ -v
ruff check src/ tests/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

---

<div align="center">
<sub><a href="LICENSE">MIT License</a> · <a href="https://github.com/bx33661/Wireshark-MCP/issues">Report a Bug</a></sub>
</div>
