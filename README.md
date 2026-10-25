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
  <a href="docs/README.md"><b>Docs</b></a> •
  <a href="CHANGELOG.md"><b>Changelog</b></a> •
  <a href="ROADMAP.md"><b>Roadmap</b></a> •
  <a href="CONTRIBUTING.md"><b>Contributing</b></a>
</p>
</div>

---

## What is this?

An [MCP server](https://modelcontextprotocol.io/introduction) that wraps `tshark` (and optional Wireshark suite tools) into a structured analysis interface. Works with Claude Desktop, Claude Code, Cursor, VS Code, and 18+ other MCP clients.

```
You:    "Find all DNS queries going to suspicious domains in this capture."
Claude: [calls wireshark_extract_dns_queries → wireshark_detect_dns_tunnel]
        "Found repeated high-entropy DNS queries consistent with tunneling: ..."
```

### New in 4.0

- **Capture index.** With the optional `[index]` extra, `wireshark_index` dissects a capture once into a local DuckDB file. Later `wireshark_aggregate` and `wireshark_extract_fields` calls read it with answers identical to tshark: 408× faster at 1 GB, and at 10 GB it answers questions the tshark path stops on. It also adds read-only SQL, capture sets, first-seen timelines, capture or window diffs and Parquet export. See [Capture index](docs/capture-index.md).
- **One finding shape.** Every detector returns `data.findings` with a stable id, evidence anchors, a native `tshark` command to re-check it and candidate ATT&CK techniques.
- **Case files.** `wireshark_case` keeps captures, recorded results, findings and analyst verdicts in a JSON case file, so a long investigation survives a context reset. See [Findings and cases](docs/findings-and-cases.md).

Upgrading from 3.x needs no configuration change. Scripts that parsed the plain-text output of `wireshark_detect_beaconing`, `wireshark_detect_exfiltration`, `wireshark_detect_protocol_anomalies`, `wireshark_detect_arp_spoofing`, `wireshark_yara_scan` or `wireshark_quick_analysis` should read the JSON envelope instead. Full notes: [4.0.0 changelog](changelog/4.0.0.md).

---

## Install

### Claude Code / Codex plugin route

Prerequisites: `uv` and Wireshark CLI (`tshark`). The plugin includes this project and both skills; the client runs the locked Python project through uv over stdio. It does not install Wireshark or capture drivers.

From a checkout containing these plugin manifests, choose your client:

```sh
# Codex
codex plugin marketplace add .
codex plugin add wireshark-mcp@wireshark-mcp

# Claude Code
claude plugin marketplace add .
claude plugin install wireshark-mcp@wireshark-mcp
```

See [plugin distribution](docs/plugin-installation.md) for local installation, old-version refresh, environment settings and the GitHub entrypoint after publication. Choose this route or the traditional registration route below, not both.

### Traditional Python package route

**Prerequisites:** Python 3.10+ and [Wireshark](https://www.wireshark.org/) with `tshark` on PATH.

Wireshark MCP runs on the stable MCP Python SDK 2.x line (`mcp>=2.1.1,<3`).

```sh
pip install wireshark-mcp
wireshark-mcp install   # choose from detected MCP clients
```

For scripts/non-interactive terminals, select clients explicitly. Preview before installing into the current project:

```sh
wireshark-mcp install --client codex --scope project --dry-run
wireshark-mcp install --client codex --scope project
```

The default scope is `global`. Repeat `--client` or explicitly use `--client all`. Restart the client to load configuration. See the [installation guide](docs/installation.md) for updates, removal, backups and exit codes.

Optional extras add features on top of the base install: `index` (DuckDB capture index for large captures), `geoip` (GeoIP enrichment) and `yara` (YARA scanning), or `all`:

```sh
pip install 'wireshark-mcp[index]'
```

The container image and the plugin route ship without extras. Every setting, extra and limit is listed in the [configuration reference](docs/configuration.md).

The project also ships MCP and full TShark CLI analysis skills; see [skill discovery and usage](docs/skills.md).

Run `wireshark-mcp doctor` if anything looks off. See [docs/manual-configuration.md](docs/manual-configuration.md) for manual setup or platform-specific notes.

---

## Quick Start

Point your AI client at a `.pcap` file and try:

```
Analyze capture.pcap using the Wireshark MCP tools.
Start with wireshark_open_file, then run wireshark_quick_analysis.
Use wireshark_aggregate for any capture-wide count or distribution.
Write findings to report.md.
```

For a large capture, or several related ones, build the index first and keep the investigation in a case file:

```
Index big.pcapng with wireshark_index, then use wireshark_aggregate and
wireshark_index action="timeline" to find when 10.0.0.5 first appeared.
Open a case with wireshark_case, record every detector result you rely on,
and verify each conclusion with wireshark_get_packet_details.
```

---

## Tools

54 tools, each backed by real `tshark` output — organized into categories:

| Category | Highlights | Count |
|----------|-----------|:-----:|
| **Entry & Workflow** | `wireshark_open_file`, `wireshark_quick_analysis`, `wireshark_case` (persistent investigation case files) | 3 |
| **Packet Analysis** | Packet list, details, bytes, context, stream follow, search, file info | 8 |
| **Data Extraction** | HTTP requests, DNS queries, arbitrary fields, object export | 4 |
| **Statistics** | Aggregate/group/distinct/top-k/time buckets, protocol hierarchy, endpoints, conversations, I/O graph, expert info, service response time, flow graph | 8 |
| **Security & Anomaly** | Credential scan, port scan, DNS tunnel, DoS, beaconing, exfiltration, protocol anomalies, YARA | 8 |
| **Protocol Analysis** | `wireshark_analyze_protocol` (25 protocols incl. BLE pairing, scanner detection, GATT timeline with handle labels, connection lifecycle), TCP health, ARP spoofing | 3 |
| **Decrypt & Dissection** | TLS/WPA decrypt, decryption check, decode-as, protocol preferences | 5 |
| **Forensics & Enrichment** | TLS fingerprints, file signature scan, GeoIP | 3 |
| **File Ops, Capture & Suite** | Live capture, interfaces, merge, filter-save, editcap trim/split/dedup/time-shift, frame extract, text2pcap, capabilities | 11 |
| **Capture Index** (optional `[index]` extra) | `wireshark_index`: one tshark pass into a local DuckDB file; `wireshark_aggregate` and `wireshark_extract_fields` reuse it. Read-only SQL, multi-capture sets, first-seen timelines, capture/window diffs and Parquet export | 1 |

One tool covers 25 protocols rather than 25 tools covering one each: `wireshark_analyze_protocol` takes a `protocol` argument (`tls_handshakes`, `mqtt`, `modbus`, `s7comm`, `zigbee`, `wifi`, `rtp`, `kerberos`, …) and applies the right fields and display filter for it. The field names are the point — `s7comm.param.item.dbnum` is not something a caller should have to guess, and a wrong guess returns an empty result that reads like a clean capture.

The server starts with only `tshark` required. Optional tools (`capinfos`, `mergecap`, `editcap`, `dumpcap`, `text2pcap`) are auto-detected and enable extra features when present.

### Context cost

The tool list travels in the prompt prefix of every request your client sends, so its size is a fixed per-request cost. The default surface is ~23 KB — about 9 KB of parameter schema, 5 KB of descriptions, and 3 KB of read/write annotations — and it is byte-identical across restarts so clients can cache the prefix rather than re-reading it each session.

If your client never captures live traffic or writes pcaps, `--profile` advertises less:

| Profile | Tools | Payload | Drops |
|---------|:-----:|:-------:|-------|
| `full` (default) | 54 | ~23 KB | nothing |
| `analysis` | 42 | ~18 KB | live capture, interface listing, all caller-directed file-writing tools |
| `core` | 34 | ~15 KB | the above, plus decryption, dissection overrides, and low-level views |

```bash
wireshark-mcp serve --profile core
```

Runtime prompts and protocol recommendations respect the selected profile. Static guides may describe `full`-only workflows, but the server never recommends an excluded tool during capture discovery.

Tool results are bounded too, since a result stays in the conversation for the rest of the session. Output over 8000 characters is truncated head-and-tail with a marker, and the tool's `offset` / `limit` / `display_filter` parameters are the way to page through the rest. Raise or lower the ceiling with:

```bash
export WIRESHARK_MCP_MAX_RESULT_CHARS=16000
```

Every tool also declares whether it reads or writes, so clients can auto-approve the 41 read-only analysis tools and still prompt for the 12 that create files (live capture, merge, filter-save, editcap, text2pcap, frame extract, object export, case files). `wireshark_index` is marked non-destructive: it writes only the server's own index cache.

Since 3.0, those tools fail closed until `WIRESHARK_MCP_ALLOWED_DIRS` names existing directories. Remote HTTP/SSE binding also stays loopback-only unless `--allow-insecure-http` is explicitly supplied behind a trusted authenticated TLS proxy. See the [3.0 security migration guide](docs/security-hardening-v3.md).

---

## Documentation

| Topic | Link |
|-------|------|
| Documentation index | [docs/README.md](docs/README.md) |
| Configuration reference (extras, environment variables, limits) | [docs/configuration.md](docs/configuration.md) |
| Capture-wide aggregation | [docs/aggregation.md](docs/aggregation.md) |
| Capture index (DuckDB) | [docs/capture-index.md](docs/capture-index.md) |
| Findings and case files | [docs/findings-and-cases.md](docs/findings-and-cases.md) |
| Install, update and uninstall | [docs/installation.md](docs/installation.md) |
| Platform setup (macOS/Linux/Windows) | [docs/platform-validation.md](docs/platform-validation.md) |
| Manual client configuration | [docs/manual-configuration.md](docs/manual-configuration.md) |
| Deployment scenarios | [docs/deployment-scenarios.md](docs/deployment-scenarios.md) |
| 3.0 security migration | [docs/security-hardening-v3.md](docs/security-hardening-v3.md) |
| Prompt templates | [docs/prompt-engineering.md](docs/prompt-engineering.md) |
| Architecture | [docs/architecture.md](docs/architecture.md) |
| Release checklist | [docs/release-checklist.md](docs/release-checklist.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |
| Feature roadmap | [ROADMAP.md](ROADMAP.md) |
| Security policy | [SECURITY.md](SECURITY.md) |

---

## Development

```sh
uv sync --group dev --extra index
uv run python -m pytest
uv run python -m ruff check src/ tests/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

---

<div align="center">
<sub><a href="LICENSE">MIT License</a> · <a href="https://github.com/bx33661/Wireshark-MCP/issues">Report a Bug</a></sub>
</div>
