<div align="center">

<br>

<img src="Logo.png" width="120" alt="Wireshark MCP">

<h1>Wireshark MCP</h1>

<p><strong>Give your AI assistant a packet analyzer.</strong><br>
Drop a <code>.pcap</code> file, ask questions in plain English — get answers backed by real <code>tshark</code> data.</p>

<p>
  <a href="https://github.com/bx33661/Wireshark-MCP/actions/workflows/ci.yml">
    <img src="https://github.com/bx33661/Wireshark-MCP/actions/workflows/ci.yml/badge.svg" alt="CI">
  </a>
  <a href="https://pypi.org/project/wireshark-mcp/">
    <img src="https://img.shields.io/pypi/v/wireshark-mcp?label=PyPI&color=0066cc" alt="PyPI">
  </a>
  <a href="https://pypi.org/project/wireshark-mcp/">
    <img src="https://img.shields.io/pypi/pyversions/wireshark-mcp?label=Python" alt="Python">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License">
  </a>
</p>

<p>
  <a href="README.md">English</a> ·
  <a href="README_zh.md">中文</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

<br>

</div>

---

## What is this?

Wireshark MCP is an [MCP Server](https://modelcontextprotocol.io/introduction) that wraps `tshark` into structured tools, letting AI assistants like Claude or Cursor perform deep packet analysis without you touching the command line.

```
You:    "Find all DNS queries going to suspicious domains in this capture."
Claude: [calls wireshark_extract_dns_queries → wireshark_check_threats]
        "Found 3 queries to domains flagged by URLhaus: ..."
```

---

## Prerequisites

- **Python 3.10+**
- **Wireshark** installed with `tshark` available in your PATH
- Any [MCP-compatible client](https://modelcontextprotocol.io/clients): Claude Desktop, Claude Code, Cursor, VS Code, etc.

---

## Installation

```sh
pip install wireshark-mcp
```

Then auto-configure **all** your MCP clients in one command:

```sh
wireshark-mcp --install
```

That's it — restart your AI client and you're ready to go. 🎉

> **What does `--install` do?** It scans your system for known MCP client config files (Claude, Cursor, VS Code, etc.) and injects the `wireshark-mcp` server entry. Existing settings are preserved. See [Supported Clients](#supported-clients) for the full list.

<details>
<summary>Install from source</summary>

```sh
pip install git+https://github.com/bx33661/Wireshark-MCP.git
wireshark-mcp --install
```

</details>

<details>
<summary>Uninstall from all clients</summary>

```sh
wireshark-mcp --uninstall
```

</details>

---

## Supported Clients

`wireshark-mcp --install` auto-configures the following clients (macOS & Linux):

| Client | Config File |
|--------|------------|
| **Claude Desktop** | `claude_desktop_config.json` |
| **Claude Code** | `~/.claude.json` |
| **Cursor** | `~/.cursor/mcp.json` |
| **VS Code** | `settings.json` (via `mcp.servers`) |
| **VS Code Insiders** | `settings.json` (via `mcp.servers`) |
| **Windsurf** | `mcp_config.json` |
| **Cline** | `cline_mcp_settings.json` |
| **Roo Code** | `mcp_settings.json` |
| **Kilo Code** | `mcp_settings.json` |
| **Antigravity IDE** | `mcp_config.json` |
| **Zed** | `settings.json` (via `mcp.servers`) |
| **LM Studio** | `mcp.json` |
| **Warp** | `mcp_config.json` |
| **Trae** | `mcp_config.json` |
| **Gemini CLI** | `settings.json` |
| **Copilot CLI** | `mcp-config.json` |
| **Amazon Q** | `mcp_config.json` |
| **Codex** | `config.toml` |

For unsupported clients, run `wireshark-mcp --config` to get the JSON snippet and paste it manually.

---

## Configuration

### Recommended: Auto-Configuration (one command)

```sh
pip install wireshark-mcp
wireshark-mcp --install
```

This detects all installed MCP clients and writes the config automatically. Existing settings are preserved.

> ⚠️ **Restart your MCP client** after running `--install` for changes to take effect.

### Manual Configuration

If you prefer to configure manually, or your client is not in the [supported list](#supported-clients):

<details>
<summary><b>Claude Desktop</b></summary>

Edit `claude_desktop_config.json`:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "wireshark-mcp": {
      "command": "wireshark-mcp",
      "args": []
    }
  }
}
```

</details>

<details>
<summary><b>Claude Code (CLI)</b></summary>

```bash
claude mcp add wireshark-mcp -- wireshark-mcp
```

Or edit `~/.claude.json` with the same JSON format above.

</details>

<details>
<summary><b>Cursor</b></summary>

Go to **Settings → Features → MCP Servers → Add new MCP server**:

- **Name**: `wireshark-mcp`
- **Type**: `command`
- **Command**: `wireshark-mcp`

Or edit `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "wireshark-mcp": {
      "command": "wireshark-mcp",
      "args": []
    }
  }
}
```

</details>

<details>
<summary><b>VS Code / VS Code Insiders</b></summary>

Add to your `settings.json`:

```json
{
  "mcp": {
    "servers": {
      "wireshark-mcp": {
        "command": "wireshark-mcp",
        "args": []
      }
    }
  }
}
```

</details>

<details>
<summary><b>OpenAI Codex CLI</b></summary>

```bash
codex mcp add wireshark-mcp -- wireshark-mcp
```

Or edit `~/.codex/config.toml`:

```toml
[mcp_servers.wireshark-mcp]
command = "wireshark-mcp"
args = []
```

</details>

<details>
<summary><b>Other clients</b></summary>

Run the following to get the JSON config snippet:

```sh
wireshark-mcp --config
```

Output:

```json
{
  "mcpServers": {
    "wireshark-mcp": {
      "command": "wireshark-mcp",
      "args": []
    }
  }
}
```

Paste this into your client's MCP config file.

</details>

> **Docker / SSE mode**: `docker compose up -d` then point your client to `http://localhost:8080/sse`

---

## Quick Start

Paste this into your AI client after pointing it at a pcap file:

```
Analyze <path/to/file.pcap> using the Wireshark MCP tools.

- Start with wireshark_open_file to load the file and activate relevant tools.
- Use wireshark_security_audit for a one-call security analysis.
- Or use wireshark_quick_analysis for a fast traffic overview.
- Drill into details with wireshark_follow_stream or wireshark_get_packet_details.
- Never guess — always verify with tools.
- Write findings to report.md.
```

---

## Prompt Engineering

LLMs perform best with specific, structured prompts. Below are refined prompts for common scenarios:

<details>
<summary><b>Security Audit</b></summary>

```
Your task is to perform a comprehensive security audit on <file.pcap>.

1. Start with wireshark_open_file to activate all relevant tools
2. Run wireshark_security_audit for automated 8-phase analysis
3. For any findings, drill deeper:
   - Use wireshark_follow_stream to inspect suspicious sessions
   - Use wireshark_extract_credentials to check for cleartext passwords
   - Use wireshark_check_threats to validate IOCs against threat intel
4. NEVER guess display filter syntax — use the wireshark://reference/display-filters resource
5. NEVER fabricate packet data — always verify with tools
6. Write a structured report to report.md with risk scores (0-100)
```

</details>

<details>
<summary><b>CTF Challenge</b></summary>

```
Your task is to solve a CTF network challenge using <file.pcap>.

1. Start with wireshark_open_file then wireshark_quick_analysis for overview
2. Look for flags using wireshark_search_packets with patterns like "flag{", "CTF{"
3. Check every stream with wireshark_follow_stream — flags often hide in HTTP bodies or TCP data
4. Use wireshark_decode_payload to decode Base64, hex, URL-encoded, or gzipped data
5. Export embedded files with wireshark_export_objects (HTTP, SMB, TFTP)
6. NEVER base64-decode or hex-decode yourself — always use wireshark_decode_payload
7. Document all steps taken and flag found in report.md
```

</details>

<details>
<summary><b>Performance Troubleshooting</b></summary>

```
Your task is to diagnose network performance issues in <file.pcap>.

1. Start with wireshark_open_file to activate protocol-specific tools
2. Use wireshark_analyze_tcp_health to check retransmissions, zero windows, RSTs
3. Use wireshark_stats_io_graph to find traffic spikes or drops
4. Use wireshark_stats_service_response_time for HTTP/DNS latency
5. Use wireshark_stats_expert_info for anomalies
6. Identify top talkers with wireshark_stats_endpoints
7. Write findings to report.md with specific timestamps and recommendations
```

</details>

> **Tips for better results:**
> - Always call `wireshark_open_file` first — it activates protocol-specific tools via Progressive Discovery
> - Use the Agentic tools (`security_audit`, `quick_analysis`) for broad analysis, then drill down
> - Never guess filter syntax — use the `wireshark://reference/display-filters` resource
> - Never decode payloads manually — use `wireshark_decode_payload`

## Tools

<details>
<summary><b>⚡ Agentic Workflows</b> — one-call comprehensive analysis (NEW in v0.6)</summary>

<br>

| Tool | Description |
|---|---|
| `wireshark_security_audit` | **One-call security audit**: 8-phase analysis (threat intel, credential scan, port scan, DNS tunnel, cleartext, anomalies) with risk scoring (0-100) and recommendations |
| `wireshark_quick_analysis` | **One-call traffic overview**: file info, protocol distribution, top talkers, conversations, hostnames, anomaly summary, suggested next steps |
| `wireshark_open_file` | **Smart file opener**: analyzes pcap content and dynamically activates protocol-specific tools (Progressive Discovery) |

> 💡 These tools replace the need to manually chain 5-10 tool calls. Just call one and get a complete report.

</details>

<details>
<summary><b>Packet Analysis</b> — inspect, navigate, and search packets</summary>

<br>

| Tool | Description |
|---|---|
| `wireshark_get_packet_list` | Paginated packet list with display filter and custom column support |
| `wireshark_get_packet_details` | Full JSON dissection of a single frame, with optional layer filtering to cut token usage |
| `wireshark_get_packet_bytes` | Raw Hex + ASCII dump (Wireshark's "Packet Bytes" pane) |
| `wireshark_get_packet_context` | View N packets before and after a frame for contextual debugging |
| `wireshark_follow_stream` | Reassemble a full TCP / UDP / HTTP stream with pagination and search |
| `wireshark_search_packets` | Pattern search across raw bytes or decoded fields (Regex supported) |

</details>

<details>
<summary><b>Data Extraction</b> — pull structured data from captures</summary>

<br>

| Tool | Description |
|---|---|
| `wireshark_extract_fields` | Extract any tshark fields as a table |
| `wireshark_extract_http_requests` | HTTP method, URI, and host for every request |
| `wireshark_extract_dns_queries` | All DNS queries in the capture |
| `wireshark_list_ips` | All unique source, destination, or both IP addresses |
| `wireshark_export_objects` | Extract embedded files (HTTP, SMB, TFTP, etc.) |
| `wireshark_verify_ssl_decryption` | Confirm TLS decryption using a keylog file |

</details>

<details>
<summary><b>Statistics</b> — traffic patterns and anomaly detection</summary>

<br>

| Tool | Description |
|---|---|
| `wireshark_stats_protocol_hierarchy` | Protocol Hierarchy Statistics — see what protocols dominate |
| `wireshark_stats_endpoints` | All endpoints sorted by traffic volume |
| `wireshark_stats_conversations` | Communication pairs with byte/packet counts |
| `wireshark_stats_io_graph` | Traffic volume over time (spot DDoS, scans, bursts) |
| `wireshark_stats_expert_info` | Wireshark's expert analysis: errors, warnings, notes |
| `wireshark_stats_service_response_time` | SRT stats for HTTP, DNS, and other protocols |

</details>

<details>
<summary><b>File Operations & Live Capture</b></summary>

<br>

| Tool | Description |
|---|---|
| `wireshark_get_file_info` | File metadata via `capinfos` (duration, packet count, link type) |
| `wireshark_merge_pcaps` | Merge multiple captures into one file |
| `wireshark_filter_save` | Apply a display filter and save matching packets to a new file |
| `wireshark_list_interfaces` | List available network interfaces |
| `wireshark_capture` | Start a live capture (duration, packet count, BPF filter, ring buffer) |

</details>

<details>
<summary><b>Security Analysis</b></summary>

<br>

| Tool | Description |
|---|---|
| `wireshark_check_threats` | Cross-reference captured IPs against [URLhaus](https://urlhaus.abuse.ch/) threat intelligence |
| `wireshark_extract_credentials` | Detect plaintext credentials in HTTP Basic Auth, FTP, and Telnet |
| `wireshark_detect_port_scan` | Detect SYN, FIN, NULL, and Xmas port scans with configurable threshold |
| `wireshark_detect_dns_tunnel` | Detect DNS tunneling (long queries, TXT abuse, subdomain entropy) |
| `wireshark_detect_dos_attack` | Detect DoS/DDoS patterns (SYN flood, ICMP/UDP flood, DNS amplification) |
| `wireshark_analyze_suspicious_traffic` | Comprehensive anomaly analysis: cleartext protocols, unusual ports, expert warnings |

</details>

<details>
<summary><b>Protocol Deep Dive</b> — TLS, TCP, ARP, SMTP, DHCP analysis</summary>

<br>

| Tool | Description |
|---|---|
| `wireshark_extract_tls_handshakes` | TLS version, cipher suite, SNI, and certificate info from Client/Server Hello |
| `wireshark_analyze_tcp_health` | TCP retransmissions, duplicate ACKs, zero window, resets, out-of-order analysis |
| `wireshark_detect_arp_spoofing` | ARP spoofing detection: IP-MAC conflicts, gratuitous ARP floods |
| `wireshark_extract_smtp_emails` | SMTP email metadata: sender, recipient, mail server info |
| `wireshark_extract_dhcp_info` | DHCP lease information: assigned IPs, hostnames, DNS servers |

</details>

<details>
<summary><b>Decoding & Visualization</b></summary>

<br>

| Tool | Description |
|---|---|
| `wireshark_decode_payload` | Auto-detect and decode Base64, Hex, URL encoding, Gzip, Deflate, Rot13, and more |
| `wireshark_plot_traffic` | ASCII bar chart of traffic over time — spot DDoS or scan patterns instantly |
| `wireshark_plot_protocols` | ASCII protocol tree — visual overview of what's in the capture |

</details>

> **Note**: Security, Protocol, and Threat tools are *contextual* — they activate automatically when you call `wireshark_open_file`. The Agentic tools (`security_audit`, `quick_analysis`) are always available.

---

## MCP Resources

| Resource URI | Description |
|---|---|
| `wireshark://reference/display-filters` | Complete display filter syntax cheatsheet with common examples |
| `wireshark://reference/protocol-fields` | Protocol field name reference for filters and extraction |
| `wireshark://guide/usage` | Recommended analysis workflows and tips |

## MCP Prompts

| Prompt | Description |
|---|---|
| `security_audit` | Full security audit workflow: threat intel, credential scan, attack detection |
| `performance_analysis` | Network performance analysis: TCP health, response times, bottlenecks |
| `ctf_solve` | CTF challenge solver: flag search, stream analysis, steganography checks |
| `incident_response` | IR workflow: triage, IOC extraction, attack timeline, containment |
| `traffic_overview` | Quick traffic summary with protocol breakdown and visualization |
## Why Wireshark MCP?

There are other network analysis MCP servers out there, but Wireshark MCP was built with a few core goals:

| Feature | Wireshark MCP | Others |
|---------|:---:|:---:|
| One-command install (`--install`) | ✅ | ❌ |
| Agentic workflows (one-call security audit) | ✅ | ❌ |
| Progressive Discovery (auto-activate tools) | ✅ | ❌ |
| 40+ specialized analysis tools | ✅ | 5-10 |
| Threat intelligence integration | ✅ | ❌ |
| Smart Python env detection | ✅ | ❌ |
| 18+ MCP client support | ✅ | Manual |

---

## Development

**Install dev dependencies:**

```sh
pip install -e ".[dev]"
```

**Test with the MCP Inspector** (opens a local web UI to call tools interactively):

```sh
npx -y @modelcontextprotocol/inspector uv run wireshark-mcp
```

**Run the test suite:**

```sh
pytest tests/ -v
```

**Lint & type check:**

```sh
ruff check src/ tests/
mypy src/wireshark_mcp/
```

**Docker:**

```sh
docker compose up -d
# Pcap files go in ./pcaps/ (mounted as /data)
```

**CLI options:**

```sh
wireshark-mcp --install                # Auto-configure all detected MCP clients
wireshark-mcp --uninstall              # Remove config from all clients
wireshark-mcp --config                 # Print JSON config for manual setup
wireshark-mcp --version                # Show version
wireshark-mcp --transport sse --port 8080 --log-level INFO   # Start SSE server
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development setup guide.

---

<div align="center">
<sub><a href="LICENSE">MIT License</a> · <a href="https://github.com/bx33661/Wireshark-MCP/issues">Report a Bug</a></sub>
</div>
