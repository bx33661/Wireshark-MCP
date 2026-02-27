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

<details>
<summary>Install from source</summary>

```sh
pip install git+https://github.com/bx33661/Wireshark-MCP.git
```

</details>

---

## Configuration

Add to your MCP client config (e.g. `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "uv",
      "args": ["tool", "run", "wireshark-mcp"]
    }
  }
}
```

> You can also run directly with `python -m wireshark_mcp`.

---

## Quick Start

Paste this into your AI client after pointing it at a pcap file:

```
Analyze <path/to/file.pcap> using the Wireshark MCP tools.

- Start with wireshark_get_packet_list to map the traffic.
- Drill into interesting frames with wireshark_get_packet_details.
- For TCP/HTTP sessions, use wireshark_follow_stream.
- Never guess — always verify with tools.
- Write findings to report.md.
```

---

## Tools

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
wireshark-mcp --version
wireshark-mcp --transport sse --port 8080 --log-level INFO
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development setup guide.

---

<div align="center">
<sub><a href="LICENSE">MIT License</a> · <a href="https://github.com/bx33661/Wireshark-MCP/issues">Report a Bug</a></sub>
</div>
