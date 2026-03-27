# Repository Agent Guide

This repository implements **Wireshark MCP** — a production-grade Model Context Protocol server that exposes Wireshark / tshark capabilities as structured tools for AI agents.

Use the project skill catalog in `skills/manifest.json` when the task involves packet captures, network forensics, traffic triage, security hunting, incident response, troubleshooting, or CTF-style stream analysis.

---

## Primary Skill

- **`wireshark-traffic-analysis`**

Canonical source: `skills/wireshark-traffic-analysis/SKILL.md`

Discovery mirrors (agent-runtime paths):

| Runtime | Path |
|---------|------|
| Codex / OpenAI | `skills/wireshark-traffic-analysis/agents/openai.yaml` |
| Claude | `.claude/skills/wireshark-traffic-analysis/SKILL.md` |
| GitHub Actions | `.github/skills/wireshark-traffic-analysis/SKILL.md` |

---

## Repository Layout

```
src/wireshark_mcp/
├── server.py          # FastMCP server entry point — registers all tools
├── tshark/
│   └── client.py      # TSharkClient / WiresharkSuiteClient — all tshark calls
├── tools/
│   ├── agents.py      # [Agent] wireshark_security_audit, wireshark_quick_analysis
│   ├── capture.py     # wireshark_capture, wireshark_list_interfaces
│   ├── decode.py      # wireshark_decode_payload
│   ├── edit.py        # editcap wrappers (deduplicate, split, trim, time-shift)
│   ├── extract.py     # field/stream/credential/DHCP/DNS/HTTP/SMTP/TLS extractors
│   ├── files.py       # wireshark_get_file_info
│   ├── imports.py     # text2pcap import
│   ├── protocol.py    # packet list, details, context, bytes, search, open-file
│   ├── registry.py    # contextual tool catalog (ToolRegistry)
│   ├── security.py    # ARP spoof, port scan, DoS, DNS tunnel, threat intel
│   ├── stats.py       # conversations, endpoints, expert info, I/O graph, PHS, SRT
│   ├── suite.py       # wireshark_get_capabilities
│   ├── threat.py      # URLhaus threat intelligence matching
│   └── visualize.py   # ASCII I/O graph, protocol tree
├── prompts.py         # Built-in MCP prompts
└── resources.py       # MCP resources (skill content, display-filter ref, etc.)

skills/wireshark-traffic-analysis/
├── SKILL.md
├── agents/openai.yaml
└── references/
    ├── playbooks.md
    ├── evidence-rubric.md
    ├── report-template.md
    └── official-wireshark-notes.md
```

---

## Tool Surface

### Agentic (one-call orchestrated)

| Tool | Description |
|------|-------------|
| `wireshark_quick_analysis` | File info → protocol distribution → top talkers → conversations → hostnames → anomaly summary |
| `wireshark_security_audit` | 8-phase security audit: threat intel, credentials, port scan, DNS tunnel, cleartext, expert info, risk score |

### Entry Point

| Tool | Description |
|------|-------------|
| `wireshark_open_file` | Opens a capture, activates contextual tool recommendations |
| `wireshark_get_capabilities` | Lists all available tools and their status |

### Statistics & Visualization

| Tool | Description |
|------|-------------|
| `wireshark_stats_protocol_hierarchy` | Protocol hierarchy statistics (PHS) tree |
| `wireshark_stats_conversations` | Conversation pairs with bytes/packets (ip, tcp, udp …) |
| `wireshark_stats_endpoints` | Endpoint inventory with traffic totals |
| `wireshark_stats_expert_info` | Automatic anomaly/error detection |
| `wireshark_stats_io_graph` | Traffic volume over time |
| `wireshark_stats_service_response_time` | HTTP/DNS/SMB service response time stats |
| `wireshark_plot_traffic` | ASCII I/O bar chart |
| `wireshark_plot_protocols` | ASCII protocol hierarchy tree |

### Packet Inspection

| Tool | Description |
|------|-------------|
| `wireshark_get_packet_list` | Summary table of packets (top-pane view) |
| `wireshark_get_packet_details` | Full JSON detail for a single frame |
| `wireshark_get_packet_context` | Packets surrounding a specific frame |
| `wireshark_get_packet_bytes` | Raw hex/ASCII dump of a frame |
| `wireshark_follow_stream` | Reassembled TCP/UDP/TLS/HTTP stream with pagination |
| `wireshark_search_packets` | Search by string, hex, regex, or display filter |
| `wireshark_extract_fields` | Tabular field extraction with display-filter scope |

### Extraction & Export

| Tool | Description |
|------|-------------|
| `wireshark_extract_http_requests` | HTTP method, URI, host |
| `wireshark_extract_dns_queries` | DNS query names and types |
| `wireshark_extract_tls_handshakes` | TLS version, cipher, SNI, cert issuer |
| `wireshark_extract_smtp_emails` | SMTP sender, recipient, subject |
| `wireshark_extract_dhcp_info` | DHCP leases, hostnames, DNS servers |
| `wireshark_extract_credentials` | Cleartext credentials (HTTP Basic, FTP, Telnet) |
| `wireshark_export_objects` | Embedded file extraction (http, smb, tftp, imf, dicom) |
| `wireshark_list_ips` | Unique IP addresses (src / dst / both) |

### Security Detection

| Tool | Description |
|------|-------------|
| `wireshark_detect_port_scan` | SYN/FIN/NULL/Xmas scan detection |
| `wireshark_detect_dos_attack` | SYN flood, ICMP/UDP flood, DNS amplification |
| `wireshark_detect_dns_tunnel` | Long queries, TXT abuse, subdomain entropy |
| `wireshark_detect_arp_spoofing` | Duplicate IP-MAC, gratuitous floods |
| `wireshark_check_threats` | URLhaus threat intelligence matching |
| `wireshark_analyze_suspicious_traffic` | Comprehensive anomaly analysis |
| `wireshark_extract_credentials` | Plaintext credential scan |

### TCP / Performance

| Tool | Description |
|------|-------------|
| `wireshark_analyze_tcp_health` | Retransmissions, dup ACKs, zero window, resets |

### Capture & File Manipulation

| Tool | Description |
|------|-------------|
| `wireshark_capture` | Live capture with BPF filter, ring buffer support |
| `wireshark_list_interfaces` | Available network interfaces |
| `wireshark_filter_save` | Filter and save packets to new file |
| `wireshark_merge_pcaps` | Merge multiple capture files |
| `wireshark_editcap_split` | Split by packet count or time interval |
| `wireshark_editcap_trim` | Trim by timestamp window |
| `wireshark_editcap_deduplicate` | Remove duplicate packets |
| `wireshark_editcap_time_shift` | Adjust packet timestamps |
| `wireshark_text2pcap_import` | Convert hex/ASCII dump to pcap |
| `wireshark_verify_ssl_decryption` | Verify TLS decryption with SSLKEYLOGFILE |

### Utility

| Tool | Description |
|------|-------------|
| `wireshark_decode_payload` | Decode Base64, Hex, URL, ROT13, Gzip, Deflate, etc. |

---

## Built-in MCP Prompts

Invoke these when the user needs a guided starting workflow:

| Prompt | Purpose |
|--------|---------|
| `traffic_overview` | Fast situational awareness of an unknown capture |
| `security_audit` | Full security posture review |
| `performance_analysis` | Latency, retransmissions, TCP health |
| `incident_response` | Timeline reconstruction and scope |
| `ctf_solve` | Flag extraction, hidden payloads, encoded streams |

---

## MCP Resources

Use `wireshark://` URIs to retrieve reference content without tool calls:

- `wireshark://guide/usage` — built-in workflow reference
- `wireshark://reference/display-filters` — valid Wireshark display filter syntax
- `wireshark://reference/protocol-fields` — field names for extraction and filters
- `wireshark://skill/wireshark-traffic-analysis` — full skill document
- `wireshark://skill/wireshark-traffic-analysis/playbooks` — mode playbooks
- `wireshark://skill/wireshark-traffic-analysis/evidence-rubric` — confidence labeling
- `wireshark://skill/wireshark-traffic-analysis/report-template` — report structure

---

## Expected Behavior

- **Always call `wireshark_open_file` first.** It provides capture-wide context and activates contextual tool recommendations.
- **Build a global picture before drilling down.** Use `wireshark_quick_analysis`, `wireshark_stats_protocol_hierarchy`, `wireshark_stats_endpoints`, and `wireshark_stats_conversations` before packet-level inspection.
- **Choose a mode, follow its playbook.** Read `skills/wireshark-traffic-analysis/references/playbooks.md` and use the section that matches the goal: `triage`, `security`, `incident-response`, `troubleshoot`, or `ctf`.
- **Confirm leads with packet evidence.** Use `wireshark_follow_stream`, `wireshark_get_packet_details`, `wireshark_get_packet_context`, and `wireshark_extract_fields` to verify findings.
- **Label all inferences.** Facts come from tool output. Inferences must be labeled `confirmed`, `likely`, `possible`, or `unresolved`.
- **Never guess display filter syntax.** Use `wireshark://reference/display-filters`.
- **Treat `wireshark_stats_expert_info` as a lead generator, not a verdict.** Confirm anomalies before reporting.
- **Paginate large captures.** Do not treat the first page of results as representative.
- **Keep findings reproducible.** Include exact tool calls, stream indexes, frame numbers, display filters, and field names in every non-trivial finding.

---

## Server Runtime Notes

- **Dependency**: requires `tshark` (Wireshark CLI) in `$PATH`. Run `wireshark-mcp doctor` to verify.
- **Transport**: defaults to `stdio`; supports `sse` and `streamable-http`.
- **Directory sandbox**: set `WIRESHARK_MCP_ALLOWED_DIRS` to restrict which paths tshark can read.
- **Installation**: `wireshark-mcp install` auto-configures supported MCP clients (Cursor, Claude Desktop, Codex, VS Code, etc.).

---

## Development

```bash
# Install with dev dependencies
uv sync --group dev

# Run tests
pytest

# Lint
ruff check src/

# Type check
mypy src/
```

Entry point: `wireshark_mcp.server:main` (registered as the `wireshark-mcp` CLI script).
