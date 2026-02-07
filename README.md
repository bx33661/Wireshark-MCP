# Wireshark MCP

Simple [MCP Server](https://modelcontextprotocol.io/introduction) to allow vibe packet analysis in Wireshark.

[English](README.md) | [中文](README_zh.md)

## Prerequisites

- [Python](https://www.python.org/downloads/) (**3.10 or higher**)
- [Wireshark](https://www.wireshark.org/) (ensure `tshark` is in your PATH)
- Supported MCP Client (pick one you like)
  - [Claude Code](https://www.anthropic.com/code)
  - [Claude](https://claude.ai/download)
  - [Cursor](https://cursor.com)
  - [VS Code](https://code.visualstudio.com/) with generic MCP client extension
  - [Other MCP Clients](https://modelcontextprotocol.io/clients#example-clients)

## Installation

Install the latest version of the Wireshark MCP package:

```sh
pip install wireshark-mcp
```

Or install directly from source:

```sh
pip install git+https://github.com/bx33661/Wireshark-MCP.git
```

## Configuration

Add the server to your MCP client configuration (e.g., `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "uv",
      "args": [
        "tool",
        "run",
        "wireshark-mcp"
      ]
    }
  }
}
```

_Note_: You can also run it directly with `python -m wireshark_mcp` if installed in your environment.

## Prompt Engineering

LLMs are good at general analysis but can struggle with the specifics of packet dissection. Below is a minimal example prompt strategy:

```md
Your task is to analyze a pcap file using Wireshark MCP tools.
- Start by getting a packet list summary to understand the traffic flow (`wireshark_get_packet_list`).
- If you see interesting packets, get full details for that specific frame (`wireshark_get_packet_details`).
- For TCP/HTTP flows, use `wireshark_follow_stream` to see the full conversation.
- Use `wireshark_extract_http_requests` or `wireshark_extract_dns_queries` for quick high-level overviews.
- NEVER try to guess packet contents; always verify with the tools.
- Create a report.md with your findings.
```

## Available Tools

### Packet Analysis (extract.py)
- `wireshark_get_packet_list(pcap_file, limit=20, offset=0, display_filter="", custom_columns="")`:
    Get summary list of packets. Supports custom columns (e.g., "ip.src,http.host") to replace default view.
- `wireshark_get_packet_details(pcap_file, frame_number, layers="")`:
    Get full JSON details for a single packet. Supports layer filtering (e.g., "ip,tcp,http") to significantly reduce token usage.
- `wireshark_get_packet_bytes(pcap_file, frame_number)`: 
    **[New]** Get raw Hex/ASCII dump (Packet Bytes view).
- `wireshark_get_packet_context(pcap_file, frame_number, count=5)`:
    **[New]** View packets surrounding a specific frame (before and after) to understand context.
- `wireshark_follow_stream(...)`: Reassemble and view complete stream content with pagination and search.
- `wireshark_search_packets(pcap_file, match_pattern, search_type="string", limit=50, scope="bytes")`: 
    **[Enhanced]** Find packets.
    *   `scope="bytes"`: Search in raw payload (Hex/String).
    *   `scope="details"`: Search in decoded text/fields (Regex supported).
- `wireshark_read_packets(...)`: [DEPRECATED] Use `get_packet_details` instead.

### Data Extraction (extract.py)
- `wireshark_extract_fields(pcap_file, fields, display_filter="", limit=100, offset=0)`: Extract specific fields as tabular data.
- `wireshark_extract_http_requests(pcap_file, limit=100)`: Convenience tool for HTTP method, URI, host.
- `wireshark_extract_dns_queries(pcap_file, limit=100)`: Convenience tool for DNS queries.
- `wireshark_list_ips(pcap_file, type="both")`: List all unique IP addresses (src, dst, or both).
- `wireshark_export_objects(pcap_file, protocol, dest_dir)`: Extract embedded files (http, smb, etc.) from traffic.
- `wireshark_verify_ssl_decryption(pcap_file, keylog_file)`: Verify TLS decryption using a keylog file.

### Statistics (stats.py)
- `wireshark_stats_protocol_hierarchy(pcap_file)`: Get Protocol Hierarchy Statistics (PHS).
- `wireshark_stats_endpoints(pcap_file, type="ip")`: List all endpoints and their traffic stats.
- `wireshark_stats_conversations(pcap_file, type="ip")`: Show communication pairs and their stats.
- `wireshark_stats_io_graph(pcap_file, interval=1)`: Get traffic volume over time (I/O Graph).
- `wireshark_stats_expert_info(pcap_file)`: Get Expert Information (anomalies, warnings).
- `wireshark_stats_service_response_time(pcap_file, protocol="http")`: Service Response Time (SRT) statistics.

### File Operations (files.py & capture.py)
- `wireshark_get_file_info(pcap_file)`: Get detailed metadata about a capture file (capinfos).
- `wireshark_merge_pcaps(output_file, input_files)`: Merge multiple capture files into one.
- `wireshark_list_interfaces()`: List available network interfaces for capture.
- `wireshark_capture(interface, output_file, duration_seconds=10, packet_count=0, capture_filter="", ring_buffer="")`: Capture live network traffic.
- `wireshark_filter_save(input_file, output_file, display_filter)`: Filter packets from a pcap and save to a new file.

### Security (security.py)
- `wireshark_check_threats(pcap_file)`: Check captured IPs against URLhaus threat intelligence.
- `wireshark_extract_credentials(pcap_file)`: Scan for plaintext credentials (HTTP Auth, FTP, Telnet).

### Decoding (decode.py)
- `wireshark_decode_payload(data, encoding="auto")`: Decode common encodings (Base64, Hex, URL, Gzip, Deflate, Rot13, etc.) with smart auto-detection.

### Visualization (visualize.py)
- `wireshark_plot_traffic(pcap_file, interval=1)`: Generate ASCII bar chart of traffic volume over time.
- `wireshark_plot_protocols(pcap_file)`: Generate ASCII tree view of protocol hierarchy.

## Development

To test the MCP server itself:

```sh
npx -y @modelcontextprotocol/inspector uv run wireshark-mcp
```

This will open a web interface where you can interact with the tools directly.
