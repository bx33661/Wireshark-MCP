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

## Core Functions

### Packet Analysis
- `wireshark_get_packet_list(pcap_file, limit, offset, display_filter)`: Get a summary list of packets (like Wireshark's top pane).
- `wireshark_get_packet_details(pcap_file, frame_number)`: Get full details for a SINGLE packet (like Wireshark's bottom pane).
- `wireshark_follow_stream(pcap_file, stream_index, protocol, ...)`: Reassemble and view complete stream content with pagination and search.

### Data Extraction
- `wireshark_extract_fields(pcap_file, fields, ...)`: Extract specific fields as tabular data.
- `wireshark_extract_http_requests(pcap_file)`: Convenience tool for HTTP method, URI, host.
- `wireshark_extract_dns_queries(pcap_file)`: Convenience tool for DNS queries.
- `wireshark_list_ips(pcap_file)`: List all unique IP addresses in capture.

### Stats & Capture
- `wireshark_stats_protocol_hierarchy(pcap_file)`: Protocol distribution.
- `wireshark_stats_conversations(pcap_file, type)`: Traffic between endpoints.
- `wireshark_filter_save(input_file, output_file, display_filter)`: Save a subset of packets to a new file.

### Security
- `wireshark_check_threats(pcap_file)`: Check IPs against threat intelligence feeds.
- `wireshark_extract_credentials(pcap_file)`: Scan for plaintext credentials.

## Development

To test the MCP server itself:

```sh
npx -y @modelcontextprotocol/inspector uv run wireshark-mcp
```

This will open a web interface where you can interact with the tools directly.
