"""MCP Resources for Wireshark MCP — expose reference data to LLMs."""

import logging

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger("wireshark_mcp")

# ── Display Filter Reference ────────────────────────────────────────────────

DISPLAY_FILTER_CHEATSHEET = """\
# Wireshark Display Filter Cheatsheet

## Comparison Operators
| Operator | Meaning          | Example                        |
|----------|------------------|--------------------------------|
| ==       | Equal            | ip.addr == 192.168.1.1         |
| !=       | Not equal        | tcp.port != 80                 |
| >        | Greater than     | frame.len > 1000               |
| <        | Less than        | tcp.window_size < 100          |
| >=       | Greater or equal | ip.ttl >= 64                   |
| contains | Contains string  | http.host contains "example"   |
| matches  | Regex match      | http.request.uri matches "api" |

## Logical Operators
| Operator | Example                                  |
|----------|------------------------------------------|
| and / && | ip.src == 10.0.0.1 and tcp.port == 443   |
| or / ||  | dns or http                              |
| not / !  | not arp                                  |

## Common Filters

### By Protocol
- `http` — HTTP traffic
- `dns` — DNS queries/responses
- `tcp` — All TCP
- `udp` — All UDP
- `tls` / `ssl` — TLS/SSL traffic
- `arp` — ARP requests/replies
- `icmp` — ICMP (ping, etc.)
- `dhcp` / `bootp` — DHCP
- `smtp` — SMTP email
- `ftp` — FTP
- `ssh` — SSH

### By IP Address
- `ip.addr == 192.168.1.1` — Source OR destination
- `ip.src == 10.0.0.0/24` — Source subnet
- `ip.dst == 8.8.8.8` — Destination host

### By Port
- `tcp.port == 443` — Source OR destination port
- `tcp.dstport == 80` — Destination port only
- `udp.port == 53` — DNS port

### HTTP Specific
- `http.request` — HTTP requests only
- `http.response` — HTTP responses only
- `http.request.method == "POST"` — POST requests
- `http.response.code == 200` — 200 OK responses
- `http.response.code >= 400` — Error responses
- `http.host contains "example.com"` — By host
- `http.content_type contains "json"` — JSON responses

### DNS Specific
- `dns.qry.name contains "evil"` — DNS query name
- `dns.qry.type == 1` — A records
- `dns.qry.type == 28` — AAAA records
- `dns.flags.response == 1` — DNS responses only

### TCP Analysis
- `tcp.analysis.retransmission` — Retransmissions
- `tcp.analysis.duplicate_ack` — Duplicate ACKs
- `tcp.analysis.zero_window` — Zero window
- `tcp.analysis.reset` — TCP resets
- `tcp.flags.syn == 1 and tcp.flags.ack == 0` — SYN only (new connections)

### TLS/SSL
- `tls.handshake.type == 1` — Client Hello
- `tls.handshake.type == 2` — Server Hello
- `tls.handshake.extensions.server_name` — SNI field

### Security
- `ftp.request.command == "PASS"` — FTP passwords
- `http.authbasic` — HTTP Basic Auth
- `telnet` — Telnet traffic (often plaintext)

## Tips
- Use `frame.number == N` to target a specific packet
- Use `frame.time_relative > 5` for packets after 5 seconds
- Combine with `&&` and `||` for complex queries
- Use parentheses: `(http or dns) and ip.src == 10.0.0.1`
"""

PROTOCOL_FIELD_REFERENCE = """\
# Common Wireshark Protocol Fields

## Ethernet (eth)
- `eth.src` / `eth.dst` — MAC addresses
- `eth.type` — EtherType

## IP (ip)
- `ip.src` / `ip.dst` — IP addresses
- `ip.proto` — Protocol number (6=TCP, 17=UDP)
- `ip.ttl` — Time to Live
- `ip.len` — Total length
- `ip.flags.df` — Don't Fragment flag

## TCP (tcp)
- `tcp.srcport` / `tcp.dstport` — Ports
- `tcp.seq` / `tcp.ack` — Sequence/ACK numbers
- `tcp.len` — Payload length
- `tcp.flags` — TCP flags
- `tcp.window_size` — Window size
- `tcp.stream` — Stream index

## UDP (udp)
- `udp.srcport` / `udp.dstport` — Ports
- `udp.length` — Length

## HTTP (http)
- `http.request.method` — GET, POST, etc.
- `http.request.uri` — Request URI
- `http.host` — Host header
- `http.user_agent` — User-Agent
- `http.response.code` — Status code
- `http.content_type` — Content-Type
- `http.content_length` — Content-Length
- `http.cookie` — Cookie header
- `http.set_cookie` — Set-Cookie header

## DNS (dns)
- `dns.qry.name` — Query name
- `dns.qry.type` — Query type
- `dns.a` — A record answer
- `dns.aaaa` — AAAA record answer
- `dns.resp.ttl` — Response TTL

## TLS (tls)
- `tls.handshake.version` — TLS version
- `tls.handshake.ciphersuite` — Cipher suite
- `tls.handshake.extensions.server_name` — SNI
- `tls.handshake.certificate` — Certificate

## Frame (frame)
- `frame.number` — Packet number
- `frame.time` — Timestamp
- `frame.time_relative` — Time since first packet
- `frame.len` — Frame length
- `frame.protocols` — Protocol stack
"""

WIRESHARK_MCP_GUIDE = """\
# Wireshark MCP Usage Guide

## Analysis Workflow

1. **Start with overview**: Use `wireshark_get_file_info` to understand the capture
2. **Protocol hierarchy**: Use `wireshark_stats_protocol_hierarchy` to see what's in the traffic
3. **Packet list**: Use `wireshark_get_packet_list` to browse packets (apply filters as needed)
4. **Deep dive**: Use `wireshark_get_packet_details` for a specific packet
5. **Follow streams**: Use `wireshark_follow_stream` to see full conversations
6. **Extract data**: Use specialized tools like `wireshark_extract_http_requests`

## Security Analysis Workflow

1. Use `wireshark_check_threats` to check IPs against threat intelligence
2. Use `wireshark_extract_credentials` to find plaintext credentials
3. Use `wireshark_detect_port_scan` to find scanning activity
4. Use `wireshark_detect_dns_tunnel` to check for DNS tunneling
5. Use `wireshark_detect_dos_attack` to identify DoS patterns
6. Use `wireshark_analyze_suspicious_traffic` for comprehensive analysis

## Protocol Analysis Workflow

1. Use `wireshark_extract_tls_handshakes` for TLS/SSL analysis
2. Use `wireshark_analyze_tcp_health` for TCP performance issues
3. Use `wireshark_detect_arp_spoofing` for ARP-level attacks
4. Use `wireshark_extract_dhcp_info` for DHCP/network config

## Tips for Efficient Analysis

- Always start broad, then narrow down with display filters
- Use `custom_columns` in `get_packet_list` to extract exactly the fields you need
- Use `layers` parameter in `get_packet_details` to reduce output size
- For large captures, use `offset` and `limit` for pagination
- Use `wireshark_search_packets` with `scope="filter"` for precise Wireshark filtering
"""


def register_resources(mcp: FastMCP) -> None:
    """Register all MCP Resources."""

    @mcp.resource("wireshark://reference/display-filters")
    def get_display_filter_reference() -> str:
        """Wireshark display filter syntax cheatsheet with common examples."""
        return DISPLAY_FILTER_CHEATSHEET

    @mcp.resource("wireshark://reference/protocol-fields")
    def get_protocol_field_reference() -> str:
        """Common Wireshark protocol field names for use in filters and extraction."""
        return PROTOCOL_FIELD_REFERENCE

    @mcp.resource("wireshark://guide/usage")
    def get_usage_guide() -> str:
        """Wireshark MCP usage guide with recommended analysis workflows."""
        return WIRESHARK_MCP_GUIDE
