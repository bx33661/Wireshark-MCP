"""MCP Prompts for Wireshark MCP — expert analysis templates for LLMs."""

import logging

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger("wireshark_mcp")


def register_prompts(mcp: FastMCP) -> None:
    """Register all MCP Prompts."""

    @mcp.prompt()
    def security_audit(pcap_file: str) -> str:
        """Comprehensive security audit of a network capture file."""
        return f"""\
You are a senior network security analyst performing a comprehensive security audit on a pcap file.

**Target file**: `{pcap_file}`

Follow this systematic workflow:

## Step 1: Reconnaissance
- Use `wireshark_get_file_info("{pcap_file}")` to understand capture duration, packet count, and file type.
- Use `wireshark_stats_protocol_hierarchy("{pcap_file}")` to see overall protocol distribution.
- Use `wireshark_stats_endpoints("{pcap_file}")` to identify all communicating hosts.

## Step 2: Threat Intelligence
- Use `wireshark_check_threats("{pcap_file}")` to check IPs against URLhaus.
- Use `wireshark_extract_credentials("{pcap_file}")` to find any plaintext credentials.

## Step 3: Attack Pattern Detection
- Use `wireshark_detect_port_scan("{pcap_file}")` to check for scanning activity.
- Use `wireshark_detect_dns_tunnel("{pcap_file}")` to check for DNS tunneling.
- Use `wireshark_detect_dos_attack("{pcap_file}")` to identify DoS patterns.

## Step 4: Protocol Deep Dive
- Use `wireshark_extract_tls_handshakes("{pcap_file}")` to analyze TLS security.
- Use `wireshark_extract_http_requests("{pcap_file}")` to review HTTP activity.
- Use `wireshark_extract_dns_queries("{pcap_file}")` to review DNS queries.

## Step 5: Anomaly Review
- Use `wireshark_stats_expert_info("{pcap_file}")` for anomalies.
- Use `wireshark_analyze_suspicious_traffic("{pcap_file}")` for comprehensive anomaly analysis.

## Output
Create a structured security report in Markdown with:
- Executive Summary (risk level: Critical/High/Medium/Low/Info)
- Findings table (ID, Severity, Description, Evidence)
- Detailed analysis for each finding
- Remediation recommendations
"""

    @mcp.prompt()
    def performance_analysis(pcap_file: str) -> str:
        """Network performance analysis of a capture file."""
        return f"""\
You are a network performance engineer analyzing traffic for performance issues.

**Target file**: `{pcap_file}`

## Step 1: Overview
- Use `wireshark_get_file_info("{pcap_file}")` for capture metadata.
- Use `wireshark_stats_io_graph("{pcap_file}", interval=1)` to visualize traffic patterns.
- Use `wireshark_plot_traffic("{pcap_file}")` for a quick visual.

## Step 2: Connection Analysis
- Use `wireshark_stats_conversations("{pcap_file}", type="tcp")` to see TCP conversations.
- Use `wireshark_stats_endpoints("{pcap_file}", type="tcp")` for endpoint traffic stats.

## Step 3: TCP Health
- Use `wireshark_analyze_tcp_health("{pcap_file}")` to find retransmissions, resets, zero windows.
- Use `wireshark_stats_expert_info("{pcap_file}")` for protocol-level warnings.

## Step 4: Application Performance
- Use `wireshark_stats_service_response_time("{pcap_file}", protocol="http")` for HTTP response times.
- Use `wireshark_extract_http_requests("{pcap_file}")` to review request patterns.

## Step 5: DNS Performance
- Use `wireshark_extract_dns_queries("{pcap_file}")` to check DNS resolution.

## Output
Create a performance analysis report with:
- Summary (overall health: Good/Degraded/Poor)
- Traffic volume and pattern analysis
- TCP health metrics (retransmission rate, RTT estimates)
- Application response time analysis
- Bottleneck identification
- Optimization recommendations
"""

    @mcp.prompt()
    def ctf_solve(pcap_file: str) -> str:
        """CTF challenge solver workflow for pcap analysis challenges."""
        return f"""\
You are an experienced CTF player solving a network forensics challenge.

**Target file**: `{pcap_file}`

## Strategy: Cast a Wide Net First

### Phase 1: Quick Overview
- Use `wireshark_get_file_info("{pcap_file}")` for basic info.
- Use `wireshark_stats_protocol_hierarchy("{pcap_file}")` — unusual protocols are often the key!
- Use `wireshark_get_packet_list("{pcap_file}", limit=50)` to scan the first packets.

### Phase 2: Data Extraction
- Use `wireshark_extract_http_requests("{pcap_file}")` — check for suspicious URIs.
- Use `wireshark_extract_dns_queries("{pcap_file}")` — DNS exfil is common in CTF.
- Use `wireshark_search_packets("{pcap_file}", "flag", scope="bytes")` — direct flag search.
- Use `wireshark_search_packets("{pcap_file}", "CTF", scope="bytes")` — variant search.
- Use `wireshark_search_packets("{pcap_file}", "password", scope="bytes")` — credential search.

### Phase 3: Deep Analysis
- Look for Base64, hex-encoded, or obfuscated data.
- Use `wireshark_follow_stream("{pcap_file}", stream_index=0)` on interesting TCP streams.
- Use `wireshark_export_objects("{pcap_file}", "http", "/tmp/ctf_objects")` to extract files.
- Use `wireshark_decode_payload(data)` to decode suspicious strings.

### Phase 4: Steganography / Hidden Data
- Use `wireshark_get_packet_bytes("{pcap_file}", frame_number=N)` for raw hex on suspicious packets.
- Check for unusual packet sizes, timing patterns, or protocol anomalies.
- Look at ICMP data, DNS TXT records, HTTP headers for hidden messages.

## Tips
- Flags often look like: `flag{{...}}`, `CTF{{...}}`, or similar patterns
- Check HTTP response bodies, not just requests
- DNS queries can encode data in subdomains
- FTP/Telnet traffic is usually plaintext
- Look for Base64 strings (long alphanumeric with = padding)
"""

    @mcp.prompt()
    def incident_response(pcap_file: str) -> str:
        """Incident response investigation workflow."""
        return f"""\
You are a SOC analyst investigating a potential security incident from a network capture.

**Target file**: `{pcap_file}`

## Phase 1: Triage (5 minutes)
- Use `wireshark_get_file_info("{pcap_file}")` — when was this captured? how long?
- Use `wireshark_stats_protocol_hierarchy("{pcap_file}")` — any unusual protocols?
- Use `wireshark_stats_endpoints("{pcap_file}")` — identify all hosts involved.

## Phase 2: IOC Extraction (10 minutes)
- Use `wireshark_check_threats("{pcap_file}")` — any known malicious IPs?
- Use `wireshark_list_ips("{pcap_file}")` — get full IP list for SIEM correlation.
- Use `wireshark_extract_dns_queries("{pcap_file}")` — check for DGA domains.
- Use `wireshark_detect_dns_tunnel("{pcap_file}")` — check for command & control.

## Phase 3: Attack Analysis (15 minutes)
- Use `wireshark_detect_port_scan("{pcap_file}")` — was there reconnaissance?
- Use `wireshark_extract_http_requests("{pcap_file}")` — any malicious URLs?
- Use `wireshark_extract_credentials("{pcap_file}")` — credential theft?
- Use `wireshark_extract_tls_handshakes("{pcap_file}")` — suspicious certificates?

## Phase 4: Impact Assessment
- Use `wireshark_analyze_suspicious_traffic("{pcap_file}")` — full anomaly analysis.
- Use `wireshark_follow_stream` on suspicious conversations for payload analysis.
- Use `wireshark_export_objects` to extract any transferred files.

## Output: Incident Report
- Incident Timeline (first seen → last activity)
- Affected hosts and services
- IOC list (IPs, domains, hashes)
- Attack narrative (what happened, in order)
- Severity assessment (Critical/High/Medium/Low)
- Immediate containment recommendations
"""

    @mcp.prompt()
    def traffic_overview(pcap_file: str) -> str:
        """Quick traffic overview and summary."""
        return f"""\
Provide a concise overview of the network traffic in the capture file.

**Target file**: `{pcap_file}`

1. Use `wireshark_get_file_info("{pcap_file}")` for capture metadata.
2. Use `wireshark_stats_protocol_hierarchy("{pcap_file}")` for protocol breakdown.
3. Use `wireshark_stats_endpoints("{pcap_file}")` for top talkers.
4. Use `wireshark_stats_conversations("{pcap_file}")` for communication pairs.
5. Use `wireshark_plot_traffic("{pcap_file}")` for traffic timeline.
6. Use `wireshark_plot_protocols("{pcap_file}")` for protocol distribution.

Summarize: what type of traffic is this? What are the main hosts communicating? Any anomalies visible at a glance?
"""
