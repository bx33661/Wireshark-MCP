"""MCP Prompts for Wireshark MCP — expert analysis templates for LLMs."""

import logging

from mcp.server import MCPServer

logger = logging.getLogger("wireshark_mcp")


def register_prompts(mcp: MCPServer, *, write_tools_enabled: bool = True) -> None:
    """Register all MCP Prompts."""

    @mcp.prompt()
    def security_audit(pcap_file: str) -> str:
        """Comprehensive security audit of a network capture file."""
        return f"""\
You are a senior network security analyst performing a comprehensive security audit on a pcap file.

**Target file**: `{pcap_file}`

Follow this systematic workflow:

## Step 1: Reconnaissance
- Use `wireshark_open_file("{pcap_file}")` first for capture-wide context and tool recommendations.
- Use `wireshark_get_file_info("{pcap_file}")` to understand capture duration, packet count, and file type.
- Use `wireshark_stats_protocol_hierarchy("{pcap_file}")` to see overall protocol distribution.
- Use `wireshark_stats_endpoints("{pcap_file}")` to identify all communicating hosts.

## Step 2: Credential Exposure
- Use `wireshark_extract_credentials("{pcap_file}")` to find any plaintext credentials.
- Use `wireshark_aggregate("{pcap_file}", display_filter="ip", group_by="ip.src", distinct="ip.dst,tcp.dstport")` to rank broad fan-out across the full capture.

## Step 3: Attack Pattern Detection
- Use `wireshark_detect_port_scan("{pcap_file}")` to check for scanning activity.
- Use `wireshark_detect_dns_tunnel("{pcap_file}")` to check for DNS tunneling.
- Use `wireshark_detect_dos_attack("{pcap_file}")` to identify DoS patterns.

## Step 4: Protocol Deep Dive
- Use `wireshark_analyze_protocol("{pcap_file}", protocol="tls_handshakes")` to analyze TLS security.
- Use `wireshark_extract_http_requests("{pcap_file}")` to review HTTP activity.
- Use `wireshark_extract_dns_queries("{pcap_file}")` to review DNS queries.

## Step 5: Anomaly Review
- Use `wireshark_stats_expert_info("{pcap_file}")` for anomalies.
- Use `wireshark_detect_beaconing("{pcap_file}")` for periodic C2 callbacks.
- Use `wireshark_detect_protocol_anomalies("{pcap_file}")` for known protocols on non-standard ports.

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
- Use `wireshark_open_file("{pcap_file}")` first for capture-wide context and tool recommendations.
- Use `wireshark_get_file_info("{pcap_file}")` for capture metadata.
- Use `wireshark_stats_io_graph("{pcap_file}", interval=1)` to visualize traffic patterns.
- Use `wireshark_aggregate("{pcap_file}", display_filter="ip", group_by="ip.src", time_bucket_seconds=60)` to quantify source activity over time.

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
    def incident_response(pcap_file: str) -> str:
        """Incident response investigation workflow."""
        impact_export = (
            "- Use `wireshark_export_objects` to extract any transferred files."
            if write_tools_enabled
            else "- Object export is disabled by the selected read-only profile; record candidate streams for later extraction."
        )
        return f"""\
You are a SOC analyst investigating a potential security incident from a network capture.

**Target file**: `{pcap_file}`

## Phase 1: Triage (5 minutes)
- Use `wireshark_open_file("{pcap_file}")` first for capture-wide context and tool recommendations.
- Use `wireshark_get_file_info("{pcap_file}")` — when was this captured? how long?
- Use `wireshark_stats_protocol_hierarchy("{pcap_file}")` — any unusual protocols?
- Use `wireshark_stats_endpoints("{pcap_file}")` — identify all hosts involved.

## Phase 2: IOC Extraction (10 minutes)
- Use `wireshark_stats_endpoints("{pcap_file}")` — get the host inventory for SIEM correlation.
- Use `wireshark_extract_dns_queries("{pcap_file}")` — check for DGA domains.
- Use `wireshark_detect_dns_tunnel("{pcap_file}")` — check for command & control.
- Use `wireshark_aggregate("{pcap_file}", display_filter="dns.flags.response == 0", group_by="ip.src", distinct="dns.qry.name", time_bucket_seconds=60)` to build a DNS activity timeline.

## Phase 3: Attack Analysis (15 minutes)
- Use `wireshark_detect_port_scan("{pcap_file}")` — was there reconnaissance?
- Use `wireshark_extract_http_requests("{pcap_file}")` — any malicious URLs?
- Use `wireshark_extract_credentials("{pcap_file}")` — credential theft?
- Use `wireshark_analyze_protocol("{pcap_file}", protocol="tls_handshakes")` — suspicious certificates?

## Phase 4: Impact Assessment
- Use `wireshark_detect_exfiltration("{pcap_file}")` — outbound data volume anomalies.
- Use `wireshark_detect_beaconing("{pcap_file}")` — periodic C2 callbacks.
- Use `wireshark_follow_stream` on suspicious conversations for payload analysis.
{impact_export}

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

1. Use `wireshark_open_file("{pcap_file}")` for capture-wide context and recommended tools.
2. Use `wireshark_get_file_info("{pcap_file}")` for capture metadata.
3. Use `wireshark_stats_protocol_hierarchy("{pcap_file}")` for protocol breakdown.
4. Use `wireshark_stats_endpoints("{pcap_file}")` for top talkers.
5. Use `wireshark_stats_conversations("{pcap_file}")` for communication pairs.
6. Use `wireshark_stats_io_graph("{pcap_file}")` for the traffic timeline.
7. Use `wireshark_aggregate("{pcap_file}", display_filter="ip", group_by="ip.src", distinct="ip.dst")` for a full-capture source distribution.

Summarize: what type of traffic is this? What are the main hosts communicating? Any anomalies visible at a glance?
"""

    @mcp.prompt()
    def analyze_with_hypothesis(pcap_file: str, hypothesis: str = "") -> str:
        """Hypothesis-driven traffic analysis — form, test, and refine hypotheses systematically."""
        hypothesis_seed = (
            f'\n**Initial hypothesis**: "{hypothesis}"\n\nStart by evaluating this hypothesis.\n'
            if hypothesis
            else "\nNo initial hypothesis provided — form one after the reconnaissance phase.\n"
        )
        return f"""\
You are a senior network analyst using the scientific method to investigate traffic.

**Target file**: `{pcap_file}`
{hypothesis_seed}
## Methodology: Hypothesis-Driven Analysis

### Phase 1: Reconnaissance (gather baseline facts)
- Use `wireshark_open_file("{pcap_file}")` for capture-wide context and tool recommendations.
- Use `wireshark_get_file_info("{pcap_file}")` for capture metadata.
- Use `wireshark_stats_protocol_hierarchy("{pcap_file}")` for protocol distribution.
- Use `wireshark_stats_endpoints("{pcap_file}")` to identify communicating hosts.

### Phase 2: Form Hypothesis
Based on the reconnaissance data, state a clear, falsifiable hypothesis about what is happening in this traffic. Examples:
- "Host X is exfiltrating data to external server Y via DNS tunneling."
- "The spike at T+30s is caused by a SYN flood from source Z."
- "The HTTP 500 errors correlate with database connection exhaustion."

### Phase 3: Identify Evidence Needed
For your hypothesis, list:
1. What evidence would **confirm** it?
2. What evidence would **refute** it?
3. Which specific tools and filters will gather that evidence?

### Phase 4: Execute and Evaluate
Run the tools you identified. For each result, explicitly state whether it supports or contradicts your hypothesis. Use tools such as:
- `wireshark_search_packets` — find specific patterns
- `wireshark_follow_stream` — inspect conversation content
- `wireshark_extract_fields` — pull targeted protocol fields
- `wireshark_get_packet_details` — deep-dive individual packets
- `wireshark_stats_conversations` — quantify communication pairs

### Phase 5: Update and Iterate
- If evidence **supports** the hypothesis: strengthen it with additional confirming data.
- If evidence **contradicts** the hypothesis: revise or discard it and form a new one.
- Repeat Phases 2–5 until you reach high confidence.

## Output
Present your final analysis as:
- **Final Hypothesis** (confirmed/revised)
- **Evidence Chain** (tool → result → interpretation for each step)
- **Confidence Level** (High/Medium/Low with justification)
- **Alternative Explanations Considered** (and why they were ruled out)
"""

    @mcp.prompt()
    def investigate_alert(pcap_file: str, ioc: str, ioc_type: str = "") -> str:
        """Investigate a single IOC/alert and expand the analysis outward."""
        type_hint = f" (type: **{ioc_type}**)" if ioc_type else " (type not specified — infer from format)"
        return f"""\
You are a threat analyst investigating a specific indicator of compromise (IOC) within captured traffic.

**Target file**: `{pcap_file}`
**IOC**: `{ioc}`{type_hint}

## Phase 1: Locate the IOC
Search for the indicator in the capture using the most appropriate method:
- For IP addresses: `wireshark_search_packets("{pcap_file}", "ip.addr == {ioc}", scope="filter")`
- For domains: `wireshark_extract_dns_queries("{pcap_file}")` and `wireshark_search_packets("{pcap_file}", "{ioc}", scope="bytes")`
- For ports: `wireshark_search_packets("{pcap_file}", "tcp.port == {ioc} || udp.port == {ioc}", scope="filter")`
- For hashes/strings: `wireshark_search_packets("{pcap_file}", "{ioc}", scope="bytes")`

Confirm the IOC is present and note the first frame number where it appears.

## Phase 2: Identify Communicating Hosts
Determine every host that interacted with the IOC:
- Use `wireshark_stats_conversations("{pcap_file}", type="ip")` filtered to the IOC.
- Use `wireshark_extract_fields("{pcap_file}", "ip.src,ip.dst,frame.time", display_filter="<ioc_filter>")` to list all source/destination pairs.
- Record each unique internal host that communicated with the IOC.

## Phase 3: Build Timeline
Construct a chronological timeline of all interactions:
- Use `wireshark_extract_fields("{pcap_file}", "frame.number,frame.time,ip.src,ip.dst,tcp.dstport,frame.len", display_filter="<ioc_filter>")`.
- Identify: first contact, peak activity, last contact, total duration.
- Note any patterns (beaconing intervals, burst transfers, protocol changes).

## Phase 4: Expand — Related Indicators
Look for additional IOCs connected to the original:
- Use `wireshark_extract_dns_queries("{pcap_file}")` — did the IOC resolve from a suspicious domain?
- Use `wireshark_analyze_protocol("{pcap_file}", protocol="tls_handshakes")` — any unusual certificates or SNI values?
- Use `wireshark_follow_stream("{pcap_file}", stream_index=<N>)` on key conversations for payload inspection.
- Check if compromised hosts communicated with other suspicious destinations.

## Phase 5: Generate Evidence Chain
Produce a structured report:
- **IOC Confirmed**: Yes/No — with frame numbers and timestamps
- **Affected Hosts**: List of internal IPs/hostnames that interacted with the IOC
- **Timeline**: First seen → Last seen, with key events annotated
- **Related IOCs Discovered**: Additional indicators found during expansion
- **Lateral Movement**: Evidence of the IOC spreading to other internal hosts
- **Data Exfiltration**: Volume and direction of data transfer
- **Recommended Actions**: Block rules, hosts to isolate, further investigation steps
"""
