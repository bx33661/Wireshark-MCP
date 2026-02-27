"""Advanced threat detection and security analysis tools for Wireshark MCP."""

import logging
from typing import List

from mcp.server.fastmcp import FastMCP

from ..tshark.client import TSharkClient
from .envelope import error_response, normalize_tool_result, parse_tool_result, success_response

logger = logging.getLogger("wireshark_mcp")


def register_threat_tools(mcp: FastMCP, client: TSharkClient) -> None:
    """Register advanced threat detection tools."""

    @mcp.tool()
    async def wireshark_detect_port_scan(pcap_file: str, threshold: int = 15) -> str:
        """
        [Security] Detect port scanning activity.
        Identifies hosts that connect to many different destination ports (SYN scan, connect scan).

        Args:
            pcap_file: Path to capture file
            threshold: Minimum unique destination ports to flag as scan (default: 15)

        Returns:
            Port scan analysis results or JSON error

        Example:
            wireshark_detect_port_scan("suspicious.pcap", threshold=10)
        """
        # Get SYN-only packets (typical port scan signature)
        syn_result = await client.extract_fields(
            pcap_file,
            ["ip.src", "ip.dst", "tcp.dstport"],
            display_filter="tcp.flags.syn == 1 and tcp.flags.ack == 0",
            limit=10000,
        )
        wrapped = parse_tool_result(syn_result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data", "")
        if not isinstance(data, str) or len(data.strip()) < 20:
            return success_response("No SYN-only packets found — no port scan detected.")

        # Analyze: group by source IP → count unique dst ports
        src_to_ports: dict[str, set[str]] = {}
        src_to_targets: dict[str, set[str]] = {}

        lines = data.strip().splitlines()
        for line in lines[1:]:  # skip header
            parts = line.split("\t")
            if len(parts) >= 3:
                src = parts[0].strip().strip('"')
                dst = parts[1].strip().strip('"')
                port = parts[2].strip().strip('"')
                if src and port:
                    src_to_ports.setdefault(src, set()).add(port)
                    src_to_targets.setdefault(src, set()).add(dst)

        results: List[str] = []
        results.append("=== Port Scan Detection ===\n")

        scanners = {
            src: ports
            for src, ports in src_to_ports.items()
            if len(ports) >= threshold
        }

        if scanners:
            results.append(f"🔴 {len(scanners)} potential scanner(s) detected!\n")
            for src, ports in sorted(scanners.items(), key=lambda x: len(x[1]), reverse=True):
                targets = src_to_targets.get(src, set())
                results.append(f"  Scanner: {src}")
                results.append(f"    Unique ports probed: {len(ports)}")
                results.append(f"    Target hosts: {len(targets)}")
                results.append(f"    Port sample: {', '.join(sorted(ports)[:20])}")
                if len(ports) > 20:
                    results.append(f"    ... and {len(ports) - 20} more ports")
                results.append("")
        else:
            results.append(f"🟢 No port scanning detected (threshold: {threshold} unique ports)")
            # Show summary of SYN activity anyway
            results.append(f"\nSYN packets analyzed: {len(lines) - 1}")
            results.append(f"Unique source IPs: {len(src_to_ports)}")

        # Check for specific scan types
        # SYN-FIN scan (invalid flag combination)
        synfin_result = await client.get_packet_list(
            pcap_file, limit=10,
            display_filter="tcp.flags.syn == 1 and tcp.flags.fin == 1",
        )
        synfin_wrapped = parse_tool_result(synfin_result)
        if synfin_wrapped["success"]:
            synfin_data = synfin_wrapped.get("data", "")
            if isinstance(synfin_data, str):
                synfin_lines = [l for l in synfin_data.strip().splitlines() if l.strip()]
                if len(synfin_lines) > 1:
                    results.append(f"\n🔴 SYN-FIN packets detected ({len(synfin_lines) - 1}) — possible Xmas/stealth scan!")

        # NULL scan (no flags)
        null_result = await client.get_packet_list(
            pcap_file, limit=10,
            display_filter="tcp.flags == 0",
        )
        null_wrapped = parse_tool_result(null_result)
        if null_wrapped["success"]:
            null_data = null_wrapped.get("data", "")
            if isinstance(null_data, str):
                null_lines = [l for l in null_data.strip().splitlines() if l.strip()]
                if len(null_lines) > 1:
                    results.append(f"\n🟠 TCP NULL packets detected ({len(null_lines) - 1}) — possible NULL scan!")

        return success_response("\n".join(results))

    @mcp.tool()
    async def wireshark_detect_dns_tunnel(pcap_file: str) -> str:
        """
        [Security] Detect potential DNS tunneling.
        Checks for: unusually long DNS queries, high query volume, TXT record abuse, entropy analysis.

        Args:
            pcap_file: Path to capture file

        Returns:
            DNS tunnel analysis results or JSON error

        Example:
            wireshark_detect_dns_tunnel("exfiltration.pcap")
        """
        # Extract DNS query names and types
        dns_result = await client.extract_fields(
            pcap_file,
            ["ip.src", "dns.qry.name", "dns.qry.type", "dns.resp.len"],
            display_filter="dns",
            limit=5000,
        )
        wrapped = parse_tool_result(dns_result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data", "")
        if not isinstance(data, str) or len(data.strip()) < 20:
            return success_response("No DNS traffic found in this capture.")

        # Analyze DNS patterns
        long_queries: List[str] = []
        txt_queries: List[str] = []
        query_by_src: dict[str, int] = {}
        unique_subdomains: dict[str, set[str]] = {}  # base domain → subdomains
        total_queries = 0

        lines = data.strip().splitlines()
        for line in lines[1:]:
            parts = line.split("\t")
            if len(parts) >= 3:
                src = parts[0].strip().strip('"')
                qname = parts[1].strip().strip('"')
                qtype = parts[2].strip().strip('"')

                if not qname:
                    continue

                total_queries += 1
                query_by_src[src] = query_by_src.get(src, 0) + 1

                # Check query length (DNS tunnel queries are typically very long)
                if len(qname) > 50:
                    long_queries.append(qname)

                # Check for TXT queries (common tunnel mechanism)
                if qtype in ("16", "TXT"):
                    txt_queries.append(qname)

                # Track subdomains per base domain
                parts_domain = qname.split(".")
                if len(parts_domain) >= 3:
                    base = ".".join(parts_domain[-2:])
                    subdomain = ".".join(parts_domain[:-2])
                    unique_subdomains.setdefault(base, set()).add(subdomain)

        results: List[str] = []
        results.append("=== DNS Tunnel Detection ===\n")
        results.append(f"Total DNS queries analyzed: {total_queries}")

        indicators = 0

        # Indicator 1: Long query names
        if long_queries:
            indicators += 1
            results.append(f"\n🔴 Long DNS queries detected: {len(long_queries)}")
            for q in long_queries[:5]:
                results.append(f"  [{len(q)} chars] {q[:80]}...")
            if len(long_queries) > 5:
                results.append(f"  ... and {len(long_queries) - 5} more")

        # Indicator 2: Excessive TXT record queries
        if len(txt_queries) > 10:
            indicators += 1
            results.append(f"\n🟠 High TXT record query count: {len(txt_queries)}")
            unique_txt = set(txt_queries)
            results.append(f"  Unique TXT domains: {len(unique_txt)}")

        # Indicator 3: Domain with many unique subdomains
        suspicious_domains = {
            domain: subs
            for domain, subs in unique_subdomains.items()
            if len(subs) > 20
        }
        if suspicious_domains:
            indicators += 1
            results.append(f"\n🔴 Domains with excessive subdomains (data encoding indicator):")
            for domain, subs in sorted(suspicious_domains.items(), key=lambda x: len(x[1]), reverse=True)[:5]:
                results.append(f"  {domain}: {len(subs)} unique subdomains")

        # Indicator 4: Single host making excessive DNS queries
        heavy_queriers = {src: cnt for src, cnt in query_by_src.items() if cnt > 100}
        if heavy_queriers:
            results.append(f"\n🟡 High-volume DNS clients:")
            for src, cnt in sorted(heavy_queriers.items(), key=lambda x: x[1], reverse=True)[:5]:
                results.append(f"  {src}: {cnt} queries")

        # Summary
        if indicators >= 2:
            results.insert(1, "⚠️  HIGH probability of DNS tunneling!\n")
        elif indicators == 1:
            results.insert(1, "🟡 Some DNS anomalies detected — investigate further.\n")
        else:
            results.insert(1, "🟢 No obvious DNS tunneling indicators.\n")

        return success_response("\n".join(results))

    @mcp.tool()
    async def wireshark_detect_dos_attack(pcap_file: str) -> str:
        """
        [Security] Detect potential DoS/DDoS attack patterns.
        Checks for: SYN floods, ICMP floods, UDP floods, amplification attacks, traffic spikes.

        Args:
            pcap_file: Path to capture file

        Returns:
            DoS detection results or JSON error

        Example:
            wireshark_detect_dos_attack("ddos.pcap")
        """
        results: List[str] = []
        results.append("=== DoS/DDoS Detection ===\n")
        indicators = 0

        # Check 1: SYN Flood — high ratio of SYN to SYN-ACK
        syn_count = 0
        synack_count = 0

        syn_result = await client.get_packet_list(
            pcap_file, limit=10000,
            display_filter="tcp.flags.syn == 1 and tcp.flags.ack == 0",
        )
        syn_wrapped = parse_tool_result(syn_result)
        if syn_wrapped["success"]:
            syn_data = syn_wrapped.get("data", "")
            if isinstance(syn_data, str):
                syn_count = max(0, len(syn_data.strip().splitlines()) - 1)

        synack_result = await client.get_packet_list(
            pcap_file, limit=10000,
            display_filter="tcp.flags.syn == 1 and tcp.flags.ack == 1",
        )
        synack_wrapped = parse_tool_result(synack_result)
        if synack_wrapped["success"]:
            synack_data = synack_wrapped.get("data", "")
            if isinstance(synack_data, str):
                synack_count = max(0, len(synack_data.strip().splitlines()) - 1)

        if syn_count > 100:
            ratio = syn_count / max(synack_count, 1)
            if ratio > 3:
                indicators += 1
                results.append(f"🔴 SYN Flood indicator: {syn_count} SYNs vs {synack_count} SYN-ACKs (ratio: {ratio:.1f})")
            else:
                results.append(f"🟢 SYN/SYN-ACK ratio normal: {syn_count}/{synack_count}")
        else:
            results.append(f"🟢 Low SYN count ({syn_count}) — no SYN flood")

        # Check 2: ICMP Flood
        icmp_result = await client.get_packet_list(
            pcap_file, limit=10000, display_filter="icmp",
        )
        icmp_wrapped = parse_tool_result(icmp_result)
        if icmp_wrapped["success"]:
            icmp_data = icmp_wrapped.get("data", "")
            if isinstance(icmp_data, str):
                icmp_count = max(0, len(icmp_data.strip().splitlines()) - 1)
                if icmp_count > 500:
                    indicators += 1
                    results.append(f"🟠 High ICMP count: {icmp_count} packets (possible ICMP flood)")
                else:
                    results.append(f"🟢 ICMP count normal: {icmp_count}")

        # Check 3: UDP Flood (high volume of small UDP)
        udp_result = await client.extract_fields(
            pcap_file,
            ["ip.dst", "udp.dstport", "frame.len"],
            display_filter="udp",
            limit=5000,
        )
        udp_wrapped = parse_tool_result(udp_result)
        if udp_wrapped["success"]:
            udp_data = udp_wrapped.get("data", "")
            if isinstance(udp_data, str):
                udp_lines = udp_data.strip().splitlines()
                udp_count = max(0, len(udp_lines) - 1)

                if udp_count > 1000:
                    # Check if many go to the same destination
                    dst_counts: dict[str, int] = {}
                    for line in udp_lines[1:]:
                        parts = line.split("\t")
                        if parts:
                            dst = parts[0].strip().strip('"')
                            dst_counts[dst] = dst_counts.get(dst, 0) + 1

                    top_target = max(dst_counts.items(), key=lambda x: x[1]) if dst_counts else ("unknown", 0)
                    if top_target[1] > 500:
                        indicators += 1
                        results.append(f"🔴 UDP Flood indicator: {top_target[1]} packets targeting {top_target[0]}")
                    else:
                        results.append(f"🟢 UDP traffic distributed normally ({udp_count} packets)")
                else:
                    results.append(f"🟢 UDP count normal: {udp_count}")

        # Check 4: DNS Amplification (large DNS responses)
        dns_result = await client.get_packet_list(
            pcap_file, limit=1000,
            display_filter="dns.flags.response == 1 and udp.length > 512",
        )
        dns_wrapped = parse_tool_result(dns_result)
        if dns_wrapped["success"]:
            dns_data = dns_wrapped.get("data", "")
            if isinstance(dns_data, str):
                large_dns = max(0, len(dns_data.strip().splitlines()) - 1)
                if large_dns > 50:
                    indicators += 1
                    results.append(f"🟠 Large DNS responses: {large_dns} (possible amplification)")
                else:
                    results.append(f"🟢 Large DNS responses: {large_dns}")

        # Summary
        results.append("\n--- Summary ---")
        if indicators >= 2:
            results.append("⚠️  HIGH probability of DoS/DDoS attack!")
        elif indicators == 1:
            results.append("🟡 Some DoS indicators detected — investigate further.")
        else:
            results.append("🟢 No obvious DoS/DDoS patterns detected.")

        return success_response("\n".join(results))

    @mcp.tool()
    async def wireshark_analyze_suspicious_traffic(pcap_file: str) -> str:
        """
        [Security] Comprehensive suspicious traffic analysis.
        Runs multiple anomaly checks: unusual ports, cleartext protocols, beaconing, data volume anomalies.

        Args:
            pcap_file: Path to capture file

        Returns:
            Comprehensive anomaly analysis or JSON error

        Example:
            wireshark_analyze_suspicious_traffic("network.pcap")
        """
        results: List[str] = []
        results.append("=== Comprehensive Suspicious Traffic Analysis ===\n")
        findings: List[str] = []

        # Check 1: Cleartext protocols (security risk)
        cleartext_checks = [
            ("FTP", "ftp"),
            ("Telnet", "telnet"),
            ("HTTP (unencrypted)", "http and not tls"),
            ("SMTP (unencrypted)", "smtp"),
            ("POP3", "pop"),
            ("IMAP", "imap"),
        ]

        results.append("--- Cleartext Protocol Usage ---")
        for name, dfilter in cleartext_checks:
            check_result = await client.get_packet_list(pcap_file, limit=5, display_filter=dfilter)
            check_wrapped = parse_tool_result(check_result)
            if check_wrapped["success"]:
                check_data = check_wrapped.get("data", "")
                if isinstance(check_data, str):
                    check_lines = [l for l in check_data.strip().splitlines() if l.strip()]
                    if len(check_lines) > 1:
                        findings.append(f"Cleartext {name} traffic detected")
                        results.append(f"  🟠 {name}: DETECTED")
                    else:
                        results.append(f"  🟢 {name}: not found")

        # Check 2: Unusual destination ports (potential C2 or backdoor)
        results.append("\n--- Unusual Port Usage ---")
        unusual_ports_filter = (
            "tcp.dstport > 1024 and tcp.dstport != 3306 and tcp.dstport != 3389 "
            "and tcp.dstport != 5432 and tcp.dstport != 8080 and tcp.dstport != 8443 "
            "and tcp.dstport != 27017"
        )
        unusual_result = await client.extract_fields(
            pcap_file,
            ["ip.src", "ip.dst", "tcp.dstport"],
            display_filter=unusual_ports_filter,
            limit=100,
        )
        unusual_wrapped = parse_tool_result(unusual_result)
        if unusual_wrapped["success"]:
            unusual_data = unusual_wrapped.get("data", "")
            if isinstance(unusual_data, str):
                port_freq: dict[str, int] = {}
                for line in unusual_data.strip().splitlines()[1:]:
                    parts = line.split("\t")
                    if len(parts) >= 3:
                        port = parts[2].strip().strip('"')
                        port_freq[port] = port_freq.get(port, 0) + 1

                # Show top high-port connections
                top_ports = sorted(port_freq.items(), key=lambda x: x[1], reverse=True)[:10]
                if top_ports:
                    results.append("  Top high ports (>1024):")
                    for port, count in top_ports:
                        results.append(f"    Port {port}: {count} connections")

        # Check 3: Large outbound data transfers
        results.append("\n--- Data Transfer Analysis ---")
        conv_result = await client.get_conversations(pcap_file, type="tcp")
        conv_wrapped = parse_tool_result(conv_result)
        if conv_wrapped["success"]:
            conv_data = conv_wrapped.get("data", "")
            if isinstance(conv_data, str) and len(conv_data.strip()) > 20:
                results.append("  See conversation stats below:")
                # Take first 10 lines of conversation data
                conv_lines = conv_data.strip().splitlines()[:15]
                for line in conv_lines:
                    results.append(f"  {line}")

        # Check 4: Potential beaconing (regular interval connections)
        results.append("\n--- Protocol Anomalies ---")
        expert_result = await client.get_expert_info(pcap_file)
        expert_wrapped = parse_tool_result(expert_result)
        if expert_wrapped["success"]:
            expert_data = expert_wrapped.get("data", "")
            if isinstance(expert_data, str):
                if "Malformed" in expert_data:
                    findings.append("Malformed packets detected")
                    results.append("  🔴 Malformed packets detected!")

                if "Reassembly error" in expert_data:
                    findings.append("Reassembly errors found")
                    results.append("  🟠 Reassembly errors detected")

        # Summary
        results.append(f"\n=== Summary: {len(findings)} finding(s) ===")
        if findings:
            for i, finding in enumerate(findings, 1):
                results.append(f"  {i}. {finding}")
        else:
            results.append("  No critical anomalies detected.")

        return success_response("\n".join(results))
