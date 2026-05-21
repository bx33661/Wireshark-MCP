"""Advanced threat detection and security analysis tools."""

import logging
from typing import Any

from ..tshark.client import TSharkClient
from .envelope import normalize_tool_result, parse_tool_result, success_response
from .formatting import CRIT, INFO, OK, WARN

logger = logging.getLogger("wireshark_mcp")


def make_contextual_threat_tools(client: TSharkClient) -> list[tuple[str, Any]]:
    """Create contextual threat tools for the stable contextual catalog."""

    async def wireshark_detect_port_scan(pcap_file: str, threshold: int = 15) -> str:
        """[Security] Detect port scanning (SYN, FIN, NULL, Xmas scans). threshold: min unique dst ports to flag."""
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

        src_to_ports: dict[str, set[str]] = {}
        src_to_targets: dict[str, set[str]] = {}

        lines = data.strip().splitlines()
        for line in lines[1:]:
            parts = line.split("\t")
            if len(parts) >= 3:
                src = parts[0].strip().strip('"')
                dst = parts[1].strip().strip('"')
                port = parts[2].strip().strip('"')
                if src and port:
                    src_to_ports.setdefault(src, set()).add(port)
                    src_to_targets.setdefault(src, set()).add(dst)

        results: list[str] = []
        scanners = {src: ports for src, ports in src_to_ports.items() if len(ports) >= threshold}

        if scanners:
            results.append(f"{CRIT} {len(scanners)} scanner(s) detected\n")
            for src, ports in sorted(scanners.items(), key=lambda x: len(x[1]), reverse=True):
                targets = src_to_targets.get(src, set())
                results.append(f"Scanner: {src}")
                results.append(f"  Ports: {len(ports)}, Targets: {len(targets)}")
                results.append(f"  Sample: {', '.join(sorted(ports)[:20])}")
                if len(ports) > 20:
                    results.append(f"  ... +{len(ports) - 20} more")
        else:
            results.append(f"{OK} No port scanning (threshold: {threshold})")
            results.append(f"SYN packets: {len(lines) - 1}, Sources: {len(src_to_ports)}")

        # SYN-FIN check
        synfin_result = await client.get_packet_list(
            pcap_file,
            limit=10,
            display_filter="tcp.flags.syn == 1 and tcp.flags.fin == 1",
        )
        synfin_wrapped = parse_tool_result(synfin_result)
        if synfin_wrapped["success"]:
            synfin_data = synfin_wrapped.get("data", "")
            if isinstance(synfin_data, str):
                synfin_lines = [line for line in synfin_data.strip().splitlines() if line.strip()]
                if len(synfin_lines) > 1:
                    results.append(f"\n{CRIT} SYN-FIN packets: {len(synfin_lines) - 1} (Xmas/stealth scan)")

        # NULL scan check
        null_result = await client.get_packet_list(
            pcap_file,
            limit=10,
            display_filter="tcp.flags == 0",
        )
        null_wrapped = parse_tool_result(null_result)
        if null_wrapped["success"]:
            null_data = null_wrapped.get("data", "")
            if isinstance(null_data, str):
                null_lines = [line for line in null_data.strip().splitlines() if line.strip()]
                if len(null_lines) > 1:
                    results.append(f"\n{WARN} NULL packets: {len(null_lines) - 1} (NULL scan)")

        return success_response("\n".join(results))

    async def wireshark_detect_dns_tunnel(pcap_file: str) -> str:
        """[Security] Detect DNS tunneling (long queries, TXT abuse, subdomain entropy)."""
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
            return success_response("No DNS traffic found.")

        long_queries: list[str] = []
        txt_queries: list[str] = []
        query_by_src: dict[str, int] = {}
        unique_subdomains: dict[str, set[str]] = {}
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
                if len(qname) > 50:
                    long_queries.append(qname)
                if qtype in ("16", "TXT"):
                    txt_queries.append(qname)
                parts_domain = qname.split(".")
                if len(parts_domain) >= 3:
                    base = ".".join(parts_domain[-2:])
                    subdomain = ".".join(parts_domain[:-2])
                    unique_subdomains.setdefault(base, set()).add(subdomain)

        results: list[str] = [f"DNS queries analyzed: {total_queries}"]
        indicators = 0

        if long_queries:
            indicators += 1
            results.append(f"{CRIT} Long queries (>50 chars): {len(long_queries)}")
            for q in long_queries[:5]:
                results.append(f"  [{len(q)}] {q[:80]}")

        if len(txt_queries) > 10:
            indicators += 1
            results.append(f"{WARN} TXT queries: {len(txt_queries)} (unique: {len(set(txt_queries))})")

        suspicious_domains = {d: s for d, s in unique_subdomains.items() if len(s) > 20}
        if suspicious_domains:
            indicators += 1
            results.append(f"{CRIT} Excessive subdomains:")
            for domain, subs in sorted(suspicious_domains.items(), key=lambda x: len(x[1]), reverse=True)[:5]:
                results.append(f"  {domain}: {len(subs)} unique")

        heavy_queriers = {src: cnt for src, cnt in query_by_src.items() if cnt > 100}
        if heavy_queriers:
            results.append(f"{INFO} High-volume clients:")
            for src, cnt in sorted(heavy_queriers.items(), key=lambda x: x[1], reverse=True)[:5]:
                results.append(f"  {src}: {cnt}")

        if indicators >= 2:
            results.insert(0, f"{CRIT} HIGH probability of DNS tunneling\n")
        elif indicators == 1:
            results.insert(0, f"{WARN} Some DNS anomalies — investigate further\n")
        else:
            results.insert(0, f"{OK} No DNS tunneling indicators\n")

        return success_response("\n".join(results))

    async def wireshark_detect_dos_attack(pcap_file: str) -> str:
        """[Security] Detect DoS/DDoS patterns (SYN flood, ICMP/UDP flood, DNS amplification)."""
        results: list[str] = []
        indicators = 0

        # SYN Flood
        syn_count = 0
        synack_count = 0
        syn_result = await client.get_packet_list(
            pcap_file,
            limit=10000,
            display_filter="tcp.flags.syn == 1 and tcp.flags.ack == 0",
        )
        syn_wrapped = parse_tool_result(syn_result)
        if syn_wrapped["success"]:
            syn_data = syn_wrapped.get("data", "")
            if isinstance(syn_data, str):
                syn_count = max(0, len(syn_data.strip().splitlines()) - 1)

        synack_result = await client.get_packet_list(
            pcap_file,
            limit=10000,
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
                results.append(f"{CRIT} SYN Flood: {syn_count} SYNs vs {synack_count} SYN-ACKs (ratio {ratio:.1f})")
            else:
                results.append(f"{OK} SYN/SYN-ACK ratio normal: {syn_count}/{synack_count}")
        else:
            results.append(f"{OK} Low SYN count ({syn_count})")

        # ICMP Flood
        icmp_result = await client.get_packet_list(pcap_file, limit=10000, display_filter="icmp")
        icmp_wrapped = parse_tool_result(icmp_result)
        if icmp_wrapped["success"]:
            icmp_data = icmp_wrapped.get("data", "")
            if isinstance(icmp_data, str):
                icmp_count = max(0, len(icmp_data.strip().splitlines()) - 1)
                if icmp_count > 500:
                    indicators += 1
                    results.append(f"{WARN} ICMP flood: {icmp_count} packets")
                else:
                    results.append(f"{OK} ICMP normal: {icmp_count}")

        # UDP Flood
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
                    dst_counts: dict[str, int] = {}
                    for line in udp_lines[1:]:
                        parts = line.split("\t")
                        if parts:
                            dst = parts[0].strip().strip('"')
                            dst_counts[dst] = dst_counts.get(dst, 0) + 1
                    top_target = max(dst_counts.items(), key=lambda x: x[1]) if dst_counts else ("unknown", 0)
                    if top_target[1] > 500:
                        indicators += 1
                        results.append(f"{CRIT} UDP flood: {top_target[1]} packets -> {top_target[0]}")
                    else:
                        results.append(f"{OK} UDP distributed normally ({udp_count})")
                else:
                    results.append(f"{OK} UDP normal: {udp_count}")

        # DNS Amplification
        dns_result = await client.get_packet_list(
            pcap_file,
            limit=1000,
            display_filter="dns.flags.response == 1 and udp.length > 512",
        )
        dns_wrapped = parse_tool_result(dns_result)
        if dns_wrapped["success"]:
            dns_data = dns_wrapped.get("data", "")
            if isinstance(dns_data, str):
                large_dns = max(0, len(dns_data.strip().splitlines()) - 1)
                if large_dns > 50:
                    indicators += 1
                    results.append(f"{WARN} Large DNS responses: {large_dns} (amplification)")
                else:
                    results.append(f"{OK} Large DNS responses: {large_dns}")

        # Summary
        if indicators >= 2:
            results.insert(0, f"{CRIT} HIGH probability of DoS/DDoS\n")
        elif indicators == 1:
            results.insert(0, f"{WARN} Some DoS indicators\n")
        else:
            results.insert(0, f"{OK} No DoS/DDoS patterns\n")

        return success_response("\n".join(results))

    async def wireshark_analyze_suspicious_traffic(pcap_file: str) -> str:
        """[Security] Comprehensive anomaly analysis (cleartext, unusual ports, data volumes)."""
        results: list[str] = []
        findings: list[str] = []

        # Cleartext protocols
        cleartext_checks = [
            ("FTP", "ftp"),
            ("Telnet", "telnet"),
            ("HTTP", "http and not tls"),
            ("SMTP", "smtp"),
            ("POP3", "pop"),
            ("IMAP", "imap"),
        ]
        for name, dfilter in cleartext_checks:
            check_result = await client.get_packet_list(pcap_file, limit=5, display_filter=dfilter)
            check_wrapped = parse_tool_result(check_result)
            if check_wrapped["success"]:
                check_data = check_wrapped.get("data", "")
                if isinstance(check_data, str):
                    check_lines = [line for line in check_data.strip().splitlines() if line.strip()]
                    if len(check_lines) > 1:
                        findings.append(f"Cleartext {name}")
                        results.append(f"{WARN} {name}: detected")

        # Unusual ports
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
                top_ports = sorted(port_freq.items(), key=lambda x: x[1], reverse=True)[:10]
                if top_ports:
                    results.append("High ports (>1024):")
                    for port, count in top_ports:
                        results.append(f"  :{port} x{count}")

        # Protocol anomalies
        expert_result = await client.get_expert_info(pcap_file)
        expert_wrapped = parse_tool_result(expert_result)
        if expert_wrapped["success"]:
            expert_data = expert_wrapped.get("data", "")
            if isinstance(expert_data, str):
                if "Malformed" in expert_data:
                    findings.append("Malformed packets")
                    results.append(f"{CRIT} Malformed packets")
                if "Reassembly error" in expert_data:
                    findings.append("Reassembly errors")
                    results.append(f"{WARN} Reassembly errors")

        results.append(f"\nFindings: {len(findings)}")
        for i, finding in enumerate(findings, 1):
            results.append(f"  {i}. {finding}")

        return success_response("\n".join(results))

    return [
        ("wireshark_detect_port_scan", wireshark_detect_port_scan),
        ("wireshark_detect_dns_tunnel", wireshark_detect_dns_tunnel),
        ("wireshark_detect_dos_attack", wireshark_detect_dos_attack),
        ("wireshark_analyze_suspicious_traffic", wireshark_analyze_suspicious_traffic),
    ]
