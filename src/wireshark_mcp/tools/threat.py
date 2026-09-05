"""Advanced threat detection and security analysis tools."""

import logging
from typing import Any

from ..tshark.client import TSharkClient
from .envelope import envelope_response, error_response, normalize_tool_result, parse_tool_result
from .findings import Finding, FindingConstraints, FindingEvidence
from .formatting import CRIT, OK, WARN

logger = logging.getLogger("wireshark_mcp")


def _parse_time(val: str) -> float | None:
    try:
        t = float(val.strip().strip('"'))
        return t if t >= 0 else None
    except (ValueError, TypeError):
        return None


def make_threat_tools(client: TSharkClient) -> list[tuple[str, Any]]:
    """Build threat tools."""

    async def wireshark_detect_port_scan(pcap_file: str, threshold: int = 15) -> str:
        """[Security] Detect port scanning (SYN, FIN, NULL, Xmas scans). threshold: min unique dst ports to flag."""
        warnings: list[str] = []
        limit = 10000

        # 1. SYN-only packets
        syn_result = await client.extract_fields(
            pcap_file,
            ["frame.number", "ip.src", "ip.dst", "tcp.dstport"],
            display_filter="tcp.flags.syn == 1 and tcp.flags.ack == 0",
            limit=limit,
        )
        syn_wrapped = parse_tool_result(syn_result)
        if not syn_wrapped["success"]:
            return normalize_tool_result(syn_wrapped)

        syn_data = syn_wrapped.get("data", "")
        if syn_wrapped.get("truncated") is True:
            warnings.append(f"SYN scan search hit ceiling of {limit} packets.")

        src_to_ports: dict[str, set[str]] = {}
        src_to_targets: dict[str, set[str]] = {}
        src_sample_frames: dict[str, list[int]] = {}

        if isinstance(syn_data, str) and syn_data.strip():
            lines = syn_data.strip().splitlines()
            start_idx = 1 if lines and ("tcp.dstport" in lines[0] or "frame.number" in lines[0]) else 0
            for line in lines[start_idx:]:
                parts = line.split("\t")
                if len(parts) >= 4:
                    frame_raw = parts[0].strip().strip('"')
                    src = parts[1].strip().strip('"')
                    dst = parts[2].strip().strip('"')
                    port = parts[3].strip().strip('"')
                    if src and port:
                        src_to_ports.setdefault(src, set()).add(port)
                        src_to_targets.setdefault(src, set()).add(dst)
                        if frame_raw.isdigit() and len(src_sample_frames.setdefault(src, [])) < 5:
                            src_sample_frames[src].append(int(frame_raw))

        failed_checks: list[str] = []

        # 2. Stealth scans: SYN-FIN check
        synfin_result = await client.extract_fields(
            pcap_file,
            ["frame.number", "ip.src", "ip.dst", "tcp.dstport"],
            display_filter="tcp.flags.syn == 1 and tcp.flags.fin == 1",
            limit=50,
        )
        synfin_wrapped = parse_tool_result(synfin_result)
        synfin_count = 0
        synfin_frames: list[int] = []
        if synfin_wrapped["success"]:
            if synfin_wrapped.get("truncated") is True:
                warnings.append("SYN-FIN scan check reached ceiling of 50 packets.")
            synfin_data = synfin_wrapped.get("data", "")
            if isinstance(synfin_data, str) and synfin_data.strip():
                sf_lines = synfin_data.strip().splitlines()
                sf_start = 1 if sf_lines and ("frame.number" in sf_lines[0] or "tcp.dstport" in sf_lines[0]) else 0
                for line in sf_lines[sf_start:]:
                    parts = line.split("\t")
                    if parts and parts[0].strip().strip('"').isdigit():
                        synfin_count += 1
                        if len(synfin_frames) < 5:
                            synfin_frames.append(int(parts[0].strip().strip('"')))
        else:
            failed_checks.append("SYN-FIN stealth scan")
            warnings.append(
                f"SYN-FIN scan query failed: {synfin_wrapped.get('error', {}).get('message', 'query failed')}"
            )

        # 3. Stealth scans: NULL scan check
        null_result = await client.extract_fields(
            pcap_file,
            ["frame.number", "ip.src", "ip.dst", "tcp.dstport"],
            display_filter="tcp.flags == 0",
            limit=50,
        )
        null_wrapped = parse_tool_result(null_result)
        null_count = 0
        null_frames: list[int] = []
        if null_wrapped["success"]:
            if null_wrapped.get("truncated") is True:
                warnings.append("NULL scan check reached ceiling of 50 packets.")
            null_data = null_wrapped.get("data", "")
            if isinstance(null_data, str) and null_data.strip():
                nl_lines = null_data.strip().splitlines()
                nl_start = 1 if nl_lines and ("frame.number" in nl_lines[0] or "tcp.dstport" in nl_lines[0]) else 0
                for line in nl_lines[nl_start:]:
                    parts = line.split("\t")
                    if parts and parts[0].strip().strip('"').isdigit():
                        null_count += 1
                        if len(null_frames) < 5:
                            null_frames.append(int(parts[0].strip().strip('"')))
        else:
            failed_checks.append("NULL stealth scan")
            warnings.append(f"NULL scan query failed: {null_wrapped.get('error', {}).get('message', 'query failed')}")

        scanners = {src: ports for src, ports in src_to_ports.items() if len(ports) >= threshold}
        findings: list[Finding] = []
        summary_lines: list[str] = []

        if scanners or synfin_count > 0 or null_count > 0:
            evidence: list[FindingEvidence] = []
            for src, ports in sorted(scanners.items(), key=lambda x: len(x[1]), reverse=True):
                targets = src_to_targets.get(src, set())
                evidence.append(
                    FindingEvidence(
                        filter=f"ip.src == {src} and tcp.flags.syn == 1 and tcp.flags.ack == 0",
                        description=f"SYN port scanner candidate: {len(ports)} unique ports across {len(targets)} target host(s)",
                        value=f"Scanner {src} ({len(ports)} ports, {len(targets)} targets)",
                        frame=src_sample_frames.get(src, [None])[0],
                    )
                )
            if synfin_count > 0:
                evidence.append(
                    FindingEvidence(
                        protocol="TCP",
                        filter="tcp.flags.syn == 1 and tcp.flags.fin == 1",
                        description=f"SYN-FIN stealth scan (Xmas scan) activity ({synfin_count} packets)",
                        value=f"{synfin_count} SYN-FIN packets",
                        frame=synfin_frames[0] if synfin_frames else None,
                    )
                )
            if null_count > 0:
                evidence.append(
                    FindingEvidence(
                        protocol="TCP",
                        filter="tcp.flags == 0",
                        description=f"NULL scan stealth probe activity ({null_count} packets)",
                        value=f"{null_count} NULL packets",
                        frame=null_frames[0] if null_frames else None,
                    )
                )

            finding: Finding = {
                "observation": f"Port scan candidate activity detected from {len(scanners)} source(s) (threshold: {threshold} ports).",
                "severity": "high",
                "confidence": "likely" if (synfin_count or null_count) else "candidate",
                "evidence": evidence,
                "constraints": FindingConstraints(
                    scanned=len(src_to_ports),
                    limit=limit,
                    truncated=bool(warnings),
                    threshold=threshold,
                ),
                "next_steps": [
                    "Isolate top scanner IP and inspect full session frames with wireshark_get_packet_context.",
                    "Verify whether scanned ports returned RST/ACK or SYN-ACK responses.",
                ],
            }
            findings.append(finding)

            summary_lines.append(f"{CRIT} {len(scanners)} scanner candidate(s) detected (threshold: {threshold}):")
            for src, ports in sorted(scanners.items(), key=lambda x: len(x[1]), reverse=True)[:5]:
                targets = src_to_targets.get(src, set())
                sample_str = ", ".join(sorted(ports)[:10])
                summary_lines.append(
                    f"  - Scanner {src}: {len(ports)} ports across {len(targets)} target(s) (Sample: {sample_str})"
                )
            if synfin_count > 0:
                summary_lines.append(f"  - {WARN} SYN-FIN stealth packets: {synfin_count}")
            if null_count > 0:
                summary_lines.append(f"  - {WARN} NULL scan stealth packets: {null_count}")
        else:
            if failed_checks:
                finding_clean: Finding = {
                    "observation": (
                        f"No port scanning activity detected exceeding threshold of {threshold} in successful checks, "
                        f"but some stealth scan checks failed to execute ({', '.join(failed_checks)})."
                    ),
                    "severity": "info",
                    "confidence": "candidate",
                    "evidence": [],
                    "constraints": FindingConstraints(
                        scanned=len(src_to_ports),
                        limit=limit,
                        truncated=bool(warnings),
                        threshold=threshold,
                    ),
                    "next_steps": [
                        f"Re-run individual extraction queries for failed checks: {', '.join(failed_checks)}.",
                    ],
                }
                findings.append(finding_clean)
                summary_lines.append(f"{WARN} Port scan evaluation incomplete: {', '.join(failed_checks)} failed.")
            else:
                finding_clean = {
                    "observation": f"No port scanning activity detected exceeding threshold of {threshold} unique ports.",
                    "severity": "info",
                    "confidence": "confirmed",
                    "evidence": [],
                    "constraints": FindingConstraints(
                        scanned=len(src_to_ports),
                        limit=limit,
                        truncated=bool(warnings),
                        threshold=threshold,
                    ),
                    "next_steps": [
                        f"If targeted reconnaissance is suspected, lower threshold below {threshold}.",
                    ],
                }
                findings.append(finding_clean)
                summary_lines.append(f"{OK} No port scanning observed (threshold: {threshold})")
            summary_lines.append(f"  Total SYN sources evaluated: {len(src_to_ports)}")

        any_truncated = (
            syn_wrapped.get("truncated") is True
            or synfin_wrapped.get("truncated") is True
            or null_wrapped.get("truncated") is True
        )
        coverage_data: dict[str, Any] = {
            "status": "partial" if (warnings or failed_checks or any_truncated) else "complete",
            "scanned": len(src_to_ports),
            "limit": limit,
        }
        if failed_checks:
            coverage_data["failed_checks"] = failed_checks

        return envelope_response(
            data={"findings": findings, "summary": "\n".join(summary_lines)},
            scope={"pcap_file": pcap_file, "threshold": threshold},
            coverage=coverage_data,
            truncated=any_truncated,
            warnings=warnings if warnings else None,
        )

    async def wireshark_detect_dns_tunnel(pcap_file: str) -> str:
        """[Security] Detect DNS tunneling candidates (long query names, TXT abuse, high subdomain fanout)."""
        limit = 5000
        # Strictly queries only: dns.flags.response == 0
        dns_result = await client.extract_fields(
            pcap_file,
            ["frame.number", "ip.src", "dns.qry.name", "dns.qry.type"],
            display_filter="dns.flags.response == 0",
            limit=limit,
        )
        wrapped = parse_tool_result(dns_result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data", "")
        warnings: list[str] = []
        if wrapped.get("truncated") is True:
            warnings.append(f"DNS query scan reached limit of {limit} queries; results represent partial capture.")

        if not isinstance(data, str) or not data.strip():
            return envelope_response(
                data={
                    "findings": [],
                    "summary": f"{OK} No DNS query traffic found in capture.",
                },
                scope={"pcap_file": pcap_file, "filter": "dns.flags.response == 0"},
                coverage={"status": "complete", "scanned": 0, "limit": limit},
            )

        lines = data.strip().splitlines()
        start_idx = 1 if lines and ("dns.qry.name" in lines[0] or "frame.number" in lines[0]) else 0

        long_queries: list[dict[str, Any]] = []
        txt_queries: list[dict[str, Any]] = []
        query_by_src: dict[str, int] = {}
        unique_subdomains: dict[str, set[str]] = {}
        total_queries = 0

        for line in lines[start_idx:]:
            parts = line.split("\t")
            if len(parts) >= 4:
                frame_raw = parts[0].strip().strip('"')
                src = parts[1].strip().strip('"')
                qname = parts[2].strip().strip('"')
                qtype = parts[3].strip().strip('"')
                if not qname:
                    continue
                total_queries += 1
                frame_num = int(frame_raw) if frame_raw.isdigit() else None
                query_by_src[src] = query_by_src.get(src, 0) + 1

                if len(qname) > 50:
                    long_queries.append({"name": qname, "frame": frame_num, "src": src})
                if qtype in ("16", "TXT"):
                    txt_queries.append({"name": qname, "frame": frame_num, "src": src})

                parts_domain = qname.split(".")
                if len(parts_domain) >= 3:
                    base = ".".join(parts_domain[-2:])
                    subdomain = ".".join(parts_domain[:-2])
                    unique_subdomains.setdefault(base, set()).add(subdomain)

        if total_queries == 0:
            return envelope_response(
                data={
                    "findings": [],
                    "summary": f"{OK} No valid DNS queries found in capture.",
                },
                scope={"pcap_file": pcap_file, "filter": "dns.flags.response == 0"},
                coverage={"status": "complete", "scanned": 0, "limit": limit},
            )

        indicators = 0
        evidence_list: list[FindingEvidence] = []

        if long_queries:
            indicators += 1
            sample = long_queries[0]
            evidence_list.append(
                FindingEvidence(
                    field="dns.qry.name",
                    filter="dns.flags.response == 0 and dns.qry.name.len > 50",
                    description=f"{len(long_queries)} query name(s) exceeding 50 characters",
                    value=f"Sample [{len(sample['name'])} chars]: {sample['name'][:60]}...",
                    frame=sample.get("frame"),
                )
            )

        if len(txt_queries) > 10:
            indicators += 1
            sample_txt = txt_queries[0]
            evidence_list.append(
                FindingEvidence(
                    field="dns.qry.type",
                    filter="dns.flags.response == 0 and dns.qry.type == 16",
                    description=f"High TXT query volume ({len(txt_queries)} queries, {len(set(q['name'] for q in txt_queries))} unique)",
                    value=f"Sample TXT query: {sample_txt['name'][:60]}",
                    frame=sample_txt.get("frame"),
                )
            )

        suspicious_domains = {d: s for d, s in unique_subdomains.items() if len(s) > 20}
        if suspicious_domains:
            indicators += 1
            top_domain, subs = max(suspicious_domains.items(), key=lambda x: len(x[1]))
            evidence_list.append(
                FindingEvidence(
                    field="dns.qry.name",
                    filter=f'dns.flags.response == 0 and dns.qry.name contains "{top_domain}"',
                    description=f"High subdomain cardinality under single base domain ({len(subs)} unique subdomains)",
                    value=f"{top_domain} with {len(subs)} subdomains",
                )
            )

        findings: list[Finding] = []
        summary_lines: list[str] = [f"DNS queries evaluated: {total_queries}"]

        if indicators >= 2:
            finding: Finding = {
                "observation": f"Candidate DNS tunneling / covert exfiltration signals observed ({indicators} indicators triggered across {total_queries} queries).",
                "severity": "high",
                "confidence": "candidate",
                "evidence": evidence_list,
                "constraints": FindingConstraints(
                    scanned=total_queries,
                    limit=limit,
                    truncated=bool(warnings),
                ),
                "next_steps": [
                    "Correlate candidate domains against known CDN and enterprise cloud infrastructure before declaring malicious intent.",
                    "Inspect payload decoding of subdomains with wireshark_follow_stream or python base64/hex decoders.",
                ],
            }
            findings.append(finding)
            summary_lines.insert(0, f"{CRIT} Candidate DNS tunneling signals detected (requires domain validation):")
        elif indicators == 1:
            finding = {
                "observation": f"Isolated DNS query anomaly observed in {total_queries} queries.",
                "severity": "medium",
                "confidence": "candidate",
                "evidence": evidence_list,
                "constraints": FindingConstraints(
                    scanned=total_queries,
                    limit=limit,
                    truncated=bool(warnings),
                ),
                "next_steps": [
                    "Inspect queries from top querying clients using wireshark_extract_dns_queries.",
                ],
            }
            findings.append(finding)
            summary_lines.insert(0, f"{WARN} Isolated DNS query anomaly observed:")
        else:
            finding = {
                "observation": f"No DNS tunneling candidate indicators observed across {total_queries} scanned queries.",
                "severity": "info",
                "confidence": "confirmed",
                "evidence": [],
                "constraints": FindingConstraints(
                    scanned=total_queries,
                    limit=limit,
                    truncated=bool(warnings),
                ),
                "next_steps": [
                    "For stealthy tunnels, run wireshark_aggregate with group_by=['dns.qry.name'] over a wider window.",
                ],
            }
            findings.append(finding)
            summary_lines.insert(0, f"{OK} No DNS tunneling indicators observed.")

        for ev in evidence_list:
            summary_lines.append(f"  - {ev.get('description')}: {ev.get('value')}")

        return envelope_response(
            data={"findings": findings, "summary": "\n".join(summary_lines)},
            scope={"pcap_file": pcap_file, "filter": "dns.flags.response == 0"},
            coverage={"status": "partial" if warnings else "complete", "scanned": total_queries, "limit": limit},
            warnings=warnings if warnings else None,
        )

    async def wireshark_detect_dos_attack(pcap_file: str) -> str:
        """[Security] Detect DoS/DDoS traffic volume patterns (SYN flood, ICMP/UDP flood, DNS amplification)."""
        limit = 10000
        warnings: list[str] = []
        all_timestamps: list[float] = []

        # 1. SYN
        syn_result = await client.extract_fields(
            pcap_file,
            ["frame.number", "frame.time_relative", "ip.src", "ip.dst"],
            display_filter="tcp.flags.syn == 1 and tcp.flags.ack == 0",
            limit=limit,
        )
        syn_wrapped = parse_tool_result(syn_result)
        if not syn_wrapped["success"]:
            return error_response(f"SYN analysis failed: {syn_wrapped.get('error', {}).get('message', 'tshark error')}")

        syn_truncated = syn_wrapped.get("truncated") is True
        if syn_truncated:
            warnings.append(f"SYN search reached ceiling of {limit} packets.")

        syn_lines = syn_wrapped.get("data", "").strip().splitlines() if isinstance(syn_wrapped.get("data"), str) else []
        syn_start = 1 if syn_lines and ("frame.number" in syn_lines[0] or "ip.src" in syn_lines[0]) else 0
        syn_count = max(0, len(syn_lines) - syn_start)
        for line in syn_lines[syn_start:]:
            parts = line.split("\t")
            if len(parts) >= 2:
                t = _parse_time(parts[1])
                if t is not None:
                    all_timestamps.append(t)

        failed_checks: list[str] = []

        # 2. SYN-ACK
        synack_result = await client.extract_fields(
            pcap_file,
            ["frame.number", "frame.time_relative"],
            display_filter="tcp.flags.syn == 1 and tcp.flags.ack == 1",
            limit=limit,
        )
        synack_wrapped = parse_tool_result(synack_result)
        synack_count: int | None = None
        if synack_wrapped["success"]:
            if synack_wrapped.get("truncated") is True:
                warnings.append(f"SYN-ACK search reached ceiling of {limit} packets.")
            synack_lines = (
                synack_wrapped.get("data", "").strip().splitlines()
                if isinstance(synack_wrapped.get("data"), str)
                else []
            )
            synack_start = (
                1
                if synack_lines and ("frame.number" in synack_lines[0] or "frame.time_relative" in synack_lines[0])
                else 0
            )
            synack_count = max(0, len(synack_lines) - synack_start)
            for line in synack_lines[synack_start:]:
                parts = line.split("\t")
                if len(parts) >= 2:
                    t = _parse_time(parts[1])
                    if t is not None:
                        all_timestamps.append(t)
        else:
            failed_checks.append("SYN-ACK response analysis")
            warnings.append(f"SYN-ACK query failed: {synack_wrapped.get('error', {}).get('message', 'query failed')}")

        # 3. ICMP
        icmp_result = await client.extract_fields(
            pcap_file,
            ["frame.number", "frame.time_relative", "ip.src", "ip.dst"],
            display_filter="icmp",
            limit=limit,
        )
        icmp_wrapped = parse_tool_result(icmp_result)
        icmp_count = 0
        if icmp_wrapped["success"]:
            if icmp_wrapped.get("truncated") is True:
                warnings.append(f"ICMP search reached ceiling of {limit} packets.")
            icmp_lines = (
                icmp_wrapped.get("data", "").strip().splitlines() if isinstance(icmp_wrapped.get("data"), str) else []
            )
            icmp_start = 1 if icmp_lines and ("frame.number" in icmp_lines[0] or "ip.src" in icmp_lines[0]) else 0
            icmp_count = max(0, len(icmp_lines) - icmp_start)
            for line in icmp_lines[icmp_start:]:
                parts = line.split("\t")
                if len(parts) >= 2:
                    t = _parse_time(parts[1])
                    if t is not None:
                        all_timestamps.append(t)
        else:
            failed_checks.append("ICMP flood analysis")
            warnings.append(f"ICMP query failed: {icmp_wrapped.get('error', {}).get('message', 'query failed')}")

        # 4. UDP
        udp_result = await client.extract_fields(
            pcap_file,
            ["frame.number", "frame.time_relative", "ip.dst", "udp.dstport", "frame.len"],
            display_filter="udp",
            limit=5000,
        )
        udp_wrapped = parse_tool_result(udp_result)
        udp_count = 0
        top_target = ("none", 0)
        if udp_wrapped["success"]:
            if udp_wrapped.get("truncated") is True:
                warnings.append("UDP search reached ceiling of 5000 packets.")
            udp_lines = (
                udp_wrapped.get("data", "").strip().splitlines() if isinstance(udp_wrapped.get("data"), str) else []
            )
            udp_start = (
                1 if udp_lines and ("frame.number" in udp_lines[0] or "frame.time_relative" in udp_lines[0]) else 0
            )
            udp_count = max(0, len(udp_lines) - udp_start)
            dst_counts: dict[str, int] = {}
            for line in udp_lines[udp_start:]:
                parts = line.split("\t")
                if len(parts) >= 3:
                    t = _parse_time(parts[1])
                    if t is not None:
                        all_timestamps.append(t)
                    dst = parts[2].strip().strip('"')
                    if dst:
                        dst_counts[dst] = dst_counts.get(dst, 0) + 1
            top_target = max(dst_counts.items(), key=lambda x: x[1]) if dst_counts else ("none", 0)
        else:
            failed_checks.append("UDP flood analysis")
            warnings.append(f"UDP query failed: {udp_wrapped.get('error', {}).get('message', 'query failed')}")

        # 5. DNS Amplification
        dns_amp_result = await client.extract_fields(
            pcap_file,
            ["frame.number", "frame.time_relative", "udp.length"],
            display_filter="dns.flags.response == 1 and udp.length > 512",
            limit=1000,
        )
        dns_amp_wrapped = parse_tool_result(dns_amp_result)
        large_dns = 0
        if dns_amp_wrapped["success"]:
            if dns_amp_wrapped.get("truncated") is True:
                warnings.append("DNS amplification search reached ceiling of 1000 packets.")
            dns_amp_lines = (
                dns_amp_wrapped.get("data", "").strip().splitlines()
                if isinstance(dns_amp_wrapped.get("data"), str)
                else []
            )
            dns_amp_start = (
                1 if dns_amp_lines and ("frame.number" in dns_amp_lines[0] or "udp.length" in dns_amp_lines[0]) else 0
            )
            large_dns = max(0, len(dns_amp_lines) - dns_amp_start)
            for line in dns_amp_lines[dns_amp_start:]:
                parts = line.split("\t")
                if len(parts) >= 2:
                    t = _parse_time(parts[1])
                    if t is not None:
                        all_timestamps.append(t)
        else:
            failed_checks.append("DNS amplification analysis")
            warnings.append(
                f"DNS amplification query failed: {dns_amp_wrapped.get('error', {}).get('message', 'query failed')}"
            )

        duration = max((max(all_timestamps) - min(all_timestamps)) if all_timestamps else 1.0, 1.0)
        syn_rate = syn_count / duration
        icmp_rate = icmp_count / duration
        udp_rate = udp_count / duration

        # Single-sided capture detection
        if (
            synack_count is not None
            and syn_count > 50
            and synack_count == 0
            and "SYN-ACK response analysis" not in failed_checks
        ):
            warnings.append(
                "Asymmetric or single-sided capture suspected: 0 SYN-ACK responses observed despite SYN activity. "
                "SYN ratios may reflect tap vantage point rather than a true denial-of-service attack."
            )

        indicators = 0
        evidence_list: list[FindingEvidence] = []
        summary_lines: list[str] = [f"Observed window: {duration:.1f}s"]

        # SYN Flood evaluation
        if synack_count is None:
            if syn_count > 50 and syn_rate > 30:
                summary_lines.append(
                    f"{WARN} Elevated SYN rate: {syn_count} pkts ({syn_rate:.1f} syn/s), "
                    f"but SYN-ACK ratio cannot be evaluated (SYN-ACK check failed)"
                )
            else:
                summary_lines.append(
                    f"{WARN} SYN-ACK response check failed; SYN traffic: {syn_count} pkts ({syn_rate:.1f}/s)"
                )
        elif syn_count > 50 and syn_rate > 30:
            ratio = syn_count / max(synack_count, 1)
            if ratio > 3 or synack_count == 0:
                indicators += 1
                evidence_list.append(
                    FindingEvidence(
                        filter="tcp.flags.syn == 1 and tcp.flags.ack == 0",
                        description=f"SYN flood candidate: {syn_count} SYNs ({syn_rate:.1f} syn/s) vs {synack_count} SYN-ACKs",
                        value=f"Ratio {ratio:.1f}, {syn_rate:.1f} pps",
                    )
                )
                summary_lines.append(
                    f"{CRIT} SYN Flood candidate: {syn_count} SYNs ({syn_rate:.1f}/s) vs {synack_count} SYN-ACKs"
                )
            else:
                summary_lines.append(
                    f"{OK} SYN/SYN-ACK ratio balanced ({syn_count} SYNs vs {synack_count} SYN-ACKs, Ratio {ratio:.1f})"
                )
        else:
            summary_lines.append(f"{OK} SYN traffic within normal bounds ({syn_count} pkts, {syn_rate:.1f}/s)")

        # ICMP Flood evaluation
        if "ICMP flood analysis" in failed_checks:
            summary_lines.append(f"{WARN} ICMP flood check failed to execute (inconclusive)")
        elif icmp_count > 200 and icmp_rate > 50:
            indicators += 1
            evidence_list.append(
                FindingEvidence(
                    filter="icmp",
                    description=f"ICMP flood candidate: {icmp_count} packets ({icmp_rate:.1f} icmp/s)",
                    value=f"{icmp_rate:.1f} icmp/s",
                )
            )
            summary_lines.append(f"{WARN} ICMP flood candidate: {icmp_count} packets ({icmp_rate:.1f}/s)")
        else:
            summary_lines.append(f"{OK} ICMP normal ({icmp_count} pkts, {icmp_rate:.1f}/s)")

        # UDP Flood evaluation
        if "UDP flood analysis" in failed_checks:
            summary_lines.append(f"{WARN} UDP flood check failed to execute (inconclusive)")
        elif top_target[1] > 200 and udp_rate > 50:
            indicators += 1
            evidence_list.append(
                FindingEvidence(
                    filter=f"udp and ip.dst == {top_target[0]}",
                    description=f"UDP flood candidate against {top_target[0]}: {top_target[1]} packets",
                    value=f"{top_target[1]} pkts to {top_target[0]}",
                )
            )
            summary_lines.append(
                f"{CRIT} UDP flood candidate: {top_target[1]} pkts -> {top_target[0]} ({udp_rate:.1f}/s)"
            )
        else:
            summary_lines.append(f"{OK} UDP normal ({udp_count} pkts, {udp_rate:.1f}/s)")

        # DNS Amplification evaluation
        if "DNS amplification analysis" in failed_checks:
            summary_lines.append(f"{WARN} DNS amplification check failed to execute (inconclusive)")
        elif large_dns > 50:
            indicators += 1
            evidence_list.append(
                FindingEvidence(
                    filter="dns.flags.response == 1 and udp.length > 512",
                    description=f"DNS amplification responses: {large_dns} responses > 512 bytes",
                    value=f"{large_dns} oversized responses",
                )
            )
            summary_lines.append(f"{WARN} Large DNS responses: {large_dns} (amplification candidate)")
        else:
            summary_lines.append(f"{OK} Large DNS responses: {large_dns}")

        any_truncated = (
            syn_truncated
            or (synack_wrapped.get("truncated") is True)
            or (icmp_wrapped.get("truncated") is True)
            or (udp_wrapped.get("truncated") is True)
            or (dns_amp_wrapped.get("truncated") is True)
        )

        findings: list[Finding] = []
        if indicators >= 2:
            findings.append(
                Finding(
                    observation=f"Candidate DoS / traffic flood patterns observed ({indicators} signals active across {duration:.1f}s window).",
                    severity="high",
                    confidence="candidate",
                    evidence=evidence_list,
                    constraints=FindingConstraints(
                        time_window_seconds=round(duration, 2),
                        single_sided=bool(warnings),
                        limit=limit,
                        truncated=any_truncated,
                    ),
                    next_steps=[
                        "Correlate volume burst times with server resource exhaustion or packet drops.",
                        "Inspect firewall connection rate limiting or SYN cookies configuration.",
                    ],
                )
            )
            summary_lines.insert(0, f"{CRIT} Candidate DoS/DDoS flood signals detected:")
        elif indicators == 1:
            findings.append(
                Finding(
                    observation=f"Isolated traffic flood pattern observed across {duration:.1f}s window.",
                    severity="medium",
                    confidence="candidate",
                    evidence=evidence_list,
                    constraints=FindingConstraints(
                        time_window_seconds=round(duration, 2),
                        single_sided=bool(warnings),
                        limit=limit,
                        truncated=any_truncated,
                    ),
                    next_steps=[
                        "Inspect traffic timeline using wireshark_stats_io_graph.",
                    ],
                )
            )
            summary_lines.insert(0, f"{WARN} Isolated traffic volume signal observed:")
        else:
            if failed_checks:
                findings.append(
                    Finding(
                        observation=(
                            f"Partial DoS/DDoS evaluation: no flood patterns observed in successful checks ({duration:.1f}s analyzed candidate window), "
                            f"but some checks failed to execute: {', '.join(failed_checks)}."
                        ),
                        severity="info",
                        confidence="candidate",
                        evidence=[],
                        constraints=FindingConstraints(
                            time_window_seconds=round(duration, 2),
                            single_sided=bool(warnings),
                            limit=limit,
                            truncated=any_truncated,
                        ),
                        next_steps=[
                            f"Re-run individual extraction queries for failed checks: {', '.join(failed_checks)}.",
                        ],
                    )
                )
                summary_lines.insert(
                    0,
                    f"{WARN} Partial DoS/DDoS evaluation: successful checks showed no floods, but {len(failed_checks)} check(s) failed.",
                )
            else:
                findings.append(
                    Finding(
                        observation=f"No anomalous DoS/DDoS flood patterns observed within {duration:.1f}s window.",
                        severity="info",
                        confidence="confirmed",
                        evidence=[],
                        constraints=FindingConstraints(
                            time_window_seconds=round(duration, 2),
                            single_sided=bool(warnings),
                            limit=limit,
                            truncated=any_truncated,
                        ),
                        next_steps=[],
                    )
                )
                summary_lines.insert(0, f"{OK} No DoS/DDoS flood patterns detected.")

        coverage_dos: dict[str, Any] = {
            "status": "partial" if (warnings or failed_checks or any_truncated) else "complete",
            "scanned": syn_count + (synack_count or 0) + icmp_count + udp_count + large_dns,
            "limit": limit,
        }
        if failed_checks:
            coverage_dos["failed_checks"] = failed_checks

        return envelope_response(
            data={"findings": findings, "summary": "\n".join(summary_lines)},
            scope={"pcap_file": pcap_file},
            coverage=coverage_dos,
            truncated=any_truncated,
            warnings=warnings if warnings else None,
        )

    return [
        ("wireshark_detect_port_scan", wireshark_detect_port_scan),
        ("wireshark_detect_dns_tunnel", wireshark_detect_dns_tunnel),
        ("wireshark_detect_dos_attack", wireshark_detect_dos_attack),
    ]
