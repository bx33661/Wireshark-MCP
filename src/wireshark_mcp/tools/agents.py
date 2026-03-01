"""Agentic Workflow — server-side orchestrated analysis tools.

These "super tools" chain multiple TSharkClient operations internally,
returning comprehensive structured reports from a single tool call.
"""

import logging

from mcp.server.fastmcp import FastMCP

from ..tshark.client import TSharkClient
from .envelope import normalize_tool_result, parse_tool_result, success_response

logger = logging.getLogger("wireshark_mcp")


# ── Shared helpers ───────────────────────────────────────────────────────────


def _count_lines(data: str) -> int:
    """Count non-empty data lines (excluding header)."""
    lines = [line for line in data.strip().splitlines() if line.strip()]
    return max(0, len(lines) - 1)


def _extract_data(result: str) -> str | None:
    """Parse a tool result and return the data string if successful, else None."""
    wrapped = parse_tool_result(normalize_tool_result(result))
    if wrapped["success"]:
        data = wrapped.get("data", "")
        if isinstance(data, str) and len(data.strip()) > 10:
            return data
    return None


async def _safe_run(coro, default=None):
    """Run a coroutine, returning default on any exception."""
    try:
        return await coro
    except Exception as e:
        logger.debug("Safe run caught exception: %s", e)
        return default


# ── Security Audit ───────────────────────────────────────────────────────────


async def _run_security_audit(client: TSharkClient, pcap_file: str) -> str:
    """Execute comprehensive security audit pipeline."""

    report: list[str] = []
    findings: list[str] = []
    risk_score = 0  # 0-100, higher = worse

    report.append("╔══════════════════════════════════════════════════════╗")
    report.append("║           SECURITY AUDIT REPORT                     ║")
    report.append("╚══════════════════════════════════════════════════════╝\n")

    # ── Phase 1: File & Protocol Overview ────────────────────────────────
    file_info_raw = await _safe_run(client.get_file_info(pcap_file), "")
    file_info = _extract_data(file_info_raw) if file_info_raw else None

    phs_raw = await _safe_run(client.get_protocol_stats(pcap_file), "")
    phs_data = _extract_data(phs_raw) if phs_raw else None

    report.append("┌─── 1. File Summary ───────────────────────────────────")
    if file_info:
        # Take first 10 lines of capinfos output
        for line in file_info.strip().splitlines()[:10]:
            report.append(f"│  {line}")
    else:
        report.append("│  ⚠️  Could not read file info")
    report.append("└───────────────────────────────────────────────────────\n")

    # Detect protocols present
    detected_protocols: set[str] = set()
    if phs_data:
        import re

        for line in phs_data.splitlines():
            match = re.match(r"^\s*(\w[\w.-]*)\s+frames:", line)
            if match:
                detected_protocols.add(match.group(1).lower())

    report.append("┌─── 2. Protocol Overview ──────────────────────────────")
    if detected_protocols:
        report.append(f"│  Detected: {', '.join(sorted(detected_protocols))}")
    else:
        report.append("│  No protocol hierarchy available")
    report.append("└───────────────────────────────────────────────────────\n")

    # ── Phase 2: Threat Intelligence ─────────────────────────────────────
    report.append("┌─── 3. Threat Intelligence ────────────────────────────")

    # Extract unique IPs
    unique_ips: set[str] = set()
    ips_raw = await _safe_run(client.extract_fields(pcap_file, ["ip.src", "ip.dst"], limit=10000), "")
    ips_data = _extract_data(ips_raw) if ips_raw else None
    if ips_data:
        for line in ips_data.splitlines()[1:]:
            for val in line.split("\t"):
                val = val.strip().strip('"')
                if val and not val.startswith("["):
                    unique_ips.add(val)

    report.append(f"│  Unique IPs found: {len(unique_ips)}")

    # Check against URLhaus
    malicious_ips: list[str] = []
    try:
        from .security import _get_threat_data

        threat_feed = await _get_threat_data()
        malicious_ips = [ip for ip in unique_ips if ip in threat_feed]

        if malicious_ips:
            risk_score += 40
            findings.append(f"🔴 {len(malicious_ips)} IP(s) found in URLhaus threat feed")
            report.append(f"│  🔴 MALICIOUS IPs: {len(malicious_ips)}")
            for ip in malicious_ips[:10]:
                report.append(f"│     • {ip}")
            if len(malicious_ips) > 10:
                report.append(f"│     ... and {len(malicious_ips) - 10} more")
        else:
            report.append("│  🟢 No IPs matched known threat feeds")
    except Exception as e:
        report.append(f"│  ⚠️  Threat feed unavailable: {e}")

    report.append("└───────────────────────────────────────────────────────\n")

    # ── Phase 3: Credential Exposure ─────────────────────────────────────
    report.append("┌─── 4. Credential Exposure ────────────────────────────")

    cred_found = False

    # HTTP Basic Auth
    http_auth_raw = await _safe_run(
        client.extract_fields(pcap_file, ["http.authbasic"], "http.authbasic", limit=50), ""
    )
    http_auth = _extract_data(http_auth_raw) if http_auth_raw else None
    if http_auth and len(http_auth.strip()) > 20:
        cred_found = True
        risk_score += 25
        findings.append("🔴 HTTP Basic Auth credentials found in cleartext")
        lines = http_auth.strip().splitlines()
        report.append(f"│  🔴 HTTP Basic Auth: {len(lines) - 1} instance(s)")

    # FTP passwords
    ftp_raw = await _safe_run(
        client.extract_fields(pcap_file, ["ftp.request.arg"], "ftp.request.command == PASS", limit=50), ""
    )
    ftp_data = _extract_data(ftp_raw) if ftp_raw else None
    if ftp_data and len(ftp_data.strip()) > 20:
        cred_found = True
        risk_score += 25
        findings.append("🔴 FTP passwords found in cleartext")
        lines = ftp_data.strip().splitlines()
        report.append(f"│  🔴 FTP Passwords: {len(lines) - 1} instance(s)")

    if not cred_found:
        report.append("│  🟢 No plaintext credentials detected")

    report.append("└───────────────────────────────────────────────────────\n")

    # ── Phase 4: Port Scanning Detection ─────────────────────────────────
    report.append("┌─── 5. Port Scanning Activity ─────────────────────────")

    syn_raw = await _safe_run(
        client.extract_fields(
            pcap_file,
            ["ip.src", "tcp.dstport"],
            display_filter="tcp.flags.syn == 1 and tcp.flags.ack == 0",
            limit=10000,
        ),
        "",
    )
    syn_data = _extract_data(syn_raw) if syn_raw else None

    if syn_data:
        src_to_ports: dict[str, set[str]] = {}
        for line in syn_data.splitlines()[1:]:
            parts = line.split("\t")
            if len(parts) >= 2:
                src = parts[0].strip().strip('"')
                port = parts[1].strip().strip('"')
                if src and port:
                    src_to_ports.setdefault(src, set()).add(port)

        scanners = {s: p for s, p in src_to_ports.items() if len(p) >= 15}
        if scanners:
            risk_score += 20
            findings.append(f"🔴 {len(scanners)} port scanner(s) detected")
            for src, ports in sorted(scanners.items(), key=lambda x: len(x[1]), reverse=True)[:5]:
                report.append(f"│  🔴 {src} → {len(ports)} unique ports")
        else:
            report.append(f"│  🟢 No port scanning detected (SYN sources: {len(src_to_ports)})")
    else:
        report.append("│  🟢 No SYN-only packets found")

    report.append("└───────────────────────────────────────────────────────\n")

    # ── Phase 5: DNS Anomalies ───────────────────────────────────────────
    report.append("┌─── 6. DNS Anomaly Detection ──────────────────────────")

    if "dns" in detected_protocols:
        dns_raw = await _safe_run(
            client.extract_fields(pcap_file, ["dns.qry.name", "dns.qry.type"], display_filter="dns", limit=5000), ""
        )
        dns_data = _extract_data(dns_raw) if dns_raw else None

        if dns_data:
            long_queries = 0
            txt_queries = 0
            subdomains_per_base: dict[str, set[str]] = {}
            total_dns = 0

            for line in dns_data.splitlines()[1:]:
                parts = line.split("\t")
                if len(parts) >= 2:
                    qname = parts[0].strip().strip('"')
                    qtype = parts[1].strip().strip('"')
                    if not qname:
                        continue
                    total_dns += 1
                    if len(qname) > 50:
                        long_queries += 1
                    if qtype in ("16", "TXT"):
                        txt_queries += 1
                    domain_parts = qname.split(".")
                    if len(domain_parts) >= 3:
                        base = ".".join(domain_parts[-2:])
                        sub = ".".join(domain_parts[:-2])
                        subdomains_per_base.setdefault(base, set()).add(sub)

            report.append(f"│  Total DNS queries: {total_dns}")

            dns_indicators = 0
            if long_queries > 5:
                dns_indicators += 1
                report.append(f"│  🔴 Long queries (>50 chars): {long_queries}")
            if txt_queries > 10:
                dns_indicators += 1
                report.append(f"│  🟠 TXT record queries: {txt_queries}")
            suspicious_bases = {b: s for b, s in subdomains_per_base.items() if len(s) > 20}
            if suspicious_bases:
                dns_indicators += 1
                for base, subs in sorted(suspicious_bases.items(), key=lambda x: len(x[1]), reverse=True)[:3]:
                    report.append(f"│  🔴 {base}: {len(subs)} unique subdomains")

            if dns_indicators >= 2:
                risk_score += 25
                findings.append("🔴 DNS tunneling indicators detected")
            elif dns_indicators == 1:
                findings.append("🟡 Minor DNS anomalies detected")
            else:
                report.append("│  🟢 No DNS tunneling indicators")
        else:
            report.append("│  No DNS data to analyze")
    else:
        report.append("│  ℹ️  No DNS traffic in capture")

    report.append("└───────────────────────────────────────────────────────\n")

    # ── Phase 6: Cleartext Protocol Usage ────────────────────────────────
    report.append("┌─── 7. Cleartext Protocol Usage ───────────────────────")

    cleartext_checks = [
        ("FTP", "ftp"),
        ("Telnet", "telnet"),
        ("HTTP (unencrypted)", "http"),
        ("SMTP", "smtp"),
        ("POP3", "pop"),
        ("IMAP", "imap"),
    ]

    cleartext_found = []
    for name, dfilter in cleartext_checks:
        if dfilter in detected_protocols or dfilter == "http":
            check_raw = await _safe_run(client.get_packet_list(pcap_file, limit=1, display_filter=dfilter), "")
            check_data = _extract_data(check_raw) if check_raw else None
            if check_data and _count_lines(check_data) > 0:
                cleartext_found.append(name)
                report.append(f"│  🟠 {name}: DETECTED")

    if cleartext_found:
        risk_score += 10
        findings.append(f"🟠 Cleartext protocols in use: {', '.join(cleartext_found)}")

    if not cleartext_found:
        report.append("│  🟢 No cleartext protocols detected")

    report.append("└───────────────────────────────────────────────────────\n")

    # ── Phase 7: Expert Info (Protocol Anomalies) ────────────────────────
    report.append("┌─── 8. Protocol Anomalies (Expert Info) ───────────────")

    expert_raw = await _safe_run(client.get_expert_info(pcap_file), "")
    expert_data = _extract_data(expert_raw) if expert_raw else None
    if expert_data:
        if "Malformed" in expert_data:
            risk_score += 10
            findings.append("🟠 Malformed packets detected")
            report.append("│  🔴 Malformed packets detected")
        if "Reassembly error" in expert_data:
            findings.append("🟡 Reassembly errors found")
            report.append("│  🟠 Reassembly errors found")
        if "Retransmission" in expert_data:
            report.append("│  🟡 TCP retransmissions present")
        if not any(w in expert_data for w in ["Malformed", "Reassembly", "Retransmission"]):
            report.append("│  🟢 No notable protocol anomalies")
    else:
        report.append("│  No expert info available")

    report.append("└───────────────────────────────────────────────────────\n")

    # ── Final Summary ────────────────────────────────────────────────────
    risk_score = min(risk_score, 100)
    if risk_score >= 60:
        risk_level = "🔴 CRITICAL"
    elif risk_score >= 40:
        risk_level = "🟠 HIGH"
    elif risk_score >= 20:
        risk_level = "🟡 MEDIUM"
    else:
        risk_level = "🟢 LOW"

    report.append("╔══════════════════════════════════════════════════════╗")
    report.append(f"║  RISK LEVEL: {risk_level:<40}║")
    report.append(f"║  RISK SCORE: {risk_score}/100{' ' * 36}║")
    report.append(f"║  FINDINGS:   {len(findings)} issue(s){' ' * 33}║")
    report.append("╚══════════════════════════════════════════════════════╝\n")

    if findings:
        report.append("── Findings Summary ──")
        for i, f in enumerate(findings, 1):
            report.append(f"  {i}. {f}")

    report.append("\n── Recommendations ──")
    if risk_score >= 40:
        report.append("  • Investigate flagged malicious IPs and credential exposure immediately")
        report.append("  • Use wireshark_follow_stream to examine suspicious connections")
        report.append("  • Consider blocking identified scanner/attacker IPs")
    if cleartext_found:
        report.append("  • Migrate cleartext protocols to encrypted alternatives (HTTPS, SFTP, etc.)")
    if risk_score < 20:
        report.append("  • No critical issues found — routine monitoring recommended")

    return success_response("\n".join(report))


# ── Quick Analysis ───────────────────────────────────────────────────────────


async def _run_quick_analysis(client: TSharkClient, pcap_file: str) -> str:
    """Execute quick traffic analysis pipeline."""

    report: list[str] = []

    report.append("╔══════════════════════════════════════════════════════╗")
    report.append("║           QUICK ANALYSIS REPORT                     ║")
    report.append("╚══════════════════════════════════════════════════════╝\n")

    # ── Phase 1: File Info ───────────────────────────────────────────────
    file_info_raw = await _safe_run(client.get_file_info(pcap_file), "")
    file_info = _extract_data(file_info_raw) if file_info_raw else None

    report.append("┌─── 1. Capture File Info ──────────────────────────────")
    if file_info:
        for line in file_info.strip().splitlines()[:12]:
            report.append(f"│  {line}")
    else:
        report.append("│  ⚠️  Could not read file info")
    report.append("└───────────────────────────────────────────────────────\n")

    # ── Phase 2: Protocol Distribution ───────────────────────────────────
    phs_raw = await _safe_run(client.get_protocol_stats(pcap_file), "")
    phs_data = _extract_data(phs_raw) if phs_raw else None

    report.append("┌─── 2. Protocol Distribution ──────────────────────────")
    if phs_data:
        for line in phs_data.strip().splitlines()[:20]:
            report.append(f"│  {line}")
    else:
        report.append("│  No protocol data available")
    report.append("└───────────────────────────────────────────────────────\n")

    # ── Phase 3: Top Talkers (Endpoints) ─────────────────────────────────
    endpoints_raw = await _safe_run(client.get_endpoints(pcap_file, "ip"), "")
    endpoints_data = _extract_data(endpoints_raw) if endpoints_raw else None

    report.append("┌─── 3. Top Talkers (IP Endpoints) ─────────────────────")
    if endpoints_data:
        for line in endpoints_data.strip().splitlines()[:15]:
            report.append(f"│  {line}")
    else:
        report.append("│  No endpoint data available")
    report.append("└───────────────────────────────────────────────────────\n")

    # ── Phase 4: Top Conversations ───────────────────────────────────────
    conv_raw = await _safe_run(client.get_conversations(pcap_file, "tcp"), "")
    conv_data = _extract_data(conv_raw) if conv_raw else None

    report.append("┌─── 4. Top Conversations (TCP) ────────────────────────")
    if conv_data:
        for line in conv_data.strip().splitlines()[:15]:
            report.append(f"│  {line}")
    else:
        report.append("│  No conversation data available")
    report.append("└───────────────────────────────────────────────────────\n")

    # ── Phase 5: Key Hostnames ───────────────────────────────────────────
    report.append("┌─── 5. Key Hostnames ──────────────────────────────────")

    # HTTP hosts
    http_hosts_raw = await _safe_run(client.extract_fields(pcap_file, ["http.host"], "http.request", limit=500), "")
    http_hosts_data = _extract_data(http_hosts_raw) if http_hosts_raw else None

    http_hosts: dict[str, int] = {}
    if http_hosts_data:
        for line in http_hosts_data.splitlines()[1:]:
            host = line.strip().strip('"')
            if host:
                http_hosts[host] = http_hosts.get(host, 0) + 1

    if http_hosts:
        report.append("│  HTTP Hosts:")
        for host, count in sorted(http_hosts.items(), key=lambda x: x[1], reverse=True)[:10]:
            report.append(f"│    {host} ({count} requests)")

    # DNS top domains
    dns_raw = await _safe_run(
        client.extract_fields(pcap_file, ["dns.qry.name"], "dns.flags.response == 0", limit=500), ""
    )
    dns_data = _extract_data(dns_raw) if dns_raw else None

    dns_domains: dict[str, int] = {}
    if dns_data:
        for line in dns_data.splitlines()[1:]:
            domain = line.strip().strip('"')
            if domain:
                dns_domains[domain] = dns_domains.get(domain, 0) + 1

    if dns_domains:
        report.append("│  DNS Queries (top domains):")
        for domain, count in sorted(dns_domains.items(), key=lambda x: x[1], reverse=True)[:10]:
            report.append(f"│    {domain} ({count} queries)")

    if not http_hosts and not dns_domains:
        report.append("│  No HTTP/DNS hostname data found")

    report.append("└───────────────────────────────────────────────────────\n")

    # ── Phase 6: Anomaly Summary ─────────────────────────────────────────
    expert_raw = await _safe_run(client.get_expert_info(pcap_file), "")
    expert_data = _extract_data(expert_raw) if expert_raw else None

    report.append("┌─── 6. Anomaly Summary (Expert Info) ──────────────────")
    if expert_data:
        anomaly_keywords = {
            "Retransmission": "🟡",
            "Duplicate ACK": "🟡",
            "Out-of-Order": "🟠",
            "Malformed": "🔴",
            "Reassembly error": "🟠",
            "Zero window": "🟡",
        }
        found_any = False
        for keyword, icon in anomaly_keywords.items():
            if keyword in expert_data:
                report.append(f"│  {icon} {keyword} detected")
                found_any = True
        if not found_any:
            report.append("│  🟢 No notable anomalies")
    else:
        report.append("│  No expert info available")
    report.append("└───────────────────────────────────────────────────────\n")

    # ── Suggested Next Steps ─────────────────────────────────────────────
    report.append("── Suggested Next Steps ──")
    report.append("  • wireshark_get_packet_list — browse specific traffic with display filters")
    report.append("  • wireshark_follow_stream — reconstruct TCP/HTTP conversations")
    report.append("  • wireshark_security_audit — run full security audit on this file")
    if http_hosts:
        report.append("  • wireshark_extract_http_requests — detailed HTTP request analysis")
    if dns_domains:
        report.append("  • wireshark_extract_dns_queries — detailed DNS query analysis")

    return success_response("\n".join(report))


# ── Registration ─────────────────────────────────────────────────────────────


def register_agent_tools(mcp: FastMCP, client: TSharkClient) -> None:
    """Register agentic workflow super tools."""

    @mcp.tool()
    async def wireshark_security_audit(pcap_file: str) -> str:
        """
        [Agent] One-call comprehensive security audit.

        Automatically runs 8 analysis phases internally and returns a structured
        security report with risk scoring. No manual tool-chaining needed.

        Phases: File summary → Protocol overview → Threat intelligence (URLhaus) →
        Credential exposure → Port scan detection → DNS anomaly detection →
        Cleartext protocol usage → Protocol anomalies (Expert Info)

        Args:
            pcap_file: Path to capture file

        Returns:
            Complete security audit report with risk level, findings, and recommendations.

        Example:
            wireshark_security_audit("suspicious_traffic.pcap")
        """
        return await _run_security_audit(client, pcap_file)

    @mcp.tool()
    async def wireshark_quick_analysis(pcap_file: str) -> str:
        """
        [Agent] One-call traffic overview and analysis.

        Automatically gathers file info, protocol distribution, top talkers,
        conversations, hostnames, and anomalies into a single comprehensive report.

        Phases: File info → Protocol distribution → Top talkers → Top conversations →
        Key hostnames (HTTP + DNS) → Anomaly summary (Expert Info)

        Args:
            pcap_file: Path to capture file

        Returns:
            Complete traffic analysis report with suggested next steps.

        Example:
            wireshark_quick_analysis("capture.pcap")
        """
        return await _run_quick_analysis(client, pcap_file)
