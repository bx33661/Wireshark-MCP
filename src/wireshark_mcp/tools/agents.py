"""Agentic Workflow — server-side orchestrated analysis tools."""

import asyncio
import logging

from mcp.server.fastmcp import FastMCP

from ..tshark.client import TSharkClient
from .envelope import normalize_tool_result, parse_tool_result, success_response
from .formatting import CRIT, INFO, OK, WARN, section, smart_truncate

logger = logging.getLogger("wireshark_mcp")

MAX_SECTION_LINES = 15
MAX_TOTAL_CHARS = 4000


def _count_lines(data: str) -> int:
    lines = [line for line in data.strip().splitlines() if line.strip()]
    return max(0, len(lines) - 1)


def _extract_data(result: str) -> str | None:
    wrapped = parse_tool_result(normalize_tool_result(result))
    if wrapped["success"]:
        data = wrapped.get("data", "")
        if isinstance(data, str) and len(data.strip()) > 10:
            return data
    return None


def _coerce_int(value: object) -> int:
    return value if isinstance(value, int) else int(value) if isinstance(value, str) and value.isdigit() else 0


async def _safe_run(coro, default=None):
    try:
        return await coro
    except Exception as e:
        logger.debug("Safe run caught exception: %s", e)
        return default


def _cap_lines(text: str, max_lines: int = MAX_SECTION_LINES) -> str:
    lines = text.strip().splitlines()
    if len(lines) <= max_lines:
        return text.strip()
    return "\n".join(lines[:max_lines]) + f"\n[... {len(lines) - max_lines} more lines]"


# ── Security Audit (concurrent) ──


async def _run_security_audit(client: TSharkClient, pcap_file: str) -> str:
    """Execute comprehensive security audit pipeline with concurrent phases."""
    import re

    report: list[str] = []
    findings: list[str] = []
    risk_score = 0

    report.append("## Security Audit\n")

    # Phase 1: File & Protocol Overview (must run first — others depend on detected_protocols)
    file_info_raw, phs_raw = await asyncio.gather(
        _safe_run(client.get_file_info(pcap_file), ""),
        _safe_run(client.get_protocol_stats(pcap_file), ""),
    )
    file_info = _extract_data(file_info_raw) if file_info_raw else None
    phs_data = _extract_data(phs_raw) if phs_raw else None

    report.append(section("1. File Summary"))
    if file_info:
        report.append(_cap_lines(file_info, 8))
    else:
        report.append(f"{WARN} Could not read file info")

    detected_protocols: set[str] = set()
    if phs_data:
        for line in phs_data.splitlines():
            match = re.match(r"^\s*(\w[\w.-]*)\s+frames:", line)
            if match:
                detected_protocols.add(match.group(1).lower())

    report.append(f"\n{section('2. Protocols')}")
    if detected_protocols:
        report.append(", ".join(sorted(detected_protocols)))
    else:
        report.append("No protocol hierarchy available")

    # Phase 2-7: Run independent analyses concurrently
    async def _phase_threat_intel() -> tuple[list[str], list[str], int]:
        """Threat intelligence check."""
        phase_report: list[str] = []
        phase_findings: list[str] = []
        phase_risk = 0
        try:
            from .security import _analyze_urlhaus_matches

            urlhaus_summary = await _analyze_urlhaus_matches(client, pcap_file)
            urls_checked = _coerce_int(urlhaus_summary.get("urls_checked", 0))
            domains_checked = _coerce_int(urlhaus_summary.get("domains_checked", 0))
            malicious_urls = urlhaus_summary.get("malicious_urls", [])
            malicious_domains = urlhaus_summary.get("malicious_domains", [])

            phase_report.append(f"URLs checked: {urls_checked}, Domains checked: {domains_checked}")
            if malicious_urls or malicious_domains:
                phase_risk += 40
                phase_findings.append(f"{CRIT} URL/domain matched URLhaus feed")
                if isinstance(malicious_urls, list) and malicious_urls:
                    phase_report.append(f"{CRIT} Malicious URLs: {len(malicious_urls)}")
                    for url in malicious_urls[:5]:
                        phase_report.append(f"  {url}")
                if isinstance(malicious_domains, list) and malicious_domains:
                    phase_report.append(f"{CRIT} Malicious domains: {len(malicious_domains)}")
                    for domain in malicious_domains[:5]:
                        phase_report.append(f"  {domain}")
            else:
                phase_report.append(f"{OK} No matches against threat feeds")
        except Exception as exc:
            phase_report.append(f"{WARN} Threat feed unavailable: {exc}")
        return phase_report, phase_findings, phase_risk

    async def _phase_credentials() -> tuple[list[str], list[str], int]:
        """Credential exposure check."""
        phase_report: list[str] = []
        phase_findings: list[str] = []
        phase_risk = 0
        cred_found = False

        http_auth_raw, ftp_raw = await asyncio.gather(
            _safe_run(client.extract_fields(pcap_file, ["http.authbasic"], "http.authbasic", limit=50), ""),
            _safe_run(
                client.extract_fields(pcap_file, ["ftp.request.arg"], "ftp.request.command == PASS", limit=50), ""
            ),
        )

        http_auth = _extract_data(http_auth_raw) if http_auth_raw else None
        if http_auth and len(http_auth.strip()) > 20:
            cred_found = True
            phase_risk += 25
            lines = http_auth.strip().splitlines()
            phase_findings.append(f"{CRIT} HTTP Basic Auth in cleartext")
            phase_report.append(f"{CRIT} HTTP Basic Auth: {len(lines) - 1} instance(s)")

        ftp_data = _extract_data(ftp_raw) if ftp_raw else None
        if ftp_data and len(ftp_data.strip()) > 20:
            cred_found = True
            phase_risk += 25
            lines = ftp_data.strip().splitlines()
            phase_findings.append(f"{CRIT} FTP passwords in cleartext")
            phase_report.append(f"{CRIT} FTP Passwords: {len(lines) - 1} instance(s)")

        if not cred_found:
            phase_report.append(f"{OK} No plaintext credentials detected")
        return phase_report, phase_findings, phase_risk

    async def _phase_port_scan() -> tuple[list[str], list[str], int]:
        """Port scan detection."""
        phase_report: list[str] = []
        phase_findings: list[str] = []
        phase_risk = 0

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
                phase_risk += 20
                phase_findings.append(f"{CRIT} {len(scanners)} port scanner(s) detected")
                for src, ports in sorted(scanners.items(), key=lambda x: len(x[1]), reverse=True)[:5]:
                    phase_report.append(f"{CRIT} {src} -> {len(ports)} unique ports")
            else:
                phase_report.append(f"{OK} No port scanning detected (SYN sources: {len(src_to_ports)})")
        else:
            phase_report.append(f"{OK} No SYN-only packets found")
        return phase_report, phase_findings, phase_risk

    async def _phase_dns(protocols: set[str]) -> tuple[list[str], list[str], int]:
        """DNS anomaly detection."""
        phase_report: list[str] = []
        phase_findings: list[str] = []
        phase_risk = 0

        if "dns" not in protocols:
            phase_report.append(f"{INFO} No DNS traffic in capture")
            return phase_report, phase_findings, phase_risk

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

            phase_report.append(f"Total DNS queries: {total_dns}")
            dns_indicators = 0
            if long_queries > 5:
                dns_indicators += 1
                phase_report.append(f"{CRIT} Long queries (>50 chars): {long_queries}")
            if txt_queries > 10:
                dns_indicators += 1
                phase_report.append(f"{WARN} TXT record queries: {txt_queries}")
            suspicious_bases = {b: s for b, s in subdomains_per_base.items() if len(s) > 20}
            if suspicious_bases:
                dns_indicators += 1
                for base, subs in sorted(suspicious_bases.items(), key=lambda x: len(x[1]), reverse=True)[:3]:
                    phase_report.append(f"{CRIT} {base}: {len(subs)} unique subdomains")

            if dns_indicators >= 2:
                phase_risk += 25
                phase_findings.append(f"{CRIT} DNS tunneling indicators detected")
            elif dns_indicators == 1:
                phase_findings.append(f"{WARN} Minor DNS anomalies")
            else:
                phase_report.append(f"{OK} No DNS tunneling indicators")
        else:
            phase_report.append("No DNS data to analyze")
        return phase_report, phase_findings, phase_risk

    async def _phase_cleartext(protocols: set[str]) -> tuple[list[str], list[str], int]:
        """Cleartext protocol detection."""
        phase_report: list[str] = []
        phase_findings: list[str] = []
        phase_risk = 0

        cleartext_checks = [
            ("FTP", "ftp"),
            ("Telnet", "telnet"),
            ("HTTP", "http"),
            ("SMTP", "smtp"),
            ("POP3", "pop"),
            ("IMAP", "imap"),
        ]
        checks_to_run = [
            (name, dfilter) for name, dfilter in cleartext_checks if dfilter in protocols or dfilter == "http"
        ]

        if checks_to_run:
            results = await asyncio.gather(
                *[
                    _safe_run(client.get_packet_list(pcap_file, limit=1, display_filter=dfilter), "")
                    for _, dfilter in checks_to_run
                ]
            )
            cleartext_found = []
            for (name, _), raw in zip(checks_to_run, results, strict=True):
                check_data = _extract_data(raw) if raw else None
                if check_data and _count_lines(check_data) > 0:
                    cleartext_found.append(name)

            if cleartext_found:
                phase_risk += 10
                phase_findings.append(f"{WARN} Cleartext protocols: {', '.join(cleartext_found)}")
                phase_report.append(f"{WARN} Detected: {', '.join(cleartext_found)}")
            else:
                phase_report.append(f"{OK} No cleartext protocols detected")
        else:
            phase_report.append(f"{OK} No cleartext protocols detected")
        return phase_report, phase_findings, phase_risk

    async def _phase_expert_info() -> tuple[list[str], list[str], int]:
        """Expert info / protocol anomalies."""
        phase_report: list[str] = []
        phase_findings: list[str] = []
        phase_risk = 0

        expert_raw = await _safe_run(client.get_expert_info(pcap_file), "")
        expert_data = _extract_data(expert_raw) if expert_raw else None
        if expert_data:
            if "Malformed" in expert_data:
                phase_risk += 10
                phase_findings.append(f"{WARN} Malformed packets detected")
                phase_report.append(f"{CRIT} Malformed packets")
            if "Reassembly error" in expert_data:
                phase_findings.append(f"{INFO} Reassembly errors")
                phase_report.append(f"{WARN} Reassembly errors")
            if "Retransmission" in expert_data:
                phase_report.append(f"{INFO} TCP retransmissions present")
            if not any(w in expert_data for w in ["Malformed", "Reassembly", "Retransmission"]):
                phase_report.append(f"{OK} No notable anomalies")
        else:
            phase_report.append("No expert info available")
        return phase_report, phase_findings, phase_risk

    # Run all independent phases concurrently
    (
        (threat_report, threat_findings, threat_risk),
        (cred_report, cred_findings, cred_risk),
        (scan_report, scan_findings, scan_risk),
        (dns_report, dns_findings, dns_risk),
        (cleartext_report, cleartext_findings, cleartext_risk),
        (expert_report, expert_findings, expert_risk),
    ) = await asyncio.gather(
        _phase_threat_intel(),
        _phase_credentials(),
        _phase_port_scan(),
        _phase_dns(detected_protocols),
        _phase_cleartext(detected_protocols),
        _phase_expert_info(),
    )

    # Assemble report in order
    report.append(f"\n{section('3. Threat Intel')}")
    report.extend(threat_report)
    findings.extend(threat_findings)
    risk_score += threat_risk

    report.append(f"\n{section('4. Credentials')}")
    report.extend(cred_report)
    findings.extend(cred_findings)
    risk_score += cred_risk

    report.append(f"\n{section('5. Port Scanning')}")
    report.extend(scan_report)
    findings.extend(scan_findings)
    risk_score += scan_risk

    report.append(f"\n{section('6. DNS Anomalies')}")
    report.extend(dns_report)
    findings.extend(dns_findings)
    risk_score += dns_risk

    report.append(f"\n{section('7. Cleartext Protocols')}")
    report.extend(cleartext_report)
    findings.extend(cleartext_findings)
    risk_score += cleartext_risk

    report.append(f"\n{section('8. Protocol Anomalies')}")
    report.extend(expert_report)
    findings.extend(expert_findings)
    risk_score += expert_risk

    # Final Summary
    risk_score = min(risk_score, 100)
    if risk_score >= 60:
        risk_level = "CRITICAL"
    elif risk_score >= 40:
        risk_level = "HIGH"
    elif risk_score >= 20:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    report.append(f"\n{section(f'Risk: {risk_level} ({risk_score}/100), {len(findings)} finding(s)')}")
    for i, f in enumerate(findings, 1):
        report.append(f"{i}. {f}")

    output = "\n".join(report)
    return success_response(smart_truncate(output, MAX_TOTAL_CHARS))


# ── Quick Analysis (concurrent) ──


async def _run_quick_analysis(client: TSharkClient, pcap_file: str) -> str:
    """Execute quick traffic analysis pipeline with concurrent data gathering."""
    report: list[str] = []
    report.append("## Quick Analysis\n")

    # All phases are independent — run concurrently
    (
        file_info_raw,
        phs_raw,
        endpoints_raw,
        conv_raw,
        http_hosts_raw,
        dns_raw,
        expert_raw,
    ) = await asyncio.gather(
        _safe_run(client.get_file_info(pcap_file), ""),
        _safe_run(client.get_protocol_stats(pcap_file), ""),
        _safe_run(client.get_endpoints(pcap_file, "ip"), ""),
        _safe_run(client.get_conversations(pcap_file, "tcp"), ""),
        _safe_run(client.extract_fields(pcap_file, ["http.host"], "http.request", limit=500), ""),
        _safe_run(client.extract_fields(pcap_file, ["dns.qry.name"], "dns.flags.response == 0", limit=500), ""),
        _safe_run(client.get_expert_info(pcap_file), ""),
    )

    # Phase 1: File Info
    file_info = _extract_data(file_info_raw) if file_info_raw else None
    report.append(section("1. File Info"))
    if file_info:
        report.append(_cap_lines(file_info, 10))
    else:
        report.append(f"{WARN} Could not read file info")

    # Phase 2: Protocol Distribution
    phs_data = _extract_data(phs_raw) if phs_raw else None
    report.append(f"\n{section('2. Protocols')}")
    if phs_data:
        report.append(_cap_lines(phs_data, MAX_SECTION_LINES))
    else:
        report.append("No protocol data available")

    # Phase 3: Top Talkers
    endpoints_data = _extract_data(endpoints_raw) if endpoints_raw else None
    report.append(f"\n{section('3. Top Talkers')}")
    if endpoints_data:
        report.append(_cap_lines(endpoints_data, 12))
    else:
        report.append("No endpoint data available")

    # Phase 4: Top Conversations
    conv_data = _extract_data(conv_raw) if conv_raw else None
    report.append(f"\n{section('4. Conversations (TCP)')}")
    if conv_data:
        report.append(_cap_lines(conv_data, 12))
    else:
        report.append("No conversation data available")

    # Phase 5: Key Hostnames
    report.append(f"\n{section('5. Hostnames')}")
    http_hosts_data = _extract_data(http_hosts_raw) if http_hosts_raw else None
    http_hosts: dict[str, int] = {}
    if http_hosts_data:
        for line in http_hosts_data.splitlines()[1:]:
            host = line.strip().strip('"')
            if host:
                http_hosts[host] = http_hosts.get(host, 0) + 1

    dns_data = _extract_data(dns_raw) if dns_raw else None
    dns_domains: dict[str, int] = {}
    if dns_data:
        for line in dns_data.splitlines()[1:]:
            domain = line.strip().strip('"')
            if domain:
                dns_domains[domain] = dns_domains.get(domain, 0) + 1

    if http_hosts:
        report.append("HTTP:")
        for host, count in sorted(http_hosts.items(), key=lambda x: x[1], reverse=True)[:8]:
            report.append(f"  {host} ({count})")
    if dns_domains:
        report.append("DNS:")
        for domain, count in sorted(dns_domains.items(), key=lambda x: x[1], reverse=True)[:8]:
            report.append(f"  {domain} ({count})")
    if not http_hosts and not dns_domains:
        report.append("No HTTP/DNS hostname data found")

    # Phase 6: Anomaly Summary
    expert_data = _extract_data(expert_raw) if expert_raw else None
    report.append(f"\n{section('6. Anomalies')}")
    if expert_data:
        anomaly_keywords = {
            "Retransmission": INFO,
            "Duplicate ACK": INFO,
            "Out-of-Order": WARN,
            "Malformed": CRIT,
            "Reassembly error": WARN,
            "Zero window": INFO,
        }
        found_any = False
        for keyword, icon in anomaly_keywords.items():
            if keyword in expert_data:
                report.append(f"{icon} {keyword}")
                found_any = True
        if not found_any:
            report.append(f"{OK} No notable anomalies")
    else:
        report.append("No expert info available")

    output = "\n".join(report)
    return success_response(smart_truncate(output, MAX_TOTAL_CHARS))


# ── Registration ──


def register_agent_tools(mcp: FastMCP, client: TSharkClient) -> None:
    """Register agentic workflow tools."""

    @mcp.tool()
    async def wireshark_security_audit(pcap_file: str) -> str:
        """[Agent] Comprehensive security audit (8 phases). Returns risk score 0-100 with findings."""
        return await _run_security_audit(client, pcap_file)

    @mcp.tool()
    async def wireshark_quick_analysis(pcap_file: str) -> str:
        """[Agent] One-call traffic overview: file info, protocols, top talkers, conversations, hostnames, anomalies."""
        return await _run_quick_analysis(client, pcap_file)
