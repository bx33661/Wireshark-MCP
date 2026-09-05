"""Agentic Workflow — server-side orchestrated analysis tools."""

import asyncio
import logging
from typing import Any

from mcp.server import MCPServer

from ..tshark.client import TSharkClient
from .envelope import parse_tool_result, success_response
from .formatting import CRIT, INFO, OK, WARN, section, smart_truncate

logger = logging.getLogger("wireshark_mcp")

MAX_SECTION_LINES = 15
MAX_TOTAL_CHARS = 4000


def _extract_data(result: str) -> str | None:
    wrapped = parse_tool_result(result)
    if wrapped["success"]:
        data = wrapped.get("data", "")
        if isinstance(data, str) and len(data.strip()) > 10:
            return data
    return None


async def _safe_run(coro: Any, default: str | None = None) -> str | None:
    try:
        return await coro  # type: ignore[no-any-return]
    except Exception as e:
        logger.debug("Safe run caught exception: %s", e)
        return default


def _cap_lines(text: str, max_lines: int = MAX_SECTION_LINES) -> str:
    lines = text.strip().splitlines()
    if len(lines) <= max_lines:
        return text.strip()
    return "\n".join(lines[:max_lines]) + f"\n[... {len(lines) - max_lines} more lines]"


# ── Security Audit (concurrent) ──


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


def register_agent_tools(mcp: MCPServer, client: TSharkClient) -> None:
    """Register agentic workflow tools."""

    @mcp.tool()
    async def wireshark_quick_analysis(pcap_file: str) -> str:
        """[Agent] One-call traffic overview: file info, protocols, top talkers, conversations, hostnames, anomalies."""
        return await _run_quick_analysis(client, pcap_file)
