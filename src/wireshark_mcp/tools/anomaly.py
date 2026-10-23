"""Anomaly detection tools for Wireshark MCP — statistical and heuristic analysis."""

import asyncio
import logging
import statistics
from typing import Any

from ..tshark.client import TSharkClient
from .envelope import envelope_response, normalize_tool_result, parse_tool_result
from .findings import Finding, FindingConstraints, FindingEvidence, finalize_findings
from .formatting import CRIT, OK, WARN, parse_tsv_rows

logger = logging.getLogger("wireshark_mcp")


def _compute_jitter(intervals: list[float]) -> float:
    """Compute jitter coefficient (stddev / mean). Lower = more periodic."""
    if len(intervals) < 2:
        return 1.0
    mean = statistics.mean(intervals)
    if mean == 0:
        return 1.0
    return statistics.stdev(intervals) / mean


def _rows_with_header(data: str) -> list[list[str]]:
    """Rows including the header line (callers slice it off) with cells kept raw."""
    return parse_tsv_rows(data, skip_header=False, strip_quotes=False)


def _cell(row: list[str], index: int) -> str:
    return row[index].strip().strip('"') if len(row) > index else ""


def _frame(value: str) -> int | None:
    return int(value) if value.isdigit() else None


BEACON_FILTER = "tcp.flags.syn == 1 && tcp.flags.ack == 0"
BEACON_LIMIT = 10000
EXTERNAL_TCP_FILTER = "tcp && !ip.dst == 10.0.0.0/8 && !ip.dst == 172.16.0.0/12 && !ip.dst == 192.168.0.0/16"
LONG_DNS_FILTER = "dns.qry.name.len > 50"
LONG_DNS_LIMIT = 1000
NONSTANDARD_PORT_FILTER = (
    "tcp && !(tcp.dstport == 80 || tcp.dstport == 443 || tcp.dstport == 8080 || tcp.dstport == 8443)"
)


def make_anomaly_tools(client: TSharkClient) -> list[tuple[str, Any]]:
    """Build anomaly detection tools."""

    async def wireshark_detect_beaconing(pcap_file: str, min_connections: int = 10, max_jitter: float = 0.2) -> str:
        """[Anomaly] Detect periodic communication patterns (C2 beacons) by analyzing connection timing intervals and jitter."""
        fields = ["ip.src", "ip.dst", "tcp.dstport", "frame.time_epoch", "frame.number"]
        result = await client.extract_fields(pcap_file, fields, display_filter=BEACON_FILTER, limit=BEACON_LIMIT)
        wrapped = parse_tool_result(result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)
        truncated = wrapped.get("truncated") is True
        scope = {"pcap_file": pcap_file, "filter": BEACON_FILTER, "min_connections": min_connections}

        data = wrapped.get("data", "")
        rows = _rows_with_header(data) if isinstance(data, str) else []
        data_rows = rows[1:]

        # Group connection attempts by (src, dst, port), keeping the first frame as an anchor.
        groups: dict[tuple[str, str, str], list[float]] = {}
        first_frames: dict[tuple[str, str, str], int | None] = {}
        for row in data_rows:
            if len(row) < 4:
                continue
            try:
                epoch = float(_cell(row, 3))
            except ValueError:
                continue
            key = (_cell(row, 0), _cell(row, 1), _cell(row, 2))
            groups.setdefault(key, []).append(epoch)
            first_frames.setdefault(key, _frame(_cell(row, 4)))

        findings: list[Finding] = []
        for (src, dst, port), timestamps in groups.items():
            if len(timestamps) < min_connections:
                continue
            timestamps.sort()
            intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
            jitter = _compute_jitter(intervals)
            if jitter > max_jitter:
                continue
            mean_interval = statistics.mean(intervals)
            findings.append(
                Finding(
                    observation=(
                        f"Periodic connections from {src} to {dst}:{port}: {len(timestamps)} SYNs, "
                        f"mean interval {mean_interval:.3f}s, jitter {jitter:.4f}."
                    ),
                    severity="medium",
                    # Regular timing alone is consistent with benign polling; very tight
                    # timing over many attempts is stronger but still not proof of C2.
                    confidence="likely" if jitter <= 0.05 and len(timestamps) >= 2 * min_connections else "candidate",
                    evidence=[
                        FindingEvidence(
                            frame=first_frames.get((src, dst, port)),
                            protocol="TCP",
                            filter=f"ip.src == {src} && ip.dst == {dst} && tcp.dstport == {port} && {BEACON_FILTER}",
                            description=f"{len(timestamps)} connection attempts at ~{mean_interval:.3f}s intervals",
                        )
                    ],
                    constraints={"scanned": len(data_rows), "limit": BEACON_LIMIT, "truncated": truncated},
                    next_steps=[
                        "Check whether the destination and interval match known software update or telemetry services.",
                        "Inspect one session with wireshark_follow_stream before treating it as command and control.",
                    ],
                    details={
                        "src": src,
                        "dst": dst,
                        "port": port,
                        "connections": len(timestamps),
                        "mean_interval_sec": round(mean_interval, 3),
                        "jitter": round(jitter, 4),
                        "periodicity_score": round(1.0 - jitter, 4),
                    },
                )
            )
        findings.sort(key=lambda item: item["details"]["periodicity_score"], reverse=True)
        finalize_findings("wireshark_detect_beaconing", pcap_file, findings, "beaconing")

        eligible = sum(1 for ts in groups.values() if len(ts) >= min_connections)
        summary = [
            "Beacon Detection Analysis",
            f"Total connection groups analyzed: {len(groups)}",
            f"Groups meeting threshold (>= {min_connections} connections): {eligible}",
        ]
        if findings:
            summary.append(f"{CRIT} {len(findings)} potential beacon(s) detected (jitter <= {max_jitter}).")
        elif not data_rows:
            summary.append(f"{OK} No SYN-only packets found for beacon analysis.")
        else:
            summary.append(f"{OK} No beaconing patterns detected (jitter threshold: {max_jitter})")
        return envelope_response(
            data={"findings": findings, "summary": "\n".join(summary)},
            scope=scope,
            coverage={
                "status": "partial" if truncated else "complete",
                "scanned": len(data_rows),
                "limit": BEACON_LIMIT,
            },
            truncated=truncated or None,
            warnings=[f"SYN rows hit the limit of {BEACON_LIMIT}; intervals may be incomplete."] if truncated else None,
        )

    async def wireshark_detect_exfiltration(pcap_file: str, limit: int = 10000) -> str:
        """[Anomaly] Detect data exfiltration (large outbound transfers, DNS length anomalies, non-standard ports)."""
        tcp_task = client.extract_fields(
            pcap_file,
            ["ip.src", "ip.dst", "tcp.dstport", "tcp.len", "frame.number"],
            display_filter=EXTERNAL_TCP_FILTER,
            limit=limit,
        )
        dns_task = client.extract_fields(
            pcap_file,
            ["ip.src", "dns.qry.name", "dns.qry.name.len", "frame.number"],
            display_filter=LONG_DNS_FILTER,
            limit=LONG_DNS_LIMIT,
        )
        tcp_wrapped, dns_wrapped = (parse_tool_result(item) for item in await asyncio.gather(tcp_task, dns_task))

        warnings: list[str] = []
        failed_checks: list[str] = []
        tcp_volumes: dict[tuple[str, str, str], int] = {}
        tcp_frames: dict[tuple[str, str, str], int | None] = {}
        tcp_rows = 0
        if tcp_wrapped["success"]:
            for row in _rows_with_header(str(tcp_wrapped.get("data", "")))[1:]:
                try:
                    length = int(_cell(row, 3))
                except ValueError:
                    continue
                tcp_rows += 1
                key = (_cell(row, 0), _cell(row, 1), _cell(row, 2))
                tcp_volumes[key] = tcp_volumes.get(key, 0) + length
                tcp_frames.setdefault(key, _frame(_cell(row, 4)))
            if tcp_wrapped.get("truncated") is True:
                warnings.append(f"Outbound TCP rows hit the limit of {limit}; volumes are lower bounds.")
        else:
            failed_checks.append("outbound TCP volume")

        long_dns: list[dict[str, Any]] = []
        if dns_wrapped["success"]:
            for row in _rows_with_header(str(dns_wrapped.get("data", "")))[1:]:
                if len(row) < 3:
                    continue
                long_dns.append(
                    {
                        "src": _cell(row, 0),
                        "query": _cell(row, 1),
                        "length": _cell(row, 2),
                        "frame": _frame(_cell(row, 3)),
                    }
                )
            if dns_wrapped.get("truncated") is True:
                warnings.append(f"Long DNS query rows hit the limit of {LONG_DNS_LIMIT}.")
        else:
            failed_checks.append("long DNS queries")
        truncated = bool(warnings)
        constraints = FindingConstraints(scanned=tcp_rows + len(long_dns), limit=limit, truncated=truncated)

        top_transfers = sorted(tcp_volumes.items(), key=lambda item: item[1], reverse=True)[:10]
        findings: list[Finding] = []
        if top_transfers:
            findings.append(
                Finding(
                    # Volume ranking is context, not a detection: backups and uploads look the same.
                    observation=f"Largest outbound TCP payload volumes to non-RFC1918 destinations ({len(tcp_volumes)} flows).",
                    severity="info",
                    confidence="confirmed",
                    evidence=[
                        FindingEvidence(
                            frame=tcp_frames.get(key),
                            protocol="TCP",
                            filter=f"ip.src == {key[0]} && ip.dst == {key[1]} && tcp.dstport == {key[2]}",
                            value=f"{total} bytes",
                            description=f"{key[0]} -> {key[1]}:{key[2]}",
                        )
                        for key, total in top_transfers
                    ],
                    constraints=constraints,
                    next_steps=["Compare the largest transfers with expected backup, sync and upload destinations."],
                    details={
                        "top_outbound_transfers": [
                            {"src": src, "dst": dst, "port": port, "bytes": total}
                            for (src, dst, port), total in top_transfers
                        ]
                    },
                )
            )
        if long_dns:
            findings.append(
                Finding(
                    observation=f"{len(long_dns)} DNS query name(s) longer than 50 characters.",
                    severity="medium",
                    confidence="candidate",
                    category="exfiltration",
                    evidence=[
                        FindingEvidence(
                            frame=entry["frame"],
                            protocol="DNS",
                            filter=f'dns.qry.name == "{entry["query"]}"',
                            value=entry["query"],
                            description=f"{entry['src']} queried a {entry['length']}-character name",
                        )
                        for entry in long_dns[:10]
                    ],
                    constraints=constraints,
                    next_steps=["Run wireshark_detect_dns_tunnel to check entropy, TXT usage and subdomain fan-out."],
                    details={"long_dns_queries": long_dns[:10]},
                )
            )
        finalize_findings("wireshark_detect_exfiltration", pcap_file, findings)

        summary = ["Data Exfiltration Detection Analysis", f"Total external TCP flows: {len(tcp_volumes)}"]
        if top_transfers:
            summary.append(
                f"{WARN} Top outbound transfer: {top_transfers[0][0][0]} -> {top_transfers[0][0][1]}:{top_transfers[0][0][2]} ({top_transfers[0][1]} bytes)"
            )
        else:
            summary.append(f"{OK} No significant outbound TCP transfers to external IPs.")
        summary.append(f"Long DNS queries (>50 chars): {len(long_dns)}")
        if failed_checks:
            summary.append(f"{WARN} Checks that failed: {', '.join(failed_checks)}")
        coverage: dict[str, Any] = {
            "status": "partial" if truncated or failed_checks else "complete",
            "scanned": tcp_rows + len(long_dns),
            "limit": limit,
        }
        if failed_checks:
            coverage["failed_checks"] = failed_checks
        return envelope_response(
            data={"findings": findings, "summary": "\n".join(summary)},
            scope={"pcap_file": pcap_file, "filters": [EXTERNAL_TCP_FILTER, LONG_DNS_FILTER]},
            coverage=coverage,
            truncated=truncated or None,
            warnings=warnings or None,
        )

    async def wireshark_detect_protocol_anomalies(pcap_file: str, limit: int = 5000) -> str:
        """[Anomaly] Detect protocol anomalies (known protocols on non-standard ports, unusual protocol distributions)."""
        fields = ["ip.src", "ip.dst", "tcp.dstport", "_ws.col.Protocol", "frame.number"]
        result = await client.extract_fields(pcap_file, fields, display_filter=NONSTANDARD_PORT_FILTER, limit=limit)
        wrapped = parse_tool_result(result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)
        truncated = wrapped.get("truncated") is True
        data_rows = _rows_with_header(str(wrapped.get("data", "")))[1:]

        # Known protocols that are suspicious on non-standard ports
        known_protocols = {"HTTP", "TLS", "SSL"}
        seen: set[tuple[str, str, str]] = set()
        anomalies: list[dict[str, Any]] = []
        for row in data_rows:
            if len(row) < 4:
                continue
            protocol = _cell(row, 3)
            dedup_key = (_cell(row, 1), _cell(row, 2), protocol.upper())
            if protocol.upper() not in known_protocols or dedup_key in seen:
                continue
            seen.add(dedup_key)
            anomalies.append(
                {
                    "src": _cell(row, 0),
                    "dst": _cell(row, 1),
                    "port": _cell(row, 2),
                    "protocol": protocol,
                    "frame": _frame(_cell(row, 4)),
                }
            )

        findings: list[Finding] = []
        if anomalies:
            findings.append(
                Finding(
                    observation=f"{len(anomalies)} HTTP/TLS service(s) observed on non-standard TCP ports.",
                    severity="low",
                    confidence="confirmed",
                    evidence=[
                        FindingEvidence(
                            frame=entry["frame"],
                            protocol=entry["protocol"],
                            filter=f"ip.dst == {entry['dst']} && tcp.dstport == {entry['port']} && {entry['protocol'].lower()}",
                            description=f"{entry['src']} -> {entry['dst']}:{entry['port']} speaks {entry['protocol']}",
                        )
                        for entry in anomalies[:20]
                    ],
                    constraints={"scanned": len(data_rows), "limit": limit, "truncated": truncated},
                    next_steps=[
                        "Confirm whether each service is an approved alternate port before treating it as evasion."
                    ],
                    details={"anomalies": anomalies[:20], "total": len(anomalies)},
                )
            )
        finalize_findings("wireshark_detect_protocol_anomalies", pcap_file, findings, "non_standard_port")

        summary = ["Protocol Anomaly Detection Analysis", f"Rows analyzed: {len(data_rows)}"]
        if anomalies:
            summary.append(f"{WARN} {len(anomalies)} protocol anomalie(s) found.")
        else:
            summary.append(f"{OK} No known protocols detected on non-standard ports.")
        return envelope_response(
            data={"findings": findings, "summary": "\n".join(summary)},
            scope={"pcap_file": pcap_file, "filter": NONSTANDARD_PORT_FILTER},
            coverage={"status": "partial" if truncated else "complete", "scanned": len(data_rows), "limit": limit},
            truncated=truncated or None,
            warnings=[f"Rows hit the limit of {limit}; later services may be missing."] if truncated else None,
        )

    return [
        ("wireshark_detect_beaconing", wireshark_detect_beaconing),
        ("wireshark_detect_exfiltration", wireshark_detect_exfiltration),
        ("wireshark_detect_protocol_anomalies", wireshark_detect_protocol_anomalies),
    ]
