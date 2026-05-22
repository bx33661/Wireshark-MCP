"""Anomaly detection tools for Wireshark MCP — statistical and heuristic analysis."""

import asyncio
import json
import logging
import statistics
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

from ..tshark.client import TSharkClient
from .envelope import normalize_tool_result, parse_tool_result, success_response
from .formatting import CRIT, INFO, OK, WARN

logger = logging.getLogger("wireshark_mcp")


def _compute_jitter(intervals: list[float]) -> float:
    """Compute jitter coefficient (stddev / mean). Lower = more periodic."""
    if len(intervals) < 2:
        return 1.0
    mean = statistics.mean(intervals)
    if mean == 0:
        return 1.0
    return statistics.stdev(intervals) / mean


def _parse_tsv_rows(data: str) -> list[list[str]]:
    """Parse TSV output into rows of fields."""
    rows = []
    for line in data.strip().split("\n"):
        if line and not line.startswith("#"):
            rows.append(line.split("\t"))
    return rows


def make_contextual_anomaly_tools(client: TSharkClient) -> list[tuple[str, Any]]:
    """Create contextual anomaly detection tools."""

    async def wireshark_detect_beaconing(
        pcap_file: str, min_connections: int = 10, max_jitter: float = 0.2
    ) -> str:
        """[Anomaly] Detect periodic communication patterns (C2 beacons) by analyzing connection timing intervals and jitter."""
        fields = ["ip.src", "ip.dst", "tcp.dstport", "frame.time_epoch"]
        result = await client.extract_fields(
            pcap_file,
            fields,
            display_filter="tcp.flags.syn == 1 && tcp.flags.ack == 0",
            limit=10000,
        )
        wrapped = parse_tool_result(result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data", "")
        if not isinstance(data, str) or len(data.strip()) < 20:
            return success_response("No SYN-only packets found for beacon analysis.")

        # Parse TSV rows (skip header)
        rows = _parse_tsv_rows(data)
        if len(rows) < 2:
            return success_response("Insufficient connection data for beacon analysis.")

        data_rows = rows[1:]

        # Group connections by (src, dst, port)
        groups: dict[tuple[str, str, str], list[float]] = {}
        for row in data_rows:
            if len(row) < 4:
                continue
            src = row[0].strip().strip('"')
            dst = row[1].strip().strip('"')
            port = row[2].strip().strip('"')
            epoch_str = row[3].strip().strip('"')
            try:
                epoch = float(epoch_str)
            except (ValueError, TypeError):
                continue
            key = (src, dst, port)
            if key not in groups:
                groups[key] = []
            groups[key].append(epoch)

        # Analyze each group for beaconing behavior
        findings: list[dict[str, object]] = []
        for (src, dst, port), timestamps in groups.items():
            if len(timestamps) < min_connections:
                continue
            timestamps.sort()
            intervals = [
                timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)
            ]
            jitter = _compute_jitter(intervals)
            if jitter <= max_jitter:
                mean_interval = statistics.mean(intervals)
                confidence = 1.0 - jitter
                findings.append(
                    {
                        "src": src,
                        "dst": dst,
                        "port": port,
                        "connections": len(timestamps),
                        "mean_interval_sec": round(mean_interval, 3),
                        "jitter": round(jitter, 4),
                        "confidence": round(confidence, 4),
                    }
                )

        # Sort by confidence descending
        findings.sort(key=lambda f: float(str(f["confidence"])), reverse=True)

        # Build output
        output_parts = ["Beacon Detection Analysis"]
        output_parts.append(f"Total connection groups analyzed: {len(groups)}")
        output_parts.append(
            f"Groups meeting threshold (>= {min_connections} connections): "
            f"{sum(1 for ts in groups.values() if len(ts) >= min_connections)}"
        )

        if not findings:
            output_parts.append(
                f"\n{OK} No beaconing patterns detected (jitter threshold: {max_jitter})"
            )
        else:
            output_parts.append(
                f"\n{CRIT} {len(findings)} potential beacon(s) detected:\n"
            )
            for f in findings:
                output_parts.append(
                    f"  {WARN} {f['src']} -> {f['dst']}:{f['port']} "
                    f"| interval={f['mean_interval_sec']}s "
                    f"| jitter={f['jitter']} "
                    f"| confidence={f['confidence']} "
                    f"| connections={f['connections']}"
                )

        output_parts.append(f"\n{INFO} Structured findings:")
        output_parts.append(json.dumps(findings, indent=2))

        return success_response("\n".join(output_parts))

    async def wireshark_detect_exfiltration(pcap_file: str, limit: int = 10000) -> str:
        """[Anomaly] Detect potential data exfiltration (large outbound transfers, DNS query length anomalies, non-standard port usage)."""
        # Two concurrent extractions
        tcp_task = client.extract_fields(
            pcap_file,
            ["ip.src", "ip.dst", "tcp.dstport", "tcp.len"],
            display_filter="tcp && !ip.dst == 10.0.0.0/8 && !ip.dst == 172.16.0.0/12 && !ip.dst == 192.168.0.0/16",
            limit=limit,
        )
        dns_task = client.extract_fields(
            pcap_file,
            ["ip.src", "dns.qry.name", "dns.qry.name.len"],
            display_filter="dns.qry.name.len > 50",
            limit=1000,
        )

        tcp_result, dns_result = await asyncio.gather(tcp_task, dns_task)

        # Parse TCP outbound data
        tcp_wrapped = parse_tool_result(tcp_result)
        dns_wrapped = parse_tool_result(dns_result)

        output_parts = ["Data Exfiltration Detection Analysis"]

        # --- TCP outbound volume analysis ---
        tcp_volumes: dict[tuple[str, str, str], int] = {}
        if tcp_wrapped["success"]:
            tcp_data = tcp_wrapped.get("data", "")
            if isinstance(tcp_data, str) and len(tcp_data.strip()) > 20:
                rows = _parse_tsv_rows(tcp_data)
                if len(rows) > 1:
                    for row in rows[1:]:
                        if len(row) < 4:
                            continue
                        src = row[0].strip().strip('"')
                        dst = row[1].strip().strip('"')
                        port = row[2].strip().strip('"')
                        length_str = row[3].strip().strip('"')
                        try:
                            length = int(length_str)
                        except (ValueError, TypeError):
                            continue
                        key = (src, dst, port)
                        tcp_volumes[key] = tcp_volumes.get(key, 0) + length

        # Top 10 by volume
        top_transfers = sorted(tcp_volumes.items(), key=lambda x: x[1], reverse=True)[:10]

        output_parts.append(f"\nTotal external TCP flows: {len(tcp_volumes)}")
        if top_transfers:
            output_parts.append(f"\n{WARN} Top 10 outbound transfers by volume:\n")
            for (src, dst, port), total_bytes in top_transfers:
                output_parts.append(
                    f"  {WARN} {src} -> {dst}:{port} | {total_bytes} bytes"
                )
        else:
            output_parts.append(f"\n{OK} No significant outbound TCP transfers to external IPs.")

        # --- DNS query length analysis ---
        long_dns_queries: list[dict[str, str]] = []
        if dns_wrapped["success"]:
            dns_data = dns_wrapped.get("data", "")
            if isinstance(dns_data, str) and len(dns_data.strip()) > 20:
                rows = _parse_tsv_rows(dns_data)
                if len(rows) > 1:
                    for row in rows[1:]:
                        if len(row) < 3:
                            continue
                        src = row[0].strip().strip('"')
                        qname = row[1].strip().strip('"')
                        qlen = row[2].strip().strip('"')
                        long_dns_queries.append({"src": src, "query": qname, "length": qlen})

        output_parts.append(f"\nLong DNS queries (>50 chars): {len(long_dns_queries)}")
        if long_dns_queries:
            output_parts.append(f"\n{CRIT} Suspicious long DNS queries (first 10):\n")
            for entry in long_dns_queries[:10]:
                output_parts.append(
                    f"  {CRIT} {entry['src']} | len={entry['length']} | {entry['query']}"
                )
        else:
            output_parts.append(f"\n{OK} No abnormally long DNS queries detected.")

        # Structured findings
        findings = {
            "top_outbound_transfers": [
                {"src": src, "dst": dst, "port": port, "bytes": total}
                for (src, dst, port), total in top_transfers
            ],
            "long_dns_queries": long_dns_queries[:10],
        }
        output_parts.append(f"\n{INFO} Structured findings:")
        output_parts.append(json.dumps(findings, indent=2))

        return success_response("\n".join(output_parts))

    async def wireshark_detect_protocol_anomalies(
        pcap_file: str, limit: int = 5000
    ) -> str:
        """[Anomaly] Detect protocol anomalies (known protocols on non-standard ports, unusual protocol distributions)."""
        fields = ["ip.src", "ip.dst", "tcp.dstport", "_ws.col.Protocol"]
        result = await client.extract_fields(
            pcap_file,
            fields,
            display_filter="tcp && !tcp.dstport in {80 443 8080 8443}",
            limit=limit,
        )
        wrapped = parse_tool_result(result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data", "")
        if not isinstance(data, str) or len(data.strip()) < 20:
            return success_response(
                f"{OK} No protocol anomalies detected (no traffic on non-standard ports)."
            )

        rows = _parse_tsv_rows(data)
        if len(rows) < 2:
            return success_response(
                f"{OK} No protocol anomalies detected (insufficient data)."
            )

        data_rows = rows[1:]

        # Known protocols that are suspicious on non-standard ports
        known_protocols = {"HTTP", "TLS", "SSL"}

        # Deduplicate by (dst, port, protocol)
        seen: set[tuple[str, str, str]] = set()
        anomalies: list[dict[str, str]] = []

        for row in data_rows:
            if len(row) < 4:
                continue
            src = row[0].strip().strip('"')
            dst = row[1].strip().strip('"')
            port = row[2].strip().strip('"')
            protocol = row[3].strip().strip('"')

            if protocol.upper() not in known_protocols:
                continue

            dedup_key = (dst, port, protocol.upper())
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            anomalies.append(
                {"src": src, "dst": dst, "port": port, "protocol": protocol}
            )

        # Build output
        output_parts = ["Protocol Anomaly Detection Analysis"]
        output_parts.append(f"Rows analyzed: {len(data_rows)}")

        if not anomalies:
            output_parts.append(
                f"\n{OK} No known protocols detected on non-standard ports."
            )
        else:
            output_parts.append(
                f"\n{WARN} {len(anomalies)} protocol anomalie(s) found:\n"
            )
            for entry in anomalies[:20]:
                output_parts.append(
                    f"  {WARN} {entry['src']} -> {entry['dst']}:{entry['port']} "
                    f"| protocol={entry['protocol']}"
                )
            if len(anomalies) > 20:
                output_parts.append(f"  ... and {len(anomalies) - 20} more")

        output_parts.append(f"\n{INFO} Structured findings:")
        output_parts.append(json.dumps(anomalies[:20], indent=2))

        return success_response("\n".join(output_parts))

    async def wireshark_detect_anomalies(
        pcap_file: str, detectors: str = "all"
    ) -> str:
        """[Anomaly] Run all anomaly detectors concurrently (beacon, exfiltration, protocol). Returns combined findings."""
        detector_map: dict[str, Callable[[str], Awaitable[str]]] = {
            "beacon": wireshark_detect_beaconing,
            "exfiltration": wireshark_detect_exfiltration,
            "protocol": wireshark_detect_protocol_anomalies,
        }

        if detectors == "all":
            selected = list(detector_map.values())
            selected_names = list(detector_map.keys())
        else:
            selected_names = [d.strip() for d in detectors.split(",") if d.strip()]
            selected = []
            for name in selected_names:
                if name in detector_map:
                    selected.append(detector_map[name])
                else:
                    return normalize_tool_result(
                        {"success": False, "error": f"Unknown detector: {name}. Available: {', '.join(detector_map.keys())}"}
                    )

        results = await asyncio.gather(*(fn(pcap_file) for fn in selected))

        output_parts = ["Aggregate Anomaly Detection Report", f"Detectors run: {', '.join(selected_names)}", ""]
        for name, result in zip(selected_names, results, strict=False):
            output_parts.append(f"{'=' * 60}")
            output_parts.append(f"  {name.upper()} DETECTOR")
            output_parts.append(f"{'=' * 60}")
            output_parts.append(result)
            output_parts.append("")

        return success_response("\n".join(output_parts))

    return [
        ("wireshark_detect_beaconing", wireshark_detect_beaconing),
        ("wireshark_detect_exfiltration", wireshark_detect_exfiltration),
        ("wireshark_detect_protocol_anomalies", wireshark_detect_protocol_anomalies),
        ("wireshark_detect_anomalies", wireshark_detect_anomalies),
    ]
