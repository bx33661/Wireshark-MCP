"""Anomaly detection tools for Wireshark MCP — statistical and heuristic analysis."""

import json
import logging
import statistics
from typing import Any

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

        header = rows[0]
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
        findings = []
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
        findings.sort(key=lambda f: f["confidence"], reverse=True)

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

    return [("wireshark_detect_beaconing", wireshark_detect_beaconing)]
