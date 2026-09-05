#!/usr/bin/env python3
"""Benchmark equivalent Wireshark MCP and direct tshark analysis primitives."""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import platform
import shutil
import statistics
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

try:
    import resource
except ImportError:  # pragma: no cover - unavailable on Windows
    resource = None  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "pcaps"

SCENARIOS: dict[str, dict[str, Any]] = {
    "packet_count": {
        "capture": "plaintext_credentials.pcap",
        "mcp": {},
        "cli_fields": ["frame.number"],
        "filter": "",
        "expected": {"packet_count": 3},
    },
    "primary_source": {
        "capture": "plaintext_credentials.pcap",
        "mcp": {"group_by": "ip.src", "top_k": 1},
        "cli_fields": ["frame.number", "ip.src"],
        "filter": "",
        "expected": {"primary_source": "192.168.1.10", "primary_source_packets": 3},
    },
    "dns_query_count": {
        "capture": "dns_tunnel_candidate.pcap",
        "mcp": {"display_filter": "dns.flags.response == 0"},
        "cli_fields": ["frame.number"],
        "filter": "dns.flags.response == 0",
        "expected": {"dns_query_count": 27},
    },
    "literal_user_agent": {
        "capture": "multivalue_fields.pcap",
        "mcp": {"distinct": "http.user_agent"},
        "cli_fields": ["frame.number", "http.user_agent"],
        "filter": "http.user_agent",
        "expected": {"distinct_http_user_agents": 1},
    },
    "numeric_frame_bytes": {
        "capture": "plaintext_credentials.pcap",
        "mcp": {"sum_fields": "frame.len"},
        "cli_fields": ["frame.number", "frame.len"],
        "filter": "",
        "expected": {"frame_bytes": 304.0},
    },
}


def _rows(text: str) -> list[list[str]]:
    lines = [line for line in text.splitlines() if line.strip()]
    return [[cell.strip().strip('"') for cell in line.split("\t")] for line in lines[1:]]


def _facts_from_rows(scenario_id: str, rows: list[list[str]]) -> dict[str, Any]:
    if scenario_id == "packet_count":
        return {"packet_count": len(rows)}
    if scenario_id == "primary_source":
        counts = Counter(row[1] for row in rows if len(row) > 1 and row[1])
        source, count = min(counts.items(), key=lambda item: (-item[1], item[0]))
        return {"primary_source": source, "primary_source_packets": count}
    if scenario_id == "dns_query_count":
        return {"dns_query_count": len(rows)}
    if scenario_id == "literal_user_agent":
        return {"distinct_http_user_agents": len({row[1] for row in rows if len(row) > 1 and row[1]})}
    if scenario_id == "numeric_frame_bytes":
        return {"frame_bytes": sum(float(row[1]) for row in rows if len(row) > 1 and row[1])}
    raise ValueError(f"Unknown scenario: {scenario_id}")


def run_cli(scenario_id: str, tshark_path: str) -> dict[str, Any]:
    scenario = SCENARIOS[scenario_id]
    command = [tshark_path, "-n", "-r", str(FIXTURES / scenario["capture"]), "-T", "fields"]
    for field in scenario["cli_fields"]:
        command.extend(["-e", field])
    if scenario["filter"]:
        command.extend(["-Y", scenario["filter"]])
    command.extend(["-E", "header=y", "-E", "separator=/t", "-E", "aggregator=,", "-E", "quote=d"])
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or f"tshark exited with {completed.returncode}")
    return _facts_from_rows(scenario_id, _rows(completed.stdout))


async def _prepare_mcp() -> Any:
    from mcp.server import MCPServer

    from wireshark_mcp.tools.stats import register_stats_tools
    from wireshark_mcp.tshark.client import TSharkClient

    server = MCPServer("analysis-path-benchmark")
    register_stats_tools(server, TSharkClient())
    return server


async def run_mcp(server: Any, scenario_id: str) -> dict[str, Any]:
    from mcp.types import CallToolResult, TextContent

    scenario = SCENARIOS[scenario_id]
    arguments = {"pcap_file": str(FIXTURES / scenario["capture"]), **scenario["mcp"]}
    result = await server.call_tool("wireshark_aggregate", arguments)
    if (
        not isinstance(result, CallToolResult)
        or len(result.content) != 1
        or not isinstance(result.content[0], TextContent)
    ):
        raise RuntimeError("MCP aggregate returned an unexpected content shape")
    payload = json.loads(result.content[0].text)
    if not payload.get("success"):
        raise RuntimeError(json.dumps(payload.get("error"), ensure_ascii=False))
    data = payload["data"]
    if scenario_id == "packet_count":
        return {"packet_count": data["matched_packets"]}
    if scenario_id == "primary_source":
        group = data["groups"][0]
        return {"primary_source": group["key"]["ip.src"], "primary_source_packets": group["count"]}
    if scenario_id == "dns_query_count":
        return {"dns_query_count": data["matched_packets"]}
    if scenario_id == "literal_user_agent":
        return {"distinct_http_user_agents": data["groups"][0]["distinct"]["http.user_agent"]}
    if scenario_id == "numeric_frame_bytes":
        return {"frame_bytes": data["groups"][0]["numeric"]["frame.len"]["sum"]}
    raise ValueError(f"Unknown scenario: {scenario_id}")


def _peak_rss_bytes() -> dict[str, int] | None:
    if resource is None:
        return None
    unit = 1 if sys.platform == "darwin" else 1024
    own = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * unit)
    children = int(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * unit)
    return {"worker": own, "tshark": children, "combined_estimate": own + children}


async def _worker(variant: str, scenario_id: str, iterations: int, warmup: int, tshark_path: str) -> dict[str, Any]:
    setup_started = time.perf_counter_ns()
    server = await _prepare_mcp() if variant == "mcp" else None
    setup_ms = (time.perf_counter_ns() - setup_started) / 1_000_000

    async def execute() -> dict[str, Any]:
        return await run_mcp(server, scenario_id) if variant == "mcp" else run_cli(scenario_id, tshark_path)

    for _ in range(warmup):
        await execute()
    elapsed: list[float] = []
    facts: dict[str, Any] = {}
    errors: list[str] = []
    for _ in range(iterations):
        started = time.perf_counter_ns()
        try:
            facts = await execute()
        except Exception as exc:  # keep all iterations reportable
            errors.append(str(exc))
        elapsed.append((time.perf_counter_ns() - started) / 1_000_000)
    expected = SCENARIOS[scenario_id]["expected"]
    return {
        "scenario_id": scenario_id,
        "variant": variant,
        "iterations": iterations,
        "warmup_iterations": warmup,
        "setup_ms": setup_ms,
        "passed": not errors and facts == expected,
        "expected": expected,
        "facts": facts,
        "errors": errors,
        "elapsed_ms": elapsed,
        "peak_rss_bytes": _peak_rss_bytes(),
        "process_calls": iterations + warmup,
    }


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(len(ordered) * fraction) - 1))
    return round(ordered[index], 3)


def summarize(records: list[dict[str, Any]]) -> dict[str, Any]:
    variants: dict[str, dict[str, Any]] = {}
    for variant in sorted({record["variant"] for record in records}):
        selected = [record for record in records if record["variant"] == variant]
        timings = [value for record in selected for value in record.get("elapsed_ms", [])]
        setup = [float(record["setup_ms"]) for record in selected if isinstance(record.get("setup_ms"), (int, float))]
        memory = [
            record["peak_rss_bytes"]["combined_estimate"]
            for record in selected
            if isinstance(record.get("peak_rss_bytes"), dict)
        ]
        variants[variant] = {
            "scenarios": len(selected),
            "scenarios_passed": sum(bool(record.get("passed")) for record in selected),
            "error_rate": round(sum(len(record.get("errors", [])) for record in selected) / max(1, len(timings)), 4),
            "mean_setup_ms": round(statistics.fmean(setup), 3) if setup else None,
            "mean_elapsed_ms": round(statistics.fmean(timings), 3) if timings else None,
            "p50_elapsed_ms": _percentile(timings, 0.5),
            "p95_elapsed_ms": _percentile(timings, 0.95),
            "max_combined_peak_rss_bytes": max(memory) if memory else None,
            "process_calls": sum(int(record.get("process_calls", 0)) for record in selected),
            "token_cost": None,
        }
    return variants


def _tshark_version(tshark_path: str) -> str:
    completed = subprocess.run([tshark_path, "--version"], capture_output=True, text=True, check=False)
    return next((line for line in completed.stdout.splitlines() if line.strip()), "unknown")


def _run_parent(iterations: int, warmup: int, output: Path | None, tshark_path: str) -> int:
    records: list[dict[str, Any]] = []
    for variant in ("mcp", "tshark-cli"):
        for scenario_id in SCENARIOS:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "_worker",
                    "--variant",
                    variant,
                    "--scenario",
                    scenario_id,
                    "--iterations",
                    str(iterations),
                    "--warmup",
                    str(warmup),
                    "--tshark",
                    tshark_path,
                ],
                capture_output=True,
                text=True,
                check=False,
                cwd=ROOT,
            )
            if completed.returncode != 0:
                raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
            records.append(json.loads(completed.stdout))
    report = {
        "schema_version": 1,
        "benchmark": "analysis-path-engine-baseline",
        "scope": "Execution primitives only; this does not measure Agent accuracy, evidence quality, or tokens.",
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "tshark": _tshark_version(tshark_path),
        },
        "summary": summarize(records),
        "records": records,
    }
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if output:
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0 if all(record["passed"] for record in records) else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command")
    run = subparsers.add_parser("run", help="run both execution paths in isolated workers")
    run.add_argument("--iterations", type=int, default=5)
    run.add_argument("--warmup", type=int, default=1)
    run.add_argument("--output", type=Path)
    run.add_argument("--tshark", default=shutil.which("tshark") or "tshark")
    worker = subparsers.add_parser("_worker")
    worker.add_argument("--variant", choices=["mcp", "tshark-cli"], required=True)
    worker.add_argument("--scenario", choices=sorted(SCENARIOS), required=True)
    worker.add_argument("--iterations", type=int, required=True)
    worker.add_argument("--warmup", type=int, required=True)
    worker.add_argument("--tshark", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "_worker":
        sys.stdout.write(
            json.dumps(asyncio.run(_worker(args.variant, args.scenario, args.iterations, args.warmup, args.tshark)))
        )
        return 0
    if args.command == "run":
        if args.iterations < 1:
            raise SystemExit("--iterations must be positive")
        if args.warmup < 0:
            raise SystemExit("--warmup must be non-negative")
        return _run_parent(args.iterations, args.warmup, args.output, args.tshark)
    _parser().print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
