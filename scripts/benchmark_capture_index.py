#!/usr/bin/env python3
"""Benchmark wireshark_aggregate with and without the DuckDB capture index.

For each synthetic scaling tier (the same deterministic captures used by
benchmark_analysis_paths.py) this measures:

* the live tshark path for each aggregate scenario,
* one index build (tshark export + DuckDB load) and the index file size,
* the indexed path for the same scenarios,

and checks every answer against the facts recorded while the capture was
written. It also times the 4.0 index features on each tier: timeline, a diff
of the capture's two halves, Parquet export, and extract_fields. The tshark path runs with a raised scan policy so 1 GB captures finish
instead of timing out; the default-policy result is already published in
docs/benchmarks/engine-2026-10-17-1gb-default-policy.json.

Requires the [index] extra and tshark on PATH.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from benchmark_analysis_paths import SCENARIOS, prepare_tier, run_mcp  # noqa: E402

TUNED_POLICY = {"WIRESHARK_MCP_AGGREGATE_SCAN_LIMIT": "10000000", "WIRESHARK_MCP_AGGREGATE_TIMEOUT": "600"}


def _peak_rss() -> dict[str, int] | None:
    try:
        import resource
    except ImportError:  # pragma: no cover - Windows
        return None
    scale = 1 if sys.platform == "darwin" else 1024
    return {
        "self": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * scale,
        "children": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * scale,
    }


async def _call_index(server: Any, capture: Path, action: str) -> dict[str, Any]:
    result = await server.call_tool("wireshark_index", {"pcap_file": str(capture), "action": action})
    return json.loads(result.content[0].text)


class _Recorder:
    """Pass-through server that keeps the last result so coverage can be read without a rerun."""

    def __init__(self, server: Any) -> None:
        self._server = server
        self.last: dict[str, Any] = {}

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        result = await self._server.call_tool(name, arguments)
        self.last = json.loads(result.content[0].text)
        return result


async def _time_scenarios(
    server: Any, capture: Path, facts: dict[str, Any], iterations: int, expect_source: str
) -> dict[str, Any]:
    recorder = _Recorder(server)
    results: dict[str, Any] = {}
    for scenario_id in SCENARIOS:
        timings: list[float] = []
        error: str | None = None
        observed: dict[str, Any] | None = None
        for _ in range(iterations):
            started = time.perf_counter()
            try:
                observed = await run_mcp(recorder, scenario_id, capture)
            except Exception as exc:  # recorded, not raised: a timeout is a result
                error = str(exc)[:300]
                timings.append((time.perf_counter() - started) * 1000)
                break
            timings.append((time.perf_counter() - started) * 1000)
        coverage = recorder.last.get("coverage", {}) if error is None else {}
        source = coverage.get("source")
        results[scenario_id] = {
            "passed": error is None and observed == facts[scenario_id] and source == expect_source,
            "source": source,
            **({"pushdown": coverage.get("pushdown")} if source == "index" else {}),
            "observed": observed,
            "expected": facts[scenario_id],
            "error": error,
            "elapsed_ms": [round(value, 1) for value in timings],
            "median_ms": round(statistics.median(timings), 1),
        }
    return results


async def _time_features(server: Any, capture: Path, facts: dict[str, Any]) -> dict[str, Any]:
    """One timed call per 4.0 index feature; each must succeed and answer from the index."""
    count = await server.call_tool(
        "wireshark_index",
        {"pcap_file": str(capture), "action": "query", "sql": "SELECT max(rel) FROM pkt"},
    )
    duration = json.loads(count.content[0].text)["data"]["rows"][0][0]
    half = f"{duration / 2:.6f}"
    calls = {
        "timeline": ("wireshark_index", {"action": "timeline"}),
        "diff_halves": (
            "wireshark_index",
            {
                "action": "diff",
                "display_filter": f"frame.time_relative < {half}",
                "compare_filter": f"frame.time_relative >= {half}",
            },
        ),
        "export_parquet": ("wireshark_index", {"action": "export"}),
        "extract_fields": (
            "wireshark_extract_fields",
            {"fields": "frame.number,ip.src,dns.qry.name", "display_filter": "dns.flags.response == 0", "limit": 100},
        ),
    }
    results: dict[str, Any] = {}
    for name, (tool, arguments) in calls.items():
        started = time.perf_counter()
        raw = await server.call_tool(tool, {"pcap_file": str(capture), **arguments})
        elapsed = (time.perf_counter() - started) * 1000
        payload = json.loads(raw.content[0].text)
        entry: dict[str, Any] = {
            "passed": bool(payload.get("success")) and payload.get("coverage", {}).get("source") == "index",
            "elapsed_ms": round(elapsed, 1),
        }
        data = payload.get("data")
        if name == "timeline" and isinstance(data, dict):
            entry["selected_packets"] = data.get("selected_packets")
            entry["passed"] = entry["passed"] and data.get("selected_packets") == facts["packet_count"]["packet_count"]
        elif name == "diff_halves" and isinstance(data, dict):
            entry["selected_packets"] = data.get("selected_packets")
        elif name == "export_parquet" and isinstance(data, dict):
            entry["files"] = {
                key: {"rows": value["rows"], "bytes": value["bytes"]} for key, value in data["files"].items()
            }
            entry["passed"] = (
                entry["passed"] and data["files"]["packets"]["rows"] == facts["packet_count"]["packet_count"]
            )
        elif not payload.get("success"):
            entry["error"] = str(payload.get("error"))[:300]
        results[name] = entry
    return results


async def _run_tier(size_mb: int, work_dir: Path, tshark_iterations: int, index_iterations: int) -> dict[str, Any]:
    from wireshark_mcp.server import _build_server

    tier = prepare_tier(size_mb, work_dir)
    capture = Path(tier["capture"])
    facts = tier["facts"]
    server = _build_server(host="127.0.0.1", port=8080, log_level="ERROR")

    await _call_index(server, capture, "drop")
    tshark_path = await _time_scenarios(server, capture, facts, tshark_iterations, "tshark")

    started = time.perf_counter()
    built = await _call_index(server, capture, "build")
    build_ms = (time.perf_counter() - started) * 1000
    if not built.get("success"):
        raise RuntimeError(f"index build failed: {built.get('error')}")
    index_path = await _time_scenarios(server, capture, facts, index_iterations, "index")
    features = await _time_features(server, capture, facts)
    index = built["data"]["index"]

    tshark_total = sum(item["median_ms"] for item in tshark_path.values())
    index_total = sum(item["median_ms"] for item in index_path.values())
    per_question_saving = (tshark_total - index_total) / len(SCENARIOS)
    return {
        "capture_bytes": tier["capture_bytes"],
        "packets": facts["packet_count"]["packet_count"],
        "seed": tier["seed"],
        "tshark_path": tshark_path,
        "index_build": {
            "elapsed_ms": round(build_ms, 1),
            "export_seconds": index.get("export_seconds"),
            "load_seconds": index.get("load_seconds"),
            "index_bytes": index.get("index_bytes"),
            "indexed_packets": index.get("packets"),
            "flows": index.get("flows"),
        },
        "index_path": index_path,
        "index_features": features,
        "summary": {
            "tshark_all_passed": all(item["passed"] for item in tshark_path.values()),
            "index_all_passed": all(item["passed"] for item in (*index_path.values(), *features.values())),
            "tshark_median_total_ms": round(tshark_total, 1),
            "index_median_total_ms": round(index_total, 1),
            "speedup": round(tshark_total / index_total, 1) if index_total else None,
            "break_even_questions": round(build_ms / per_question_saving, 2) if per_question_saving > 0 else None,
            "note": None
            if all(item["passed"] for item in tshark_path.values())
            else "The tshark path failed at least one scenario (see errors); speed-up compares failed calls.",
        },
    }


def _tshark_version(tshark: str) -> str:
    output = subprocess.run([tshark, "--version"], capture_output=True, text=True, check=False).stdout
    return output.splitlines()[0] if output else "unknown"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tiers", default="100,1000", help="comma-separated tier sizes in MB")
    parser.add_argument("--work-dir", type=Path, required=True, help="where captures and the index are kept")
    parser.add_argument("--tshark-iterations", type=int, default=1)
    parser.add_argument("--index-iterations", type=int, default=3)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    tshark = shutil.which("tshark")
    if tshark is None:
        parser.error("tshark is not on PATH")
    args.work_dir.mkdir(parents=True, exist_ok=True)
    os.environ.update(TUNED_POLICY)
    os.environ["WIRESHARK_MCP_INDEX_DIR"] = str(args.work_dir / "index")

    import duckdb

    report: dict[str, Any] = {
        "schema_version": 2,
        "benchmark": "capture-index-vs-tshark",
        "scope": "wireshark_aggregate latency and answer accuracy; not Agent accuracy or tokens.",
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "tshark": _tshark_version(tshark),
            "duckdb": duckdb.__version__,
            "cpu_count": os.cpu_count(),
            "scan_policy_env": TUNED_POLICY,
        },
        "tiers": {},
    }
    for size in (int(part) for part in args.tiers.split(",") if part.strip()):
        print(f"tier {size}MB ...", file=sys.stderr, flush=True)
        report["tiers"][f"{size}MB"] = asyncio.run(
            _run_tier(size, args.work_dir, args.tshark_iterations, args.index_iterations)
        )
        print(json.dumps(report["tiers"][f"{size}MB"]["summary"]), file=sys.stderr, flush=True)
    report["peak_rss_bytes"] = _peak_rss()

    text = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    # The tshark path is expected to fail where captures outgrow its scan policy; the index must not.
    return 0 if all(tier["summary"]["index_all_passed"] for tier in report["tiers"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
