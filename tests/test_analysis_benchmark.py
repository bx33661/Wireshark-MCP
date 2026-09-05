from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
SCRIPT = ROOT / "scripts" / "benchmark_analysis_paths.py"
SPEC = importlib.util.spec_from_file_location("benchmark_analysis_paths", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_engine_benchmark_covers_representative_reducers() -> None:
    assert set(MODULE.SCENARIOS) == {
        "packet_count",
        "primary_source",
        "dns_query_count",
        "literal_user_agent",
        "numeric_frame_bytes",
    }
    assert all(scenario["expected"] for scenario in MODULE.SCENARIOS.values())


def test_summary_keeps_tokens_explicitly_unmeasured() -> None:
    records = [
        {
            "variant": "mcp",
            "passed": True,
            "errors": [],
            "elapsed_ms": [10.0, 20.0],
            "peak_rss_bytes": {"combined_estimate": 1234},
            "process_calls": 2,
        }
    ]
    summary = MODULE.summarize(records)["mcp"]
    assert summary["mean_elapsed_ms"] == 15.0
    assert summary["max_combined_peak_rss_bytes"] == 1234
    assert summary["token_cost"] is None


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
@pytest.mark.parametrize("scenario_id", list(MODULE.SCENARIOS))
def test_native_cli_benchmark_queries_return_expected_facts(scenario_id: str) -> None:
    assert MODULE.run_cli(scenario_id, shutil.which("tshark")) == MODULE.SCENARIOS[scenario_id]["expected"]
