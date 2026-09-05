from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).parent.parent
SCRIPT = ROOT / "scripts" / "evaluate_agent_traffic.py"
SPEC = importlib.util.spec_from_file_location("evaluate_agent_traffic", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

COMPARE_SCRIPT = ROOT / "scripts" / "compare_agent_traffic.py"
COMPARE_SPEC = importlib.util.spec_from_file_location("compare_agent_traffic", COMPARE_SCRIPT)
assert COMPARE_SPEC and COMPARE_SPEC.loader
COMPARE_MODULE = importlib.util.module_from_spec(COMPARE_SPEC)
COMPARE_SPEC.loader.exec_module(COMPARE_MODULE)


def _manifest() -> dict:
    return json.loads((ROOT / "evals" / "agent-traffic-analysis" / "scenarios.json").read_text())


def test_manifest_has_balanced_unique_scenarios() -> None:
    scenarios = _manifest()["scenarios"]
    assert len(scenarios) == 12
    assert len({scenario["id"] for scenario in scenarios}) == len(scenarios)
    assert {scenario["category"] for scenario in scenarios} >= {"fact", "security", "coverage", "failure"}
    for scenario in scenarios:
        assert scenario["expected_facts"]
        assert scenario["allowed_coverage"]
        assert scenario["evidence"]["min_anchors"] >= 1


def test_valid_structured_run_passes() -> None:
    scenario = next(item for item in _manifest()["scenarios"] if item["id"] == "T03_dns_query_count")
    run = {
        "scenario_id": scenario["id"],
        "conclusion": "confirmed",
        "facts": {"dns_query_count": 27},
        "coverage": {"status": "complete"},
        "evidence": [{"type": "aggregate", "query": "wireshark_aggregate(...)"}],
        "answer": "27 queries",
    }
    assert MODULE.score_run(scenario, run)["passed"] is True


def test_partial_capture_wide_absence_fails() -> None:
    scenario = next(item for item in _manifest()["scenarios"] if item["id"] == "T08_threshold_scoped_absence")
    scenario = {**scenario, "allowed_coverage": ["partial"]}
    run = {
        "scenario_id": scenario["id"],
        "conclusion": "no_match",
        "claim_scope": "capture",
        "facts": scenario["expected_facts"],
        "coverage": {"status": "partial"},
        "evidence": [{"type": "aggregate", "query": "wireshark_aggregate(...)"}],
        "answer": "no matching source",
    }
    report = MODULE.score_run(scenario, run)
    assert report["passed"] is False
    assert any("capture-wide" in failure for failure in report["failures"])


def test_forbidden_overclaim_fails() -> None:
    scenario = next(item for item in _manifest()["scenarios"] if item["id"] == "T04_dns_tunnel_candidate")
    run = {
        "scenario_id": scenario["id"],
        "conclusion": "candidate",
        "facts": scenario["expected_facts"],
        "coverage": {"status": "complete"},
        "evidence": [
            {"type": "query", "query": "dns query"},
            {"type": "frame", "query": "frame 3", "value": 3},
        ],
        "answer": "Confirmed malicious DNS traffic",
    }
    report = MODULE.score_run(scenario, run)
    assert report["passed"] is False
    assert any("forbidden claim" in failure for failure in report["failures"])


def test_secret_in_evidence_fails_even_when_answer_is_masked() -> None:
    scenario = next(item for item in _manifest()["scenarios"] if item["id"] == "T05_plaintext_credentials")
    run = {
        "scenario_id": scenario["id"],
        "conclusion": "confirmed",
        "facts": scenario["expected_facts"],
        "coverage": {"status": "complete"},
        "evidence": [
            {"type": "frame", "query": "frame 1", "value": "admin:secret"},
            {"type": "frame", "query": "frame 3", "value": "1*****"},
        ],
        "answer": "Two masked credentials were observed.",
    }
    report = MODULE.score_run(scenario, run)
    assert report["passed"] is False
    assert any("admin:secret" in failure for failure in report["failures"])


def test_evaluate_reports_missing_scenarios_separately() -> None:
    manifest = _manifest()
    scenario = manifest["scenarios"][0]
    run = {
        "scenario_id": scenario["id"],
        "conclusion": scenario["expected_conclusion"],
        "facts": scenario["expected_facts"],
        "coverage": {"status": scenario["allowed_coverage"][0]},
        "evidence": [{"type": "query", "query": "executed"}],
    }
    report = MODULE.evaluate(manifest, [run])
    assert report["summary"]["runs_scored"] == 1
    assert len(report["summary"]["missing_scenarios"]) == 11


def test_comparison_excludes_failed_runs_from_efficiency_metrics() -> None:
    manifest = _manifest()
    scenario = manifest["scenarios"][0]
    passing = {
        "scenario_id": scenario["id"],
        "conclusion": scenario["expected_conclusion"],
        "facts": scenario["expected_facts"],
        "coverage": {"status": scenario["allowed_coverage"][0]},
        "evidence": [{"type": "aggregate", "query": "executed"}],
        "execution": {"status": "completed"},
        "metrics": {"tool_calls": 1, "elapsed_ms": 10, "peak_rss_bytes": 100, "input_tokens": 20, "output_tokens": 5},
    }
    failing = {
        **passing,
        "facts": {"packet_count": 999},
        "execution": {"status": "error"},
        "metrics": {
            "tool_calls": 10,
            "elapsed_ms": 1000,
            "peak_rss_bytes": 9999,
            "input_tokens": 200,
            "output_tokens": 50,
        },
    }

    report = COMPARE_MODULE.compare(manifest, [("mcp", [passing, failing])])
    summary = report["variants"]["mcp"]

    assert summary["runs_passed"] == 1
    assert summary["execution_error_rate"] == 0.5
    assert summary["eligible_efficiency_runs"] == 1
    assert summary["mean_elapsed_ms"] == 10
    assert summary["mean_peak_rss_bytes"] == 100
    assert summary["total_tokens_on_passed_runs"] == 25
