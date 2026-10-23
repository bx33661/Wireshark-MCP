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
    return json.loads((ROOT / "evals" / "agent-traffic-analysis" / "scenarios.json").read_text(encoding="utf-8"))


def test_manifest_has_balanced_unique_scenarios() -> None:
    scenarios = _manifest()["scenarios"]
    assert len(scenarios) == 20
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
    assert MODULE.score_run(scenario, run, _trace_for(scenario, run))["passed"] is True


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
    assert len(report["summary"]["missing_scenarios"]) == len(manifest["scenarios"]) - 1


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

    trace = _trace_for(scenario, passing)
    failing["trace_id"] = passing["trace_id"]
    report = COMPARE_MODULE.compare(manifest, [("mcp", [passing, failing])], {"mcp": {passing["trace_id"]: trace}})
    summary = report["variants"]["mcp"]

    assert summary["runs_passed"] == 1
    assert summary["execution_error_rate"] == 0.5
    assert summary["eligible_efficiency_runs"] == 1
    assert summary["mean_elapsed_ms"] == 10
    assert summary["mean_peak_rss_bytes"] == 100
    assert summary["total_tokens_on_passed_runs"] == 25


def _trace_for(scenario: dict, run: dict) -> dict:
    """Unit-test harness data, not a real Agent execution or accuracy result."""
    calls = []
    for index, anchor in enumerate(run.get("evidence", [])):
        call_id = f"call-{index}"
        anchor["call_id"] = call_id
        calls.append(
            {
                "id": call_id,
                "query": anchor["query"],
                "status": "completed",
                "coverage": run["coverage"]["status"],
                "observations": {
                    "facts": run.get("facts", {}),
                    "frames": [anchor["value"]] if anchor["type"] == "frame" else [],
                    "streams": [anchor["value"]] if anchor["type"] == "stream" else [],
                },
            }
        )
    run.setdefault("execution", {"status": "completed"})
    run["trace_id"] = "unit-trace.json"
    return {"input_id": scenario["capture"], "input_sha256": "a" * 64, "calls": calls}


def test_fabricated_or_unexecuted_evidence_fails() -> None:
    scenario = _manifest()["scenarios"][4]
    run = {
        "facts": scenario["expected_facts"],
        "conclusion": "confirmed",
        "coverage": {"status": "complete"},
        "execution": {"status": "error"},
        "evidence": [{"type": "frame", "query": "NOT_EXECUTED", "value": 999999}],
    }
    report = MODULE.score_run(scenario, run)
    assert not report["passed"]
    assert any("trace" in failure for failure in report["failures"])


def test_anchor_and_query_must_match_trace() -> None:
    scenario = _manifest()["scenarios"][4]
    run = {
        "facts": scenario["expected_facts"],
        "conclusion": "confirmed",
        "coverage": {"status": "complete"},
        "evidence": [
            {"type": "frame", "query": "frame 1", "value": 1},
            {"type": "frame", "query": "frame 3", "value": 3},
        ],
    }
    trace = _trace_for(scenario, run)
    assert MODULE.score_run(scenario, run, trace)["passed"]
    run["evidence"][0]["value"] = 999999
    run["evidence"][1]["query"] = "not the executed query"
    report = MODULE.score_run(scenario, run, trace)
    assert not report["passed"]
    assert any("not observed" in f for f in report["failures"])
    assert any("differs" in f for f in report["failures"])


def test_trace_artifact_tampering_and_path_escape_fail(tmp_path: Path) -> None:
    import hashlib

    result = tmp_path / "result.txt"
    result.write_text("actual output", encoding="utf-8")
    trace = {"calls": [{"result_file": "result.txt", "result_sha256": hashlib.sha256(result.read_bytes()).hexdigest()}]}
    sidecar = tmp_path / "trace.json"
    sidecar.write_text(json.dumps(trace), encoding="utf-8")
    run = {"trace_id": "trace.json", "trace_sha256": hashlib.sha256(sidecar.read_bytes()).hexdigest()}
    assert "load_error" not in MODULE.load_traces(tmp_path, [run])["trace.json"]
    result.write_text("modified output", encoding="utf-8")
    assert "load_error" in MODULE.load_traces(tmp_path, [run])["trace.json"]
    escaped = {"trace_id": "../outside.json", "trace_sha256": "a" * 64}
    assert "load_error" in MODULE.load_traces(tmp_path, [escaped])["../outside.json"]


def test_result_example_is_valid_json() -> None:
    value = json.loads((ROOT / "evals/agent-traffic-analysis/result.example.json").read_text(encoding="utf-8"))
    assert value["runs"]


def test_complete_claim_rejects_partial_call_and_failed_execution() -> None:
    scenario = _manifest()["scenarios"][2]
    run = {
        "facts": scenario["expected_facts"],
        "conclusion": "confirmed",
        "coverage": {"status": "complete"},
        "evidence": [{"type": "aggregate", "query": "real call"}],
    }
    trace = _trace_for(scenario, run)
    trace["calls"][0]["coverage"] = "partial"
    assert not MODULE.score_run(scenario, run, trace)["passed"]
    trace["calls"][0]["coverage"] = "complete"
    run["execution"]["status"] = "error"
    assert not MODULE.score_run(scenario, run, trace)["passed"]


def test_capture_digest_is_checked_against_actual_input(tmp_path: Path) -> None:
    import hashlib

    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"original input")
    result = tmp_path / "result.txt"
    result.write_bytes(b"one result")
    trace = {
        "input_id": str(capture),
        "input_sha256": hashlib.sha256(capture.read_bytes()).hexdigest(),
        "calls": [{"result_file": "result.txt", "result_sha256": hashlib.sha256(result.read_bytes()).hexdigest()}],
    }
    path = tmp_path / "trace.json"
    path.write_text(json.dumps(trace), encoding="utf-8")
    run = {"trace_id": "trace.json", "trace_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    assert "load_error" not in MODULE.load_traces(tmp_path, [run])["trace.json"]
    capture.write_bytes(b"changed input")
    assert "load_error" in MODULE.load_traces(tmp_path, [run])["trace.json"]


def test_unavailable_metric_is_missing_not_zero_or_failure() -> None:
    scenario = _manifest()["scenarios"][2]
    run = {
        "facts": scenario["expected_facts"],
        "conclusion": "confirmed",
        "coverage": {"status": "complete"},
        "evidence": [{"type": "query", "query": "actual call"}],
        "metrics": {"peak_rss_bytes": None},
    }
    trace = _trace_for(scenario, run)
    result = MODULE.score_run(scenario, run, trace)
    assert result["passed"]
    assert "peak_rss_bytes" not in result["metrics"]


def test_supporting_evidence_of_other_types_counts_only_when_true() -> None:
    scenario = next(item for item in _manifest()["scenarios"] if item["id"] == "T03_dns_query_count")
    run = {
        "scenario_id": scenario["id"],
        "conclusion": "confirmed",
        "facts": {"dns_query_count": 27},
        "coverage": {"status": "complete"},
        "evidence": [
            {"type": "aggregate", "query": "wireshark_aggregate(...)"},
            {"type": "frame", "query": "wireshark_aggregate(...)", "value": 1},
        ],
        "answer": "27 queries",
    }
    trace = _trace_for(scenario, run)
    assert MODULE.score_run(scenario, run, trace)["passed"] is True

    trace["calls"][1]["observations"]["frames"] = []
    assert MODULE.score_run(scenario, run, trace)["passed"] is False

    only_support = {**run, "evidence": [dict(run["evidence"][1])]}
    trace = _trace_for(scenario, only_support)
    failures = MODULE.score_run(scenario, only_support, trace)["failures"]
    assert any("evidence anchors of type" in failure for failure in failures)


def test_scenarios_may_accept_more_than_one_conclusion() -> None:
    scenario = next(item for item in _manifest()["scenarios"] if item["id"] == "T17_changed_capture")
    assert scenario["acceptable_conclusions"] == ["unresolved", "confirmed"]
    run = {
        "scenario_id": scenario["id"],
        "conclusion": "confirmed",
        "facts": scenario["expected_facts"],
        "coverage": {"status": "complete"},
        "evidence": [{"type": "query", "query": "sha256 after.pcap"}],
        "answer": "The capture changed; earlier results cannot be reused.",
    }
    assert MODULE.score_run(scenario, run, _trace_for(scenario, run))["passed"] is True
    rejected = {**run, "conclusion": "no_match"}
    failures = MODULE.score_run(scenario, rejected, _trace_for(scenario, rejected))["failures"]
    assert any("conclusion expected" in failure for failure in failures)
