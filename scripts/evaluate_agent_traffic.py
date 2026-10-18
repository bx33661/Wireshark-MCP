#!/usr/bin/env python3
"""Score structured Agent traffic-analysis runs against the repository suite."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable

DEFAULT_MANIFEST = Path("evals/agent-traffic-analysis/scenarios.json")
VALID_CONCLUSIONS = {"confirmed", "likely", "candidate", "unresolved", "no_match"}


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_runs(path: Path) -> list[dict[str, Any]]:
    if path.suffix == ".jsonl":
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    data = _load_json(path)
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("runs"), list):
        return data["runs"]
    raise ValueError('results must be a JSON list, {"runs": [...]}, or JSONL records')


def _same_value(actual: Any, expected: Any) -> bool:
    if isinstance(actual, bool) != isinstance(expected, bool):
        return False
    if isinstance(expected, list):
        return isinstance(actual, list) and sorted(actual, key=str) == sorted(expected, key=str)
    return actual == expected


def _claim_text(run: dict[str, Any]) -> str:
    reportable = {key: run.get(key) for key in ("answer", "claims", "facts", "evidence") if run.get(key) is not None}
    return json.dumps(reportable, ensure_ascii=False, default=str).casefold()


def load_traces(directory: Path, runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Load harness-owned sidecars, checking result artifacts before scoring reports.

    This checks integrity/consistency, not collector authenticity or causal reasoning.
    Keep this directory separate from the Agent's writable answer directory.
    """
    traces: dict[str, Any] = {}
    root = directory.resolve()
    for run in runs:
        trace_id = run.get("trace_id")
        if not isinstance(trace_id, str) or not trace_id or trace_id in traces:
            continue
        try:
            path = (root / trace_id).resolve()
            path.relative_to(root)
            raw = path.read_bytes()
            expected = run.get("trace_sha256")
            if not isinstance(expected, str) or hashlib.sha256(raw).hexdigest() != expected:
                raise ValueError("trace SHA-256 mismatch or missing digest")
            trace = json.loads(raw)
            if not isinstance(trace, dict) or not isinstance(trace.get("calls"), list):
                raise ValueError("invalid trace object")
            input_id = trace.get("input_id")
            if isinstance(input_id, str) and not input_id.startswith("synthetic://"):
                capture = Path(input_id)
                if not capture.is_absolute():
                    capture = Path(__file__).resolve().parents[1] / capture
                identity = hashlib.sha256()
                with capture.open("rb") as source:
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        identity.update(chunk)
                if identity.hexdigest() != trace.get("input_sha256"):
                    raise ValueError("input capture SHA-256 mismatch")
            for call in trace["calls"]:
                if not isinstance(call, dict):
                    raise ValueError("invalid trace call")
                artifact = (root / call["result_file"]).resolve()
                artifact.relative_to(root)
                if hashlib.sha256(artifact.read_bytes()).hexdigest() != call["result_sha256"]:
                    raise ValueError("result SHA-256 mismatch")
            trace["_verified_file_sha256"] = hashlib.sha256(raw).hexdigest()
            traces[trace_id] = trace
        except (OSError, ValueError, KeyError, TypeError) as exc:
            traces[trace_id] = {"load_error": str(exc)}
    return traces


def _check_trace(scenario: dict[str, Any], run: dict[str, Any], trace: Any, failures: list[str]) -> dict[str, Any]:
    if not isinstance(trace, dict) or trace.get("load_error"):
        failures.append("verified execution trace missing or invalid")
        return {}
    if "_verified_file_sha256" in trace and trace["_verified_file_sha256"] != run.get("trace_sha256"):
        failures.append("run trace SHA-256 differs from loaded sidecar")
    if trace.get("input_id") != scenario.get("capture"):
        failures.append("trace input does not match scenario capture")
    digest = trace.get("input_sha256")
    if not str(scenario.get("capture", "")).startswith("synthetic://") and (
        not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
    ):
        failures.append("trace capture SHA-256 missing or invalid")
    calls = trace.get("calls")
    if not isinstance(calls, list) or not calls:
        failures.append("trace has no calls")
        return {}
    indexed: dict[str, Any] = {}
    for call in calls:
        if not isinstance(call, dict) or not isinstance(call.get("id"), str) or not call["id"]:
            failures.append("invalid trace call ID")
            continue
        if call["id"] in indexed:
            failures.append("duplicate trace call ID")
        indexed[call["id"]] = call
    return indexed


def score_run(scenario: dict[str, Any], run: dict[str, Any], trace: dict[str, Any] | None = None) -> dict[str, Any]:
    failures: list[str] = []
    execution = run.get("execution")
    if not isinstance(execution, dict) or execution.get("status") != "completed":
        failures.append("investigation execution must be completed")
    calls = _check_trace(scenario, run, trace, failures)
    conclusion = run.get("conclusion")
    if conclusion not in VALID_CONCLUSIONS:
        failures.append(f"invalid conclusion: {conclusion!r}")
    elif conclusion not in scenario.get("acceptable_conclusions", [scenario["expected_conclusion"]]):
        expected = scenario.get("acceptable_conclusions", scenario["expected_conclusion"])
        failures.append(f"conclusion expected {expected!r}, got {conclusion!r}")

    facts = run.get("facts")
    if not isinstance(facts, dict):
        failures.append("facts must be an object")
        facts = {}
    evidence_ids = (
        {
            anchor["call_id"]
            for anchor in run.get("evidence", [])
            if isinstance(anchor, dict) and isinstance(anchor.get("call_id"), str)
        }
        if isinstance(run.get("evidence"), list)
        else set()
    )
    for key, expected in scenario.get("expected_facts", {}).items():
        if key not in facts:
            failures.append(f"missing fact: {key}")
        elif not _same_value(facts[key], expected):
            failures.append(f"fact {key!r} expected {expected!r}, got {facts[key]!r}")
        supporting = [
            call.get("observations", {}).get("facts", {})
            for call_id, call in calls.items()
            if call_id in evidence_ids
            if isinstance(call.get("observations"), dict)
        ]
        if not any(
            isinstance(values, dict) and key in values and _same_value(values[key], facts.get(key))
            for values in supporting
        ):
            failures.append(f"fact {key!r} has no trace observation")

    coverage = run.get("coverage")
    coverage_status = coverage.get("status") if isinstance(coverage, dict) else None
    if coverage_status not in scenario.get("allowed_coverage", []):
        failures.append(f"coverage {coverage_status!r} not in {scenario.get('allowed_coverage', [])!r}")
    if coverage_status != "complete" and conclusion == "no_match" and run.get("claim_scope") == "capture":
        failures.append("partial or unknown coverage cannot support a capture-wide no-match claim")
    if conclusion == "no_match" and run.get("claim_scope") not in {"capture", "filter", "window", "observed"}:
        failures.append("no-match conclusion requires an explicit claim scope")

    evidence = run.get("evidence")
    if not isinstance(evidence, list):
        failures.append("evidence must be a list")
        evidence = []
    rule = scenario.get("evidence", {})
    # Only accepted types count toward min_anchors; other items are supporting
    # context, but every item must still be true to the trace.
    accepted = set(rule.get("accepted_types", []))
    counted = sum(1 for anchor in evidence if isinstance(anchor, dict) and anchor.get("type") in accepted)
    if counted < rule.get("min_anchors", 0):
        failures.append(f"expected at least {rule.get('min_anchors', 0)} evidence anchors of type {sorted(accepted)!r}")
    for index, anchor in enumerate(evidence):
        if not isinstance(anchor, dict):
            failures.append(f"evidence[{index}] must be an object")
            continue
        if anchor.get("type") not in {"aggregate", "query", "frame", "stream", "error"}:
            failures.append(f"evidence[{index}] type {anchor.get('type')!r} is unknown")
        if rule.get("query_required") and not str(anchor.get("query", "")).strip():
            failures.append(f"evidence[{index}] is missing the executed query")
        call_id = anchor.get("call_id")
        call = calls.get(call_id) if isinstance(call_id, str) else None
        if call is None:
            failures.append(f"evidence[{index}] references no executed call")
            continue
        if anchor.get("query") != call.get("query"):
            failures.append(f"evidence[{index}] query differs from execution trace")
        is_error = anchor.get("type") == "error"
        if call.get("status") not in ({"error", "timeout", "output_limit"} if is_error else {"completed"}):
            failures.append(f"evidence[{index}] call status cannot support this evidence")
        if not is_error and coverage_status == "complete" and call.get("coverage") != "complete":
            failures.append(f"evidence[{index}] complete claim contradicts call coverage")
        if anchor.get("type") in {"frame", "stream"}:
            value = anchor.get("value")
            field = "frames" if anchor["type"] == "frame" else "streams"
            observed = call.get("observations", {})
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < (1 if field == "frames" else 0)
                or not isinstance(observed, dict)
                or value not in observed.get(field, [])
            ):
                failures.append(f"evidence[{index}] anchor was not observed in the executed result")

    text = _claim_text(run)
    for forbidden in scenario.get("forbidden_claims", []):
        if forbidden.casefold() in text:
            failures.append(f"forbidden claim present: {forbidden!r}")

    metrics = run.get("metrics", {}) if isinstance(run.get("metrics"), dict) else {}
    for key, value in metrics.items():
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            failures.append(f"invalid metric: {key}")
    return {
        "scenario_id": scenario["id"],
        "variant": run.get("variant", "unspecified"),
        "passed": not failures,
        "failures": failures,
        "metrics": {
            key: metrics.get(key)
            for key in ("tool_calls", "elapsed_ms", "peak_rss_bytes", "input_tokens", "output_tokens")
            if metrics.get(key) is not None
        },
    }


def _mean(values: Iterable[float]) -> float | None:
    collected = list(values)
    return round(sum(collected) / len(collected), 2) if collected else None


def evaluate(
    manifest: dict[str, Any], runs: list[dict[str, Any]], traces: dict[str, Any] | None = None
) -> dict[str, Any]:
    scenarios = {item["id"]: item for item in manifest.get("scenarios", [])}
    reports: list[dict[str, Any]] = []
    unknown: list[str] = []
    for run in runs:
        scenario_id = run.get("scenario_id")
        scenario = scenarios.get(scenario_id)
        if scenario is None:
            unknown.append(str(scenario_id))
            continue
        trace_id = run.get("trace_id")
        reports.append(score_run(scenario, run, (traces or {}).get(trace_id) if isinstance(trace_id, str) else None))

    submitted = {report["scenario_id"] for report in reports}
    missing = sorted(set(scenarios) - submitted)
    passed = sum(report["passed"] for report in reports)
    summary: dict[str, Any] = {
        "suite": manifest.get("suite"),
        "scenarios_total": len(scenarios),
        "runs_scored": len(reports),
        "runs_passed": passed,
        "pass_rate": round(passed / len(reports), 4) if reports else 0.0,
        "missing_scenarios": missing,
        "unknown_scenarios": unknown,
    }
    for key in ("tool_calls", "elapsed_ms", "peak_rss_bytes", "input_tokens", "output_tokens"):
        average = _mean(
            float(report["metrics"][key]) for report in reports if isinstance(report["metrics"].get(key), (int, float))
        )
        if average is not None:
            summary[f"mean_{key}"] = average
    return {"summary": summary, "results": reports}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path, help="JSON or JSONL structured Agent run records")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, help="write the JSON report to this path")
    parser.add_argument("--allow-missing", action="store_true", help="do not fail solely because scenarios are missing")
    parser.add_argument(
        "--trace-dir", type=Path, help="harness-owned trace/result directory; default: results sibling traces/"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    runs = _load_runs(args.results)
    report = evaluate(
        _load_json(args.manifest), runs, load_traces(args.trace_dir or args.results.parent / "traces", runs)
    )
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    summary = report["summary"]
    failed = summary["runs_passed"] != summary["runs_scored"]
    incomplete = bool(summary["missing_scenarios"] or summary["unknown_scenarios"])
    return 1 if failed or (incomplete and not args.allow_missing) else 0


if __name__ == "__main__":
    raise SystemExit(main())
