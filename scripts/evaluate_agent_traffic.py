#!/usr/bin/env python3
"""Score structured Agent traffic-analysis runs against the repository suite."""

from __future__ import annotations

import argparse
import json
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
    if isinstance(expected, list):
        return isinstance(actual, list) and sorted(actual, key=str) == sorted(expected, key=str)
    return actual == expected


def _claim_text(run: dict[str, Any]) -> str:
    reportable = {key: run.get(key) for key in ("answer", "claims", "facts", "evidence") if run.get(key) is not None}
    return json.dumps(reportable, ensure_ascii=False, default=str).casefold()


def score_run(scenario: dict[str, Any], run: dict[str, Any]) -> dict[str, Any]:
    failures: list[str] = []
    conclusion = run.get("conclusion")
    if conclusion not in VALID_CONCLUSIONS:
        failures.append(f"invalid conclusion: {conclusion!r}")
    elif conclusion != scenario["expected_conclusion"]:
        failures.append(f"conclusion expected {scenario['expected_conclusion']!r}, got {conclusion!r}")

    facts = run.get("facts")
    if not isinstance(facts, dict):
        failures.append("facts must be an object")
        facts = {}
    for key, expected in scenario.get("expected_facts", {}).items():
        if key not in facts:
            failures.append(f"missing fact: {key}")
        elif not _same_value(facts[key], expected):
            failures.append(f"fact {key!r} expected {expected!r}, got {facts[key]!r}")

    coverage = run.get("coverage")
    coverage_status = coverage.get("status") if isinstance(coverage, dict) else None
    if coverage_status not in scenario.get("allowed_coverage", []):
        failures.append(f"coverage {coverage_status!r} not in {scenario.get('allowed_coverage', [])!r}")
    if coverage_status != "complete" and conclusion == "no_match" and run.get("claim_scope") == "capture":
        failures.append("partial or unknown coverage cannot support a capture-wide no-match claim")

    evidence = run.get("evidence")
    if not isinstance(evidence, list):
        failures.append("evidence must be a list")
        evidence = []
    rule = scenario.get("evidence", {})
    if len(evidence) < rule.get("min_anchors", 0):
        failures.append(f"expected at least {rule.get('min_anchors', 0)} evidence anchors")
    accepted = set(rule.get("accepted_types", []))
    for index, anchor in enumerate(evidence):
        if not isinstance(anchor, dict):
            failures.append(f"evidence[{index}] must be an object")
            continue
        if anchor.get("type") not in accepted:
            failures.append(f"evidence[{index}] type {anchor.get('type')!r} is not accepted")
        if rule.get("query_required") and not str(anchor.get("query", "")).strip():
            failures.append(f"evidence[{index}] is missing the executed query")

    text = _claim_text(run)
    for forbidden in scenario.get("forbidden_claims", []):
        if forbidden.casefold() in text:
            failures.append(f"forbidden claim present: {forbidden!r}")

    metrics = run.get("metrics", {}) if isinstance(run.get("metrics"), dict) else {}
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


def evaluate(manifest: dict[str, Any], runs: list[dict[str, Any]]) -> dict[str, Any]:
    scenarios = {item["id"]: item for item in manifest.get("scenarios", [])}
    reports: list[dict[str, Any]] = []
    unknown: list[str] = []
    for run in runs:
        scenario_id = run.get("scenario_id")
        scenario = scenarios.get(scenario_id)
        if scenario is None:
            unknown.append(str(scenario_id))
            continue
        reports.append(score_run(scenario, run))

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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    report = evaluate(_load_json(args.manifest), _load_runs(args.results))
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
