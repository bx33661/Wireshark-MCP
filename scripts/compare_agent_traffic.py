#!/usr/bin/env python3
"""Compare independently collected Agent traffic-analysis result sets."""

from __future__ import annotations

import argparse
import importlib.util
import json
import statistics
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
EVALUATOR_PATH = ROOT / "scripts" / "evaluate_agent_traffic.py"
DEFAULT_MANIFEST = ROOT / "evals" / "agent-traffic-analysis" / "scenarios.json"


def _load_evaluator() -> Any:
    spec = importlib.util.spec_from_file_location("agent_traffic_evaluator", EVALUATOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load evaluator: {EVALUATOR_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _mean(values: list[float]) -> float | None:
    return round(statistics.fmean(values), 2) if values else None


def summarize_variant(evaluation: dict[str, Any], runs: list[dict[str, Any]]) -> dict[str, Any]:
    results = evaluation["results"]
    passed = [result for result in results if result["passed"]]

    def passed_metrics(key: str) -> list[float]:
        return [
            float(result["metrics"][key])
            for result in passed
            if isinstance(result.get("metrics", {}).get(key), (int, float))
        ]

    failed_executions = sum(
        1
        for run in runs
        if isinstance(run.get("execution"), dict) and run["execution"].get("status") in {"error", "timeout"}
    )
    input_tokens = passed_metrics("input_tokens")
    output_tokens = passed_metrics("output_tokens")
    return {
        "runs": len(results),
        "runs_passed": len(passed),
        "pass_rate": round(len(passed) / len(results), 4) if results else 0.0,
        "execution_error_rate": round(failed_executions / len(runs), 4) if runs else 0.0,
        "missing_scenarios": evaluation["summary"]["missing_scenarios"],
        "unknown_scenarios": evaluation["summary"]["unknown_scenarios"],
        "eligible_efficiency_runs": len(passed),
        "mean_tool_calls": _mean(passed_metrics("tool_calls")),
        "mean_elapsed_ms": _mean(passed_metrics("elapsed_ms")),
        "mean_peak_rss_bytes": _mean(passed_metrics("peak_rss_bytes")),
        "mean_input_tokens": _mean(input_tokens),
        "mean_output_tokens": _mean(output_tokens),
        "total_tokens_on_passed_runs": int(sum(input_tokens) + sum(output_tokens))
        if input_tokens or output_tokens
        else None,
    }


def compare(manifest: dict[str, Any], inputs: list[tuple[str, list[dict[str, Any]]]]) -> dict[str, Any]:
    evaluator = _load_evaluator()
    variants: dict[str, Any] = {}
    details: dict[str, Any] = {}
    for name, runs in inputs:
        if name in variants:
            raise ValueError(f"Duplicate variant name: {name}")
        normalized = [{**run, "variant": name} for run in runs]
        evaluation = evaluator.evaluate(manifest, normalized)
        variants[name] = summarize_variant(evaluation, normalized)
        details[name] = evaluation["results"]
    return {
        "schema_version": 1,
        "suite": manifest.get("suite"),
        "comparison_rule": "Efficiency metrics include only runs that pass correctness, evidence, coverage, and calibration checks.",
        "variants": variants,
        "results": details,
    }


def _variant_argument(value: str) -> tuple[str, Path]:
    name, separator, raw_path = value.partition("=")
    if not separator or not name.strip() or not raw_path.strip():
        raise argparse.ArgumentTypeError("variant must use NAME=RESULTS.json")
    return name.strip(), Path(raw_path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", action="append", type=_variant_argument, required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    evaluator = _load_evaluator()
    manifest = evaluator._load_json(args.manifest)
    inputs = [(name, evaluator._load_runs(path)) for name, path in args.variant]
    report = compare(manifest, inputs)
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    complete = all(
        not data["missing_scenarios"] and not data["unknown_scenarios"] for data in report["variants"].values()
    )
    return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
