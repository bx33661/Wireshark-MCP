from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
SCRIPT = ROOT / "scripts" / "agent_eval_harness.py"
SPEC = importlib.util.spec_from_file_location("agent_eval_harness", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

needs_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")


def _harness(*args: str) -> str:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), *args], capture_output=True, text=True, check=True, cwd=ROOT
    )
    return completed.stdout


def _prepare(root: Path, *extra: str) -> None:
    _harness("prepare", str(root), "--model", "m", "--reasoning-effort", "e", "--budget", "b", *extra)


def test_numeric_facts_need_a_standalone_value() -> None:
    assert MODULE._shows("Number of packets:   3", 3)
    assert MODULE._shows("total 3.", 3)
    assert not MODULE._shows("6c07a57ad1327dfce4bf13a6c864", 3)
    assert not MODULE._shows("3.5 seconds", 3)
    assert not MODULE._shows("13 packets", 3)


@needs_tshark
def test_prepare_writes_blind_cells_and_private_answers(tmp_path: Path) -> None:
    root = tmp_path / "eval"
    _prepare(root, "--repeats", "1")
    cells = sorted(path.name for path in (root / "cells").iterdir())
    assert len(cells) == 60
    assert {name.split("--")[1] for name in cells} == set(MODULE.VARIANTS)
    task = json.loads((root / "cells" / cells[0] / "task.json").read_text(encoding="utf-8"))
    assert "expected_facts" not in json.dumps(task)
    assert set(task) >= {"prompt", "inputs", "fact_keys"}
    private = json.loads((root / ".collector/cells.json").read_text(encoding="utf-8"))
    assert set(private) == set(cells)
    experiment = json.loads((root / "experiment.json").read_text(encoding="utf-8"))
    assert {"model", "reasoning_effort", "budget", "engine_version", "source_revision"} <= set(experiment)


@needs_tshark
def test_recorded_calls_score_through_the_evaluator(tmp_path: Path) -> None:
    root = tmp_path / "eval"
    _prepare(root, "--repeats", "1", "--variant", "with-skill", "--variant", "tshark-cli")
    capture = str(ROOT / "tests/fixtures/pcaps/plaintext_credentials.pcap")
    cells = {
        "with-skill": ["mcp", "wireshark_get_file_info", json.dumps({"pcap_file": capture})],
        "tshark-cli": ["cmd", "capinfos", "-c", capture],
    }
    for variant, request in cells.items():
        cell = root / "cells" / f"T01_capture_packet_count--{variant}--t1"
        output = _harness("call", "--cell", str(cell), *request)
        call_id, query = (line.split(": ", 1)[1] for line in output.splitlines()[:2])
        answer = {
            "answer": "3 packets.",
            "conclusion": "confirmed",
            "claim_scope": "capture",
            "facts": {"packet_count": 3},
            "coverage": {"status": "complete"},
            "evidence": [{"type": "aggregate", "call_id": call_id, "query": query, "value": 3}],
            "claims": ["The capture holds 3 packets."],
            "execution": {"status": "completed"},
        }
        (cell / "answer.json").write_text(json.dumps(answer), encoding="utf-8")

    _harness("finalize", str(root), "--output", str(tmp_path / "runs"))
    for variant in cells:
        report_path = tmp_path / f"{variant}-report.json"
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/evaluate_agent_traffic.py"),
                str(tmp_path / "runs" / f"{variant}.json"),
                "--trace-dir",
                str(root / ".collector/traces" / variant),
                "--allow-missing",
                "--output",
                str(report_path),
            ],
            capture_output=True,
            text=True,
            check=False,
            cwd=ROOT,
        )
        report = json.loads(report_path.read_text(encoding="utf-8"))
        assert report["summary"]["runs_passed"] == 1, report["results"]


@needs_tshark
def test_input_paths_do_not_count_as_observed_judgments(tmp_path: Path) -> None:
    root = tmp_path / "eval"
    _prepare(root, "--repeats", "1", "--variant", "tshark-cli")
    capture = str(ROOT / "tests/fixtures/pcaps/plaintext_credentials.pcap")
    cell = root / "cells" / "T05_plaintext_credentials--tshark-cli--t1"
    _harness("call", "--cell", str(cell), "hash", capture)
    _harness("call", "--cell", str(cell), "cmd", "capinfos", "-c", capture)
    trace_dir = root / ".collector/traces/tshark-cli"
    trace = json.loads(next(trace_dir.glob("T05_*.trace.json")).read_text(encoding="utf-8"))
    assert [call["observations"]["facts"] for call in trace["calls"]] == [{}, {}]


@needs_tshark
def test_partial_check_injection_is_visible_to_the_agent(tmp_path: Path) -> None:
    root = tmp_path / "eval"
    _prepare(root, "--repeats", "1", "--variant", "with-skill")
    cell = root / "cells" / "T11_partial_check_failure--with-skill--t1"
    capture = str(root / "inputs/partial-dos-check.pcap")
    output = _harness(
        "call", "--cell", str(cell), "mcp", "wireshark_detect_dos_attack", json.dumps({"pcap_file": capture})
    )
    assert "coverage: partial" in output
    assert MODULE.INJECTED_FAILURE in output
    trace = json.loads(next((root / ".collector/traces/with-skill").glob("T11_*.trace.json")).read_text("utf-8"))
    assert trace["calls"][0]["observations"]["facts"] == {"complete_assessment": False, "failed_checks_reported": True}


@needs_tshark
def test_drive_runs_the_agent_template_once_per_open_cell(tmp_path: Path) -> None:
    root = tmp_path / "eval"
    _prepare(root, "--repeats", "1", "--variant", "tshark-cli")
    agent = (
        sys.executable + " -c \"import json; print(json.dumps({'usage': {'input_tokens': 5, 'output_tokens': 2}}))\""
    )
    output = _harness("drive", str(root), "--agent", agent, "--only", "T01_")
    assert output.count("exit 0") == 1
    metrics = json.loads((root / ".collector/metrics/T01_capture_packet_count--tshark-cli--t1.json").read_text("utf-8"))
    assert metrics["input_tokens"] == 5
    assert metrics["output_tokens"] == 2
