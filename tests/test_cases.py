"""Persistent investigation case files (`wireshark_case`)."""

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from conftest import call_tool_text

from wireshark_mcp.cases import CaseError, CaseStore, render_case_markdown, summarize_case
from wireshark_mcp.mcp_app import WiresharkMCP
from wireshark_mcp.tools.case import register_case_tools
from wireshark_mcp.tools.findings import finalize_findings
from wireshark_mcp.tools.threat import make_threat_tools
from wireshark_mcp.tshark.client import TSharkClient

FIXTURES = Path(__file__).parent / "fixtures" / "pcaps"


def _tool_result(pcap: str, observation: str = "Scanner 10.0.0.5 probed 20 ports.") -> str:
    findings = finalize_findings(
        "wireshark_detect_port_scan",
        pcap,
        [
            {
                "observation": observation,
                "severity": "high",
                "confidence": "likely",
                "evidence": [{"frame": 1, "filter": "ip.src == 10.0.0.5"}],
            }
        ],
        "port_scan",
    )
    return json.dumps(
        {
            "success": True,
            "data": {"findings": findings, "summary": "x"},
            "scope": {"pcap_file": pcap},
            "coverage": {"status": "complete"},
        }
    )


@pytest.fixture
def capture(tmp_path: Path) -> Path:
    path = tmp_path / "evidence.pcap"
    shutil.copy(FIXTURES / "syn_scan_burst.pcap", path)
    return path


def test_case_lifecycle_round_trips_through_disk(tmp_path: Path, capture: Path) -> None:
    store = CaseStore(tmp_path / "cases")
    case = store.create("Scan triage", [capture])
    assert case["captures"][0]["sha256"] and case["captures"][0]["bytes"] == capture.stat().st_size

    first = store.record(case["case_id"], _tool_result(str(capture)))
    again = store.record(case["case_id"], _tool_result(str(capture)))
    assert len(first["new_findings"]) == 1
    assert again["new_findings"] == [] and again["known_findings"] == 1

    finding_id = first["new_findings"][0]
    store.set_verdict(case["case_id"], finding_id, "confirmed", "Matches the change window scanner.")
    store.add_note(case["case_id"], "Scanner is the vulnerability management appliance.")

    reloaded = CaseStore(tmp_path / "cases").load(case["case_id"])
    summary = summarize_case(reloaded)
    assert summary["queries"] == 2
    assert summary["verdicts"] == {"open": 0, "confirmed": 1, "dismissed": 0}
    assert reloaded["findings"][finding_id]["queries"] == [1, 2]

    report = render_case_markdown(reloaded)
    assert "## Confirmed findings" in report
    assert "tshark -n -r" in report and finding_id in report
    assert "Matches the change window scanner." in report


def test_record_rejects_failures_and_unidentified_findings(tmp_path: Path, capture: Path) -> None:
    store = CaseStore(tmp_path)
    case_id = store.create("t", [capture])["case_id"]
    with pytest.raises(CaseError):
        store.record(case_id, json.dumps({"success": False, "error": {"message": "x"}}))
    with pytest.raises(CaseError):
        store.record(case_id, "not json")
    with pytest.raises(CaseError):
        store.record(case_id, json.dumps({"success": True, "data": {"findings": [{"observation": "no id"}]}}))


def test_record_warns_when_result_came_from_another_capture(tmp_path: Path, capture: Path) -> None:
    store = CaseStore(tmp_path)
    case_id = store.create("t", [capture])["case_id"]
    result = store.record(case_id, _tool_result("/elsewhere/other.pcap"))
    assert result["warnings"]


def test_case_ids_cannot_escape_the_store(tmp_path: Path) -> None:
    store = CaseStore(tmp_path)
    for bad in ("../x", "case-../../etc", "case-ZZZZZZZZZZZZ", ""):
        with pytest.raises(CaseError):
            store.load(bad)


def test_verdict_requires_a_recorded_finding(tmp_path: Path, capture: Path) -> None:
    store = CaseStore(tmp_path)
    case_id = store.create("t", [capture])["case_id"]
    with pytest.raises(CaseError):
        store.set_verdict(case_id, "wf-0000000000000000", "confirmed")
    with pytest.raises(CaseError):
        store.set_verdict(case_id, "wf-0000000000000000", "maybe")


def _server(allowed: list[str] | None) -> WiresharkMCP:
    mcp = WiresharkMCP("test")
    register_case_tools(mcp, TSharkClient(allowed_dirs=allowed))
    return mcp


@pytest.mark.asyncio
async def test_case_tool_fails_closed_without_an_allowed_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WIRESHARK_MCP_CASE_DIR", raising=False)
    text = await call_tool_text(_server(None), "wireshark_case", {"action": "list"})
    payload = json.loads(text)
    assert payload["success"] is False
    assert payload["error"]["type"] == "PermissionDenied"


@pytest.mark.asyncio
async def test_case_dir_override_must_stay_inside_allowed_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WIRESHARK_MCP_CASE_DIR", "/tmp/not-allowed-cases")
    text = await call_tool_text(_server([str(tmp_path)]), "wireshark_case", {"action": "list"})
    assert json.loads(text)["error"]["type"] == "PermissionDenied"


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
@pytest.mark.asyncio
async def test_case_tool_records_a_real_detector_result(
    tmp_path: Path, capture: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("WIRESHARK_MCP_CASE_DIR", raising=False)
    mcp = _server([str(tmp_path)])

    async def call(**arguments: Any) -> dict[str, Any]:
        result: dict[str, Any] = json.loads(await call_tool_text(mcp, "wireshark_case", arguments))
        assert result["success"], result
        return result

    created = await call(action="create", text="SYN burst", target=str(capture))
    case_id = created["data"]["case_id"]
    assert (tmp_path / ".wireshark-mcp-cases" / f"{case_id}.json").is_file()

    detector = dict(make_threat_tools(TSharkClient(allowed_dirs=[str(tmp_path)])))
    scan = await detector["wireshark_detect_port_scan"](str(capture))
    recorded = await call(action="record", case_id=case_id, text=scan)
    assert recorded["data"]["warnings"] == []
    finding_id = recorded["data"]["new_findings"][0]

    await call(action="verdict", case_id=case_id, target=finding_id, text="dismissed: authorised scanner")
    shown = await call(action="show", case_id=case_id)
    assert shown["data"]["verdicts"]["dismissed"] == 1
    report = await call(action="report", case_id=case_id)
    assert "authorised scanner" in report["data"]["markdown"]
    listed = await call(action="list")
    assert listed["data"]["cases"][0]["case_id"] == case_id
