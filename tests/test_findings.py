"""Unified Finding contract shared by every detection tool."""

import shutil
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from wireshark_mcp.tools.anomaly import make_anomaly_tools
from wireshark_mcp.tools.envelope import parse_tool_result, success_response
from wireshark_mcp.tools.findings import (
    Finding,
    finalize_findings,
    finding_id,
    render_findings_markdown,
    reproduce_commands,
)
from wireshark_mcp.tools.protocol import make_protocol_tools
from wireshark_mcp.tools.security import make_security_tools
from wireshark_mcp.tools.threat import make_threat_tools

FIXTURES = Path(__file__).parent / "fixtures" / "pcaps"


def _finding(**overrides: Any) -> Finding:
    finding: Finding = {
        "observation": "Port scan candidate from 10.0.0.5.",
        "severity": "high",
        "confidence": "candidate",
        "evidence": [{"frame": 7, "filter": "ip.src == 10.0.0.5"}],
    }
    finding.update(overrides)  # type: ignore[typeddict-item]
    return finding


def assert_finding_contract(finding: dict[str, Any], tool: str) -> None:
    assert finding["id"].startswith("wf-") and len(finding["id"]) == 19
    assert finding["tool"] == tool
    assert finding["severity"] in {"info", "low", "medium", "high", "critical"}
    assert finding["confidence"] in {"candidate", "likely", "confirmed"}
    assert isinstance(finding["observation"], str) and finding["observation"]
    assert isinstance(finding["evidence"], list)


def test_finding_id_is_stable_and_content_addressed() -> None:
    assert finding_id("t", _finding()) == finding_id("t", _finding())
    assert finding_id("t", _finding()) != finding_id("other", _finding())
    assert finding_id("t", _finding()) != finding_id("t", _finding(evidence=[{"frame": 8}]))


def test_finalize_adds_provenance_and_attack_candidates() -> None:
    findings = finalize_findings("wireshark_detect_port_scan", "/tmp/a b.pcap", [_finding()], "port_scan")
    finding = findings[0]
    assert_finding_contract(dict(finding), "wireshark_detect_port_scan")
    assert finding["category"] == "port_scan"
    assert finding["mitre_attack"] == ["T1046"]
    assert finding["reproduce"] == ["tshark -n -r '/tmp/a b.pcap' -Y 'ip.src == 10.0.0.5'"]


def test_informational_findings_do_not_claim_attack_techniques() -> None:
    finding = finalize_findings("tool", "x.pcap", [_finding(severity="info")], "port_scan")[0]
    assert "mitre_attack" not in finding


def test_reproduce_falls_back_to_frame_detail() -> None:
    assert reproduce_commands("c.pcap", [{"frame": 3}]) == ["tshark -n -r c.pcap -Y 'frame.number == 3' -V"]
    assert reproduce_commands("c.pcap", [{"description": "no anchor"}]) == []


def test_markdown_is_rendered_from_findings_in_severity_order() -> None:
    findings = finalize_findings(
        "tool", "c.pcap", [_finding(severity="low", observation="minor"), _finding(observation="major")]
    )
    text = render_findings_markdown(findings)
    assert text.index("major") < text.index("minor")
    assert findings[0]["id"] in text
    assert "filter `ip.src == 10.0.0.5`" in text
    assert render_findings_markdown([]) == "No findings."


@pytest.mark.asyncio
async def test_beaconing_emits_structured_findings() -> None:
    rows = ["ip.src\tip.dst\ttcp.dstport\tframe.time_epoch\tframe.number"]
    rows += [f"10.0.0.9\t198.51.100.7\t443\t{1000 + 60 * i}.0\t{i + 1}" for i in range(12)]
    client = AsyncMock()
    client.extract_fields.return_value = success_response("\n".join(rows))
    tools = dict(make_anomaly_tools(client))
    parsed = parse_tool_result(await tools["wireshark_detect_beaconing"]("cap.pcap"))
    assert parsed["coverage"]["status"] == "complete"
    [finding] = parsed["data"]["findings"]
    assert_finding_contract(finding, "wireshark_detect_beaconing")
    assert finding["details"]["connections"] == 12
    assert finding["evidence"][0]["frame"] == 1
    assert finding["mitre_attack"] == ["T1071", "T1573"]


@pytest.mark.asyncio
async def test_exfiltration_volume_ranking_is_not_a_detection() -> None:
    client = AsyncMock()
    client.extract_fields.side_effect = [
        success_response("ip.src\tip.dst\ttcp.dstport\ttcp.len\tframe.number\n10.0.0.2\t203.0.113.5\t443\t9000\t4"),
        success_response(""),
    ]
    tools = dict(make_anomaly_tools(client))
    parsed = parse_tool_result(await tools["wireshark_detect_exfiltration"]("cap.pcap"))
    [finding] = parsed["data"]["findings"]
    assert finding["severity"] == "info"
    assert "mitre_attack" not in finding
    assert finding["details"]["top_outbound_transfers"][0]["bytes"] == 9000


@pytest.mark.asyncio
async def test_arp_conflict_becomes_candidate_finding() -> None:
    rows = [
        "arp.src.hw_mac\tarp.src.proto_ipv4\tarp.dst.proto_ipv4\tarp.opcode\tframe.number",
        "aa:aa:aa:aa:aa:01\t10.0.0.1\t10.0.0.9\t2\t1",
        "bb:bb:bb:bb:bb:02\t10.0.0.1\t10.0.0.9\t2\t2",
    ]
    client = AsyncMock()
    client.extract_fields.return_value = success_response("\n".join(rows))
    tools = dict(make_protocol_tools(client))
    parsed = parse_tool_result(await tools["wireshark_detect_arp_spoofing"]("cap.pcap"))
    [finding] = parsed["data"]["findings"]
    assert_finding_contract(finding, "wireshark_detect_arp_spoofing")
    assert finding["confidence"] == "candidate"
    assert [item["frame"] for item in finding["evidence"]] == [1, 2]


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("factory", "tool", "capture"),
    [
        (make_threat_tools, "wireshark_detect_port_scan", "syn_scan_burst.pcap"),
        (make_threat_tools, "wireshark_detect_dns_tunnel", "dns_tunnel_candidate.pcap"),
        (make_threat_tools, "wireshark_detect_dos_attack", "syn_scan_burst.pcap"),
        (make_security_tools, "wireshark_extract_credentials", "plaintext_credentials.pcap"),
        (make_anomaly_tools, "wireshark_detect_beaconing", "syn_scan_burst.pcap"),
        (make_anomaly_tools, "wireshark_detect_exfiltration", "dns_tunnel_candidate.pcap"),
        (make_anomaly_tools, "wireshark_detect_protocol_anomalies", "plaintext_credentials.pcap"),
        (make_protocol_tools, "wireshark_detect_arp_spoofing", "plaintext_credentials.pcap"),
    ],
)
async def test_real_detectors_share_the_finding_contract(
    real_client: Any, factory: Any, tool: str, capture: str
) -> None:
    tools = dict(factory(real_client))
    parsed = parse_tool_result(await tools[tool](str(FIXTURES / capture)))
    assert parsed["success"], parsed
    assert isinstance(parsed["data"]["findings"], list)
    assert isinstance(parsed["data"]["summary"], str)
    for finding in parsed["data"]["findings"]:
        assert_finding_contract(finding, tool)
