"""End-to-end regression tests running against real tshark with deterministic pcap fixtures."""

import shutil
from pathlib import Path

import pytest
from conftest import call_tool_text
from mcp.server import MCPServer

from wireshark_mcp.tools.envelope import parse_tool_result
from wireshark_mcp.tools.security import make_security_tools
from wireshark_mcp.tools.stats import register_stats_tools
from wireshark_mcp.tools.threat import make_threat_tools
from wireshark_mcp.tshark.client import TSharkClient

pytestmark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "pcaps"


@pytest.fixture(scope="module")
def pcap_fixtures() -> dict[str, str]:
    from fixtures.generate_pcaps import build_all_fixtures

    paths = build_all_fixtures(FIXTURES_DIR)
    return {k: str(v) for k, v in paths.items()}


@pytest.mark.asyncio
async def test_real_pcap_credential_extraction(pcap_fixtures: dict[str, str]) -> None:
    client = TSharkClient()
    tools = dict(make_security_tools(client))
    pcap = pcap_fixtures["credentials"]

    raw = await tools["wireshark_extract_credentials"](pcap)
    parsed = parse_tool_result(raw)

    assert parsed["success"] is True
    data = parsed["data"]
    assert len(data["findings"]) == 1

    finding = data["findings"][0]
    assert finding["severity"] == "high"
    assert finding["confidence"] == "confirmed"

    evidence = finding["evidence"]
    protocols = {e.get("protocol") for e in evidence}
    assert "HTTP" in protocols
    assert "FTP" in protocols

    # Ensure passwords under 20 chars (admin:secret and 123456) were NOT dropped
    http_ev = next(e for e in evidence if e.get("protocol") == "HTTP")
    assert "admin:" in http_ev["value"]
    assert "secret" not in http_ev["value"]  # masked!

    ftp_ev = next(e for e in evidence if e.get("protocol") == "FTP")
    assert ftp_ev["value"] == "1*****"  # 123456 masked!


@pytest.mark.asyncio
async def test_real_pcap_dns_tunnel_candidate(pcap_fixtures: dict[str, str]) -> None:
    client = TSharkClient()
    tools = dict(make_threat_tools(client))
    pcap = pcap_fixtures["dns_tunnel"]

    raw = await tools["wireshark_detect_dns_tunnel"](pcap)
    parsed = parse_tool_result(raw)

    assert parsed["success"] is True
    data = parsed["data"]
    assert len(data["findings"]) == 1

    finding = data["findings"][0]
    assert finding["severity"] == "high"
    assert finding["confidence"] == "candidate"
    assert "Candidate DNS tunneling" in finding["observation"]
    assert finding["constraints"]["scanned"] == 27  # 2 normal + 25 exfil
    assert finding["constraints"]["limit"] == 5000


@pytest.mark.asyncio
async def test_real_pcap_port_scan_detection(pcap_fixtures: dict[str, str]) -> None:
    client = TSharkClient()
    tools = dict(make_threat_tools(client))
    pcap = pcap_fixtures["syn_scan"]

    # Threshold 15: should flag scanner with 25 ports
    raw_hit = await tools["wireshark_detect_port_scan"](pcap, threshold=15)
    parsed_hit = parse_tool_result(raw_hit)
    assert parsed_hit["success"] is True
    finding_hit = parsed_hit["data"]["findings"][0]
    assert finding_hit["severity"] == "high"
    assert "192.168.1.50" in finding_hit["evidence"][0]["value"]

    # Threshold 30: should report clean (only 25 scanned)
    raw_clean = await tools["wireshark_detect_port_scan"](pcap, threshold=30)
    parsed_clean = parse_tool_result(raw_clean)
    assert parsed_clean["success"] is True
    finding_clean = parsed_clean["data"]["findings"][0]
    assert finding_clean["severity"] == "info"
    assert finding_clean["confidence"] == "confirmed"


@pytest.mark.asyncio
async def test_real_pcap_aggregation_and_multivalue(pcap_fixtures: dict[str, str]) -> None:
    client = TSharkClient()
    mcp = MCPServer("test")
    register_stats_tools(mcp, client)
    pcap = pcap_fixtures["multivalue"]

    raw = await call_tool_text(
        mcp,
        "wireshark_aggregate",
        {
            "pcap_file": pcap,
            "group_by": "ip.src,tcp.dstport",
            "distinct": "http.user_agent",
        },
    )
    parsed = parse_tool_result(raw)
    assert parsed["success"] is True
    data = parsed["data"]
    assert data["matched_packets"] == 1
    assert data["groups_total"] == 1
    group = data["groups"][0]
    assert group["key"]["ip.src"] == "10.1.1.5"
    assert group["key"]["tcp.dstport"] == "80"


@pytest.mark.asyncio
async def test_real_pcap_numeric_aggregation(pcap_fixtures: dict[str, str]) -> None:
    client = TSharkClient()
    mcp = MCPServer("test")
    register_stats_tools(mcp, client)

    raw = await call_tool_text(
        mcp,
        "wireshark_aggregate",
        {
            "pcap_file": pcap_fixtures["credentials"],
            "group_by": "ip.src",
            "sum_fields": "frame.len",
            "avg_fields": "frame.len",
            "sort_by": "numeric_desc",
            "sort_numeric": "frame.len",
        },
    )
    parsed = parse_tool_result(raw)

    assert parsed["success"] is True
    group = parsed["data"]["groups"][0]
    assert group["key"] == {"ip.src": "192.168.1.10"}
    assert group["numeric"]["frame.len"] == {
        "valid_values": 3,
        "missing_values": 0,
        "invalid_values": 0,
        "sum": 304.0,
        "avg": pytest.approx(304 / 3),
    }


@pytest.mark.asyncio
async def test_real_pcap_empty_capture_handling(pcap_fixtures: dict[str, str]) -> None:
    client = TSharkClient()
    tools_sec = dict(make_security_tools(client))
    tools_thr = dict(make_threat_tools(client))
    pcap = pcap_fixtures["empty"]

    raw_sec = await tools_sec["wireshark_extract_credentials"](pcap)
    parsed_sec = parse_tool_result(raw_sec)
    assert parsed_sec["success"] is True
    assert parsed_sec["data"]["findings"] == []

    raw_dns = await tools_thr["wireshark_detect_dns_tunnel"](pcap)
    parsed_dns = parse_tool_result(raw_dns)
    assert parsed_dns["success"] is True
    assert parsed_dns["data"]["findings"] == []
