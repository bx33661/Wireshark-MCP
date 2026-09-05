"""Smoke tests for the public prompt and resource surface."""

import asyncio
import json

from conftest import MockTSharkClient
from mcp.server import MCPServer

from wireshark_mcp.prompts import register_prompts
from wireshark_mcp.resources import register_resources


def _run_async(coro):
    return asyncio.run(coro)


def test_register_prompts_exposes_expected_prompt_names() -> None:
    mcp = MCPServer("test")
    register_prompts(mcp)

    names = {prompt.name for prompt in _run_async(mcp.list_prompts())}
    assert names == {
        "security_audit",
        "performance_analysis",
        "incident_response",
        "traffic_overview",
        "analyze_with_hypothesis",
        "investigate_alert",
    }


def test_security_audit_prompt_uses_open_file_and_credential_review() -> None:
    mcp = MCPServer("test")
    register_prompts(mcp)

    result = _run_async(mcp.get_prompt("security_audit", {"pcap_file": "demo.pcap"}))
    text = result.messages[0].content.text

    assert 'wireshark_open_file("demo.pcap")' in text
    assert 'wireshark_extract_credentials("demo.pcap")' in text
    assert "wireshark_check_threats" not in text


def test_usage_guide_mentions_open_file_aggregate_and_deprecation_note() -> None:
    mcp = MCPServer("test")
    register_resources(mcp, MockTSharkClient())

    contents = _run_async(mcp.read_resource("wireshark://guide/usage"))
    text = contents[0].content

    assert "wireshark_open_file" in text
    assert "wireshark_aggregate" in text
    assert "wireshark_read_packets" in text
    assert "deprecated" in text


def test_capabilities_resource_returns_machine_readable_json() -> None:
    mcp = MCPServer("test")
    register_resources(mcp, MockTSharkClient())

    contents = _run_async(mcp.read_resource("wireshark://capabilities"))
    payload = json.loads(contents[0].content)

    assert payload["tshark"]["available"] is True
    assert payload["_meta"]["capture_backend"] == "dumpcap"
