"""Smoke tests for the public prompt and resource surface."""

import asyncio
import json

from conftest import MockTSharkClient
from mcp.server.fastmcp import FastMCP

from wireshark_mcp.prompts import register_prompts
from wireshark_mcp.resources import register_resources


def _run_async(coro):
    return asyncio.run(coro)


def test_register_prompts_exposes_expected_prompt_names() -> None:
    mcp = FastMCP("test")
    register_prompts(mcp)

    names = {prompt.name for prompt in mcp._prompt_manager.list_prompts()}
    assert names == {
        "security_audit",
        "performance_analysis",
        "ctf_solve",
        "incident_response",
        "traffic_overview",
    }


def test_security_audit_prompt_uses_open_file_and_url_domain_wording() -> None:
    mcp = FastMCP("test")
    register_prompts(mcp)

    messages = _run_async(mcp._prompt_manager.render_prompt("security_audit", {"pcap_file": "demo.pcap"}))
    text = messages[0].content.text

    assert 'wireshark_open_file("demo.pcap")' in text
    assert "captured URLs and hostnames" in text


def test_usage_guide_mentions_open_file_and_compatibility_note() -> None:
    mcp = FastMCP("test")
    register_resources(mcp, MockTSharkClient())

    resource = _run_async(mcp._resource_manager.get_resource("wireshark://guide/usage"))
    text = _run_async(resource.read())

    assert "wireshark_open_file" in text
    assert "wireshark_read_packets" in text
    assert "1.x compatibility" in text


def test_capabilities_resource_returns_machine_readable_json() -> None:
    mcp = FastMCP("test")
    register_resources(mcp, MockTSharkClient())

    resource = _run_async(mcp._resource_manager.get_resource("wireshark://capabilities"))
    payload = json.loads(_run_async(resource.read()))

    assert payload["tshark"]["available"] is True
    assert payload["_meta"]["capture_backend"] == "dumpcap"
