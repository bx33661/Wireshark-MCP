"""Smoke tests for public tool registration and compatibility behavior."""

import asyncio
import json

from conftest import MockTSharkClient
from mcp.server.fastmcp import FastMCP

from wireshark_mcp.tools.envelope import success_response
from wireshark_mcp.tools.extract import register_extract_tools
from wireshark_mcp.tools.registry import ToolRegistry


def _run_async(coro):
    return asyncio.run(coro)


def test_read_packets_remains_available_for_1_x_compatibility(mock_client: MockTSharkClient) -> None:
    mcp = FastMCP("test")
    register_extract_tools(mcp, mock_client)

    result = json.loads(_run_async(mcp._tool_manager.call_tool("wireshark_read_packets", {"pcap_file": "demo.pcap"})))

    assert result["success"] is True
    assert "-T json" in result["data"]


def test_list_ips_preserves_public_behavior(mock_client: MockTSharkClient) -> None:
    async def fake_extract_fields(*_args, **_kwargs) -> str:
        return success_response('ip.src\tip.dst\n"1.1.1.1"\t"2.2.2.2"\n"1.1.1.1"\t""\n')

    mcp = FastMCP("test")
    register_extract_tools(mcp, mock_client)
    mock_client.extract_fields = fake_extract_fields  # type: ignore[method-assign]

    result = json.loads(_run_async(mcp._tool_manager.call_tool("wireshark_list_ips", {"pcap_file": "demo.pcap"})))

    assert result["success"] is True
    assert result["data"] == "1.1.1.1\n2.2.2.2"


def test_contextual_protocol_tool_smoke(mock_client: MockTSharkClient) -> None:
    mcp = FastMCP("test")
    registry = ToolRegistry(mcp, mock_client)
    registry.build_catalog()
    registry.register_all_contextual_tools()

    result = json.loads(
        _run_async(mcp._tool_manager.call_tool("wireshark_extract_tls_handshakes", {"pcap_file": "demo.pcap"}))
    )

    assert result["success"] is True
    assert "Client Hello" in result["data"]


def test_contextual_threat_tool_smoke(mock_client: MockTSharkClient) -> None:
    mcp = FastMCP("test")
    registry = ToolRegistry(mcp, mock_client)
    registry.build_catalog()
    registry.register_all_contextual_tools()

    result = json.loads(
        _run_async(mcp._tool_manager.call_tool("wireshark_detect_port_scan", {"pcap_file": "demo.pcap"}))
    )

    assert result["success"] is True
    assert "Port Scan Detection" in result["data"]


def test_contextual_extract_tool_smoke(mock_client: MockTSharkClient) -> None:
    mcp = FastMCP("test")
    registry = ToolRegistry(mcp, mock_client)
    registry.build_catalog()
    registry.register_all_contextual_tools()

    result = json.loads(
        _run_async(mcp._tool_manager.call_tool("wireshark_extract_dns_queries", {"pcap_file": "demo.pcap"}))
    )

    assert result["success"] is True
    assert "-e dns.qry.name" in result["data"]
