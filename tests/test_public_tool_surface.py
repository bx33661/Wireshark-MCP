"""Smoke tests for public tool registration and compatibility behavior."""

import asyncio
import json

from conftest import MockTSharkClient, call_tool_text
from mcp.server import MCPServer

from wireshark_mcp.tools.extract import register_extract_tools
from wireshark_mcp.tools.registry import ToolRegistry


def _run_async(coro):
    return asyncio.run(coro)


def test_read_packets_remains_available_as_a_deprecated_compatibility_tool(mock_client: MockTSharkClient) -> None:
    mcp = MCPServer("test")
    register_extract_tools(mcp, mock_client)

    result = json.loads(_run_async(call_tool_text(mcp, "wireshark_read_packets", {"pcap_file": "demo.pcap"})))

    assert result["success"] is True
    assert "-T json" in result["data"]


def test_protocol_tool_smoke(mock_client: MockTSharkClient) -> None:
    mcp = MCPServer("test")
    registry = ToolRegistry(mcp, mock_client)
    registry.register()

    result = json.loads(
        _run_async(
            call_tool_text(
                mcp,
                "wireshark_analyze_protocol",
                {"pcap_file": "demo.pcap", "protocol": "tls_handshakes"},
            )
        )
    )

    assert result["success"] is True
    assert "Client Hello" in result["data"]


def test_threat_tool_smoke(mock_client: MockTSharkClient) -> None:
    mcp = MCPServer("test")
    registry = ToolRegistry(mcp, mock_client)
    registry.register()

    result = json.loads(_run_async(call_tool_text(mcp, "wireshark_detect_port_scan", {"pcap_file": "demo.pcap"})))

    assert result["success"] is True
    data_str = result["data"]["summary"] if isinstance(result["data"], dict) else result["data"]
    assert "port scanning" in data_str.lower()


def test_extract_tool_smoke(mock_client: MockTSharkClient) -> None:
    mcp = MCPServer("test")
    registry = ToolRegistry(mcp, mock_client)
    registry.register()

    result = json.loads(_run_async(call_tool_text(mcp, "wireshark_extract_dns_queries", {"pcap_file": "demo.pcap"})))

    assert result["success"] is True
    assert "-e dns.qry.name" in result["data"]


def test_full_server_exposes_a_stable_tool_surface(monkeypatch) -> None:
    """Guard the advertised tool count so docs and code cannot silently drift."""
    from wireshark_mcp.server import _build_server

    mcp = _build_server(host="127.0.0.1", port=8080, log_level="ERROR")
    tools = _run_async(mcp.list_tools())
    names = {t.name for t in tools}

    # Entry point + agentic workflows are always present.
    assert "wireshark_open_file" in names
    assert "wireshark_quick_analysis" in names

    # No tools from the removed investigation/report/playbook/nl_query surface.
    removed = {
        "wireshark_security_audit",
        "wireshark_investigate",
        "wireshark_execute_playbook_step",
        "wireshark_add_hypothesis",
        "wireshark_generate_report",
        "wireshark_suggest_rules",
        "wireshark_list_playbooks",
        "wireshark_nl_query",
    }
    assert names.isdisjoint(removed)

    # Ceiling, not a floor. The surface is being deliberately reduced: every tool in the
    # list costs prefix bytes on every request and, more importantly, competes for the
    # model's attention at selection time. Lower this as tools are removed; raising it
    # should require justifying why a new tool is not reachable through an existing one.
    assert len(names) <= 52, f"tool surface grew to {len(names)}; justify or consolidate"


def test_every_protocol_recommendation_is_registered() -> None:
    """No PROTOCOL_TOOL_MAP entry may point at a tool the server never registers."""
    from wireshark_mcp.server import _build_server
    from wireshark_mcp.tools.registry import PROTOCOL_TOOL_MAP

    mcp = _build_server(host="127.0.0.1", port=8080, log_level="ERROR")
    names = {t.name for t in _run_async(mcp.list_tools())}

    referenced = {rec.tool for recs in PROTOCOL_TOOL_MAP.values() for rec in recs}
    missing = referenced - names
    assert not missing, f"Recommended but unregistered tools: {sorted(missing)}"


def test_every_recommended_protocol_value_is_in_the_enum() -> None:
    """A recommended `protocol` argument outside the enum renders an uncallable suggestion."""
    from wireshark_mcp.tools.analyze import supported_protocols
    from wireshark_mcp.tools.registry import PROTOCOL_TOOL_MAP

    referenced = {rec.protocol for recs in PROTOCOL_TOOL_MAP.values() for rec in recs if rec.protocol}
    unsupported = referenced - set(supported_protocols())
    assert not unsupported, f"Recommended but unsupported protocol values: {sorted(unsupported)}"
