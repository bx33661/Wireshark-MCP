"""Tests for the consolidated wireshark_analyze_protocol tool.

These replace the per-protocol test modules (test_protocol / test_ics / test_iot /
test_new_protocols / test_protocol_wireless), which called
`mock_client.extract_fields(...)` directly with a hand-copied field list and asserted
the echoed command contained it. That shape cannot fail: the expected value was a
second copy of the implementation, and no tool was ever invoked. A wrong field name
— the exact defect this tool exists to prevent, because it returns an empty result
that reads like a clean capture — passed both copies.

Here every assertion goes through the registered tool, so the field list and display
filter under test are the ones the tool actually sends to tshark.
"""

import json
from typing import Any

import pytest
from conftest import MockTSharkClient, call_tool_text
from mcp.server import MCPServer

from wireshark_mcp.tools.analyze import make_analyze_tools, supported_protocols
from wireshark_mcp.tools.registry import ToolRegistry


async def _analyze(mock_client: MockTSharkClient, protocol: str, **kwargs: Any) -> dict[str, Any]:
    """Call wireshark_analyze_protocol through the MCP tool manager."""
    mcp = MCPServer("test")
    ToolRegistry(mcp, mock_client).register()
    raw = await call_tool_text(
        mcp,
        "wireshark_analyze_protocol",
        {"pcap_file": "demo.pcap", "protocol": protocol, **kwargs},
    )
    return json.loads(raw)


class TestDispatchContract:
    """The enum in the schema and the handler table must not drift apart."""

    @pytest.mark.asyncio
    async def test_every_declared_protocol_has_a_handler(self, mock_client: MockTSharkClient) -> None:
        # A declared value with no handler is worse than a missing one: it passes schema
        # validation, so the caller gets a runtime error for a documented option.
        tools = dict(make_analyze_tools(mock_client))
        assert set(tools) == {"wireshark_analyze_protocol"}

        for protocol in supported_protocols():
            result = json.loads(await tools["wireshark_analyze_protocol"]("demo.pcap", protocol))
            assert result["success"] is True, f"{protocol} is in the enum but failed to dispatch"

    def test_enum_is_sorted_and_unique(self) -> None:
        # The enum ships in the prompt prefix of every request; a stable order keeps the
        # bytes identical across restarts so the client's cache survives.
        values = supported_protocols()
        assert list(values) == sorted(values)
        assert len(set(values)) == len(values)

    @pytest.mark.asyncio
    async def test_unknown_protocol_is_rejected(self, mock_client: MockTSharkClient) -> None:
        tools = dict(make_analyze_tools(mock_client))
        result = json.loads(await tools["wireshark_analyze_protocol"]("demo.pcap", "not_a_protocol"))
        assert result["success"] is False
        assert "not_a_protocol" in result["error"]["message"]


class TestProtocolQueries:
    """Each protocol must send its own fields and display filter."""

    # (protocol, display filter, a field only this protocol asks for)
    CASES = [
        ("tls_handshakes", "tls.handshake.type == 1", "tls.handshake.extensions_server_name"),
        ("smtp", "smtp", "smtp.req.parameter"),
        ("dhcp", "dhcp", "dhcp.option.domain_name_server"),
        ("quic", "quic", "quic.connection.number"),
        ("websocket", "websocket", "websocket.payload_length"),
        ("mqtt", "mqtt", "mqtt.clientid"),
        ("grpc", "grpc", "grpc.message_length"),
        ("ble", "btle", "btle.advertising_address"),
        ("wifi", "wlan.fc.type == 0", "wlan.rsn.akms.type"),
        ("wireguard", "wg", "wg.receiver"),
        ("doh", 'http2.header.name == "content-type"', "http2.header.value"),
        ("icmp_tunnel", "icmp && data.len > 48", "data.len"),
        ("modbus", "modbus", "modbus.func_code"),
        ("s7comm", "s7comm", "s7comm.param.item.db"),
        ("dnp3", "dnp3", "dnp3.al.iin"),
        ("coap", "coap", "coap.opt.uri_path"),
        ("zigbee", "zbee_nwk", "zbee_aps.cluster"),
    ]

    @pytest.mark.parametrize(("protocol", "display_filter", "field"), CASES)
    @pytest.mark.asyncio
    async def test_sends_expected_filter_and_field(
        self, mock_client: MockTSharkClient, protocol: str, display_filter: str, field: str
    ) -> None:
        result = await _analyze(mock_client, protocol)
        assert result["success"] is True
        # Exact tokens, not a substring of the echoed command: `"-e foo.bar" in text`
        # also matches `foo.barbaz`, so a mistyped field name would slip through.
        assert field in mock_client.fields_requested(), f"{protocol} did not request {field}"
        assert any(display_filter in f for f in mock_client.filters_applied()), (
            f"{protocol} did not apply filter {display_filter!r}"
        )

    @pytest.mark.asyncio
    async def test_rtp_uses_the_stats_facility_not_field_extraction(self, mock_client: MockTSharkClient) -> None:
        # rtp and smb go through -z, so they carry no -e fields at all.
        result = await _analyze(mock_client, "rtp")
        assert result["success"] is True
        assert "-z rtp,streams" in result["data"]
        assert mock_client.fields_requested() == set()

    @pytest.mark.asyncio
    async def test_smb_uses_the_srt_facility(self, mock_client: MockTSharkClient) -> None:
        result = await _analyze(mock_client, "smb")
        assert result["success"] is True
        assert "-z smb,srt" in result["data"]

    @pytest.mark.asyncio
    async def test_kerberos_extracts_ticket_fields(self, mock_client: MockTSharkClient) -> None:
        result = await _analyze(mock_client, "kerberos")
        assert result["success"] is True
        assert "kerberos" in result["data"]


class TestLimit:
    """`limit` must reach tshark, and the default must not silently change."""

    @pytest.mark.asyncio
    async def test_limit_is_forwarded(self, mock_client: MockTSharkClient) -> None:
        await _analyze(mock_client, "ble", limit=7)
        # Line capping is applied by the runner, not argv, so assert on the recorded
        # limit rather than the echoed command string.
        assert mock_client._last_limit_lines == 7

    @pytest.mark.asyncio
    async def test_default_limit_is_one_hundred(self, mock_client: MockTSharkClient) -> None:
        mcp = MCPServer("test")
        ToolRegistry(mcp, mock_client).register()
        tool = mcp._tool_manager.get_tool("wireshark_analyze_protocol")
        assert tool is not None
        assert tool.parameters["properties"]["limit"]["default"] == 100
