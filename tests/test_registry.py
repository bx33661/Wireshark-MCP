"""Tests for the analysis tool registry and protocol-aware recommendations."""

import json

from conftest import MockTSharkClient, call_tool_text

from wireshark_mcp.tools.envelope import error_response, success_response
from wireshark_mcp.tools.registry import ToolRegistry, parse_protocol_hierarchy, register_open_file_tool


class TestParseProtocolHierarchy:
    """Tests for protocol hierarchy parsing."""

    def test_parses_standard_output(self) -> None:
        phs = (
            "eth  frames:100 bytes:12345\n"
            "  ip  frames:90 bytes:11000\n"
            "    tcp  frames:80 bytes:10000\n"
            "      http  frames:30 bytes:5000\n"
            "      tls  frames:50 bytes:5000\n"
            "    udp  frames:10 bytes:1000\n"
            "      dns  frames:10 bytes:1000\n"
            "  arp  frames:10 bytes:1345\n"
        )
        protocols = parse_protocol_hierarchy(phs)
        assert {"eth", "ip", "tcp", "http", "tls", "udp", "dns", "arp"} <= protocols

    def test_empty_output(self) -> None:
        assert parse_protocol_hierarchy("") == set()

    def test_no_matching_lines(self) -> None:
        assert parse_protocol_hierarchy("some random text\n===\n") == set()

    def test_single_protocol(self) -> None:
        protocols = parse_protocol_hierarchy("eth  frames:5 bytes:100\n")
        assert protocols == {"eth"}


class TestToolRegistration:
    """Tests for the static analysis tool catalog."""

    def _registry(self, mock_client: MockTSharkClient) -> ToolRegistry:
        from mcp.server import MCPServer

        registry = ToolRegistry(MCPServer("test"), mock_client)
        registry.register()
        return registry

    def test_registers_nonempty_catalog(self, mock_client: MockTSharkClient) -> None:
        registry = self._registry(mock_client)
        assert registry.catalog_size > 0

    def test_catalog_contains_expected_tools(self, mock_client: MockTSharkClient) -> None:
        registry = self._registry(mock_client)
        expected_tools = [
            "wireshark_extract_http_requests",
            "wireshark_extract_dns_queries",
            "wireshark_export_objects",
            "wireshark_verify_ssl_decryption",
            "wireshark_analyze_protocol",
            "wireshark_analyze_tcp_health",
            "wireshark_detect_arp_spoofing",
            "wireshark_extract_credentials",
            "wireshark_detect_port_scan",
            "wireshark_detect_dns_tunnel",
            "wireshark_detect_dos_attack",
        ]
        for tool_name in expected_tools:
            assert tool_name in registry._catalog, f"Missing tool: {tool_name}"

    def test_register_returns_all_catalog_names(self, mock_client: MockTSharkClient) -> None:
        from mcp.server import MCPServer

        registry = ToolRegistry(MCPServer("test"), mock_client)
        registered = registry.register()
        assert len(registered) == registry.catalog_size


class TestRecommendations:
    """Tests for protocol → tool recommendations."""

    def _registry(self, mock_client: MockTSharkClient) -> ToolRegistry:
        from mcp.server import MCPServer

        registry = ToolRegistry(MCPServer("test"), mock_client)
        registry.register()
        return registry

    def test_recommends_http_tools(self, mock_client: MockTSharkClient) -> None:
        recommended = self._registry(mock_client).recommended_tools_for_protocols({"http"})
        assert "wireshark_extract_http_requests" in recommended
        assert "wireshark_export_objects" in recommended
        assert "wireshark_extract_credentials" in recommended

    def test_does_not_recommend_tools_excluded_by_profile(self, mock_client: MockTSharkClient) -> None:
        from wireshark_mcp.mcp_app import WiresharkMCP

        registry = ToolRegistry(
            WiresharkMCP(
                "test",
                excluded_tools=frozenset({"wireshark_export_objects", "wireshark_yara_scan"}),
            ),
            mock_client,
        )
        registry.register()
        recommended = registry.recommended_tools_for_protocols({"http"})
        assert "wireshark_export_objects" not in recommended
        assert "wireshark_yara_scan" not in recommended

    def test_recommends_dns_tools(self, mock_client: MockTSharkClient) -> None:
        recommended = self._registry(mock_client).recommended_tools_for_protocols({"dns"})
        assert "wireshark_extract_dns_queries" in recommended
        assert "wireshark_detect_dns_tunnel" in recommended
        assert "wireshark_extract_http_requests" not in recommended

    def test_recommends_tls_tools(self, mock_client: MockTSharkClient) -> None:
        recommended = self._registry(mock_client).recommended_tools_for_protocols({"tls"})
        # Per-protocol analysis is one tool now, so the recommendation has to carry the
        # argument: the bare tool name would leave the caller guessing the enum value.
        assert 'wireshark_analyze_protocol(protocol="tls_handshakes")' in recommended
        assert "wireshark_verify_ssl_decryption" in recommended

    def test_ip_recommends_security_tools(self, mock_client: MockTSharkClient) -> None:
        recommended = self._registry(mock_client).recommended_tools_for_protocols({"ip"})
        assert "wireshark_detect_port_scan" in recommended
        assert "wireshark_detect_dos_attack" in recommended
        assert "wireshark_geoip_enrich" in recommended

    def test_multiple_protocols(self, mock_client: MockTSharkClient) -> None:
        recommended = self._registry(mock_client).recommended_tools_for_protocols({"http", "dns", "tls", "ip"})
        assert "wireshark_extract_http_requests" in recommended
        assert "wireshark_extract_dns_queries" in recommended
        assert 'wireshark_analyze_protocol(protocol="tls_handshakes")' in recommended
        assert "wireshark_detect_port_scan" in recommended

    def test_unknown_protocol_recommends_nothing(self, mock_client: MockTSharkClient) -> None:
        recommended = self._registry(mock_client).recommended_tools_for_protocols({"unknown_protocol"})
        assert recommended == []

    def test_every_recommended_tool_is_registered(self, mock_client: MockTSharkClient) -> None:
        from wireshark_mcp.tools.registry import PROTOCOL_TOOL_MAP

        registry = self._registry(mock_client)
        all_protocols = set(PROTOCOL_TOOL_MAP)
        recommended = registry.recommended_tools_for_protocols(all_protocols)
        assert recommended, "expected recommendations for the full protocol map"
        for call in recommended:
            assert call.split("(", 1)[0] in registry._catalog


class TestOpenFileTool:
    def test_open_file_recommends_tools(self, mock_client: MockTSharkClient) -> None:
        from mcp.server import MCPServer

        async def fake_get_protocol_stats(_pcap_file: str) -> str:
            return success_response(
                "eth  frames:10 bytes:100\n  ip  frames:10 bytes:90\n    tcp  frames:5 bytes:50\n      http  frames:5 bytes:50\n"
            )

        async def fake_get_file_info(_pcap_file: str) -> str:
            return success_response("file name: test.pcap\n")

        mcp = MCPServer("test")
        registry = ToolRegistry(mcp, mock_client)
        registry.register()
        mock_client.get_protocol_stats = fake_get_protocol_stats  # type: ignore[method-assign]
        mock_client.get_file_info = fake_get_file_info  # type: ignore[method-assign]
        register_open_file_tool(mcp, mock_client, registry)

        result = json.loads(self._run_async(call_tool_text(mcp, "wireshark_open_file", {"pcap_file": "test.pcap"})))

        assert result["success"] is True
        assert "Recommended Tools" in result["data"]
        assert "wireshark_extract_http_requests" in result["data"]

    def test_open_file_degrades_when_capinfos_is_unavailable(self, mock_client: MockTSharkClient) -> None:
        from mcp.server import MCPServer

        async def fake_get_protocol_stats(_pcap_file: str) -> str:
            return success_response("eth  frames:10 bytes:100\n  ip  frames:10 bytes:90\n")

        async def fake_get_file_info(_pcap_file: str) -> str:
            return error_response("capinfos tool not found", error_type="ToolNotFound")

        mcp = MCPServer("test")
        registry = ToolRegistry(mcp, mock_client)
        registry.register()
        mock_client.get_protocol_stats = fake_get_protocol_stats  # type: ignore[method-assign]
        mock_client.get_file_info = fake_get_file_info  # type: ignore[method-assign]
        register_open_file_tool(mcp, mock_client, registry)

        result = json.loads(self._run_async(call_tool_text(mcp, "wireshark_open_file", {"pcap_file": "test.pcap"})))

        assert result["success"] is True
        assert "Detailed file metadata unavailable" in result["data"]

    @staticmethod
    def _run_async(coro):
        import asyncio

        return asyncio.run(coro)
