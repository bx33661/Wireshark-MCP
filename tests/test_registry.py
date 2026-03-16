"""Tests for the stable contextual tool registry module."""

import json

from conftest import MockTSharkClient

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
        assert "eth" in protocols
        assert "ip" in protocols
        assert "tcp" in protocols
        assert "http" in protocols
        assert "tls" in protocols
        assert "udp" in protocols
        assert "dns" in protocols
        assert "arp" in protocols

    def test_empty_output(self) -> None:
        assert parse_protocol_hierarchy("") == set()

    def test_no_matching_lines(self) -> None:
        assert parse_protocol_hierarchy("some random text\n===\n") == set()

    def test_single_protocol(self) -> None:
        protocols = parse_protocol_hierarchy("eth  frames:5 bytes:100\n")
        assert protocols == {"eth"}


class TestToolRegistryBuildCatalog:
    """Tests for catalog building."""

    def test_builds_nonempty_catalog(self, mock_client: MockTSharkClient) -> None:
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        registry = ToolRegistry(mcp, mock_client)
        registry.build_catalog()
        assert registry.catalog_size > 0

    def test_catalog_contains_expected_tools(self, mock_client: MockTSharkClient) -> None:
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        registry = ToolRegistry(mcp, mock_client)
        registry.build_catalog()

        expected_tools = [
            "wireshark_extract_http_requests",
            "wireshark_extract_dns_queries",
            "wireshark_export_objects",
            "wireshark_verify_ssl_decryption",
            "wireshark_extract_tls_handshakes",
            "wireshark_analyze_tcp_health",
            "wireshark_detect_arp_spoofing",
            "wireshark_extract_smtp_emails",
            "wireshark_extract_dhcp_info",
            "wireshark_check_threats",
            "wireshark_extract_credentials",
            "wireshark_detect_port_scan",
            "wireshark_detect_dns_tunnel",
            "wireshark_detect_dos_attack",
            "wireshark_analyze_suspicious_traffic",
        ]
        for tool_name in expected_tools:
            assert tool_name in registry._contextual_catalog, f"Missing tool: {tool_name}"


class TestContextualRegistration:
    """Tests for stable contextual registration and recommendations."""

    def test_registers_all_contextual_tools_at_startup(self, mock_client: MockTSharkClient) -> None:
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        registry = ToolRegistry(mcp, mock_client)
        registry.build_catalog()

        registered = registry.register_all_contextual_tools()
        assert len(registered) == registry.catalog_size
        assert registry.active_contextual_tools == set(registered)

    def test_recommends_http_tools(self, mock_client: MockTSharkClient) -> None:
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        registry = ToolRegistry(mcp, mock_client)
        registry.build_catalog()

        recommended = registry.recommended_tools_for_protocols({"http"})
        assert "wireshark_extract_http_requests" in recommended
        assert "wireshark_export_objects" in recommended
        assert "wireshark_extract_credentials" in recommended

    def test_recommends_dns_tools(self, mock_client: MockTSharkClient) -> None:
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        registry = ToolRegistry(mcp, mock_client)
        registry.build_catalog()

        recommended = registry.recommended_tools_for_protocols({"dns"})
        assert "wireshark_extract_dns_queries" in recommended
        assert "wireshark_detect_dns_tunnel" in recommended
        assert "wireshark_extract_http_requests" not in recommended

    def test_recommends_tls_tools(self, mock_client: MockTSharkClient) -> None:
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        registry = ToolRegistry(mcp, mock_client)
        registry.build_catalog()

        recommended = registry.recommended_tools_for_protocols({"tls"})
        assert "wireshark_extract_tls_handshakes" in recommended
        assert "wireshark_verify_ssl_decryption" in recommended

    def test_recommendations_do_not_mutate_registered_tools(self, mock_client: MockTSharkClient) -> None:
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        registry = ToolRegistry(mcp, mock_client)
        registry.build_catalog()
        registry.register_all_contextual_tools()

        before = registry.active_contextual_tools

        registry.recommended_tools_for_protocols({"http"})
        registry.recommended_tools_for_protocols({"dns"})

        assert registry.active_contextual_tools == before

    def test_ip_recommends_security_tools(self, mock_client: MockTSharkClient) -> None:
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        registry = ToolRegistry(mcp, mock_client)
        registry.build_catalog()

        recommended = registry.recommended_tools_for_protocols({"ip"})
        assert "wireshark_check_threats" in recommended
        assert "wireshark_detect_port_scan" in recommended
        assert "wireshark_detect_dos_attack" in recommended
        assert "wireshark_analyze_suspicious_traffic" in recommended

    def test_multiple_protocols(self, mock_client: MockTSharkClient) -> None:
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        registry = ToolRegistry(mcp, mock_client)
        registry.build_catalog()

        recommended = registry.recommended_tools_for_protocols({"http", "dns", "tls", "ip"})
        assert "wireshark_extract_http_requests" in recommended
        assert "wireshark_extract_dns_queries" in recommended
        assert "wireshark_extract_tls_handshakes" in recommended
        assert "wireshark_check_threats" in recommended

    def test_unknown_protocol_registers_nothing(self, mock_client: MockTSharkClient) -> None:
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        registry = ToolRegistry(mcp, mock_client)
        registry.build_catalog()

        recommended = registry.recommended_tools_for_protocols({"unknown_protocol"})
        assert len(recommended) == 0


class TestOpenFileTool:
    def test_open_file_recommends_tools_without_mutating_tool_surface(self, mock_client: MockTSharkClient) -> None:
        from mcp.server.fastmcp import FastMCP

        async def fake_get_protocol_stats(_pcap_file: str) -> str:
            return success_response("eth  frames:10 bytes:100\n  ip  frames:10 bytes:90\n    tcp  frames:5 bytes:50\n      http  frames:5 bytes:50\n")

        async def fake_get_file_info(_pcap_file: str) -> str:
            return success_response("file name: test.pcap\n")

        mcp = FastMCP("test")
        registry = ToolRegistry(mcp, mock_client)
        registry.build_catalog()
        registry.register_all_contextual_tools()
        mock_client.get_protocol_stats = fake_get_protocol_stats  # type: ignore[method-assign]
        mock_client.get_file_info = fake_get_file_info  # type: ignore[method-assign]
        register_open_file_tool(mcp, mock_client, registry)

        before = registry.active_contextual_tools
        result = json.loads(
            self._run_async(mcp._tool_manager.call_tool("wireshark_open_file", {"pcap_file": "test.pcap"}))
        )

        assert result["success"] is True
        assert "Recommended Tools" in result["data"]
        assert "wireshark_extract_http_requests" in result["data"]
        assert registry.active_contextual_tools == before

    def test_open_file_degrades_when_capinfos_is_unavailable(self, mock_client: MockTSharkClient) -> None:
        from mcp.server.fastmcp import FastMCP

        async def fake_get_protocol_stats(_pcap_file: str) -> str:
            return success_response("eth  frames:10 bytes:100\n  ip  frames:10 bytes:90\n")

        async def fake_get_file_info(_pcap_file: str) -> str:
            return error_response("capinfos tool not found", error_type="ToolNotFound")

        mcp = FastMCP("test")
        registry = ToolRegistry(mcp, mock_client)
        registry.build_catalog()
        registry.register_all_contextual_tools()
        mock_client.get_protocol_stats = fake_get_protocol_stats  # type: ignore[method-assign]
        mock_client.get_file_info = fake_get_file_info  # type: ignore[method-assign]
        register_open_file_tool(mcp, mock_client, registry)

        result = json.loads(
            self._run_async(mcp._tool_manager.call_tool("wireshark_open_file", {"pcap_file": "test.pcap"}))
        )

        assert result["success"] is True
        assert "Detailed file metadata unavailable" in result["data"]

    @staticmethod
    def _run_async(coro):
        import asyncio

        return asyncio.run(coro)
