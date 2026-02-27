"""Tests for the Progressive Discovery registry module."""

import pytest

from conftest import MockTSharkClient
from wireshark_mcp.tools.registry import ToolRegistry, parse_protocol_hierarchy


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
    """Tests for dynamic tool registration and removal."""

    def test_registers_http_tools(self, mock_client: MockTSharkClient) -> None:
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("test")
        registry = ToolRegistry(mcp, mock_client)
        registry.build_catalog()

        registered = registry.register_contextual_tools({"http"})
        assert "wireshark_extract_http_requests" in registered
        assert "wireshark_export_objects" in registered
        assert "wireshark_extract_credentials" in registered

    def test_registers_dns_tools(self, mock_client: MockTSharkClient) -> None:
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("test")
        registry = ToolRegistry(mcp, mock_client)
        registry.build_catalog()

        registered = registry.register_contextual_tools({"dns"})
        assert "wireshark_extract_dns_queries" in registered
        assert "wireshark_detect_dns_tunnel" in registered
        # HTTP tools should NOT be registered
        assert "wireshark_extract_http_requests" not in registered

    def test_registers_tls_tools(self, mock_client: MockTSharkClient) -> None:
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("test")
        registry = ToolRegistry(mcp, mock_client)
        registry.build_catalog()

        registered = registry.register_contextual_tools({"tls"})
        assert "wireshark_extract_tls_handshakes" in registered
        assert "wireshark_verify_ssl_decryption" in registered

    def test_clear_removes_all_contextual(self, mock_client: MockTSharkClient) -> None:
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("test")
        registry = ToolRegistry(mcp, mock_client)
        registry.build_catalog()

        registry.register_contextual_tools({"http", "dns"})
        assert len(registry.active_contextual_tools) > 0

        registry.clear_contextual_tools()
        assert len(registry.active_contextual_tools) == 0

    def test_switching_protocols_replaces_tools(self, mock_client: MockTSharkClient) -> None:
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("test")
        registry = ToolRegistry(mcp, mock_client)
        registry.build_catalog()

        # First: register HTTP tools
        registry.register_contextual_tools({"http"})
        assert "wireshark_extract_http_requests" in registry.active_contextual_tools

        # Switch to DNS-only
        registry.register_contextual_tools({"dns"})
        assert "wireshark_extract_dns_queries" in registry.active_contextual_tools
        assert "wireshark_extract_http_requests" not in registry.active_contextual_tools

    def test_ip_registers_security_tools(self, mock_client: MockTSharkClient) -> None:
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("test")
        registry = ToolRegistry(mcp, mock_client)
        registry.build_catalog()

        registered = registry.register_contextual_tools({"ip"})
        assert "wireshark_check_threats" in registered
        assert "wireshark_detect_port_scan" in registered
        assert "wireshark_detect_dos_attack" in registered
        assert "wireshark_analyze_suspicious_traffic" in registered

    def test_multiple_protocols(self, mock_client: MockTSharkClient) -> None:
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("test")
        registry = ToolRegistry(mcp, mock_client)
        registry.build_catalog()

        registered = registry.register_contextual_tools({"http", "dns", "tls", "ip"})
        # Should have HTTP + DNS + TLS + IP security tools
        assert "wireshark_extract_http_requests" in registered
        assert "wireshark_extract_dns_queries" in registered
        assert "wireshark_extract_tls_handshakes" in registered
        assert "wireshark_check_threats" in registered

    def test_unknown_protocol_registers_nothing(self, mock_client: MockTSharkClient) -> None:
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("test")
        registry = ToolRegistry(mcp, mock_client)
        registry.build_catalog()

        registered = registry.register_contextual_tools({"unknown_protocol"})
        assert len(registered) == 0
