"""Progressive Discovery — dynamic tool registration based on pcap content.

Manages two categories of tools:
- **Core tools**: Always registered at startup (packet list, stats, capture, etc.)
- **Contextual tools**: Registered on-demand based on detected protocols in a pcap file.
"""

import logging
import re
from collections.abc import Callable
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..tshark.client import TSharkClient
from .envelope import normalize_tool_result, parse_tool_result, success_response

logger = logging.getLogger("wireshark_mcp")

# Type alias: a function that creates contextual tool functions
# Returns list of (tool_name, tool_function) pairs
ContextualToolFactory = Callable[[TSharkClient], list[tuple[str, Any]]]


# ── Protocol → Tool mapping ─────────────────────────────────────────────────

# Each entry: protocol_keyword → list of tool names that should be activated
PROTOCOL_TOOL_MAP: dict[str, list[str]] = {
    # HTTP-related
    "http": [
        "wireshark_extract_http_requests",
        "wireshark_export_objects",
        "wireshark_extract_credentials",
    ],
    # DNS-related
    "dns": [
        "wireshark_extract_dns_queries",
        "wireshark_detect_dns_tunnel",
    ],
    # TLS/SSL-related
    "tls": [
        "wireshark_extract_tls_handshakes",
        "wireshark_verify_ssl_decryption",
    ],
    "ssl": [
        "wireshark_extract_tls_handshakes",
        "wireshark_verify_ssl_decryption",
    ],
    # ARP-related
    "arp": [
        "wireshark_detect_arp_spoofing",
    ],
    # SMTP-related
    "smtp": [
        "wireshark_extract_smtp_emails",
    ],
    # DHCP-related
    "dhcp": [
        "wireshark_extract_dhcp_info",
    ],
    "bootp": [
        "wireshark_extract_dhcp_info",
    ],
    # FTP/Telnet (credential extraction)
    "ftp": [
        "wireshark_extract_credentials",
    ],
    "telnet": [
        "wireshark_extract_credentials",
    ],
    # IP traffic (security analysis — broad match)
    "ip": [
        "wireshark_check_threats",
        "wireshark_detect_port_scan",
        "wireshark_detect_dos_attack",
        "wireshark_analyze_suspicious_traffic",
    ],
    # TCP-specific deep analysis
    "tcp": [
        "wireshark_analyze_tcp_health",
    ],
}


class ToolRegistry:
    """Manages progressive discovery of MCP tools."""

    def __init__(self, mcp: FastMCP, client: TSharkClient) -> None:
        self._mcp = mcp
        self._client = client
        # All contextual tool functions, keyed by tool name
        self._contextual_catalog: dict[str, Any] = {}
        # Currently registered contextual tool names
        self._active_contextual: set[str] = set()

    def build_catalog(self) -> None:
        """Build the catalog of all available contextual tools.

        This collects tool functions from all contextual modules without
        registering them on the MCP server yet.
        """
        from .extract import make_contextual_extract_tools
        from .protocol import make_contextual_protocol_tools
        from .security import make_contextual_security_tools
        from .threat import make_contextual_threat_tools

        for factory in [
            make_contextual_extract_tools,
            make_contextual_protocol_tools,
            make_contextual_security_tools,
            make_contextual_threat_tools,
        ]:
            for name, fn in factory(self._client):
                self._contextual_catalog[name] = fn

        logger.info(
            "Contextual tool catalog built: %d tools available",
            len(self._contextual_catalog),
        )

    def clear_contextual_tools(self) -> None:
        """Remove all currently registered contextual tools."""
        for name in list(self._active_contextual):
            try:
                self._mcp.remove_tool(name)
                logger.debug("Removed contextual tool: %s", name)
            except Exception:
                logger.debug("Tool %s was not registered, skipping removal", name)
        self._active_contextual.clear()

    def register_contextual_tools(self, detected_protocols: set[str]) -> list[str]:
        """Register contextual tools based on detected protocols.

        Args:
            detected_protocols: Set of protocol names found in the current pcap.

        Returns:
            List of newly registered tool names.
        """
        # First, clear any previously registered contextual tools
        self.clear_contextual_tools()

        # Determine which tools to activate
        tools_to_activate: set[str] = set()
        for protocol in detected_protocols:
            protocol_lower = protocol.lower().strip()
            if protocol_lower in PROTOCOL_TOOL_MAP:
                tools_to_activate.update(PROTOCOL_TOOL_MAP[protocol_lower])

        # Register the tools
        newly_registered: list[str] = []
        for tool_name in sorted(tools_to_activate):
            if tool_name in self._contextual_catalog:
                fn = self._contextual_catalog[tool_name]
                try:
                    self._mcp.add_tool(fn, name=tool_name)
                    self._active_contextual.add(tool_name)
                    newly_registered.append(tool_name)
                    logger.debug("Registered contextual tool: %s", tool_name)
                except Exception as e:
                    logger.warning("Failed to register tool %s: %s", tool_name, e)
            else:
                logger.warning("Tool %s is in PROTOCOL_TOOL_MAP but not in catalog", tool_name)

        logger.info(
            "Registered %d contextual tools for protocols: %s",
            len(newly_registered),
            ", ".join(sorted(detected_protocols)),
        )
        return newly_registered

    @property
    def active_contextual_tools(self) -> set[str]:
        """Return the set of currently registered contextual tool names."""
        return self._active_contextual.copy()

    @property
    def catalog_size(self) -> int:
        """Return the total number of contextual tools in the catalog."""
        return len(self._contextual_catalog)


def parse_protocol_hierarchy(phs_output: str) -> set[str]:
    """Parse tshark protocol hierarchy output to extract protocol names.

    Handles the typical tshark -z io,phs output format like:
        eth  frames:100 bytes:12345
          ip  frames:90 bytes:11000
            tcp  frames:80 bytes:10000
              http  frames:30 bytes:5000
              tls  frames:50 bytes:5000
            udp  frames:10 bytes:1000
              dns  frames:10 bytes:1000
        arp  frames:10 bytes:1345
    """
    protocols: set[str] = set()
    for line in phs_output.splitlines():
        # Match lines like "  tcp  frames:123 bytes:456" or "tcp  frames:123"
        match = re.match(r"^\s*(\w[\w.-]*)\s+frames:", line)
        if match:
            protocols.add(match.group(1).lower())
    return protocols


def register_open_file_tool(mcp: FastMCP, client: TSharkClient, registry: ToolRegistry) -> None:
    """Register the wireshark_open_file entry-point tool."""

    @mcp.tool()
    async def wireshark_open_file(pcap_file: str) -> str:
        """
        [Entry Point] Open a pcap file and activate relevant analysis tools.

        This is the recommended FIRST tool to call. It analyzes the capture file,
        detects what protocols are present, and dynamically enables the most relevant
        tools for your analysis. This keeps the tool list focused and efficient.

        After calling this tool, new protocol-specific tools will become available
        (e.g., HTTP extraction, DNS tunnel detection, TLS handshake analysis).

        Args:
            pcap_file: Path to the capture file (.pcap, .pcapng, etc.)

        Returns:
            File overview, protocol summary, and list of newly activated tools.

        Example:
            wireshark_open_file("/path/to/capture.pcap")
        """
        # Step 1: Get file info
        file_info_raw = await client.get_file_info(pcap_file)
        file_info = parse_tool_result(normalize_tool_result(file_info_raw))

        if not file_info["success"]:
            return normalize_tool_result(file_info)

        # Step 2: Get protocol hierarchy
        phs_raw = await client.get_protocol_stats(pcap_file)
        phs_result = parse_tool_result(normalize_tool_result(phs_raw))

        detected_protocols: set[str] = set()
        if phs_result["success"]:
            phs_data = phs_result.get("data", "")
            if isinstance(phs_data, str):
                detected_protocols = parse_protocol_hierarchy(phs_data)

        # Step 3: Register contextual tools based on detected protocols
        newly_registered = registry.register_contextual_tools(detected_protocols)

        # Step 4: Build response
        output_parts = [
            "=== File Opened Successfully ===\n",
            "--- File Info ---",
            file_info.get("data", "N/A")
            if isinstance(file_info.get("data"), str)
            else str(file_info.get("data", "N/A")),
        ]

        if detected_protocols:
            output_parts.append(f"\n--- Detected Protocols ({len(detected_protocols)}) ---")
            output_parts.append(", ".join(sorted(detected_protocols)))

        if newly_registered:
            output_parts.append(f"\n--- Activated Tools ({len(newly_registered)}) ---")
            output_parts.append("The following specialized tools are now available for this capture:")
            for tool_name in newly_registered:
                fn = registry._contextual_catalog.get(tool_name)
                doc = (fn.__doc__ or "").strip().split("\n")[0] if fn else ""
                output_parts.append(f"  • {tool_name}: {doc}")
        else:
            output_parts.append("\n--- No additional tools activated ---")
            output_parts.append("No protocol-specific tools were needed for this capture.")

        output_parts.append(
            "\n💡 Tip: Use the core tools (wireshark_get_packet_list, wireshark_stats_*, etc.) to begin your analysis."
        )

        return success_response("\n".join(output_parts))
