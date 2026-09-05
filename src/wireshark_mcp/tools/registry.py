"""Analysis tool registration with protocol-aware recommendations.

All analysis tools are registered once at startup — the tool surface is static.
`wireshark_open_file` inspects a capture's protocol hierarchy and points the
caller at the subset of already-registered tools most relevant to what the
capture actually contains. It does not add or remove tools.
"""

import logging
import re
from collections.abc import Callable
from typing import Any, NamedTuple

from mcp.server import MCPServer

from ..tshark.client import TSharkClient
from .envelope import normalize_tool_result, parse_tool_result, success_response

logger = logging.getLogger("wireshark_mcp")

# A factory maps a client to a list of (tool_name, tool_function) pairs.
ToolFactory = Callable[[TSharkClient], list[tuple[str, Any]]]


class Recommendation(NamedTuple):
    """A tool to run, plus the `protocol` argument to pass if it needs one."""

    tool: str
    protocol: str | None = None

    def render(self) -> str:
        """The call to suggest, e.g. `wireshark_analyze_protocol(protocol="mqtt")`."""
        if self.protocol is None:
            return self.tool
        return f'{self.tool}(protocol="{self.protocol}")'


# ── Protocol → recommended tools ────────────────────────────────────────────
# Maps a protocol seen in the capture to the analysis worth running for it.
# Used only to build recommendation text; every listed tool is always registered.
#
# An entry may carry a `protocol` argument, because most per-protocol analysis now
# lives behind the single `wireshark_analyze_protocol` tool. Recommending the bare
# tool name would drop the one thing the caller cannot infer — which enum value
# applies to the capture in front of them — so the argument travels with the name.
PROTOCOL_TOOL_MAP: dict[str, list[Recommendation]] = {
    "http": [
        Recommendation("wireshark_extract_http_requests"),
        Recommendation("wireshark_export_objects"),
        Recommendation("wireshark_extract_credentials"),
        Recommendation("wireshark_yara_scan"),
    ],
    "dns": [
        Recommendation("wireshark_extract_dns_queries"),
        Recommendation("wireshark_detect_dns_tunnel"),
    ],
    "tls": [
        Recommendation("wireshark_analyze_protocol", "tls_handshakes"),
        Recommendation("wireshark_verify_ssl_decryption"),
        Recommendation("wireshark_extract_fingerprints"),
    ],
    "ssl": [
        Recommendation("wireshark_analyze_protocol", "tls_handshakes"),
        Recommendation("wireshark_verify_ssl_decryption"),
    ],
    "arp": [
        Recommendation("wireshark_detect_arp_spoofing"),
    ],
    "smtp": [
        Recommendation("wireshark_analyze_protocol", "smtp"),
    ],
    "dhcp": [
        Recommendation("wireshark_analyze_protocol", "dhcp"),
    ],
    "bootp": [
        Recommendation("wireshark_analyze_protocol", "dhcp"),
    ],
    "ftp": [
        Recommendation("wireshark_extract_credentials"),
    ],
    "telnet": [
        Recommendation("wireshark_extract_credentials"),
    ],
    "ip": [
        Recommendation("wireshark_detect_port_scan"),
        Recommendation("wireshark_detect_dos_attack"),
        Recommendation("wireshark_geoip_enrich"),
    ],
    "tcp": [
        Recommendation("wireshark_analyze_tcp_health"),
    ],
    "quic": [
        Recommendation("wireshark_analyze_protocol", "quic"),
    ],
    "http3": [
        Recommendation("wireshark_analyze_protocol", "quic"),
    ],
    "websocket": [
        Recommendation("wireshark_analyze_protocol", "websocket"),
    ],
    "mqtt": [
        Recommendation("wireshark_analyze_protocol", "mqtt"),
    ],
    "grpc": [
        Recommendation("wireshark_analyze_protocol", "grpc"),
    ],
    "http2": [
        Recommendation("wireshark_analyze_protocol", "grpc"),
        Recommendation("wireshark_analyze_protocol", "doh"),
    ],
    "rtp": [
        Recommendation("wireshark_analyze_protocol", "rtp"),
    ],
    "smb": [
        Recommendation("wireshark_analyze_protocol", "smb"),
    ],
    "smb2": [
        Recommendation("wireshark_analyze_protocol", "smb"),
    ],
    "kerberos": [
        Recommendation("wireshark_analyze_protocol", "kerberos"),
    ],
    "modbus": [
        Recommendation("wireshark_analyze_protocol", "modbus"),
    ],
    "mbtcp": [
        Recommendation("wireshark_analyze_protocol", "modbus"),
    ],
    "s7comm": [
        Recommendation("wireshark_analyze_protocol", "s7comm"),
    ],
    "dnp3": [
        Recommendation("wireshark_analyze_protocol", "dnp3"),
    ],
    "coap": [
        Recommendation("wireshark_analyze_protocol", "coap"),
    ],
    "zbee_nwk": [
        Recommendation("wireshark_analyze_protocol", "zigbee"),
    ],
    "zbee_aps": [
        Recommendation("wireshark_analyze_protocol", "zigbee"),
    ],
    "btle": [
        Recommendation("wireshark_analyze_protocol", "ble"),
    ],
    "wlan": [
        Recommendation("wireshark_analyze_protocol", "wifi"),
    ],
    "wg": [
        Recommendation("wireshark_analyze_protocol", "wireguard"),
    ],
    "icmp": [
        Recommendation("wireshark_analyze_protocol", "icmp_tunnel"),
    ],
}


class ToolRegistry:
    """Registers the analysis tool catalog and maps protocols to recommendations."""

    def __init__(self, mcp: MCPServer, client: TSharkClient) -> None:
        self._mcp = mcp
        self._client = client
        # tool_name -> tool function, for docstring lookup and recommendation validation
        self._catalog: dict[str, Any] = {}

    def register(self) -> list[str]:
        """Register every analysis tool on the MCP server. Returns registered names."""
        from .analyze import make_analyze_tools
        from .anomaly import make_anomaly_tools
        from .extract import make_extract_tools
        from .forensics import make_forensics_tools
        from .geoip import make_geoip_tools
        from .protocol import make_protocol_tools
        from .security import make_security_tools
        from .threat import make_threat_tools
        from .yara_scan import make_yara_tools

        factories: list[ToolFactory] = [
            make_extract_tools,
            make_protocol_tools,
            make_analyze_tools,
            make_security_tools,
            make_threat_tools,
            make_forensics_tools,
            make_anomaly_tools,
            make_geoip_tools,
            make_yara_tools,
        ]

        for factory in factories:
            for name, fn in factory(self._client):
                self._catalog[name] = fn

        registered: list[str] = []
        excluded: frozenset[str] = getattr(self._mcp, "excluded_tools", frozenset())
        for name in sorted(self._catalog):
            if name in excluded:
                continue
            try:
                self._mcp.add_tool(self._catalog[name], name=name)
                registered.append(name)
            except Exception as exc:
                logger.warning("Failed to register tool %s: %s", name, exc)

        self._warn_on_unknown_recommendations()
        logger.info("Registered %d analysis tools", len(registered))
        return registered

    def _warn_on_unknown_recommendations(self) -> None:
        """Flag any PROTOCOL_TOOL_MAP entry that names a tool we never registered."""
        from .analyze import supported_protocols

        referenced = {rec.tool for recs in PROTOCOL_TOOL_MAP.values() for rec in recs}
        for tool_name in sorted(referenced - self._catalog.keys()):
            logger.warning("PROTOCOL_TOOL_MAP references unregistered tool: %s", tool_name)

        # A `protocol` value not in the tool's enum renders a call that fails schema
        # validation, so catch it here rather than at the caller.
        known = set(supported_protocols())
        bad = {rec.protocol for recs in PROTOCOL_TOOL_MAP.values() for rec in recs if rec.protocol} - known
        for value in sorted(bad):
            logger.warning("PROTOCOL_TOOL_MAP references unsupported protocol value: %s", value)

    def recommended_tools_for_protocols(self, detected_protocols: set[str]) -> list[str]:
        """Return calls worth making for the detected protocols, as rendered strings."""
        recommended: set[str] = set()
        excluded: frozenset[str] = getattr(self._mcp, "excluded_tools", frozenset())
        for protocol in detected_protocols:
            for rec in PROTOCOL_TOOL_MAP.get(protocol.lower().strip(), []):
                if rec.tool in self._catalog and rec.tool not in excluded:
                    recommended.add(rec.render())
        return sorted(recommended)

    def tool_doc(self, tool_name: str) -> str:
        """Return the first docstring line for a registered tool, or empty string.

        Accepts either a bare tool name or a rendered call from
        `recommended_tools_for_protocols`.
        """
        fn = self._catalog.get(tool_name.split("(", 1)[0])
        return (fn.__doc__ or "").strip().split("\n")[0] if fn else ""

    @property
    def catalog_size(self) -> int:
        """Number of analysis tools in the catalog."""
        return len(self._catalog)


def parse_protocol_hierarchy(phs_output: str) -> set[str]:
    """Parse tshark `-z io,phs` output into a set of protocol names.

    Handles the typical hierarchy format::

        eth  frames:100 bytes:12345
          ip  frames:90 bytes:11000
            tcp  frames:80 bytes:10000
              http  frames:30 bytes:5000
    """
    protocols: set[str] = set()
    for line in phs_output.splitlines():
        match = re.match(r"^\s*(\w[\w.-]*)\s+frames:", line)
        if match:
            protocols.add(match.group(1).lower())
    return protocols


def register_open_file_tool(mcp: MCPServer, client: TSharkClient, registry: ToolRegistry) -> None:
    """Register the wireshark_open_file entry-point tool."""

    @mcp.tool()
    async def wireshark_open_file(pcap_file: str) -> str:
        """[Entry Point] Open a pcap and get protocol-aware tool recommendations. Returns protocols and relevant tools."""
        phs_raw = await client.get_protocol_stats(pcap_file)
        phs_result = parse_tool_result(normalize_tool_result(phs_raw))
        if not phs_result["success"]:
            return normalize_tool_result(phs_result)

        file_info_raw = await client.get_file_info(pcap_file)
        file_info = parse_tool_result(normalize_tool_result(file_info_raw))

        detected_protocols: set[str] = set()
        phs_data = phs_result.get("data", "")
        if isinstance(phs_data, str):
            detected_protocols = parse_protocol_hierarchy(phs_data)

        recommended_tools = registry.recommended_tools_for_protocols(detected_protocols)

        output_parts = ["File Info:"]
        if file_info["success"]:
            data = file_info.get("data", "N/A")
            output_parts.append(data if isinstance(data, str) else str(data))
        else:
            output_parts.append("Detailed file metadata unavailable (capinfos not installed or file summary failed).")

        if detected_protocols:
            output_parts.append(f"\nProtocols ({len(detected_protocols)}):")
            output_parts.append(", ".join(sorted(detected_protocols)))

        if recommended_tools:
            output_parts.append(f"\nRecommended Tools ({len(recommended_tools)}):")
            for tool_name in recommended_tools:
                output_parts.append(f"  {tool_name}: {registry.tool_doc(tool_name)}")
        else:
            output_parts.append("\nNo protocol-specific recommendations. Core tools are available.")

        output_parts.append(
            "\nStart with wireshark_quick_analysis or wireshark_get_packet_list. "
            "Use wireshark_aggregate for capture-wide counts and distributions, then use recommended tools."
        )

        return success_response("\n".join(output_parts))
