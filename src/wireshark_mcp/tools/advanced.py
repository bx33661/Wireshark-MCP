"""Advanced analysis tools — decryption, decode-as, flow graphs, protocol stats."""

from mcp.server import MCPServer

from ..tshark.client import TSharkClient
from .envelope import normalize_tool_result


def register_advanced_tools(mcp: MCPServer, client: TSharkClient) -> None:

    @mcp.tool()
    async def wireshark_decode_as(
        pcap_file: str,
        decode_rules: str,
        fields: str = "",
        display_filter: str = "",
        limit: int = 100,
    ) -> str:
        """[Dissection] Decode-as for non-standard ports. Rules: 'tcp.port==8080,http;udp.port==5353,dns'."""
        rules = [r.strip() for r in decode_rules.split(";") if r.strip()]
        field_list = [f.strip() for f in fields.split(",") if f.strip()] if fields else []
        return normalize_tool_result(
            await client.extract_with_decode_as(pcap_file, rules, field_list, display_filter, limit)
        )

    @mcp.tool()
    async def wireshark_set_protocol_prefs(
        pcap_file: str,
        prefs: str,
        fields: str = "",
        display_filter: str = "",
        limit: int = 100,
    ) -> str:
        """[Dissection] Protocol preference overrides. Prefs: 'tcp.desegment_tcp_streams:TRUE;http.ssl.port:8443'."""
        pref_list = [p.strip() for p in prefs.split(";") if p.strip()]
        field_list = [f.strip() for f in fields.split(",") if f.strip()] if fields else []
        return normalize_tool_result(
            await client.extract_with_prefs(pcap_file, pref_list, field_list, display_filter, limit)
        )

    @mcp.tool()
    async def wireshark_decrypt_tls(pcap_file: str, keylog_file: str, display_filter: str = "") -> str:
        """[Decrypt] Decrypt TLS traffic using SSLKEYLOGFILE, show HTTP data."""
        return normalize_tool_result(await client.decrypt_tls_traffic(pcap_file, keylog_file, display_filter))

    @mcp.tool()
    async def wireshark_decrypt_wpa(
        pcap_file: str, wpa_passphrase: str, ssid: str = "", display_filter: str = ""
    ) -> str:
        """[Decrypt] Decrypt WPA/WPA2 traffic with passphrase (+SSID)."""
        key = f"{wpa_passphrase}:{ssid}" if ssid else wpa_passphrase
        return normalize_tool_result(await client.decrypt_wpa_traffic(pcap_file, [key], display_filter))

    @mcp.tool()
    async def wireshark_extract_frames(pcap_file: str, output_file: str, frame_ranges: str) -> str:
        """[File] Extract specific frame ranges to a new pcap. Ranges: '1-10 15 20-30'."""
        return normalize_tool_result(await client.editcap_extract_frames(pcap_file, output_file, frame_ranges))

    @mcp.tool()
    async def wireshark_flow_graph(pcap_file: str, flow_type: str = "any") -> str:
        """[Stats] Flow/sequence graph showing packet exchange. Types: 'any', 'tcp', 'icmp'."""
        return normalize_tool_result(await client.get_flow_graph(pcap_file, flow_type))
