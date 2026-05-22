from typing import Any

from mcp.server.fastmcp import FastMCP

from ..tshark.client import TSharkClient
from .envelope import error_response, normalize_tool_result, parse_tool_result, success_response


def register_extract_tools(mcp: FastMCP, client: TSharkClient) -> None:
    """Register core extract tools (always available)."""

    @mcp.tool()
    async def wireshark_get_packet_list(
        pcap_file: str, limit: int = 20, offset: int = 0, display_filter: str = "", custom_columns: str = ""
    ) -> str:
        """[Summary] Packet summary list (top pane). Returns TSV: No/Time/Src/Dst/Proto/Len/Info. custom_columns: comma-separated fields to replace defaults."""
        columns = [c.strip() for c in custom_columns.split(",")] if custom_columns else None
        return normalize_tool_result(await client.get_packet_list(pcap_file, limit, offset, display_filter, columns))

    @mcp.tool()
    async def wireshark_get_packet_details(pcap_file: str, frame_number: int, layers: str = "") -> str:
        """[Detail] Full JSON details for a single packet. layers: comma-separated protocol filter (e.g. "ip,tcp,http") to reduce output size."""
        layer_list = [layer.strip() for layer in layers.split(",")] if layers else None
        return normalize_tool_result(await client.get_packet_details(pcap_file, frame_number, layer_list))

    @mcp.tool()
    async def wireshark_get_packet_bytes(pcap_file: str, frame_number: int) -> str:
        """[Bytes] Raw hex/ASCII dump of a single packet."""
        return normalize_tool_result(await client.get_packet_bytes(pcap_file, frame_number))

    @mcp.tool()
    async def wireshark_get_packet_context(pcap_file: str, frame_number: int, count: int = 5) -> str:
        """[Context] Packets surrounding a specific frame (count before and after)."""
        start = max(1, frame_number - count)
        limit = count * 2 + 1
        d_filter = f"frame.number >= {start}"
        return normalize_tool_result(
            await client.get_packet_list(pcap_file, limit=limit, offset=0, display_filter=d_filter)
        )

    @mcp.tool()
    async def wireshark_read_packets(
        pcap_file: str, limit: int = 100, offset: int = 0, display_filter: str = ""
    ) -> str:
        """[DEPRECATED] JSON packet data. Use get_packet_list + get_packet_details instead."""
        return normalize_tool_result(await client.read_packets_json(pcap_file, limit, display_filter, offset))

    @mcp.tool()
    async def wireshark_extract_fields(
        pcap_file: str, fields: str, display_filter: str = "", limit: int = 100, offset: int = 0
    ) -> str:
        """[Tabular] Extract specific fields as TSV. fields: comma-separated field names (e.g. "ip.src,tcp.port,http.host")."""
        field_list = [f.strip() for f in fields.split(",")]
        return normalize_tool_result(
            await client.extract_fields(pcap_file, field_list, display_filter, limit=limit, offset=offset)
        )

    @mcp.tool()
    async def wireshark_list_ips(pcap_file: str, type: str = "both") -> str:
        """[Convenience] List unique IP addresses. type: 'src'|'dst'|'both'."""
        fields = []
        if type in ["src", "both"]:
            fields.append("ip.src")
        if type in ["dst", "both"]:
            fields.append("ip.dst")

        result = await client.extract_fields(pcap_file, fields, limit=10000)
        wrapped = parse_tool_result(result)

        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data")
        if not isinstance(data, str):
            return error_response(
                "Unexpected data format from IP extraction",
                error_type="DependencyError",
                details={"expected": "string", "received": data.__class__.__name__},
            )

        unique_ips = set()
        for line in data.splitlines()[1:]:
            for ip in line.split("\t"):
                ip = ip.strip().strip('"')
                if ip and ip != "":
                    unique_ips.add(ip)

        return success_response("\n".join(sorted(unique_ips)))

    @mcp.tool()
    async def wireshark_search_packets(
        pcap_file: str, match_pattern: str, search_type: str = "string", limit: int = 50, scope: str = "bytes"
    ) -> str:
        """[Search] Find packets by content. scope: 'bytes'|'details'|'filter'. search_type: 'string'|'hex'|'regex'."""
        return normalize_tool_result(
            await client.search_packet_contents(pcap_file, match_pattern, search_type, limit=limit, scope=scope)
        )

    @mcp.tool()
    async def wireshark_follow_stream(
        pcap_file: str,
        stream_index: int,
        protocol: str = "tcp",
        output_mode: str = "ascii",
        limit_lines: int = 500,
        offset_lines: int = 0,
        search_content: str = "",
    ) -> str:
        """[Stream] Reassemble stream content with pagination. protocol: 'tcp'|'udp'|'tls'|'http'|'http2'. output_mode: 'ascii'|'hex'|'raw'."""
        return normalize_tool_result(
            await client.follow_stream(
                pcap_file,
                stream_index,
                protocol,
                output_mode,
                limit_lines=limit_lines,
                offset_lines=offset_lines,
                search_content=search_content,
            )
        )


def make_contextual_extract_tools(client: TSharkClient) -> list[tuple[str, Any]]:
    """Create contextual extract tools for the stable contextual catalog."""

    async def wireshark_extract_http_requests(pcap_file: str, limit: int = 100) -> str:
        """[HTTP] Extract HTTP request details (method, URI, host, user-agent) as TSV."""
        return normalize_tool_result(
            await client.extract_fields(
                pcap_file,
                ["http.request.method", "http.request.uri", "http.host", "http.user_agent"],
                display_filter="http.request",
                limit=limit,
            )
        )

    async def wireshark_extract_dns_queries(pcap_file: str, limit: int = 100) -> str:
        """[DNS] Extract DNS query details (name, type, response flag) as TSV."""
        return normalize_tool_result(
            await client.extract_fields(
                pcap_file, ["dns.qry.name", "dns.qry.type", "dns.flags.response"], display_filter="dns", limit=limit
            )
        )

    async def wireshark_export_objects(pcap_file: str, protocol: str, dest_dir: str) -> str:
        """[Export] Extract embedded files from traffic. protocol: 'http'|'smb'|'tftp'|'imf'|'dicom'."""
        return normalize_tool_result(await client.export_objects(pcap_file, protocol, dest_dir))

    async def wireshark_verify_ssl_decryption(pcap_file: str, keylog_file: str) -> str:
        """[TLS] Verify TLS decryption with SSLKEYLOGFILE-format keylog file."""
        return normalize_tool_result(await client.decrypt_ssl(pcap_file, keylog_file))

    return [
        ("wireshark_extract_http_requests", wireshark_extract_http_requests),
        ("wireshark_extract_dns_queries", wireshark_extract_dns_queries),
        ("wireshark_export_objects", wireshark_export_objects),
        ("wireshark_verify_ssl_decryption", wireshark_verify_ssl_decryption),
    ]
