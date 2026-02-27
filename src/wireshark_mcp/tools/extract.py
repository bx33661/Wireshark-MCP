from mcp.server.fastmcp import FastMCP
from ..tshark.client import TSharkClient
from .envelope import error_response, normalize_tool_result, parse_tool_result, success_response

def register_extract_tools(mcp: FastMCP, client: TSharkClient):

    @mcp.tool()
    async def wireshark_get_packet_list(pcap_file: str, limit: int = 20, offset: int = 0,
                                      display_filter: str = "", custom_columns: str = "") -> str:
        """
        [Summary] Get a summary list of packets (like Wireshark's top pane).
        Use this first to scan traffic before drilling down.
        
        Args:
            pcap_file: Path to capture file
            limit: Rows to return (default: 20)
            offset: Skip first N rows
            display_filter: Wireshark display filter (e.g. "tcp.port == 80")
            custom_columns: Comma-separated list of fields (e.g. "ip.src,http.host")
                            If provided, replaces default columns.
            
        Returns:
            Tabular list with columns: No, Time, Source, Destination, Protocol, Length, Info
            (Or your custom columns if specified)
            
        Example:
            wireshark_get_packet_list("traffic.pcap", display_filter="http", custom_columns="ip.src,http.host,http.request.uri")
        """
        columns = [c.strip() for c in custom_columns.split(",")] if custom_columns else None
        return normalize_tool_result(await client.get_packet_list(pcap_file, limit, offset, display_filter, columns))

    @mcp.tool()
    async def wireshark_get_packet_details(pcap_file: str, frame_number: int, layers: str = "") -> str:
        """
        [Detail] Get full details for a SINGLE packet (like Wireshark's bottom pane).
        
        Args:
            pcap_file: Path to capture file
            frame_number: The packet number (from wireshark_get_packet_list)
            layers: Comma-separated list of layers/protocols to include (e.g. "ip,tcp,http").
                    Reduces output size significantly.
            
        Returns:
            Complete JSON structure of the packet
            
        Example:
            wireshark_get_packet_details("traffic.pcap", frame_number=42, layers="http")
        """
        layer_list = [l.strip() for l in layers.split(",")] if layers else None
        return normalize_tool_result(await client.get_packet_details(pcap_file, frame_number, layer_list))

    @mcp.tool()
    async def wireshark_get_packet_bytes(pcap_file: str, frame_number: int) -> str:
        """
        [Bytes] Get raw Hex/ASCII dump (like Wireshark's 'Packet Bytes' pane).
        
        Args:
            pcap_file: Path to capture file
            frame_number: The packet number
            
        Returns:
            Standard Wireshark Hex/ASCII dump.
            
        Example:
            wireshark_get_packet_bytes("traffic.pcap", 42)
        """
        return normalize_tool_result(await client.get_packet_bytes(pcap_file, frame_number))

    @mcp.tool()
    async def wireshark_get_packet_context(pcap_file: str, frame_number: int, count: int = 5) -> str:
        """
        [Context] View packets surrounding a specific frame (before and after).
        Useful for understanding what led to an error or what happened immediately after.
        
        Args:
            pcap_file: Path to capture file
            frame_number: The center packet number
            count: Number of packets to show before and after (default: 5)
            
        Returns:
            Tabular packet list centering on the target frame.
        """
        start = max(1, frame_number - count)
        # We can't easily limit the *end* without knowing the total count, 
        # but we can use 'limit' parameter.
        # Total rows = count (before) + 1 (target) + count (after) = 2*count + 1
        limit = count * 2 + 1
        
        # We use display filter to ensure we get the specific range
        # Note: frame.number is 1-based
        d_filter = f"frame.number >= {start}"
        
        # We need to fetch enough packets. 
        # Since we filter by >= start, if we ask for limit=2*count+1, we get the range [start, start + limit - 1]
        # which corresponds to [target-count, target+count].
        # This assumes no display filter is applied in context, which is correct (context is absolute).
        
        return normalize_tool_result(await client.get_packet_list(pcap_file, limit=limit, offset=0, display_filter=d_filter))

    @mcp.tool()
    async def wireshark_read_packets(pcap_file: str, limit: int = 100, offset: int = 0,
                                   display_filter: str = "") -> str:
        """
        [DEPRECATED] Read packet data in structured JSON format.
        WARNING: This tool can return very large, complex JSON. 
        Prefer `wireshark_get_packet_list` and `wireshark_get_packet_details` for efficient analysis.
        
        Args:
            pcap_file: Path to capture file
            limit: Maximum packets to return (default: 100)
            offset: Skip first N packets (pagination)
            display_filter: Wireshark display filter (e.g. "tcp.port == 80")
            
        Returns:
            JSON array of packets with full layer details on success
            JSON error object on failure: {"success": false, "error": {...}}
            
        Errors:
            FileNotFound: pcap_file does not exist
            ExecutionError: tshark JSON parsing failed
            
        Example:
            wireshark_read_packets("traffic.pcap", limit=10, display_filter="http")
        """
        return normalize_tool_result(await client.read_packets_json(pcap_file, limit, display_filter, offset))

    @mcp.tool()
    async def wireshark_extract_fields(pcap_file: str, fields: str, display_filter: str = "",
                                     limit: int = 100, offset: int = 0) -> str:
        """
        [Tabular] Extract specific fields as comma/tab-separated data.
        
        Args:
            fields: Comma-separated field names (e.g. "ip.src,tcp.port,http.host")
            display_filter: Optional filter (e.g. "http.request.method == POST")
            limit: Max rows to return (default: 100)
            offset: Skip first N rows (pagination)
            
        Returns:
            Tabular text output or JSON error
            
        Errors:
            FileNotFound: pcap_file does not exist
            ExecutionError: Field extraction failed
            
        Example:
            wireshark_extract_fields("file.pcap", "ip.src,ip.dst,tcp.port", display_filter="tcp")
        """
        field_list = [f.strip() for f in fields.split(",")]
        return normalize_tool_result(await client.extract_fields(pcap_file, field_list, display_filter, limit=limit, offset=offset))

    @mcp.tool()
    async def wireshark_extract_http_requests(pcap_file: str, limit: int = 100) -> str:
        """
        [Convenience] Extract HTTP request details (method, URI, host).
        Pre-configured field extraction for HTTP analysis.
        
        Returns:
            Tabular text with HTTP request data or JSON error
            
        Example:
            wireshark_extract_http_requests("web_traffic.pcap", limit=50)
        """
        return normalize_tool_result(await client.extract_fields(
            pcap_file,
            ["http.request.method", "http.request.uri", "http.host", "http.user_agent"],
            display_filter="http.request",
            limit=limit
        ))

    @mcp.tool()
    async def wireshark_extract_dns_queries(pcap_file: str, limit: int = 100) -> str:
        """
        [Convenience] Extract DNS query details (name, type).
        Pre-configured for DNS analysis.
        
        Returns:
            Tabular text with DNS queries or JSON error
            
        Example:
            wireshark_extract_dns_queries("dns_traffic.pcap")
        """
        return normalize_tool_result(await client.extract_fields(
            pcap_file,
            ["dns.qry.name", "dns.qry.type", "dns.flags.response"],
            display_filter="dns",
            limit=limit
        ))

    @mcp.tool()
    async def wireshark_list_ips(pcap_file: str, type: str = "both") -> str:
        """
        [Convenience] List all unique IP addresses in capture.
        
        Args:
            type: IP type to extract - 'src', 'dst', or 'both'
            
        Returns:
            Newline-separated list of unique IPs or JSON error
            
        Example:
            wireshark_list_ips("traffic.pcap", type="src")
        """
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
        for line in data.splitlines()[1:]:  # Skip header
            for ip in line.split('\t'):
                ip = ip.strip().strip('"')
                if ip and ip != '':
                    unique_ips.add(ip)
        
        return success_response('\n'.join(sorted(unique_ips)))

    @mcp.tool()
    async def wireshark_export_objects(pcap_file: str, protocol: str, dest_dir: str) -> str:
        """
        [Export] Extract embedded files from traffic.
        
        Args:
            protocol: Protocol type - 'http', 'smb', 'tftp', 'imf', 'dicom'
            dest_dir: Destination directory for extracted files
            
        Returns:
            Success message or JSON error
            
        Errors:
            FileNotFound: pcap_file does not exist
            InvalidParameter: Invalid protocol
            
        Example:
            wireshark_export_objects("traffic.pcap", "http", "/tmp/exported")
        """
        return normalize_tool_result(await client.export_objects(pcap_file, protocol, dest_dir))

    @mcp.tool()
    async def wireshark_search_packets(pcap_file: str, match_pattern: str, search_type: str = "string",
                                     limit: int = 50, scope: str = "bytes") -> str:
        """
        [Search] Find packets containing specific data.
        
        Args:
            pcap_file: Path to capture file
            match_pattern: Pattern to search for
            search_type: Search method - 'string', 'hex', 'regex'
            limit: Maximum matches to return (default: 50)
            scope: Search scope - 'bytes' (default), 'details', or 'filter'
                   - 'bytes': Searches raw packet payload (frame contains)
                   - 'details': Searches decoded text layer (frame matches)
                   - 'filter': Uses standard Wireshark display filter syntax (e.g. "http.response.code == 200")
            
        Returns:
            List of matching packets (summary view) or JSON error
            
        Errors:
            FileNotFound: pcap_file does not exist
            
        Example:
            wireshark_search_packets("traffic.pcap", "password", scope="bytes")
            wireshark_search_packets("traffic.pcap", "http.response.code == 200", scope="filter")
        """
        return normalize_tool_result(
            await client.search_packet_contents(pcap_file, match_pattern, search_type, limit=limit, scope=scope)
        )

    @mcp.tool()
    async def wireshark_follow_stream(pcap_file: str, stream_index: int, 
                                    protocol: str = "tcp", output_mode: str = "ascii",
                                    limit_lines: int = 500, offset_lines: int = 0,
                                    search_content: str = "") -> str:
        """
        [Stream] Reassemble and view complete stream content.
        Supports pagination to avoid token limits.
        
        Args:
            stream_index: Stream ID from conversations/stats
            protocol: Stream protocol - 'tcp', 'udp', 'tls', 'http', 'http2'
            output_mode: Output format - 'ascii', 'hex', 'raw'
            limit_lines: Max lines to return (default: 500)
            offset_lines: Skip first N lines (for pagination)
            search_content: Optional string to grep/search within the stream
            
        Returns:
            Reconstructed stream data or JSON error
            
        Errors:
            FileNotFound: pcap_file does not exist
            InvalidParameter: Invalid protocol
            
        Example:
            wireshark_follow_stream("traffic.pcap", stream_index=0, search_content="password")
        """
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

    @mcp.tool()
    async def wireshark_verify_ssl_decryption(pcap_file: str, keylog_file: str) -> str:
        """
        [SSL] Verify TLS decryption with keylog file.
        
        Args:
            keylog_file: Path to SSL/TLS keylog file (SSLKEYLOGFILE format)
            
        Returns:
            Expert info with decryption status or JSON error
            
        Errors:
            FileNotFound: pcap_file or keylog_file does not exist
            
        Example:
            wireshark_verify_ssl_decryption("https.pcap", "ssl_keylog.txt")
        """
        return normalize_tool_result(await client.decrypt_ssl(pcap_file, keylog_file))
