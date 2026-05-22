import os

from mcp.server.fastmcp import FastMCP

from ..tshark.client import TSharkClient
from .envelope import normalize_tool_result, parse_tool_result, success_response


def register_capture_tools(mcp: FastMCP, client: TSharkClient) -> None:

    @mcp.tool()
    async def wireshark_list_interfaces() -> str:
        """List available network interfaces for capture."""
        return normalize_tool_result(await client.list_interfaces())

    @mcp.tool()
    async def wireshark_capture(
        interface: str,
        output_file: str,
        duration_seconds: int = 10,
        packet_count: int = 0,
        capture_filter: str = "",
        ring_buffer: str = "",
    ) -> str:
        """Capture live network traffic. capture_filter: BPF syntax. ring_buffer: "filesize:1024,files:5"."""
        res = await client.capture_packets(
            interface, output_file, duration_seconds, packet_count, capture_filter, ring_buffer=ring_buffer
        )

        wrapped = parse_tool_result(res)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        if os.path.exists(output_file):
            return success_response(f"Capture saved to {output_file}\n{wrapped['data']}")

        return success_response(f"Capture completed but file not found:\n{wrapped['data']}")

    @mcp.tool()
    async def wireshark_filter_save(input_file: str, output_file: str, display_filter: str) -> str:
        """Filter packets from a pcap and save to a new file using a Wireshark display filter."""
        return normalize_tool_result(await client.filter_and_save(input_file, output_file, display_filter))
