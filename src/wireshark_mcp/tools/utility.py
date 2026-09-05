"""Utility, suite, file manipulation, and capture tools for Wireshark MCP."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from .envelope import normalize_tool_result, parse_tool_result, success_response

if TYPE_CHECKING:
    from mcp.server import MCPServer

    from ..tshark.client import TSharkClient


def register_utility_tools(mcp: MCPServer, client: TSharkClient) -> None:
    """Register all utility, file manipulation, capture, and suite tools."""

    # ── Suite Capabilities ──────────────────────────────────────────────
    @mcp.tool()
    async def wireshark_get_capabilities() -> str:
        """Get Wireshark suite capabilities for this MCP server instance (available tools and versions)."""
        return normalize_tool_result(await client.check_capabilities())

    # ── File Operations ────────────────────────────────────────────────
    @mcp.tool()
    async def wireshark_get_file_info(pcap_file: str) -> str:
        """Get capture file metadata (type, packet count, duration, size) via capinfos."""
        return normalize_tool_result(await client.get_file_info(pcap_file))

    @mcp.tool()
    async def wireshark_merge_pcaps(output_file: str, input_files: str) -> str:
        """Merge multiple capture files into one. input_files: comma-separated paths."""
        files = [f.strip() for f in input_files.split(",")]
        return normalize_tool_result(await client.merge_pcap_files(output_file, files))

    # ── Text2pcap Import ───────────────────────────────────────────────
    @mcp.tool()
    async def wireshark_text2pcap_import(
        input_text_file: str,
        output_file: str,
        encapsulation: str = "ether",
        timestamp_format: str = "",
        ascii_mode: bool = False,
    ) -> str:
        """Convert ASCII or hex dump into a capture file using text2pcap. encapsulation: link-layer type (default: ether)."""
        return normalize_tool_result(
            await client.text2pcap_import(input_text_file, output_file, encapsulation, timestamp_format, ascii_mode)
        )

    # ── Capture Operations ─────────────────────────────────────────────
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

    # ── Editcap Operations ─────────────────────────────────────────────
    @mcp.tool()
    async def wireshark_editcap_trim(
        input_file: str,
        output_file: str,
        start_time: str = "",
        stop_time: str = "",
    ) -> str:
        """Trim capture to a timestamp window. Times in editcap format."""
        return normalize_tool_result(await client.editcap_trim(input_file, output_file, start_time, stop_time))

    @mcp.tool()
    async def wireshark_editcap_split(
        input_file: str,
        output_prefix: str,
        packets_per_file: int = 0,
        seconds_per_file: int = 0,
    ) -> str:
        """Split a capture into smaller files by packet count or interval."""
        return normalize_tool_result(
            await client.editcap_split(input_file, output_prefix, packets_per_file, seconds_per_file)
        )

    @mcp.tool()
    async def wireshark_editcap_time_shift(input_file: str, output_file: str, seconds: float) -> str:
        """Adjust all packet timestamps by a positive or negative offset in seconds."""
        return normalize_tool_result(await client.editcap_time_shift(input_file, output_file, seconds))

    @mcp.tool()
    async def wireshark_editcap_deduplicate(input_file: str, output_file: str, duplicate_window: int = 5) -> str:
        """Remove duplicate packets within a sliding window (default: 5 packets)."""
        return normalize_tool_result(await client.editcap_deduplicate(input_file, output_file, duplicate_window))
