from mcp.server.fastmcp import FastMCP

from ..tshark.client import TSharkClient
from .envelope import normalize_tool_result


def register_files_tools(mcp: FastMCP, client: TSharkClient):

    @mcp.tool()
    async def wireshark_get_file_info(pcap_file: str) -> str:
        """Get capture file metadata (type, packet count, duration, size) via capinfos."""
        return normalize_tool_result(await client.get_file_info(pcap_file))

    @mcp.tool()
    async def wireshark_merge_pcaps(output_file: str, input_files: str) -> str:
        """Merge multiple capture files into one. input_files: comma-separated paths."""
        files = [f.strip() for f in input_files.split(",")]
        return normalize_tool_result(await client.merge_pcap_files(output_file, files))
