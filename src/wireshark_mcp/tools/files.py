from mcp.server.fastmcp import FastMCP

from ..tshark.client import TSharkClient
from .envelope import normalize_tool_result


def register_files_tools(mcp: FastMCP, client: TSharkClient):

    @mcp.tool()
    async def wireshark_get_file_info(pcap_file: str) -> str:
        """
        Get detailed metadata about a capture file.
        Uses capinfos to show: file type, packet count, duration, size, etc.

        Returns:
            Detailed file metadata or JSON error

        Errors:
            FileNotFound: pcap_file does not exist
            ToolNotFound: capinfos not available

        Example:
            wireshark_get_file_info("traffic.pcap")
        """
        return normalize_tool_result(await client.get_file_info(pcap_file))

    @mcp.tool()
    async def wireshark_merge_pcaps(output_file: str, input_files: str) -> str:
        """
        Merge multiple capture files into one.

        Args:
            output_file: Path for merged output file
            input_files: Comma-separated list of input file paths

        Returns:
            Success message or JSON error

        Errors:
            FileNotFound: One or more input files not found
            ToolNotFound: mergecap not available

        Example:
            wireshark_merge_pcaps("merged.pcap", "file1.pcap,file2.pcap,file3.pcap")
        """
        files = [f.strip() for f in input_files.split(",")]
        return normalize_tool_result(await client.merge_pcap_files(output_file, files))
