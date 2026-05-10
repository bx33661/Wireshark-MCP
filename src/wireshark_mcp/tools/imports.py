from mcp.server.fastmcp import FastMCP

from ..tshark.client import TSharkClient
from .envelope import normalize_tool_result


def register_import_tools(mcp: FastMCP, client: TSharkClient) -> None:

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
