from mcp.server.fastmcp import FastMCP

from ..tshark.client import TSharkClient
from .envelope import normalize_tool_result


def register_edit_tools(mcp: FastMCP, client: TSharkClient) -> None:

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
        """Split capture into multiple files by packet count or time interval."""
        return normalize_tool_result(
            await client.editcap_split(input_file, output_prefix, packets_per_file, seconds_per_file)
        )

    @mcp.tool()
    async def wireshark_editcap_time_shift(input_file: str, output_file: str, seconds: float) -> str:
        """Shift packet timestamps by a relative number of seconds."""
        return normalize_tool_result(await client.editcap_time_shift(input_file, output_file, seconds))

    @mcp.tool()
    async def wireshark_editcap_deduplicate(input_file: str, output_file: str, duplicate_window: int = 5) -> str:
        """Remove duplicate packets using editcap's duplicate window matching."""
        return normalize_tool_result(await client.editcap_deduplicate(input_file, output_file, duplicate_window))
