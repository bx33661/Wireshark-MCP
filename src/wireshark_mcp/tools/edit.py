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
        """
        Trim a capture file to a timestamp window using editcap.

        Args:
            input_file: Source capture file
            output_file: Destination capture file
            start_time: Optional inclusive start time in editcap format
            stop_time: Optional exclusive stop time in editcap format

        Returns:
            Success message or JSON error
        """
        return normalize_tool_result(await client.editcap_trim(input_file, output_file, start_time, stop_time))

    @mcp.tool()
    async def wireshark_editcap_split(
        input_file: str,
        output_prefix: str,
        packets_per_file: int = 0,
        seconds_per_file: int = 0,
    ) -> str:
        """
        Split a capture into multiple files using editcap.

        Args:
            input_file: Source capture file
            output_prefix: Output filename prefix or base path
            packets_per_file: Split after this many packets per file
            seconds_per_file: Split after this many seconds per file

        Returns:
            Success message or JSON error
        """
        return normalize_tool_result(
            await client.editcap_split(input_file, output_prefix, packets_per_file, seconds_per_file)
        )

    @mcp.tool()
    async def wireshark_editcap_time_shift(input_file: str, output_file: str, seconds: float) -> str:
        """
        Shift packet timestamps by a relative number of seconds using editcap.

        Args:
            input_file: Source capture file
            output_file: Destination capture file
            seconds: Relative time adjustment in seconds

        Returns:
            Success message or JSON error
        """
        return normalize_tool_result(await client.editcap_time_shift(input_file, output_file, seconds))

    @mcp.tool()
    async def wireshark_editcap_deduplicate(input_file: str, output_file: str, duplicate_window: int = 5) -> str:
        """
        Remove duplicate packets using editcap's duplicate window matching.

        Args:
            input_file: Source capture file
            output_file: Destination capture file
            duplicate_window: Number of prior packets to compare against

        Returns:
            Success message or JSON error
        """
        return normalize_tool_result(await client.editcap_deduplicate(input_file, output_file, duplicate_window))
