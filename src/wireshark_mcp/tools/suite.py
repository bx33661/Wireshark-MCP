from mcp.server.fastmcp import FastMCP

from ..tshark.client import TSharkClient
from .envelope import normalize_tool_result


def register_suite_tools(mcp: FastMCP, client: TSharkClient) -> None:

    @mcp.tool()
    async def wireshark_get_capabilities() -> str:
        """Get Wireshark suite capabilities for this MCP server instance (available tools and versions)."""
        return normalize_tool_result(await client.check_capabilities())
