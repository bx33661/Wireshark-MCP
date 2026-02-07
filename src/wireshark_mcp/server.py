from mcp.server.fastmcp import FastMCP
from .tshark.client import TSharkClient
from .tools.capture import register_capture_tools
from .tools.stats import register_stats_tools
from .tools.extract import register_extract_tools
from .tools.files import register_files_tools
from .tools.security import register_security_tools
from .tools.decode import register_decode_tools
from .tools.visualize import register_visualize_tools
import asyncio

# Initialize Server
mcp = FastMCP("Wireshark MCP", dependencies=["tshark"])

client = TSharkClient()

# Register Tools
register_capture_tools(mcp, client)
register_stats_tools(mcp, client)
register_extract_tools(mcp, client)
register_files_tools(mcp, client)
register_security_tools(mcp, client)
register_decode_tools(mcp)
register_visualize_tools(mcp, client)

def main():
    """Entry point for the application script"""
    # Don't run async checks during startup - they block stdio
    mcp.run()

if __name__ == "__main__":
    main()
