import argparse
import logging
import os
import sys

from mcp.server.fastmcp import FastMCP

from .__init__ import __version__
from .prompts import register_prompts
from .resources import register_resources
from .tshark.client import TSharkClient
from .tools.capture import register_capture_tools
from .tools.decode import register_decode_tools
from .tools.extract import register_extract_tools
from .tools.files import register_files_tools
from .tools.protocol import register_protocol_tools
from .tools.security import register_security_tools
from .tools.stats import register_stats_tools
from .tools.threat import register_threat_tools
from .tools.visualize import register_visualize_tools

logger = logging.getLogger("wireshark_mcp")


def _build_server() -> FastMCP:
    """Build and configure the MCP server with all tools registered."""
    # Read allowed directories from environment
    allowed_dirs_env = os.environ.get("WIRESHARK_MCP_ALLOWED_DIRS", "")
    allowed_dirs = [d.strip() for d in allowed_dirs_env.split(",") if d.strip()] or None

    mcp = FastMCP("Wireshark MCP", dependencies=["tshark"])
    client = TSharkClient(allowed_dirs=allowed_dirs)

    # Register all tool modules
    register_capture_tools(mcp, client)
    register_stats_tools(mcp, client)
    register_extract_tools(mcp, client)
    register_files_tools(mcp, client)
    register_security_tools(mcp, client)
    register_decode_tools(mcp)
    register_visualize_tools(mcp, client)
    register_protocol_tools(mcp, client)
    register_threat_tools(mcp, client)

    # Register Resources and Prompts
    register_resources(mcp)
    register_prompts(mcp)

    return mcp


def main() -> None:
    """Entry point for the application script."""
    parser = argparse.ArgumentParser(
        prog="wireshark-mcp",
        description="Wireshark MCP Server — AI-powered packet analysis",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="MCP transport to use (default: stdio)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port for SSE transport (default: 8080)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="WARNING",
        help="Logging level (default: WARNING)",
    )

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    mcp = _build_server()

    if args.transport == "sse":
        logger.info("Starting SSE transport on port %d", args.port)
        mcp.run(transport="sse")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
