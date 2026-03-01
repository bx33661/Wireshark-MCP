import argparse
import logging
import os
import sys

from mcp.server.fastmcp import FastMCP

from .__init__ import __version__
from .prompts import register_prompts
from .resources import register_resources
from .tools.agents import register_agent_tools
from .tools.capture import register_capture_tools
from .tools.decode import register_decode_tools
from .tools.extract import register_extract_tools
from .tools.files import register_files_tools
from .tools.registry import ToolRegistry, register_open_file_tool
from .tools.stats import register_stats_tools
from .tools.visualize import register_visualize_tools
from .tshark.client import TSharkClient

logger = logging.getLogger("wireshark_mcp")


def _build_server() -> FastMCP:
    """Build and configure the MCP server with progressive discovery."""
    # Read allowed directories from environment
    allowed_dirs_env = os.environ.get("WIRESHARK_MCP_ALLOWED_DIRS", "")
    allowed_dirs = [d.strip() for d in allowed_dirs_env.split(",") if d.strip()] or None

    mcp = FastMCP("Wireshark MCP", dependencies=["tshark"])
    client = TSharkClient(allowed_dirs=allowed_dirs)

    # ── Core tools (always registered) ──────────────────────────────────
    register_capture_tools(mcp, client)
    register_stats_tools(mcp, client)
    register_extract_tools(mcp, client)
    register_files_tools(mcp, client)
    register_decode_tools(mcp)
    register_visualize_tools(mcp, client)
    register_agent_tools(mcp, client)

    # ── Progressive Discovery ───────────────────────────────────────────
    # Build the contextual tool catalog (not registered yet)
    registry = ToolRegistry(mcp, client)
    registry.build_catalog()

    # Register the entry-point tool that activates contextual tools
    register_open_file_tool(mcp, client, registry)

    # ── Resources and Prompts ───────────────────────────────────────────
    register_resources(mcp)
    register_prompts(mcp)

    return mcp


def main() -> None:
    """Entry point for the application script."""
    from .installer import run_install

    parser = argparse.ArgumentParser(
        prog="wireshark-mcp",
        description="Wireshark MCP Server — AI-powered packet analysis",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    # ── Install / Uninstall ─────────────────────────────────────────────
    parser.add_argument(
        "--install",
        action="store_true",
        help="Install wireshark-mcp into all detected MCP clients and exit",
    )
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="Uninstall wireshark-mcp from all detected MCP clients and exit",
    )
    parser.add_argument(
        "--config",
        action="store_true",
        help="Print MCP config JSON for manual client setup and exit",
    )

    # ── Server options ──────────────────────────────────────────────────
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

    # Handle install / uninstall / config — exit without starting server
    if args.install or args.uninstall or args.config:
        run_install(
            install=args.install,
            uninstall=args.uninstall,
            config=args.config,
        )
        return

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
