import argparse
import asyncio
import logging
import os
import sys
from collections.abc import Sequence
from typing import Literal, cast

from mcp.server.fastmcp import FastMCP

from .__init__ import __version__
from .prompts import register_prompts
from .resources import register_resources
from .tools.agents import register_agent_tools
from .tools.capture import register_capture_tools
from .tools.decode import register_decode_tools
from .tools.edit import register_edit_tools
from .tools.extract import register_extract_tools
from .tools.files import register_files_tools
from .tools.imports import register_import_tools
from .tools.registry import ToolRegistry, register_open_file_tool
from .tools.stats import register_stats_tools
from .tools.suite import register_suite_tools
from .tools.visualize import register_visualize_tools
from .tshark.client import WiresharkSuiteClient

logger = logging.getLogger("wireshark_mcp")
LogLevelName = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
LOG_LEVELS: tuple[LogLevelName, ...] = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
TRANSPORTS = ("stdio", "sse", "streamable-http")


class _HelpFormatter(argparse.RawDescriptionHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    """Help formatter that keeps examples readable while showing defaults."""


def _configure_windows_event_loop() -> None:
    """Keep the asyncio policy compatible with subprocess-heavy workloads."""
    if sys.platform != "win32":
        return

    policy_cls = getattr(asyncio, "WindowsProactorEventLoopPolicy", None)
    if policy_cls is None:
        return

    if not isinstance(asyncio.get_event_loop_policy(), policy_cls):
        asyncio.set_event_loop_policy(policy_cls())


def _build_server(*, host: str, port: int, log_level: LogLevelName) -> FastMCP:
    """Build and configure the MCP server with a stable contextual tool surface."""
    # Read allowed directories from environment
    allowed_dirs_env = os.environ.get("WIRESHARK_MCP_ALLOWED_DIRS", "")
    allowed_dirs = [d.strip() for d in allowed_dirs_env.split(",") if d.strip()] or None

    mcp = FastMCP("Wireshark MCP", dependencies=["tshark"], host=host, port=port, log_level=log_level)
    client = WiresharkSuiteClient(allowed_dirs=allowed_dirs)

    # ── Core tools (always registered) ──────────────────────────────────
    register_capture_tools(mcp, client)
    register_stats_tools(mcp, client)
    register_extract_tools(mcp, client)
    register_files_tools(mcp, client)
    register_decode_tools(mcp)
    register_visualize_tools(mcp, client)
    register_agent_tools(mcp, client)
    register_suite_tools(mcp, client)
    register_edit_tools(mcp, client)
    register_import_tools(mcp, client)

    # ── Contextual recommendations ─────────────────────────────────────
    # Build and register the contextual tool catalog once for a stable tool surface
    registry = ToolRegistry(mcp, client)
    registry.build_catalog()
    registry.register_all_contextual_tools()

    # Register the entry-point tool that recommends the most relevant tools
    register_open_file_tool(mcp, client, registry)

    # ── Resources and Prompts ───────────────────────────────────────────
    register_resources(mcp, client)
    register_prompts(mcp)

    return mcp


def _add_server_arguments(parser: argparse.ArgumentParser) -> None:
    """Add server runtime options to a parser."""
    parser.add_argument(
        "--transport",
        choices=TRANSPORTS,
        default="stdio",
        help="MCP transport to use",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address for SSE and Streamable HTTP transports",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Bind port for SSE and Streamable HTTP transports",
    )
    parser.add_argument(
        "--mount-path",
        default="/",
        help="Mount path for SSE transport",
    )
    parser.add_argument(
        "--log-level",
        choices=LOG_LEVELS,
        default="WARNING",
        help="Logging level",
    )


def _add_client_selector_argument(parser: argparse.ArgumentParser) -> None:
    """Add repeatable client filters to a parser."""
    parser.add_argument(
        "--client",
        action="append",
        dest="clients",
        metavar="NAME",
        help="Limit the action to one or more MCP clients (repeatable)",
    )


def _add_text_or_json_format_argument(parser: argparse.ArgumentParser, *, help_text: str) -> None:
    """Add a text/json output format selector to a parser."""
    parser.add_argument(
        "--format",
        dest="output_format",
        choices=["text", "json"],
        default="text",
        help=help_text,
    )


def _build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser for server and installer workflows."""
    parser = argparse.ArgumentParser(
        prog="wireshark-mcp",
        description="Wireshark MCP server with packet-analysis tools and MCP client auto-configuration.",
        epilog=(
            "Examples:\n"
            "  wireshark-mcp\n"
            "  wireshark-mcp serve --transport sse --host 0.0.0.0 --port 8080\n"
            "  wireshark-mcp install --client cursor --client codex\n"
            "  wireshark-mcp doctor --format json\n"
            "  wireshark-mcp clients --format json\n"
            "  wireshark-mcp config --format codex-toml"
        ),
        formatter_class=_HelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    _add_server_arguments(parser)

    # Backward-compatible legacy flags. Keep them hidden so the help focuses on subcommands.
    parser.add_argument("--install", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--uninstall", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--config", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--doctor", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--clients", action="store_true", dest="legacy_list_clients", help=argparse.SUPPRESS)
    parser.add_argument("--client", action="append", dest="legacy_clients", metavar="NAME", help=argparse.SUPPRESS)
    parser.add_argument(
        "--format",
        dest="legacy_output_format",
        choices=["text", "json"],
        default="text",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--config-format",
        dest="legacy_config_format",
        choices=["json", "codex-toml"],
        default="json",
        help=argparse.SUPPRESS,
    )

    subparsers = parser.add_subparsers(dest="command", metavar="command")

    serve_parser = subparsers.add_parser("serve", help="Start the MCP server", formatter_class=_HelpFormatter)
    _add_server_arguments(serve_parser)

    install_parser = subparsers.add_parser(
        "install",
        help="Install wireshark-mcp into detected MCP clients",
        formatter_class=_HelpFormatter,
    )
    _add_client_selector_argument(install_parser)

    uninstall_parser = subparsers.add_parser(
        "uninstall",
        help="Remove wireshark-mcp from detected MCP clients",
        formatter_class=_HelpFormatter,
    )
    _add_client_selector_argument(uninstall_parser)

    doctor_parser = subparsers.add_parser(
        "doctor",
        help="Show Wireshark tool and MCP client diagnostics",
        formatter_class=_HelpFormatter,
    )
    _add_client_selector_argument(doctor_parser)
    _add_text_or_json_format_argument(doctor_parser, help_text="Diagnostics output format")

    config_parser = subparsers.add_parser(
        "config",
        help="Print manual configuration snippets",
        formatter_class=_HelpFormatter,
    )
    config_parser.add_argument(
        "--format",
        dest="config_format",
        choices=["json", "codex-toml"],
        default="json",
        help="Manual configuration output format",
    )

    clients_parser = subparsers.add_parser(
        "clients",
        help="List supported MCP clients and detection paths",
        formatter_class=_HelpFormatter,
    )
    _add_client_selector_argument(clients_parser)
    _add_text_or_json_format_argument(clients_parser, help_text="Client listing output format")

    return parser


def _resolve_command(args: argparse.Namespace, parser: argparse.ArgumentParser) -> str:
    """Resolve subcommands and legacy flags into a single action."""
    legacy_actions = {
        "install": args.install,
        "uninstall": args.uninstall,
        "config": args.config,
        "doctor": args.doctor,
        "clients": args.legacy_list_clients,
    }
    selected_legacy = [name for name, enabled in legacy_actions.items() if enabled]

    if args.command and selected_legacy:
        parser.error("Do not mix subcommands with legacy flags like --install or --doctor.")

    if len(selected_legacy) > 1:
        parser.error("Choose only one legacy action flag at a time.")

    if args.command:
        return cast("str", args.command)

    if selected_legacy:
        return selected_legacy[0]

    return "serve"


def main(argv: Sequence[str] | None = None) -> None:
    """Entry point for the application script."""
    from .installer import run_install

    parser = _build_parser()
    args = parser.parse_args(argv)
    command = _resolve_command(args, parser)

    if command in {"install", "uninstall", "config", "doctor", "clients"}:
        selected_clients = getattr(args, "clients", None) if args.command else args.legacy_clients
        config_format = getattr(args, "config_format", args.legacy_config_format)
        output_format = getattr(args, "output_format", args.legacy_output_format)
        run_install(
            install=command == "install",
            uninstall=command == "uninstall",
            config=command == "config",
            doctor=command == "doctor",
            list_clients=command == "clients",
            selected_clients=selected_clients,
            config_format=config_format,
            output_format=output_format,
        )
        return

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    mcp = _build_server(host=args.host, port=args.port, log_level=args.log_level)
    _configure_windows_event_loop()

    if args.transport == "sse":
        logger.info("Starting SSE transport on http://%s:%d%s", args.host, args.port, args.mount_path)
        mcp.run(transport="sse", mount_path=args.mount_path)
    elif args.transport == "streamable-http":
        logger.info("Starting Streamable HTTP transport on http://%s:%d", args.host, args.port)
        mcp.run(transport="streamable-http")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
