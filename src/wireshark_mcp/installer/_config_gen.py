"""MCP config generation and rendering."""

from __future__ import annotations

import json
from typing import Any

from ._detection import _collect_runtime_env, _get_python_executable

SERVER_NAME = "wireshark-mcp"


def generate_mcp_config() -> dict[str, Any]:
    """Generate the MCP server configuration snippet."""
    env = _collect_runtime_env()
    config: dict[str, Any] = {
        "command": _get_python_executable(),
        "args": ["-u", "-m", "wireshark_mcp.server"],
    }
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUNBUFFERED", "1")

    if env:
        config["env"] = env

    return config


def _generate_opencode_config() -> dict[str, Any]:
    """Generate an OpenCode-format MCP server entry."""
    env = _collect_runtime_env()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUNBUFFERED", "1")

    config: dict[str, Any] = {
        "type": "local",
        "command": [_get_python_executable(), "-u", "-m", "wireshark_mcp.server"],
    }
    if env:
        config["environment"] = env

    return config


def _render_codex_toml_block() -> str:
    """Render the Codex TOML block for this MCP server."""
    config = generate_mcp_config()
    lines = [
        f"[mcp_servers.{SERVER_NAME}]",
        f"command = {json.dumps(config['command'])}",
        f"args = {json.dumps(config.get('args', []))}",
    ]

    env = config.get("env") or {}
    if env:
        lines.append(f"[mcp_servers.{SERVER_NAME}.env]")
        for key, value in sorted(env.items()):
            lines.append(f"{key} = {json.dumps(value)}")

    return "\n".join(lines)


def print_mcp_config(*, output_format: str = "json") -> None:
    """Print a manual MCP config snippet in the requested format."""
    if output_format == "json":
        config = {"mcpServers": {SERVER_NAME: generate_mcp_config()}}
        print(json.dumps(config, indent=2))
        return

    if output_format == "codex-toml":
        print(_render_codex_toml_block())
        return

    raise ValueError(f"Unsupported config format: {output_format}")
