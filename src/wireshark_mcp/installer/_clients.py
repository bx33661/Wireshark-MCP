"""Client config registry — maps client name to (config_dir, config_filename)."""

from __future__ import annotations

import os
import re
import sys

from ._detection import _get_linux_config_home, _join_path

_SPECIAL_JSON_STRUCTURES: dict[str, tuple[str, str]] = {
    "VS Code": ("mcp", "servers"),
    "VS Code Insiders": ("mcp", "servers"),
    "Zed": ("mcp", "servers"),
}

_OPENCODE_STYLE_CLIENTS: frozenset[str] = frozenset({"OpenCode"})


def _get_client_configs() -> dict[str, tuple[str, str]]:
    """Return known MCP client config locations for the current OS."""
    home = os.path.expanduser("~")

    if sys.platform == "darwin":
        configs: dict[str, tuple[str, str]] = {
            "Claude": (
                _join_path(home, "Library", "Application Support", "Claude"),
                "claude_desktop_config.json",
            ),
            "Cursor": (_join_path(home, ".cursor"), "mcp.json"),
            "Windsurf": (_join_path(home, ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (home, ".claude.json"),
            "Cline": (
                _join_path(
                    home,
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                _join_path(
                    home,
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                _join_path(
                    home,
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "LM Studio": (_join_path(home, ".lmstudio"), "mcp.json"),
            "Codex": (_join_path(home, ".codex"), "config.toml"),
            "Antigravity IDE": (_join_path(home, ".gemini", "antigravity"), "mcp_config.json"),
            "Zed": (_join_path(home, "Library", "Application Support", "Zed"), "settings.json"),
            "Gemini CLI": (_join_path(home, ".gemini"), "settings.json"),
            "Warp": (_join_path(home, ".warp"), "mcp_config.json"),
            "Trae": (_join_path(home, ".trae"), "mcp_config.json"),
            "Copilot CLI": (_join_path(home, ".copilot"), "mcp-config.json"),
            "Amazon Q": (_join_path(home, ".aws", "amazonq"), "mcp_config.json"),
            "OpenCode": (
                _join_path(
                    os.environ.get("XDG_CONFIG_HOME") or _join_path(home, ".config"),
                    "opencode",
                ),
                "opencode.json",
            ),
            "Void": (
                _join_path(
                    os.environ.get("XDG_CONFIG_HOME") or _join_path(home, ".config"),
                    "void",
                ),
                "mcp_servers.json",
            ),
            "BoltAI": (_join_path(home, ".boltai"), "mcp.json"),
            "Kiro": (_join_path(home, ".kiro", "settings"), "mcp.json"),
            "VS Code": (
                _join_path(home, "Library", "Application Support", "Code", "User"),
                "settings.json",
            ),
            "VS Code Insiders": (
                _join_path(home, "Library", "Application Support", "Code - Insiders", "User"),
                "settings.json",
            ),
        }
    elif sys.platform == "linux":
        config_home = _get_linux_config_home(home)
        configs = {
            "Claude Code": (home, ".claude.json"),
            "Cursor": (_join_path(home, ".cursor"), "mcp.json"),
            "Windsurf": (_join_path(home, ".codeium", "windsurf"), "mcp_config.json"),
            "Cline": (
                _join_path(
                    config_home,
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                _join_path(
                    config_home,
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                _join_path(
                    config_home,
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "LM Studio": (_join_path(home, ".lmstudio"), "mcp.json"),
            "Codex": (_join_path(home, ".codex"), "config.toml"),
            "Antigravity IDE": (_join_path(home, ".gemini", "antigravity"), "mcp_config.json"),
            "Zed": (_join_path(config_home, "zed"), "settings.json"),
            "Gemini CLI": (_join_path(home, ".gemini"), "settings.json"),
            "Warp": (_join_path(home, ".warp"), "mcp_config.json"),
            "Trae": (_join_path(home, ".trae"), "mcp_config.json"),
            "Copilot CLI": (_join_path(home, ".copilot"), "mcp-config.json"),
            "Amazon Q": (_join_path(home, ".aws", "amazonq"), "mcp_config.json"),
            "OpenCode": (_join_path(config_home, "opencode"), "opencode.json"),
            "Void": (_join_path(config_home, "void"), "mcp_servers.json"),
            "Kiro": (_join_path(home, ".kiro", "settings"), "mcp.json"),
            "VS Code": (_join_path(config_home, "Code", "User"), "settings.json"),
            "VS Code Insiders": (_join_path(config_home, "Code - Insiders", "User"), "settings.json"),
        }
    elif sys.platform == "win32":
        appdata = os.environ.get("APPDATA") or _join_path(home, "AppData", "Roaming", platform="win32")
        configs = {
            "Claude": (_join_path(appdata, "Claude", platform="win32"), "claude_desktop_config.json"),
            "Claude Code": (home, ".claude.json"),
            "Cursor": (_join_path(home, ".cursor", platform="win32"), "mcp.json"),
            "Windsurf": (_join_path(home, ".codeium", "windsurf", platform="win32"), "mcp_config.json"),
            "Cline": (
                _join_path(
                    appdata,
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                    platform="win32",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                _join_path(
                    appdata,
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                    platform="win32",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                _join_path(
                    appdata,
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                    platform="win32",
                ),
                "mcp_settings.json",
            ),
            "LM Studio": (_join_path(home, ".lmstudio", platform="win32"), "mcp.json"),
            "Codex": (_join_path(home, ".codex", platform="win32"), "config.toml"),
            "Antigravity IDE": (_join_path(home, ".gemini", "antigravity", platform="win32"), "mcp_config.json"),
            "Zed": (_join_path(appdata, "Zed", platform="win32"), "settings.json"),
            "Gemini CLI": (_join_path(home, ".gemini", platform="win32"), "settings.json"),
            "Warp": (_join_path(home, ".warp", platform="win32"), "mcp_config.json"),
            "Trae": (_join_path(appdata, "Trae", platform="win32"), "mcp_config.json"),
            "Copilot CLI": (_join_path(home, ".copilot", platform="win32"), "mcp-config.json"),
            "Amazon Q": (_join_path(home, ".aws", "amazonq", platform="win32"), "mcp_config.json"),
            "OpenCode": (_join_path(appdata, "opencode", platform="win32"), "opencode.json"),
            "Void": (_join_path(appdata, "void", platform="win32"), "mcp_servers.json"),
            "Kiro": (_join_path(home, ".kiro", "settings", platform="win32"), "mcp.json"),
            "VS Code": (_join_path(appdata, "Code", "User", platform="win32"), "settings.json"),
            "VS Code Insiders": (_join_path(appdata, "Code - Insiders", "User", platform="win32"), "settings.json"),
        }
    else:
        configs = {}

    return configs


def _normalize_client_key(name: str) -> str:
    """Normalize a client name for forgiving CLI matching."""
    return re.sub(r"[^a-z0-9]+", "", name.casefold())


def get_client_configs(selected_clients: list[str] | None = None) -> dict[str, tuple[str, str]]:
    """Return all known clients or a validated subset selected by the CLI."""
    configs = _get_client_configs()
    if not selected_clients:
        return configs

    normalized_map = {_normalize_client_key(name): name for name in configs}
    resolved: dict[str, tuple[str, str]] = {}
    unknown: list[str] = []

    for raw_name in selected_clients:
        normalized = _normalize_client_key(raw_name)
        if not normalized or normalized == "all":
            return configs

        client_name = normalized_map.get(normalized)
        if client_name is None:
            unknown.append(raw_name)
            continue

        resolved[client_name] = configs[client_name]

    if unknown:
        supported = ", ".join(configs) if configs else "none"
        raise ValueError(f"Unknown client(s): {', '.join(unknown)}. Supported clients: {supported}.")

    return resolved
