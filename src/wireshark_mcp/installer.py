"""
Auto-configuration installer for Wireshark MCP.

Detects installed MCP clients (Claude, Cursor, VS Code, etc.)
and automatically injects or removes the wireshark-mcp server config.
"""

import json
import os
import shutil
import sys
import tempfile
from typing import Any

SERVER_NAME = "wireshark-mcp"


# ---------------------------------------------------------------------------
# Python environment smart detection
# ---------------------------------------------------------------------------


def _get_python_executable() -> str:
    """Resolve the actual Python executable path.

    Checks VIRTUAL_ENV first, then inspects sys.path for common layouts,
    and falls back to sys.executable.  This ensures that MCP clients
    (which may not inherit PATH or venv activation) can still locate
    the correct interpreter.
    """
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        if sys.platform == "win32":
            python = os.path.join(venv, "Scripts", "python.exe")
        else:
            python = os.path.join(venv, "bin", "python3")
        if os.path.exists(python):
            return python

    # Heuristic: look through sys.path for a zip file (common in
    # Windows embedded Python) and derive the interpreter from there.
    for path in sys.path:
        split = path.replace("/", os.sep).split(os.sep)
        if split and split[-1].endswith(".zip"):
            parent = os.path.dirname(path)
            if sys.platform == "win32":
                candidate = os.path.join(parent, "python.exe")
            else:
                candidate = os.path.abspath(os.path.join(parent, "..", "bin", "python3"))
            if os.path.exists(candidate):
                return candidate

    return sys.executable


def _collect_python_env() -> dict[str, str]:
    """Collect Python-related environment variables that MCP clients
    need to forward so dependency resolution works correctly.

    Reference: https://docs.python.org/3/using/cmdline.html#environment-variables
    """
    env: dict[str, str] = {}
    for var in (
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSAFEPATH",
        "PYTHONPLATLIBDIR",
        "PYTHONPYCACHEPREFIX",
        "PYTHONNOUSERSITE",
        "PYTHONUSERBASE",
        "VIRTUAL_ENV",
    ):
        value = os.environ.get(var)
        if value:
            env[var] = value
    return env


def generate_mcp_config() -> dict[str, Any]:
    """Generate the MCP server configuration snippet.

    Uses the full Python path + module invocation to guarantee the
    correct interpreter is called, even outside the venv.  Forwards
    any custom Python environment variables as well.
    """
    # Prefer the wireshark-mcp console script if reachable
    script = shutil.which("wireshark-mcp")
    if script:
        config: dict[str, Any] = {"command": script, "args": []}
    else:
        # Fallback: invoke via python -m
        python = _get_python_executable()
        config = {
            "command": python,
            "args": ["-m", "wireshark_mcp.server"],
        }

    env = _collect_python_env()
    if env:
        config["env"] = env

    return config


def print_mcp_config() -> None:
    """Print the MCP config JSON for manual client setup."""
    config = {
        "mcpServers": {
            SERVER_NAME: generate_mcp_config(),
        }
    }
    print(json.dumps(config, indent=2))


# ---------------------------------------------------------------------------
# Client config registry — maps name -> (config_dir, config_filename)
# ---------------------------------------------------------------------------


def _get_client_configs() -> dict[str, tuple[str, str]]:
    """Return a dict of known MCP client config locations for the current OS."""
    home = os.path.expanduser("~")

    if sys.platform == "darwin":
        configs: dict[str, tuple[str, str]] = {
            "Claude": (
                os.path.join(home, "Library", "Application Support", "Claude"),
                "claude_desktop_config.json",
            ),
            "Cursor": (
                os.path.join(home, ".cursor"),
                "mcp.json",
            ),
            "Windsurf": (
                os.path.join(home, ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Claude Code": (home, ".claude.json"),
            "Cline": (
                os.path.join(
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
                os.path.join(
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
                os.path.join(
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
            "LM Studio": (
                os.path.join(home, ".lmstudio"),
                "mcp.json",
            ),
            "Codex": (
                os.path.join(home, ".codex"),
                "config.toml",
            ),
            "Antigravity IDE": (
                os.path.join(home, ".gemini", "antigravity"),
                "mcp_config.json",
            ),
            "Zed": (
                os.path.join(home, "Library", "Application Support", "Zed"),
                "settings.json",
            ),
            "Gemini CLI": (
                os.path.join(home, ".gemini"),
                "settings.json",
            ),
            "Warp": (
                os.path.join(home, ".warp"),
                "mcp_config.json",
            ),
            "Trae": (
                os.path.join(home, ".trae"),
                "mcp_config.json",
            ),
            "Copilot CLI": (
                os.path.join(home, ".copilot"),
                "mcp-config.json",
            ),
            "Amazon Q": (
                os.path.join(home, ".aws", "amazonq"),
                "mcp_config.json",
            ),
            "VS Code": (
                os.path.join(
                    home,
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "VS Code Insiders": (
                os.path.join(
                    home,
                    "Library",
                    "Application Support",
                    "Code - Insiders",
                    "User",
                ),
                "settings.json",
            ),
        }
    elif sys.platform == "linux":
        configs = {
            "Claude Code": (home, ".claude.json"),
            "Cursor": (
                os.path.join(home, ".cursor"),
                "mcp.json",
            ),
            "Windsurf": (
                os.path.join(home, ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Cline": (
                os.path.join(
                    home,
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    home,
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(
                    home,
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "LM Studio": (
                os.path.join(home, ".lmstudio"),
                "mcp.json",
            ),
            "Codex": (
                os.path.join(home, ".codex"),
                "config.toml",
            ),
            "Antigravity IDE": (
                os.path.join(home, ".gemini", "antigravity"),
                "mcp_config.json",
            ),
            "Zed": (
                os.path.join(home, ".config", "zed"),
                "settings.json",
            ),
            "Gemini CLI": (
                os.path.join(home, ".gemini"),
                "settings.json",
            ),
            "Warp": (
                os.path.join(home, ".warp"),
                "mcp_config.json",
            ),
            "Trae": (
                os.path.join(home, ".trae"),
                "mcp_config.json",
            ),
            "Copilot CLI": (
                os.path.join(home, ".copilot"),
                "mcp-config.json",
            ),
            "Amazon Q": (
                os.path.join(home, ".aws", "amazonq"),
                "mcp_config.json",
            ),
            "VS Code": (
                os.path.join(home, ".config", "Code", "User"),
                "settings.json",
            ),
            "VS Code Insiders": (
                os.path.join(home, ".config", "Code - Insiders", "User"),
                "settings.json",
            ),
        }
    else:
        configs = {}

    return configs


# Clients that use special JSON nesting instead of top-level "mcpServers"
_SPECIAL_JSON_STRUCTURES: dict[str, tuple[str, str]] = {
    "VS Code": ("mcp", "servers"),
    "VS Code Insiders": ("mcp", "servers"),
    "Zed": ("mcp", "servers"),
}


def _read_json_config(path: str) -> dict[str, Any]:
    """Read a JSON config file, returning {} for missing/empty/invalid files."""
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        data = f.read().strip()
        if not data:
            return {}
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            return {}


def _write_json_config(path: str, config: dict[str, Any]) -> None:
    """Atomically write a JSON config file."""
    config_dir = os.path.dirname(path)
    fd, temp_path = tempfile.mkstemp(dir=config_dir, prefix=".tmp_", suffix=".json", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
            f.write("\n")
        os.replace(temp_path, path)
    except Exception:
        os.unlink(temp_path)
        raise


def _get_mcp_servers_dict(config: dict[str, Any], client_name: str) -> dict[str, Any]:
    """Navigate into the correct nesting level for the mcpServers dict."""
    if client_name in _SPECIAL_JSON_STRUCTURES:
        top_key, nested_key = _SPECIAL_JSON_STRUCTURES[client_name]
        if top_key not in config:
            config[top_key] = {}
        if nested_key not in config[top_key]:
            config[top_key][nested_key] = {}
        return config[top_key][nested_key]
    else:
        if "mcpServers" not in config:
            config["mcpServers"] = {}
        return config["mcpServers"]


def install_mcp_servers(*, uninstall: bool = False) -> int:
    """Install or uninstall wireshark-mcp from all detected MCP clients.

    Returns the number of clients that were modified.
    """
    configs = _get_client_configs()
    if not configs:
        print(f"Unsupported platform: {sys.platform}")
        return 0

    installed = 0
    action_word = "uninstall" if uninstall else "installation"

    for name, (config_dir, config_file) in configs.items():
        config_path = os.path.join(config_dir, config_file)

        # Skip TOML configs (e.g. Codex) — not supported yet
        if config_file.endswith(".toml"):
            continue

        # Skip clients whose config dir doesn't exist
        if not os.path.exists(config_dir):
            print(f"Skipping {name} {action_word}\n  Config: {config_path} (not found)")
            continue

        config = _read_json_config(config_path)
        mcp_servers = _get_mcp_servers_dict(config, name)

        if uninstall:
            if SERVER_NAME not in mcp_servers:
                print(f"Skipping {name} uninstall\n  Config: {config_path} (not installed)")
                continue
            del mcp_servers[SERVER_NAME]
        else:
            mcp_servers[SERVER_NAME] = generate_mcp_config()

        _write_json_config(config_path, config)

        done_word = "Uninstalled" if uninstall else "Installed"
        print(f"{done_word} {name} MCP server (restart required)\n  Config: {config_path}")
        installed += 1

    if not uninstall and installed == 0:
        print("No MCP clients detected. For unsupported clients, use the following config:\n")
        print_mcp_config()

    return installed


def run_install(*, install: bool = False, uninstall: bool = False, config: bool = False) -> None:
    """Dispatcher called from the CLI entry point."""
    if install and uninstall:
        print("Cannot install and uninstall at the same time.")
        sys.exit(1)

    if install:
        install_mcp_servers(uninstall=False)
        return

    if uninstall:
        install_mcp_servers(uninstall=True)
        return

    if config:
        print_mcp_config()
        return
