"""
Auto-configuration installer for Wireshark MCP.

Detects installed MCP clients (Claude, Cursor, VS Code, etc.)
and automatically injects or removes the wireshark-mcp server config.
"""

import json
import ntpath
import os
import posixpath
import re
import shutil
import sys
import tempfile
from typing import Any, cast

SERVER_NAME = "wireshark-mcp"
WIRESHARK_TOOL_ENV_VARS = {
    "tshark": "WIRESHARK_MCP_TSHARK_PATH",
    "capinfos": "WIRESHARK_MCP_CAPINFOS_PATH",
    "mergecap": "WIRESHARK_MCP_MERGECAP_PATH",
    "editcap": "WIRESHARK_MCP_EDITCAP_PATH",
}


# ---------------------------------------------------------------------------
# Python environment smart detection
# ---------------------------------------------------------------------------


def _get_python_executable() -> str:
    """Resolve the actual Python executable path.

    Checks VIRTUAL_ENV first, then inspects sys.path for common layouts,
    and falls back to sys.executable. This ensures that MCP clients
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
    """Collect Python-related environment variables for MCP clients."""
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


def _collect_runtime_env() -> dict[str, str]:
    """Collect runtime env vars needed by GUI MCP clients."""
    env = _collect_python_env()

    for var in ("PATH",):
        value = os.environ.get(var)
        if value:
            env[var] = value

    if sys.platform == "win32":
        for var in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"):
            value = os.environ.get(var)
            if value:
                env[var] = value

    for env_var, tool_path in _detect_wireshark_tool_paths().items():
        if tool_path:
            env[env_var] = tool_path

    return env


def _get_path_module(platform: str | None = None):
    """Return the path module matching the target platform."""
    if (platform or sys.platform) == "win32":
        return ntpath
    return posixpath


def _join_path(*parts: str, platform: str | None = None) -> str:
    """Join paths using separators for the target platform."""
    path_mod = _get_path_module(platform)
    return str(path_mod.normpath(path_mod.join(*parts)))


def _get_linux_config_home(home: str | None = None) -> str:
    """Return the XDG config home on Linux."""
    return os.environ.get("XDG_CONFIG_HOME") or _join_path(home or os.path.expanduser("~"), ".config")


def _iter_wireshark_search_dirs() -> list[str]:
    """Return common install directories for Wireshark CLI tools."""
    home = os.path.expanduser("~")

    if sys.platform == "win32":
        local_appdata = os.environ.get("LOCALAPPDATA") or _join_path(home, "AppData", "Local", platform="win32")
        roots = [
            os.environ.get("PROGRAMFILES"),
            os.environ.get("PROGRAMFILES(X86)"),
            _join_path(local_appdata, "Programs", platform="win32"),
        ]
        return [_join_path(root, "Wireshark", platform="win32") for root in roots if root]

    if sys.platform == "darwin":
        return [
            "/Applications/Wireshark.app/Contents/MacOS",
            "/Applications/Wireshark.app/Contents/Helpers",
            _join_path(home, "Applications", "Wireshark.app", "Contents", "MacOS"),
            _join_path(home, "Applications", "Wireshark.app", "Contents", "Helpers"),
            "/opt/homebrew/bin",
            "/usr/local/bin",
        ]

    return [
        "/usr/bin",
        "/usr/local/bin",
        "/snap/bin",
        "/opt/homebrew/bin",
        "/home/linuxbrew/.linuxbrew/bin",
    ]


def _find_wireshark_tool_path(tool_name: str) -> str | None:
    """Find a Wireshark CLI tool using env overrides, PATH, and common install locations."""
    env_var = WIRESHARK_TOOL_ENV_VARS[tool_name]
    candidates: list[str] = []

    env_value = os.environ.get(env_var)
    if env_value:
        candidates.append(env_value)

    try:
        resolved = shutil.which(tool_name)
    except AttributeError:
        resolved = None
    if resolved:
        candidates.append(resolved)

    executable_name = f"{tool_name}.exe" if sys.platform == "win32" else tool_name
    for directory in _iter_wireshark_search_dirs():
        candidates.append(_join_path(directory, executable_name, platform=sys.platform))

    seen: set[str] = set()
    for candidate in candidates:
        normalized = os.path.normcase(os.path.normpath(candidate))
        if normalized in seen:
            continue
        seen.add(normalized)
        if os.path.isfile(candidate):
            return candidate

    return None


def _detect_wireshark_tool_paths() -> dict[str, str | None]:
    """Resolve absolute paths for Wireshark CLI tools."""
    return {env_var: _find_wireshark_tool_path(tool_name) for tool_name, env_var in WIRESHARK_TOOL_ENV_VARS.items()}


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


def print_mcp_config() -> None:
    """Print the MCP config JSON for manual client setup."""
    config = {"mcpServers": {SERVER_NAME: generate_mcp_config()}}
    print(json.dumps(config, indent=2))


# ---------------------------------------------------------------------------
# Client config registry maps name -> (config_dir, config_filename)
# ---------------------------------------------------------------------------


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
            "VS Code": (_join_path(appdata, "Code", "User", platform="win32"), "settings.json"),
            "VS Code Insiders": (_join_path(appdata, "Code - Insiders", "User", platform="win32"), "settings.json"),
        }
    else:
        configs = {}

    return configs


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
            parsed = json.loads(data)
            return cast("dict[str, Any]", parsed) if isinstance(parsed, dict) else {}
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


def _write_text_config(path: str, text: str, suffix: str) -> None:
    """Atomically write a text config file."""
    config_dir = os.path.dirname(path)
    fd, temp_path = tempfile.mkstemp(dir=config_dir, prefix=".tmp_", suffix=suffix, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.replace(temp_path, path)
    except Exception:
        os.unlink(temp_path)
        raise


def _get_mcp_servers_dict(config: dict[str, Any], client_name: str) -> dict[str, Any]:
    """Navigate into the correct nesting level for the mcpServers dict."""
    if client_name in _SPECIAL_JSON_STRUCTURES:
        top_key, nested_key = _SPECIAL_JSON_STRUCTURES[client_name]
        top_level = config.get(top_key)
        if not isinstance(top_level, dict):
            top_level = {}
            config[top_key] = top_level

        nested = top_level.get(nested_key)
        if not isinstance(nested, dict):
            nested = {}
            top_level[nested_key] = nested

        return nested

    if not isinstance(config.get("mcpServers"), dict):
        config["mcpServers"] = {}
    return cast("dict[str, Any]", config["mcpServers"])


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


def _has_server_entry_in_json_config(config: dict[str, Any], client_name: str) -> bool:
    """Check whether a JSON config already contains this MCP server."""
    if client_name in _SPECIAL_JSON_STRUCTURES:
        top_key, nested_key = _SPECIAL_JSON_STRUCTURES[client_name]
        return SERVER_NAME in config.get(top_key, {}).get(nested_key, {})
    return SERVER_NAME in config.get("mcpServers", {})


def _has_server_entry(config_path: str, client_name: str) -> bool:
    """Check whether a client config contains this MCP server."""
    if not os.path.exists(config_path):
        return False

    if config_path.endswith(".toml"):
        with open(config_path, encoding="utf-8") as f:
            content = f.read()
        return f"[mcp_servers.{SERVER_NAME}]" in content

    return _has_server_entry_in_json_config(_read_json_config(config_path), client_name)


def print_install_doctor() -> None:
    """Print install diagnostics for Python, Wireshark tools, and client configs."""
    print("Wireshark MCP doctor")
    print(f"  Python: {_get_python_executable()}")
    print()
    print("Wireshark CLI tools:")

    detected_tools = _detect_wireshark_tool_paths()
    for env_var, tool_path in detected_tools.items():
        tool_name = env_var.removeprefix("WIRESHARK_MCP_").removesuffix("_PATH").lower()
        status = tool_path or "missing"
        print(f"  {tool_name}: {status}")

    if not detected_tools["WIRESHARK_MCP_TSHARK_PATH"]:
        print()
        print("Warning: tshark was not found.")
        print("  Install Wireshark CLI tools or set WIRESHARK_MCP_TSHARK_PATH before starting the MCP server.")

    print()
    print("MCP client targets:")
    for name, (config_dir, config_file) in _get_client_configs().items():
        config_path = os.path.join(config_dir, config_file)
        if os.path.exists(config_path):
            status = "configured" if _has_server_entry(config_path, name) else "config file found"
        elif os.path.exists(config_dir):
            status = "client detected"
        else:
            status = "not detected"
        print(f"  {name}: {status}")
        print(f"    {config_path}")


def _upsert_named_toml_block(content: str, section_name: str, block: str) -> str:
    """Replace an existing TOML table block or append it if missing."""
    lines = content.splitlines()
    output: list[str] = []
    section_header = f"[{section_name}]"
    section_prefix = f"[{section_name}."
    skip_mode = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if stripped == section_header or stripped.startswith(section_prefix):
                skip_mode = True
                continue
            if skip_mode:
                skip_mode = False
        if not skip_mode:
            output.append(line)

    rendered = "\n".join(output).rstrip()
    if rendered:
        rendered += "\n\n"
    rendered += block.rstrip() + "\n"
    return rendered


def _remove_named_toml_block(content: str, section_name: str) -> tuple[str, bool]:
    """Remove a TOML table block and any nested subtables."""
    pattern = re.compile(rf"(?ms)^\[{re.escape(section_name)}\]\n.*?(?=^\[(?!{re.escape(section_name)}(?:\.|\]))|\Z)")
    updated, count = pattern.subn("", content)
    updated = updated.rstrip()
    if updated:
        updated += "\n"
    return updated, count > 0


def _install_codex_config(config_path: str, *, uninstall: bool) -> bool:
    """Install or uninstall the Codex TOML configuration."""
    content = ""
    if os.path.exists(config_path):
        with open(config_path, encoding="utf-8") as f:
            content = f.read()

    section_name = f"mcp_servers.{SERVER_NAME}"
    if uninstall:
        updated, changed = _remove_named_toml_block(content, section_name)
        if not changed:
            return False
        _write_text_config(config_path, updated, ".toml")
        return True

    updated = _upsert_named_toml_block(content, section_name, _render_codex_toml_block())
    if updated == content:
        return False
    _write_text_config(config_path, updated, ".toml")
    return True


def install_mcp_servers(*, uninstall: bool = False) -> int:
    """Install or uninstall wireshark-mcp from all detected MCP clients."""
    configs = _get_client_configs()
    if not configs:
        print(f"Unsupported platform: {sys.platform}")
        return 0

    installed = 0
    skipped = 0
    action_word = "uninstall" if uninstall else "installation"

    if not uninstall:
        detected_tools = _detect_wireshark_tool_paths()
        if not detected_tools["WIRESHARK_MCP_TSHARK_PATH"]:
            print(
                "Warning: tshark was not found. The MCP server config will be installed, but packet analysis will fail until Wireshark CLI tools are available."
            )
            print("Run `wireshark-mcp --doctor` after installing Wireshark to verify the tool paths.\n")

    for name, (config_dir, config_file) in configs.items():
        config_path = os.path.join(config_dir, config_file)

        if not os.path.exists(config_dir):
            print(f"Skipping {name} {action_word}\n  Config: {config_path} (not found)")
            skipped += 1
            continue

        if config_file.endswith(".toml"):
            changed = _install_codex_config(config_path, uninstall=uninstall)
            if not changed:
                reason = "not installed" if uninstall else "already configured"
                print(f"Skipping {name} {action_word}\n  Config: {config_path} ({reason})")
                skipped += 1
                continue

            done_word = "Uninstalled" if uninstall else "Installed"
            print(f"{done_word} {name} MCP server (restart required)\n  Config: {config_path}")
            installed += 1
            continue

        config = _read_json_config(config_path)
        mcp_servers = _get_mcp_servers_dict(config, name)

        if uninstall:
            if SERVER_NAME not in mcp_servers:
                print(f"Skipping {name} uninstall\n  Config: {config_path} (not installed)")
                skipped += 1
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
    else:
        action_done = "updated" if uninstall else "configured"
        print(f"\nSummary: {installed} client(s) {action_done}, {skipped} skipped.")

    return installed


def run_install(*, install: bool = False, uninstall: bool = False, config: bool = False, doctor: bool = False) -> None:
    """Dispatcher called from the CLI entry point."""
    if sum(bool(flag) for flag in (install, uninstall, config, doctor)) > 1:
        print("Choose only one of: --install, --uninstall, --config, --doctor.")
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

    if doctor:
        print_install_doctor()
        return
