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

from .toolchain import (
    WIRESHARK_TOOL_ENV_VARS,
    WIRESHARK_TOOL_ORDER,
    WIRESHARK_TOOL_PURPOSES,
    WIRESHARK_TOOL_REQUIREMENTS,
)

# ---------------------------------------------------------------------------
# TUI: arrow-key + space checkbox selector (pure stdlib, no dependencies)
# ---------------------------------------------------------------------------

# ANSI escape sequences
_ANSI_HIDE_CURSOR = "\x1b[?25l"
_ANSI_SHOW_CURSOR = "\x1b[?25h"
_ANSI_CLEAR_LINE = "\x1b[2K\r"
_ANSI_UP = "\x1b[{}A"
_ANSI_CYAN = "\x1b[96m"
_ANSI_GREEN = "\x1b[92m"
_ANSI_DIM = "\x1b[2m"
_ANSI_RESET = "\x1b[0m"


def _read_key_unix() -> str:
    """Read a single keypress on Unix, handling escape sequences."""
    import os
    import select
    import termios
    import tty

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        # Use os.read(fd) directly instead of sys.stdin.buffer.read() to avoid
        # Python's BufferedReader pre-buffering the entire escape sequence
        # (e.g. \x1b[A) into its internal buffer, which empties the underlying
        # fd so that the subsequent select.select() always times out and the
        # arrow key is misread as ESC.
        ch = os.read(fd, 1)
        if ch == b"\x1b":
            # Handle both CSI (\x1b[A/B) and SS3 (\x1bOA/B) sequences.
            # SS3 is sent by macOS Terminal, iTerm2, and other emulators when
            # application cursor-key mode is active.
            if select.select([fd], [], [], 0.1)[0]:
                ch2 = os.read(fd, 1)
                if ch2 in (b"[", b"O") and select.select([fd], [], [], 0.1)[0]:
                    ch3 = os.read(fd, 1)
                    return {b"A": "UP", b"B": "DOWN"}.get(ch3, "ESC")
            return "ESC"
        return {
            b" ": "SPACE",
            b"\r": "ENTER",
            b"\n": "ENTER",
            b"a": "a",
            b"A": "a",
            b"n": "n",
            b"N": "n",
            b"q": "ESC",
            b"Q": "ESC",
            b"\x03": "ESC",  # Ctrl-C
        }.get(ch, "")
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _read_key_windows() -> str:
    """Read a single keypress on Windows."""
    import importlib

    msvcrt = importlib.import_module("msvcrt")
    ch = msvcrt.getch().decode("mbcs", errors="replace")
    if ch in ("\x00", "\xe0"):
        ch2 = msvcrt.getch().decode("mbcs", errors="replace")
        return {"H": "UP", "P": "DOWN"}.get(ch2, "")
    return {
        " ": "SPACE",
        "\r": "ENTER",
        "\n": "ENTER",
        "a": "a",
        "A": "a",
        "n": "n",
        "N": "n",
        "q": "ESC",
        "Q": "ESC",
        "\x03": "ESC",
    }.get(ch, "")


def _supports_ansi() -> bool:
    """Return True if the terminal likely supports ANSI colour codes."""
    if sys.platform == "win32":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            # Enable VIRTUAL_TERMINAL_PROCESSING (0x0004)
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _interactive_select_clients(all_clients: dict[str, tuple[str, str]]) -> list[str] | None:
    """Arrow-key + space TUI checkbox to pick which MCP clients to configure.

    Returns None  — stdin not a TTY (fall back to install-all).
    Returns []    — user aborted (ESC / q) or confirmed with nothing selected.
    Returns [str] — list of client names chosen by the user.
    """
    if not sys.stdin.isatty():
        return None

    read_key = _read_key_windows if sys.platform == "win32" else _read_key_unix
    use_ansi = _supports_ansi()

    names = list(all_clients)
    detected = {name for name, (config_dir, _) in all_clients.items() if os.path.exists(config_dir)}
    selected: set[int] = {i for i, n in enumerate(names) if n in detected}
    cursor = 0
    n = len(names)

    def _c(code: str, text: str) -> str:
        return f"{code}{text}{_ANSI_RESET}" if use_ansi else text

    def _render(first: bool = False) -> int:
        header = [
            "",
            "  Select MCP clients to install wireshark-mcp into:",
            _c(_ANSI_DIM, "  ↑/↓ move   Space toggle   a select-all   n clear   Enter confirm   q quit"),
            "",
        ]
        rows = []
        for i, name in enumerate(names):
            chk = _c(_ANSI_GREEN, "●") if i in selected else _c(_ANSI_DIM, "○")
            tag = _c(_ANSI_DIM, " (detected)") if name in detected else ""
            line = _c(_ANSI_CYAN, f"  ❯ {chk} {name}") + tag if i == cursor else f"    {chk} {name}{tag}"
            rows.append(line)
        footer = [""]
        lines = header + rows + footer
        total = len(lines)

        if not first and use_ansi:
            sys.stdout.write(_ANSI_UP.format(total) + "\r")
        for line in lines:
            if use_ansi:
                sys.stdout.write(_ANSI_CLEAR_LINE + line + "\n")
            else:
                print(line)
        sys.stdout.flush()
        return total

    if use_ansi:
        sys.stdout.write(_ANSI_HIDE_CURSOR)
        sys.stdout.flush()

    try:
        _render(first=True)
        while True:
            key = read_key()
            if key == "UP":
                cursor = (cursor - 1) % n
            elif key == "DOWN":
                cursor = (cursor + 1) % n
            elif key == "SPACE":
                if cursor in selected:
                    selected.discard(cursor)
                else:
                    selected.add(cursor)
            elif key == "a":
                selected = set(range(n))
            elif key == "n":
                selected = set()
            elif key == "ENTER":
                _render()
                break
            elif key == "ESC":
                _render()
                return []
            else:
                continue
            _render()
    finally:
        if use_ansi:
            sys.stdout.write(_ANSI_SHOW_CURSOR)
            sys.stdout.flush()

    return [names[i] for i in sorted(selected)]


SERVER_NAME = "wireshark-mcp"


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


def _generate_opencode_config() -> dict[str, Any]:
    """Generate an OpenCode-format MCP server entry.

    OpenCode expects command as an array and env under "environment".
    """
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


_SPECIAL_JSON_STRUCTURES: dict[str, tuple[str, str]] = {
    "VS Code": ("mcp", "servers"),
    "VS Code Insiders": ("mcp", "servers"),
    "Zed": ("mcp", "servers"),
}

# Clients that use a flat {"mcp": {"server-name": {...}}} structure (no nested "servers" key).
_OPENCODE_STYLE_CLIENTS: frozenset[str] = frozenset({"OpenCode"})


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
    if client_name in _OPENCODE_STYLE_CLIENTS:
        top_level = config.get("mcp")
        if not isinstance(top_level, dict):
            top_level = {}
            config["mcp"] = top_level
        return top_level

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
    if client_name in _OPENCODE_STYLE_CLIENTS:
        return SERVER_NAME in config.get("mcp", {})
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


def _status_marker(status: str) -> str:
    """Return a short ASCII status label for CLI output."""
    return {
        "configured": "[OK]",
        "installed": "[OK]",
        "uninstalled": "[OK]",
        "config file found": "[INFO]",
        "client detected": "[INFO]",
        "already configured": "[SKIP]",
        "not installed": "[SKIP]",
        "not detected": "[MISS]",
    }.get(status, "[INFO]")


def _print_title(title: str) -> None:
    """Print a simple section header."""
    print(title)
    print("=" * len(title))


def _print_rows(rows: list[dict[str, str]]) -> None:
    """Print aligned status rows with optional paths."""
    if not rows:
        return

    width = max(len(row["name"]) for row in rows)
    for row in rows:
        marker = row.get("marker") or _status_marker(row.get("status", ""))
        detail = row.get("detail", "")
        print(f"  {marker:<6} {row['name']:<{width}} {detail}")
        path = row.get("path")
        if path:
            print(f"         {path}")


def _summarize_status_rows(rows: list[dict[str, str]], statuses: tuple[str, ...]) -> dict[str, int]:
    """Summarize row counts for the requested statuses."""
    return {
        status: sum(row["status"] == status for row in rows)
        for status in statuses
        if any(row["status"] == status for row in rows)
    }


def _collect_client_rows(selected_clients: list[str] | None = None) -> list[dict[str, str]]:
    """Collect client detection/configuration status rows."""
    rows: list[dict[str, str]] = []
    for name, (config_dir, config_file) in get_client_configs(selected_clients).items():
        config_path = os.path.join(config_dir, config_file)
        if os.path.exists(config_path):
            status = "configured" if _has_server_entry(config_path, name) else "config file found"
        elif os.path.exists(config_dir):
            status = "client detected"
        else:
            status = "not detected"
        rows.append({"name": name, "status": status, "detail": status, "path": config_path})
    return rows


def _build_client_targets_payload(selected_clients: list[str] | None = None) -> dict[str, Any]:
    """Build a machine-readable payload for client detection status."""
    rows = _collect_client_rows(selected_clients)
    summary_order = ("configured", "config file found", "client detected", "not detected")
    return {
        "clients": rows,
        "summary": _summarize_status_rows(rows, summary_order),
    }


def print_client_targets(*, selected_clients: list[str] | None = None, output_format: str = "text") -> None:
    """Print supported client targets and detection status."""
    payload = _build_client_targets_payload(selected_clients)
    rows = cast("list[dict[str, str]]", payload["clients"])
    if output_format == "json":
        print(json.dumps(payload, indent=2))
        return

    _print_title("Wireshark MCP clients")
    _print_rows(rows)

    summary = [f"{count} {status}" for status, count in cast("dict[str, int]", payload["summary"]).items()]
    if summary:
        print()
        print("Summary: " + ", ".join(summary))


def _build_doctor_payload(selected_clients: list[str] | None = None) -> dict[str, Any]:
    """Build a machine-readable payload for doctor diagnostics."""
    detected_tools = _detect_wireshark_tool_paths()
    tools: dict[str, dict[str, Any]] = {}
    for tool_name in WIRESHARK_TOOL_ORDER:
        env_var = WIRESHARK_TOOL_ENV_VARS[tool_name]
        tool_path = detected_tools.get(env_var)
        tools[tool_name] = {
            "available": bool(tool_path),
            "path": tool_path,
            "requirement": WIRESHARK_TOOL_REQUIREMENTS[tool_name],
            "purpose": WIRESHARK_TOOL_PURPOSES[tool_name],
        }

    warnings: list[str] = []
    capture_backend: str | None = None
    if not detected_tools["WIRESHARK_MCP_TSHARK_PATH"]:
        warnings.append(
            "tshark was not found. Install Wireshark CLI tools or set WIRESHARK_MCP_TSHARK_PATH before starting the MCP server."
        )
    else:
        capture_backend = "dumpcap" if detected_tools.get("WIRESHARK_MCP_DUMPCAP_PATH") else "tshark"

    client_payload = _build_client_targets_payload(selected_clients)
    return {
        "python_executable": _get_python_executable(),
        "wireshark_tools": tools,
        "capture_backend": capture_backend,
        "warnings": warnings,
        "clients": client_payload["clients"],
        "client_summary": client_payload["summary"],
    }


def print_install_doctor(*, selected_clients: list[str] | None = None, output_format: str = "text") -> None:
    """Print install diagnostics for Python, Wireshark tools, and client configs."""
    payload = _build_doctor_payload(selected_clients)
    if output_format == "json":
        print(json.dumps(payload, indent=2))
        return

    _print_title("Wireshark MCP doctor")
    print(f"Python executable : {payload['python_executable']}")
    print()
    print("Wireshark suite tools")
    print("---------------------")

    tools = cast("dict[str, dict[str, Any]]", payload["wireshark_tools"])
    for requirement in ("required", "recommended", "optional"):
        print(f"{requirement.title()}:")
        for tool_name in WIRESHARK_TOOL_ORDER:
            if WIRESHARK_TOOL_REQUIREMENTS[tool_name] != requirement:
                continue
            tool_path = cast("str | None", tools[tool_name]["path"])
            marker = "[OK]" if tool_path else "[MISS]"
            print(f"  {marker:<6} {tool_name:<10} {tool_path or 'not found'}")

    print()
    warnings = cast("list[str]", payload["warnings"])
    if warnings:
        print("[WARN] tshark was not found.")
        print("       Install Wireshark CLI tools or set WIRESHARK_MCP_TSHARK_PATH before starting the MCP server.")
    else:
        capture_backend = cast("str", payload["capture_backend"])
        print(f"Preferred capture backend : {capture_backend}")

    print()
    print("MCP client targets")
    print("------------------")
    client_rows = cast("list[dict[str, str]]", payload["clients"])
    _print_rows(client_rows)

    summary = [f"{count} {status}" for status, count in cast("dict[str, int]", payload["client_summary"]).items()]
    if summary:
        print()
        print("Summary: " + ", ".join(summary))


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


def install_mcp_servers(
    *, uninstall: bool = False, update: bool = False, selected_clients: list[str] | None = None
) -> int:
    """Install, update, or uninstall wireshark-mcp from detected MCP clients.

    update=True  — only touch clients that already have a wireshark-mcp entry;
                   skip clients where it is not yet installed.
    uninstall=True — remove the entry from every matched client.
    Neither flag  — write/overwrite the entry (install or re-install).

    When no clients are explicitly selected and stdin is a TTY, an interactive
    checklist is shown so the user can pick which clients to configure.
    """
    all_configs = get_client_configs()
    if not all_configs:
        print(f"Unsupported platform: {sys.platform}")
        return 0

    if selected_clients:
        configs = get_client_configs(selected_clients)
    else:
        chosen = _interactive_select_clients(all_configs)
        if chosen is None:
            # Non-interactive: fall back to all clients (original behaviour).
            configs = all_configs
        elif not chosen:
            print("No clients selected. Nothing to do.")
            return 0
        else:
            configs = {name: all_configs[name] for name in chosen}

    installed = 0
    skipped = 0
    action_word = "uninstall" if uninstall else ("update" if update else "installation")
    result_rows: list[dict[str, str]] = []

    if uninstall:
        title = "Wireshark MCP uninstall"
    elif update:
        title = "Wireshark MCP update"
    else:
        title = "Wireshark MCP install"
    _print_title(title)

    if not uninstall:
        detected_tools = _detect_wireshark_tool_paths()
        if not detected_tools["WIRESHARK_MCP_TSHARK_PATH"]:
            print("[WARN] tshark was not found. Client configs can still be written,")
            print("       but packet analysis will fail until Wireshark CLI tools are available.")
            print("       Run `wireshark-mcp doctor` after installing Wireshark to verify the tool paths.")
            print()

    for name, (config_dir, config_file) in configs.items():
        config_path = os.path.join(config_dir, config_file)

        if not os.path.exists(config_dir):
            result_rows.append(
                {
                    "marker": "[SKIP]",
                    "name": name,
                    "detail": f"{action_word} skipped (config dir not found)",
                    "path": config_path,
                }
            )
            skipped += 1
            continue

        if config_file.endswith(".toml"):
            # For update mode, skip if the server block is not already present.
            if update and not _has_server_entry(config_path, name):
                result_rows.append({"marker": "[SKIP]", "name": name, "detail": "not installed", "path": config_path})
                skipped += 1
                continue

            changed = _install_codex_config(config_path, uninstall=uninstall)
            if not changed:
                reason = "not installed" if uninstall else ("already up to date" if update else "already configured")
                result_rows.append({"marker": "[SKIP]", "name": name, "detail": reason, "path": config_path})
                skipped += 1
                continue

            done_word = "uninstalled" if uninstall else "updated" if update else "installed"
            result_rows.append(
                {"marker": "[OK]", "name": name, "detail": f"{done_word} (restart required)", "path": config_path}
            )
            installed += 1
            continue

        config = _read_json_config(config_path)
        mcp_servers = _get_mcp_servers_dict(config, name)

        if uninstall:
            if SERVER_NAME not in mcp_servers:
                result_rows.append({"marker": "[SKIP]", "name": name, "detail": "not installed", "path": config_path})
                skipped += 1
                continue
            del mcp_servers[SERVER_NAME]
        elif update:
            if SERVER_NAME not in mcp_servers:
                result_rows.append({"marker": "[SKIP]", "name": name, "detail": "not installed", "path": config_path})
                skipped += 1
                continue
            entry_config = _generate_opencode_config() if name in _OPENCODE_STYLE_CLIENTS else generate_mcp_config()
            mcp_servers[SERVER_NAME] = entry_config
        else:
            entry_config = _generate_opencode_config() if name in _OPENCODE_STYLE_CLIENTS else generate_mcp_config()
            mcp_servers[SERVER_NAME] = entry_config

        _write_json_config(config_path, config)

        done_word = "uninstalled" if uninstall else "updated" if update else "installed"
        result_rows.append(
            {"marker": "[OK]", "name": name, "detail": f"{done_word} (restart required)", "path": config_path}
        )
        installed += 1

    _print_rows(result_rows)

    if not uninstall and not update and installed == 0:
        print()
        print("No MCP clients detected. For unsupported clients, use the following config:\n")
        print_mcp_config()
    else:
        if uninstall:
            action_done = "uninstalled"
        elif update:
            action_done = "updated"
        else:
            action_done = "configured"
        print(f"\nSummary: {installed} client(s) {action_done}, {skipped} skipped.")

    return installed


def run_install(
    *,
    install: bool = False,
    update: bool = False,
    uninstall: bool = False,
    config: bool = False,
    doctor: bool = False,
    list_clients: bool = False,
    selected_clients: list[str] | None = None,
    config_format: str = "json",
    output_format: str = "text",
) -> None:
    """Dispatcher called from the CLI entry point."""
    if sum(bool(flag) for flag in (install, update, uninstall, config, doctor, list_clients)) > 1:
        print("Choose only one action at a time: install, update, uninstall, config, doctor, or clients.")
        sys.exit(1)

    if install:
        install_mcp_servers(uninstall=False, update=False, selected_clients=selected_clients)
        return

    if update:
        install_mcp_servers(uninstall=False, update=True, selected_clients=selected_clients)
        return

    if uninstall:
        install_mcp_servers(uninstall=True, update=False, selected_clients=selected_clients)
        return

    if config:
        print_mcp_config(output_format=config_format)
        return

    if doctor:
        print_install_doctor(selected_clients=selected_clients, output_format=output_format)
        return

    if list_clients:
        print_client_targets(selected_clients=selected_clients, output_format=output_format)
        return
