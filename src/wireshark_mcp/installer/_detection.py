"""Python environment and Wireshark tool path detection."""

from __future__ import annotations

import ntpath
import os
import posixpath
import shutil
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import types

from ..toolchain import WIRESHARK_TOOL_ENV_VARS


def _get_python_executable() -> str:
    """Resolve the actual Python executable path."""
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


def _get_path_module(platform: str | None = None) -> types.ModuleType:
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
