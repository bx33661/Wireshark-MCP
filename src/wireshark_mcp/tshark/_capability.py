"""Capability discovery and tool resolution mixin."""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess
from typing import Any

from ..toolchain import (
    WIRESHARK_CAPTURE_BACKEND_ORDER,
    WIRESHARK_TOOL_ORDER,
    WIRESHARK_TOOL_PURPOSES,
    WIRESHARK_TOOL_REQUIREMENTS,
)

logger = logging.getLogger("wireshark_mcp")


class CapabilityMixin:
    """Tool path resolution, availability checks, and capability reporting."""

    _tool_paths: dict[str, str | None]
    _TOOL_ENV_VARS: dict[str, str]

    def _resolve_tool_path(self, tool_name: str, preferred: str | None = None) -> str | None:
        """Resolve a suite tool using env overrides, PATH, or the provided value."""
        env_override = os.environ.get(self._TOOL_ENV_VARS[tool_name])
        if env_override:
            return env_override

        if preferred and preferred != tool_name:
            return shutil.which(preferred) or preferred

        return shutil.which(tool_name) or preferred

    @staticmethod
    def _tool_is_available(tool_path: str | None) -> bool:
        """Return True when a binary path or command is resolvable."""
        if not tool_path:
            return False
        return os.path.isfile(tool_path) or shutil.which(tool_path) is not None

    def _select_capture_backend(self) -> str:
        """Pick the best available capture backend without making optional tools mandatory."""
        for tool_name in WIRESHARK_CAPTURE_BACKEND_ORDER:
            tool_path = self._tool_paths.get(tool_name)
            if self._tool_is_available(tool_path):
                return tool_name
        return "tshark"

    def _select_capture_backend_path(self) -> str:
        """Return the resolved executable for the preferred capture backend."""
        return self._get_checked_tool_path(self._select_capture_backend())

    def _capability_snapshot(self) -> dict[str, Any]:
        """Return the current suite capability map without version probing."""
        capabilities: dict[str, Any] = {}
        for tool_name in WIRESHARK_TOOL_ORDER:
            path = self._tool_paths.get(tool_name)
            capabilities[tool_name] = {
                "available": self._tool_is_available(path),
                "path": path,
                "requirement": WIRESHARK_TOOL_REQUIREMENTS[tool_name],
                "purpose": WIRESHARK_TOOL_PURPOSES[tool_name],
            }

        capabilities["_meta"] = {
            "required": [name for name, level in WIRESHARK_TOOL_REQUIREMENTS.items() if level == "required"],
            "recommended": [name for name, level in WIRESHARK_TOOL_REQUIREMENTS.items() if level == "recommended"],
            "optional": [name for name, level in WIRESHARK_TOOL_REQUIREMENTS.items() if level == "optional"],
            "capture_backend": self._select_capture_backend(),
        }
        return capabilities

    def describe_capabilities(self) -> dict[str, Any]:
        """Public capability snapshot for resources and diagnostics."""
        return self._capability_snapshot()

    def _require_tool(self, tool_name: str) -> dict[str, Any]:
        """Return success or a ToolNotFound error payload for an optional suite tool."""
        tool_path = self._tool_paths.get(tool_name)
        if self._tool_is_available(tool_path):
            return {"success": True}
        return {
            "success": False,
            "error": {
                "type": "ToolNotFound",
                "message": f"{tool_name} tool not found",
                "details": {
                    "tool": tool_name,
                    "requirement": WIRESHARK_TOOL_REQUIREMENTS[tool_name],
                    "env_var": self._TOOL_ENV_VARS[tool_name],
                },
            },
        }

    def _get_checked_tool_path(self, tool_name: str) -> str:
        """Return a tool path after availability has already been validated."""
        tool_path = self._tool_paths.get(tool_name)
        if not self._tool_is_available(tool_path):
            raise RuntimeError(f"{tool_name} tool not available")
        assert tool_path is not None
        return tool_path

    async def check_capabilities(self) -> dict[str, Any]:
        """Check availability and version of all Wireshark suite tools."""

        async def get_version(tool_path: str | None) -> dict[str, Any]:
            if not self._tool_is_available(tool_path):
                return {"available": False}
            assert tool_path is not None
            try:
                proc = await asyncio.create_subprocess_exec(
                    tool_path,
                    "-v",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                version_line = stdout.decode("utf-8").split("\n")[0]
                version = version_line.split()[-1] if version_line else "unknown"
                return {"available": True, "version": version}
            except Exception:
                return {"available": True, "version": "unknown"}

        capabilities = self._capability_snapshot()
        for tool_name in WIRESHARK_TOOL_ORDER:
            capabilities[tool_name].update(await get_version(self._tool_paths.get(tool_name)))

        return {"success": True, "data": capabilities}
