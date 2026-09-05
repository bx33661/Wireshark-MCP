"""Validation mixin for file path and protocol checks."""

from __future__ import annotations

import logging
import sys
import tempfile
from pathlib import Path, PureWindowsPath
from typing import Any

logger = logging.getLogger("wireshark_mcp")

_WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}
)


class ValidationMixin:
    """Path sandbox, file existence, and protocol whitelist validation."""

    _allowed_dirs: list[Path] | None

    @staticmethod
    def _is_unsafe_windows_path(filepath: str) -> bool:
        """Reject Windows device namespaces, reserved names, and NTFS ADS paths."""
        if sys.platform != "win32":
            return False

        normalized = filepath.replace("/", "\\")
        if normalized.startswith(("\\\\.\\", "\\\\?\\")):
            return True

        path = PureWindowsPath(filepath)
        parts = path.parts[1:] if path.anchor else path.parts
        for part in parts:
            if ":" in part:
                return True
            base_name = part.rstrip(" .").split(".", 1)[0].rstrip(" ").upper()
            if base_name in _WINDOWS_RESERVED_NAMES:
                return True
        return False

    def _validate_file(self, filepath: str) -> dict[str, Any]:
        """Validate file exists, is readable, and within allowed directories."""
        if not filepath:
            return {"success": False, "error": {"type": "InvalidParameter", "message": "File path cannot be empty"}}

        if self._is_unsafe_windows_path(filepath):
            return {
                "success": False,
                "error": {
                    "type": "InvalidParameter",
                    "message": "Windows device paths, reserved names, and alternate data streams are not allowed",
                },
            }

        try:
            path = Path(filepath).resolve()
        except OSError:
            return {
                "success": False,
                "error": {"type": "InvalidParameter", "message": "File path could not be resolved"},
            }

        if self._allowed_dirs and not any(self._is_path_within(path, allowed) for allowed in self._allowed_dirs):
            logger.warning("Path sandbox violation: %s", filepath)
            return {
                "success": False,
                "error": {
                    "type": "PermissionDenied",
                    "message": "Access denied: path is outside allowed directories",
                },
            }

        if not path.exists():
            return {"success": False, "error": {"type": "FileNotFound", "message": f"File not found: {filepath}"}}

        if not path.is_file():
            return {
                "success": False,
                "error": {"type": "InvalidParameter", "message": f"Path is not a file: {filepath}"},
            }

        return {"success": True}

    @staticmethod
    def _is_path_within(path: Path, parent: Path) -> bool:
        """Check if path is within parent directory (symlink-safe)."""
        try:
            path.resolve().relative_to(parent.resolve())
            return True
        except ValueError:
            return False

    @staticmethod
    def _get_binary_name(command: str) -> str:
        """Extract the executable name from POSIX or Windows-style paths."""
        return command.replace("\\", "/").rsplit("/", 1)[-1].lower()

    def _validate_protocol(self, protocol: str, valid_set: set[str]) -> dict[str, Any]:
        """Validate protocol against whitelist."""
        if protocol.lower() not in valid_set:
            return {
                "success": False,
                "error": {
                    "type": "InvalidParameter",
                    "message": f"Invalid protocol: {protocol}",
                    "details": f"Valid options: {', '.join(sorted(valid_set))}",
                },
            }
        return {"success": True}

    def _validate_output_path(self, filepath: str) -> dict[str, Any]:
        """Validate output file path is within allowed directories."""
        if not filepath:
            return {"success": False, "error": {"type": "InvalidParameter", "message": "Output path cannot be empty"}}

        if self._is_unsafe_windows_path(filepath):
            return {
                "success": False,
                "error": {
                    "type": "InvalidParameter",
                    "message": "Windows device paths, reserved names, and alternate data streams are not allowed",
                },
            }

        if not self._allowed_dirs:
            logger.warning("Blocked file write because WIRESHARK_MCP_ALLOWED_DIRS is not configured")
            return {
                "success": False,
                "error": {
                    "type": "PermissionDenied",
                    "message": (
                        "File writes are disabled. Set WIRESHARK_MCP_ALLOWED_DIRS "
                        "to one or more dedicated writable directories."
                    ),
                },
            }

        try:
            path = Path(filepath).resolve()
        except OSError:
            return {
                "success": False,
                "error": {"type": "InvalidParameter", "message": "Output path could not be resolved"},
            }

        if not any(self._is_path_within(path, allowed) for allowed in self._allowed_dirs):
            logger.warning("Output path sandbox violation: %s", filepath)
            return {
                "success": False,
                "error": {
                    "type": "PermissionDenied",
                    "message": "Access denied: output path is outside allowed directories",
                },
            }

        return {"success": True}

    def _create_temporary_output_dir(self, prefix: str) -> dict[str, Any]:
        """Create a private temporary directory inside an explicitly allowed root."""
        if not self._allowed_dirs:
            return {
                "success": False,
                "error": {
                    "type": "PermissionDenied",
                    "message": (
                        "Temporary file writes are disabled. Set WIRESHARK_MCP_ALLOWED_DIRS "
                        "to one or more dedicated writable directories."
                    ),
                },
            }

        for root in self._allowed_dirs:
            try:
                return {"success": True, "path": tempfile.mkdtemp(prefix=prefix, dir=root)}
            except OSError:
                continue
        return {
            "success": False,
            "error": {
                "type": "PermissionDenied",
                "message": "No configured allowed directory is writable",
            },
        }
