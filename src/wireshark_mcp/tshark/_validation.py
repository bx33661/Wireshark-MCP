"""Validation mixin for file path and protocol checks."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("wireshark_mcp")


class ValidationMixin:
    """Path sandbox, file existence, and protocol whitelist validation."""

    _allowed_dirs: list[Path] | None

    def _validate_file(self, filepath: str) -> dict[str, Any]:
        """Validate file exists, is readable, and within allowed directories."""
        if not filepath:
            return {"success": False, "error": {"type": "InvalidParameter", "message": "File path cannot be empty"}}

        path = Path(filepath).resolve()

        if self._allowed_dirs and not any(self._is_path_within(path, allowed) for allowed in self._allowed_dirs):
            logger.warning("Path sandbox violation: %s", filepath)
            return {
                "success": False,
                "error": {
                    "type": "PermissionDenied",
                    "message": "Access denied: path is outside allowed directories",
                    "details": f"Allowed directories: {[str(d) for d in self._allowed_dirs]}",
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

    def _validate_protocol(self, protocol: str, valid_set: set) -> dict[str, Any]:
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

        path = Path(filepath).resolve()

        if self._allowed_dirs and not any(self._is_path_within(path, allowed) for allowed in self._allowed_dirs):
            logger.warning("Output path sandbox violation: %s", filepath)
            return {
                "success": False,
                "error": {
                    "type": "PermissionDenied",
                    "message": "Access denied: output path is outside allowed directories",
                },
            }

        return {"success": True}
