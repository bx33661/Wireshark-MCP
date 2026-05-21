"""Wireshark suite client — composed from focused mixins."""

import asyncio
import contextlib
import json
import logging
import subprocess
from pathlib import Path

from ..toolchain import (
    WIRESHARK_TOOL_ENV_VARS,
    WIRESHARK_TOOL_ORDER,
)
from ._capability import CapabilityMixin
from ._capture import CaptureMixin
from ._extraction import ExtractionMixin
from ._packets import PacketsMixin
from ._stats import StatsMixin
from ._suite_ops import SuiteOpsMixin
from ._validation import ValidationMixin
from .cache import ResultCache

logger = logging.getLogger("wireshark_mcp")


class WiresharkSuiteClient(
    ValidationMixin,
    CapabilityMixin,
    StatsMixin,
    PacketsMixin,
    ExtractionMixin,
    SuiteOpsMixin,
    CaptureMixin,
):
    """Production-grade Wireshark CLI suite wrapper with validation and error handling."""

    VALID_ENDPOINT_TYPES = {"eth", "ip", "ipv6", "tcp", "udp", "sctp", "wlan"}
    VALID_EXPORT_PROTOCOLS = {"http", "smb", "tftp", "imf", "dicom"}
    VALID_STREAM_PROTOCOLS = {"tcp", "udp", "tls", "http", "http2"}

    _ALLOWED_BINARIES = {name for tool in WIRESHARK_TOOL_ORDER for name in (tool, f"{tool}.exe")}
    _TOOL_ENV_VARS = WIRESHARK_TOOL_ENV_VARS

    def __init__(
        self,
        tshark_path: str = "tshark",
        allowed_dirs: list[str] | None = None,
    ) -> None:
        self._tool_paths: dict[str, str | None] = {
            "tshark": self._resolve_tool_path("tshark", tshark_path),
            "capinfos": self._resolve_tool_path("capinfos"),
            "mergecap": self._resolve_tool_path("mergecap"),
            "editcap": self._resolve_tool_path("editcap"),
            "dumpcap": self._resolve_tool_path("dumpcap"),
            "text2pcap": self._resolve_tool_path("text2pcap"),
        }
        self.tshark_path = self._tool_paths["tshark"] or tshark_path
        self.capinfos_path = self._tool_paths["capinfos"]
        self.mergecap_path = self._tool_paths["mergecap"]
        self.editcap_path = self._tool_paths["editcap"]
        self.dumpcap_path = self._tool_paths["dumpcap"]
        self.text2pcap_path = self._tool_paths["text2pcap"]
        self._version: str | None = None
        self._cache = ResultCache()

        self._allowed_dirs: list[Path] | None = None
        if allowed_dirs:
            self._allowed_dirs = [Path(d).resolve() for d in allowed_dirs]
            logger.info("Path sandbox enabled: %s", self._allowed_dirs)

    async def _run_command(
        self,
        cmd: list[str],
        limit_lines: int = 0,
        offset_lines: int = 0,
        timeout: int = 30,
    ) -> str:
        """Run command with error handling, validation, timeout, and caching."""
        pcap_file = None
        if "-r" in cmd:
            r_idx = cmd.index("-r")
            if r_idx + 1 < len(cmd):
                pcap_file = cmd[r_idx + 1]

        if pcap_file:
            cached = self._cache.get(pcap_file, cmd)
            if cached is not None:
                logger.debug("Cache hit for: %s", " ".join(cmd[:4]))
                return cached

        binary = self._get_binary_name(cmd[0]) if cmd else ""
        if binary not in self._ALLOWED_BINARIES:
            logger.error("Blocked execution of disallowed binary: %s", binary)
            return json.dumps(
                {
                    "success": False,
                    "error": {
                        "type": "SecurityError",
                        "message": f"Execution of '{binary}' is not allowed",
                        "details": f"Allowed binaries: {', '.join(sorted(self._ALLOWED_BINARIES))}",
                    },
                }
            )

        logger.debug("Executing: %s", " ".join(cmd))
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
            )

            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                logger.warning("Command timed out after %ds: %s", timeout, " ".join(cmd))
                return json.dumps(
                    {
                        "success": False,
                        "error": {
                            "type": "TimeoutError",
                            "message": f"Command timed out after {timeout} seconds",
                            "details": f"Command: {' '.join(cmd)}",
                        },
                    }
                )

            output = stdout.decode("utf-8", errors="replace")
            error = stderr.decode("utf-8", errors="replace")

            if proc.returncode != 0:
                logger.warning("Command failed (exit %d): %s", proc.returncode, " ".join(cmd))
                return json.dumps(
                    {
                        "success": False,
                        "error": {
                            "type": "ExecutionError",
                            "message": f"Command failed with exit code {proc.returncode}",
                            "details": error or output,
                        },
                    }
                )

            lines = output.splitlines()
            total_lines = len(lines)

            if offset_lines > 0:
                lines = lines[offset_lines:]

            truncated = False
            if limit_lines > 0 and len(lines) > limit_lines:
                lines = lines[:limit_lines]
                truncated = True

            final_output = "\n".join(lines)

            if truncated:
                final_output += (
                    f"\n\n[Showing {limit_lines}/{total_lines} lines. Next: offset={offset_lines + limit_lines}]"
                )

            if error and not truncated:
                final_output += f"\n[Stderr]: {error}"

            if pcap_file and not truncated:
                self._cache.put(pcap_file, cmd, final_output)

            return final_output

        except Exception as e:
            logger.exception("Command execution failed: %s", " ".join(cmd))
            return json.dumps(
                {
                    "success": False,
                    "error": {
                        "type": "ExecutionError",
                        "message": "Command execution failed",
                        "details": str(e),
                    },
                }
            )


TSharkClient = WiresharkSuiteClient
