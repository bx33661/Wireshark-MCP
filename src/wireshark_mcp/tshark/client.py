"""Wireshark suite client — composed from focused mixins."""

import asyncio
import contextlib
import json
import logging

# Subprocess execution is restricted to allowlisted Wireshark binaries and never uses a shell.
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Any

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
from ._typing import FieldRowConsumer, FieldStreamResult
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
    MAX_STDOUT_BYTES = 16 * 1024 * 1024
    MAX_STREAM_STDOUT_BYTES = 50 * 1024 * 1024
    MAX_STDERR_BYTES = 1024 * 1024

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
            resolved_dirs = [Path(d).resolve() for d in allowed_dirs]
            invalid_dirs = [str(path) for path in resolved_dirs if not path.is_dir()]
            if invalid_dirs:
                raise ValueError("Allowed directories must already exist and be directories")
            self._allowed_dirs = resolved_dirs
            logger.info("Path sandbox enabled: %s", self._allowed_dirs)

    @staticmethod
    def _ok(data: str, stderr: str = "", truncated: bool = False) -> str:
        """Wrap successful command output in the canonical success envelope.

        Every client method returns this shape (or an error envelope), so the
        raw text lives in ``data`` and is never re-parsed by consumers — output
        that happens to look like JSON can no longer be mistaken for an error.
        Diagnostic stderr is kept in a separate field so it never corrupts
        structured (``-T json`` / ``-T fields``) output in ``data``.
        """
        envelope: dict[str, Any] = {"success": True, "data": data}
        if stderr:
            envelope["stderr"] = stderr
        if truncated:
            envelope["truncated"] = True
        return json.dumps(envelope)

    @staticmethod
    def _unwrap(result: str) -> tuple[bool, str]:
        """Extract (success, text) from a client envelope for internal reuse.

        On a success envelope, returns the ``data`` text. On an error envelope,
        returns ``(False, <original envelope>)`` so callers can propagate it
        unchanged. Non-envelope strings are treated as raw success text.
        """
        try:
            parsed = json.loads(result)
        except (json.JSONDecodeError, ValueError):
            return True, result
        if isinstance(parsed, dict) and "success" in parsed:
            if parsed.get("success") is True:
                data = parsed.get("data", "")
                return True, data if isinstance(data, str) else json.dumps(data)
            return False, result
        return True, result

    @staticmethod
    def _output_paths(cmd: list[str]) -> list[str]:
        """Return files a command writes to via `-w`, so their cache can be dropped."""
        paths: list[str] = []
        for i, arg in enumerate(cmd):
            if arg == "-w" and i + 1 < len(cmd):
                paths.append(cmd[i + 1])
        return paths

    @staticmethod
    def _redact_command(cmd: list[str]) -> str:
        """Render a command without exposing passphrases or key-log paths."""
        redacted: list[str] = []
        for arg in cmd:
            if arg.startswith("uat:80211_keys:"):
                redacted.append("uat:80211_keys:<redacted>")
            elif arg.startswith("tls.keylog_file:"):
                redacted.append("tls.keylog_file:<redacted>")
            else:
                redacted.append(arg)
        return " ".join(redacted)

    @staticmethod
    def _redact_diagnostics(text: str, cmd: list[str]) -> str:
        """Remove sensitive command arguments from subprocess diagnostics."""
        for arg in cmd:
            if arg.startswith(("uat:80211_keys:", "tls.keylog_file:")):
                text = text.replace(arg, "<redacted>")
        return text

    @staticmethod
    def _paginate(output: str, limit_lines: int, offset_lines: int) -> tuple[str, bool]:
        """Slice full command output to an offset/limit window.

        Returns the windowed text and whether it was truncated. A truncation
        footer is appended so callers can page forward. Applied *after* caching
        so the cache always holds the complete output.
        """
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
        return final_output, truncated

    @staticmethod
    async def _read_stream_bounded(
        stream: asyncio.StreamReader,
        maximum: int,
        proc: asyncio.subprocess.Process,
    ) -> tuple[bytes, bool]:
        """Drain one pipe while enforcing a byte ceiling and killing on overflow."""
        chunks = bytearray()
        while True:
            chunk = await stream.read(min(64 * 1024, maximum + 1 - len(chunks)))
            if not chunk:
                return bytes(chunks), False
            chunks.extend(chunk)
            if len(chunks) > maximum:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                return bytes(chunks[:maximum]), True

    async def _read_process_output(
        self,
        proc: asyncio.subprocess.Process,
        *,
        limit_lines: int = 0,
        offset_lines: int = 0,
        stream_limit: bool = False,
        timeout: int = 30,
    ) -> tuple[str, str, bool, str | None, bool]:
        """Read process stdout and stderr with optional streaming truncation.

        Returns (final_output, error, truncated, raw_to_cache, byte_limit_exceeded).
        """
        can_stream = stream_limit and limit_lines > 0 and proc.stdout is not None and hasattr(proc.stdout, "readline")

        if can_stream:
            lines: list[str] = []
            target_lines = offset_lines + limit_lines
            truncated = False
            stdout_exceeded = False
            read_lines = 0
            total_stdout_bytes = 0

            stderr_task = (
                asyncio.create_task(self._read_stream_bounded(proc.stderr, self.MAX_STDERR_BYTES, proc))
                if proc.stderr is not None
                else None
            )

            stdout_stream = proc.stdout
            if stdout_stream is None:  # defensive: guarded by can_stream above
                raise RuntimeError("subprocess stdout pipe is unavailable")
            try:
                while True:
                    line_bytes = await stdout_stream.readline()
                    if not line_bytes:
                        break
                    total_stdout_bytes += len(line_bytes)
                    if total_stdout_bytes > self.MAX_STDOUT_BYTES:
                        truncated = True
                        stdout_exceeded = True
                        with contextlib.suppress(ProcessLookupError):
                            proc.kill()
                        break
                    read_lines += 1
                    if read_lines > target_lines:
                        truncated = True
                        with contextlib.suppress(ProcessLookupError):
                            proc.kill()
                        break
                    lines.append(line_bytes.decode("utf-8", errors="replace").rstrip("\r\n"))
            except (asyncio.CancelledError, Exception):
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                await proc.wait()
                if stderr_task is not None:
                    stderr_task.cancel()
                raise

            await proc.wait()
            stderr_bytes = b""
            stderr_exceeded = False
            if stderr_task is not None:
                stderr_bytes, stderr_exceeded = await stderr_task

            error = stderr_bytes.decode("utf-8", errors="replace")
            windowed = lines[offset_lines:] if offset_lines > 0 else lines
            final_output = "\n".join(windowed)
            if truncated:
                final_output += (
                    f"\n\n[Showing {limit_lines}/{read_lines} lines. Next: offset={offset_lines + limit_lines}]"
                )
            raw_to_cache = "\n".join(lines) if not truncated and not stdout_exceeded else None
            return final_output, error, truncated, raw_to_cache, (stdout_exceeded or stderr_exceeded)

        stdout_pipe = getattr(proc, "stdout", None)
        stderr_pipe = getattr(proc, "stderr", None)
        if stdout_pipe is None or stderr_pipe is None:
            try:
                stdout, stderr = await proc.communicate()
            except (asyncio.CancelledError, Exception):
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                with contextlib.suppress(Exception):
                    await proc.wait()
                raise
            exceeded = len(stdout) > self.MAX_STDOUT_BYTES or len(stderr) > self.MAX_STDERR_BYTES
            stdout = stdout[: self.MAX_STDOUT_BYTES]
            stderr = stderr[: self.MAX_STDERR_BYTES]
        else:
            stdout_task = asyncio.create_task(self._read_stream_bounded(stdout_pipe, self.MAX_STDOUT_BYTES, proc))
            stderr_task = asyncio.create_task(self._read_stream_bounded(stderr_pipe, self.MAX_STDERR_BYTES, proc))
            try:
                (stdout, stdout_exceeded), (stderr, stderr_exceeded) = await asyncio.gather(stdout_task, stderr_task)
                await proc.wait()
            except (asyncio.CancelledError, Exception):
                stdout_task.cancel()
                stderr_task.cancel()
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                with contextlib.suppress(Exception):
                    await proc.wait()
                raise
            exceeded = stdout_exceeded or stderr_exceeded
        output = stdout.decode("utf-8", errors="replace")
        error = stderr.decode("utf-8", errors="replace")
        final_output, truncated = self._paginate(output, limit_lines, offset_lines)
        return final_output, error, truncated, output if not exceeded else None, exceeded

    async def _stream_field_rows(
        self,
        cmd: list[str],
        consumer: FieldRowConsumer,
        *,
        max_rows: int,
        timeout: int = 30,
    ) -> FieldStreamResult:
        """Run one fields command and fold decoded rows through a consumer.

        This seam owns subprocess lifetime, byte/row limits, stderr draining,
        timeout, and cancellation. Callers only keep their aggregate state.
        Streamed results intentionally bypass the raw-output cache.
        """
        binary = self._get_binary_name(cmd[0]) if cmd else ""
        if binary not in self._ALLOWED_BINARIES:
            return {
                "success": False,
                "error": {
                    "type": "SecurityError",
                    "message": f"Execution of '{binary}' is not allowed",
                },
            }
        if max_rows < 1:
            return {
                "success": False,
                "error": {"type": "InvalidParameter", "message": "max_rows must be positive"},
            }

        process_kwargs: dict[str, Any] = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "stdin": subprocess.DEVNULL,
        }
        if sys.platform == "win32":
            create_no_window = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            if create_no_window:
                process_kwargs["creationflags"] = create_no_window

        try:
            proc = await asyncio.create_subprocess_exec(*cmd, **process_kwargs)
        except Exception as exc:
            logger.exception("Stream command execution failed: %s", self._redact_command(cmd))
            return {
                "success": False,
                "error": {
                    "type": "ExecutionError",
                    "message": "Command execution failed",
                    "details": str(exc),
                },
            }
        stderr_task = (
            asyncio.create_task(self._read_stream_bounded(proc.stderr, self.MAX_STDERR_BYTES, proc))
            if proc.stderr is not None
            else None
        )

        async def stop_stderr_reader() -> None:
            if stderr_task is None:
                return
            if not stderr_task.done():
                stderr_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await stderr_task

        async def consume() -> FieldStreamResult:
            rows = 0
            bytes_read = 0
            header_seen = False
            stdout = proc.stdout
            if stdout is None:
                raise RuntimeError("subprocess stdout pipe is unavailable")
            while True:
                line_bytes = await stdout.readline()
                if not line_bytes:
                    break
                bytes_read += len(line_bytes)
                if bytes_read > self.MAX_STREAM_STDOUT_BYTES:
                    with contextlib.suppress(ProcessLookupError):
                        proc.kill()
                    return {
                        "success": False,
                        "rows": rows,
                        "bytes_read": bytes_read,
                        "error": {
                            "type": "LimitExceeded",
                            "message": f"Streamed stdout exceeded {self.MAX_STREAM_STDOUT_BYTES} bytes",
                        },
                    }
                line = line_bytes.decode("utf-8", errors="replace").rstrip("\r\n")
                if not header_seen:
                    header_seen = True
                    continue
                if not line:
                    continue
                if rows >= max_rows:
                    with contextlib.suppress(ProcessLookupError):
                        proc.kill()
                    return {
                        "success": False,
                        "rows": rows,
                        "bytes_read": bytes_read,
                        "error": {
                            "type": "LimitExceeded",
                            "message": f"Matching packet rows exceed the {max_rows} row limit",
                        },
                    }
                consumer([cell.strip().strip('"') for cell in line.split("\t")])
                rows += 1

            await proc.wait()
            stderr = ""
            stderr_exceeded = False
            if stderr_task is not None:
                stderr_bytes, stderr_exceeded = await stderr_task
                stderr = stderr_bytes.decode("utf-8", errors="replace")
            if stderr_exceeded:
                return {
                    "success": False,
                    "rows": rows,
                    "bytes_read": bytes_read,
                    "error": {"type": "LimitExceeded", "message": "tshark stderr exceeded its safety limit"},
                }
            if proc.returncode != 0:
                return {
                    "success": False,
                    "rows": rows,
                    "bytes_read": bytes_read,
                    "error": {
                        "type": "ExecutionError",
                        "message": f"Command failed with exit code {proc.returncode}",
                        "details": self._redact_diagnostics(stderr, cmd),
                    },
                }
            result: FieldStreamResult = {"success": True, "rows": rows, "bytes_read": bytes_read}
            if stderr:
                result["stderr"] = self._redact_diagnostics(stderr, cmd)
            return result

        try:
            result = await asyncio.wait_for(consume(), timeout=timeout)
            if not result["success"]:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                with contextlib.suppress(Exception):
                    await proc.wait()
                await stop_stderr_reader()
            return result
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            with contextlib.suppress(Exception):
                await proc.wait()
            await stop_stderr_reader()
            return {
                "success": False,
                "error": {"type": "TimeoutError", "message": f"Command timed out after {timeout} seconds"},
            }
        except asyncio.CancelledError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            with contextlib.suppress(Exception):
                await proc.wait()
            await stop_stderr_reader()
            raise
        except Exception as exc:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            with contextlib.suppress(Exception):
                await proc.wait()
            await stop_stderr_reader()
            logger.exception("Stream command failed while consuming rows: %s", self._redact_command(cmd))
            return {
                "success": False,
                "error": {
                    "type": "ExecutionError",
                    "message": "Command output could not be consumed",
                    "details": str(exc),
                },
            }

    async def _run_command(
        self,
        cmd: list[str],
        limit_lines: int = 0,
        offset_lines: int = 0,
        timeout: int = 30,
        stream_limit: bool = False,
    ) -> str:
        """Run command with error handling, validation, timeout, and caching."""
        pcap_file = None
        if "-r" in cmd:
            r_idx = cmd.index("-r")
            if r_idx + 1 < len(cmd):
                pcap_file = cmd[r_idx + 1]

        # The cache stores the full, unpaginated stdout keyed by the command only.
        # Pagination is applied *after* retrieval so different offset/limit values
        # over the same command never pollute one another.
        if pcap_file:
            cached = self._cache.get(pcap_file, cmd)
            if cached is not None:
                logger.debug("Cache hit for: %s", self._redact_command(cmd[:4]))
                text, truncated = self._paginate(cached, limit_lines, offset_lines)
                return self._ok(text, truncated=truncated)

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

        safe_command = self._redact_command(cmd)
        logger.debug("Executing: %s", safe_command)
        try:
            process_kwargs: dict[str, Any] = {
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "stdin": subprocess.DEVNULL,
            }
            if sys.platform == "win32":
                create_no_window = getattr(subprocess, "CREATE_NO_WINDOW", 0)
                if create_no_window:
                    process_kwargs["creationflags"] = create_no_window
            proc = await asyncio.create_subprocess_exec(*cmd, **process_kwargs)

            try:
                final_output, error, truncated, raw_to_cache, byte_limit_exceeded = await asyncio.wait_for(
                    self._read_process_output(
                        proc,
                        limit_lines=limit_lines,
                        offset_lines=offset_lines,
                        stream_limit=stream_limit,
                        timeout=timeout,
                    ),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                with contextlib.suppress(Exception):
                    await proc.wait()
                logger.warning("Command timed out after %ds: %s", timeout, safe_command)
                return json.dumps(
                    {
                        "success": False,
                        "error": {
                            "type": "TimeoutError",
                            "message": f"Command timed out after {timeout} seconds",
                            "details": "The Wireshark subprocess was terminated.",
                        },
                    }
                )
            except (asyncio.CancelledError, Exception):
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                with contextlib.suppress(Exception):
                    await proc.wait()
                raise

            if byte_limit_exceeded:
                logger.warning("Command exceeded output limit and was terminated: %s", safe_command)
                return json.dumps(
                    {
                        "success": False,
                        "error": {
                            "type": "LimitExceeded",
                            "message": "Wireshark subprocess output exceeded the safety limit",
                            "details": (
                                f"stdout is limited to {self.MAX_STDOUT_BYTES} bytes and "
                                f"stderr to {self.MAX_STDERR_BYTES} bytes"
                            ),
                        },
                    }
                )

            if proc.returncode != 0 and not truncated:
                logger.warning("Command failed (exit %d): %s", proc.returncode, safe_command)
                return json.dumps(
                    {
                        "success": False,
                        "error": {
                            "type": "ExecutionError",
                            "message": f"Command failed with exit code {proc.returncode}",
                            "details": self._redact_diagnostics(error or final_output, cmd),
                        },
                    }
                )

            for out_path in self._output_paths(cmd):
                self._cache.invalidate_file(out_path)

            if pcap_file and raw_to_cache is not None:
                self._cache.put(pcap_file, cmd, raw_to_cache)

            stderr_note = error if (error and not truncated) else ""
            return self._ok(final_output, stderr_note, truncated=truncated)

        except Exception as e:
            logger.exception("Command execution failed: %s", self._redact_command(cmd))
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
