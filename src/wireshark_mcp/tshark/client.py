import asyncio
import contextlib
import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from ..toolchain import (
    WIRESHARK_CAPTURE_BACKEND_ORDER,
    WIRESHARK_TOOL_ENV_VARS,
    WIRESHARK_TOOL_ORDER,
    WIRESHARK_TOOL_PURPOSES,
    WIRESHARK_TOOL_REQUIREMENTS,
)

logger = logging.getLogger("wireshark_mcp")


class WiresharkSuiteClient:
    """Production-grade Wireshark CLI suite wrapper with validation and error handling."""

    # Protocol whitelists
    VALID_ENDPOINT_TYPES = {"eth", "ip", "ipv6", "tcp", "udp", "sctp", "wlan"}
    VALID_EXPORT_PROTOCOLS = {"http", "smb", "tftp", "imf", "dicom"}
    VALID_STREAM_PROTOCOLS = {"tcp", "udp", "tls", "http", "http2"}

    # Commands that are allowed to be executed
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

        # Path sandbox: if set, only files within these directories are accessible
        self._allowed_dirs: list[Path] | None = None
        if allowed_dirs:
            self._allowed_dirs = [Path(d).resolve() for d in allowed_dirs]
            logger.info("Path sandbox enabled: %s", self._allowed_dirs)

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

    # --- Validation Methods ---

    def _validate_file(self, filepath: str) -> dict[str, Any]:
        """Validate file exists, is readable, and within allowed directories."""
        if not filepath:
            return {"success": False, "error": {"type": "InvalidParameter", "message": "File path cannot be empty"}}

        path = Path(filepath).resolve()

        # Sandbox check
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

    # --- Core Methods ---

    async def check_capabilities(self) -> dict[str, Any]:
        """Check availability and version of all Wireshark suite tools."""

        async def get_version(tool_path: str | None) -> dict[str, Any]:
            if not self._tool_is_available(tool_path):
                return {"available": False}
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

    async def list_interfaces(self) -> str:
        """List interfaces (-D)."""
        backend = self.dumpcap_path if self._tool_is_available(self.dumpcap_path) else self.tshark_path
        return await self._run_command([backend, "-D"])

    # --- Capture Management ---

    async def capture_packets(
        self,
        interface: str,
        output_file: str,
        duration: int = 0,
        packet_count: int = 0,
        capture_filter: str = "",
        ring_buffer: str = "",
    ) -> str:
        """Capture packets with validation."""
        output_validation = self._validate_output_path(output_file)
        if not output_validation["success"]:
            return json.dumps(output_validation)

        backend = self.dumpcap_path if self._tool_is_available(self.dumpcap_path) else self.tshark_path
        cmd = [backend, "-i", interface, "-w", output_file]

        if capture_filter:
            cmd.extend(["-f", capture_filter])

        if ring_buffer:
            for part in ring_buffer.split(","):
                cmd.extend(["-b", part.strip()])

        if duration > 0:
            cmd.extend(["-a", f"duration:{duration}"])
        if packet_count > 0:
            cmd.extend(["-c", str(packet_count)])

        return await self._run_command(cmd)

    # --- Statistics ---

    async def get_protocol_stats(self, pcap_file: str) -> str:
        """Protocol Hierarchy (-z io,phs)."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        return await self._run_command([self.tshark_path, "-r", pcap_file, "-q", "-z", "io,phs"])

    async def get_protocol_stats_data(self, pcap_file: str) -> str:
        """Protocol Hierarchy raw output for parsing."""
        return await self.get_protocol_stats(pcap_file)

    async def get_endpoints(self, pcap_file: str, type: str = "ip") -> str:
        """Endpoints (-z endpoints,type)."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        proto_validation = self._validate_protocol(type, self.VALID_ENDPOINT_TYPES)
        if not proto_validation["success"]:
            return json.dumps(proto_validation)

        return await self._run_command([self.tshark_path, "-r", pcap_file, "-q", "-z", f"endpoints,{type}"])

    async def get_conversations(self, pcap_file: str, type: str = "ip") -> str:
        """Conversations (-z conv,type)."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        proto_validation = self._validate_protocol(type, self.VALID_ENDPOINT_TYPES)
        if not proto_validation["success"]:
            return json.dumps(proto_validation)

        return await self._run_command([self.tshark_path, "-r", pcap_file, "-q", "-z", f"conv,{type}"])

    async def get_io_graph(self, pcap_file: str, interval: int = 1) -> str:
        """I/O Graphs (-z io,stat,interval)."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        return await self._run_command(
            [
                self.tshark_path,
                "-r",
                pcap_file,
                "-q",
                "-z",
                f"io,stat,{interval}",
            ]
        )

    async def get_io_graph_data(self, pcap_file: str, interval: int = 1) -> str:
        """Raw I/O Graph data for visualization."""
        return await self.get_io_graph(pcap_file, interval)

    async def get_service_response_time(self, pcap_file: str, protocol: str = "http") -> str:
        """Service Response Time (-z proto,tree)."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        return await self._run_command(
            [
                self.tshark_path,
                "-r",
                pcap_file,
                "-q",
                "-z",
                f"{protocol},tree",
            ]
        )

    async def get_expert_info(self, pcap_file: str) -> str:
        """Expert Information (-z expert)."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        return await self._run_command([self.tshark_path, "-r", pcap_file, "-q", "-z", "expert"])

    # --- JSON Packet Reading ---

    async def read_packets_json(
        self,
        pcap_file: str,
        limit: int = 100,
        display_filter: str = "",
        offset: int = 0,
    ) -> str:
        """
        Read packets in JSON format (-T json).
        Returns structured packet data for AI parsing.
        """
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        cmd = [self.tshark_path, "-r", pcap_file, "-T", "json"]

        if display_filter:
            cmd.extend(["-Y", display_filter])

        if limit > 0:
            cmd.extend(["-c", str(limit + offset)])

        result = await self._run_command(cmd)

        if offset > 0:
            try:
                packets = json.loads(result)
                if isinstance(packets, list):
                    packets = packets[offset:]
                    result = json.dumps(packets)
            except json.JSONDecodeError:
                pass

        return result

    async def get_packet_list(
        self,
        pcap_file: str,
        limit: int = 20,
        offset: int = 0,
        display_filter: str = "",
        custom_columns: list[str] | None = None,
    ) -> str:
        """
        Get summary list of packets (like Wireshark's top pane).
        If custom_columns provided, uses those instead of default [No, Time, Src, Dst, Proto, Len, Info].
        """
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        if custom_columns:
            fields = custom_columns
        else:
            fields = [
                "frame.number",
                "_ws.col.Time",
                "_ws.col.Source",
                "_ws.col.Destination",
                "_ws.col.Protocol",
                "_ws.col.Length",
                "_ws.col.Info",
            ]

        cmd = [self.tshark_path, "-r", pcap_file, "-T", "fields"]
        for f in fields:
            cmd.extend(["-e", f])

        if display_filter:
            cmd.extend(["-Y", display_filter])

        cmd.extend(["-E", "header=y", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f"])

        return await self._run_command(cmd, limit_lines=limit, offset_lines=offset)

    async def get_packet_details(
        self,
        pcap_file: str,
        frame_number: int,
        included_layers: list[str] | None = None,
    ) -> str:
        """
        Get full JSON details for a single packet.
        Optionally filter to specific layers using included_layers (TShark -j).
        """
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        cmd = [
            self.tshark_path,
            "-r",
            pcap_file,
            "-Y",
            f"frame.number == {frame_number}",
            "-T",
            "json",
        ]

        if included_layers:
            filter_str = " ".join(included_layers)
            cmd.extend(["-j", filter_str])

        return await self._run_command(cmd)

    async def get_packet_bytes(self, pcap_file: str, frame_number: int) -> str:
        """Get standard Hex/ASCII dump of a packet (Packet Bytes view)."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        cmd = [
            self.tshark_path,
            "-r",
            pcap_file,
            "-Y",
            f"frame.number == {frame_number}",
            "-x",
        ]

        return await self._run_command(cmd)

    # --- Extraction ---

    async def extract_fields(
        self,
        pcap_file: str,
        fields: list[str],
        display_filter: str = "",
        separator: str = "\t",
        limit: int = 100,
        offset: int = 0,
    ) -> str:
        """Extract fields (-T fields -e ...)."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        cmd = [self.tshark_path, "-r", pcap_file, "-T", "fields"]
        for f in fields:
            cmd.extend(["-e", f])
        if display_filter:
            cmd.extend(["-Y", display_filter])

        cmd.extend(["-E", "header=y", "-E", f"separator={separator}", "-E", "quote=d"])

        return await self._run_command(cmd, limit_lines=limit, offset_lines=offset)

    async def export_objects(self, pcap_file: str, protocol: str, dest_dir: str) -> str:
        """Export Objects (--export-objects protocol,dest_dir)."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        proto_validation = self._validate_protocol(protocol, self.VALID_EXPORT_PROTOCOLS)
        if not proto_validation["success"]:
            return json.dumps(proto_validation)

        output_validation = self._validate_output_path(dest_dir)
        if not output_validation["success"]:
            return json.dumps(output_validation)

        os.makedirs(dest_dir, exist_ok=True)
        cmd = [
            self.tshark_path,
            "-r",
            pcap_file,
            "--export-objects",
            f"{protocol},{dest_dir}",
        ]
        return await self._run_command(cmd)

    async def search_packet_contents(
        self,
        pcap_file: str,
        match_pattern: str,
        search_type: str = "string",
        limit: int = 50,
        scope: str = "bytes",
    ) -> str:
        """
        Search for packets.
        scope="bytes" -> searches raw payload (frame contains)
        scope="details" -> searches decoded text (frame matches)
        """
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        display_filter = ""

        if scope == "bytes":
            if search_type == "hex":
                display_filter = f"frame contains {match_pattern}"
            else:
                safe_pattern = match_pattern.replace('"', '\\"')
                display_filter = f'frame contains "{safe_pattern}"'

        elif scope == "details":
            if search_type == "regex":
                display_filter = f'frame matches "{match_pattern}"'
            else:
                import re

                safe_pattern = re.escape(match_pattern)
                display_filter = f'frame matches "{safe_pattern}"'

        elif scope == "filter":
            display_filter = match_pattern

        else:
            return json.dumps({"success": False, "error": f"Invalid scope: {scope}. Use 'bytes' or 'details'."})

        return await self.get_packet_list(pcap_file, limit=limit, display_filter=display_filter)

    async def follow_stream(
        self,
        pcap_file: str,
        stream_index: int,
        protocol: str = "tcp",
        mode: str = "ascii",
        limit_lines: int = 500,
        offset_lines: int = 0,
        search_content: str = "",
    ) -> str:
        """
        Follow Stream (-z follow).
        Supports pagination (limit_lines, offset_lines) and searching (grep).
        """
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        proto_validation = self._validate_protocol(protocol, self.VALID_STREAM_PROTOCOLS)
        if not proto_validation["success"]:
            return json.dumps(proto_validation)

        output = await self._run_command(
            [
                self.tshark_path,
                "-r",
                pcap_file,
                "-q",
                "-z",
                f"follow,{protocol},{mode},{stream_index}",
            ],
            limit_lines=0,
            offset_lines=0,
        )

        lines = output.splitlines()

        if search_content:
            lines = [line for line in lines if search_content in line]
            if not lines:
                return f"No occurrences of '{search_content}' found in stream {stream_index}."

        total_lines = len(lines)

        if offset_lines > 0:
            lines = lines[offset_lines:]

        truncated = False
        if limit_lines > 0 and len(lines) > limit_lines:
            lines = lines[:limit_lines]
            truncated = True

        final_output = "\n".join(lines)

        if truncated:
            remaining = total_lines - (offset_lines + limit_lines)
            final_output += f"\n\n[Displaying {limit_lines} lines. {remaining} more lines available. Use offset={offset_lines + limit_lines} to see more.]"

        return final_output

    async def decrypt_ssl(self, pcap_file: str, keylog_file: str) -> str:
        """Decrypt SSL/TLS using a Keylog file."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        keylog_validation = self._validate_file(keylog_file)
        if not keylog_validation["success"]:
            return json.dumps(keylog_validation)

        cmd = [
            self.tshark_path,
            "-r",
            pcap_file,
            "-o",
            f"tls.keylog_file:{keylog_file}",
            "-q",
            "-z",
            "expert",
        ]
        return await self._run_command(cmd)

    # --- File Utilities ---

    async def get_file_info(self, pcap_file: str) -> str:
        """Capinfos: Get file metadata."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        required = self._require_tool("capinfos")
        if not required["success"]:
            return json.dumps(required)

        return await self._run_command([self.capinfos_path, pcap_file])

    async def merge_pcap_files(self, output_file: str, input_files: list[str]) -> str:
        """Mergecap: Merge multiple pcaps."""
        required = self._require_tool("mergecap")
        if not required["success"]:
            return json.dumps(required)

        for f in input_files:
            validation = self._validate_file(f)
            if not validation["success"]:
                return json.dumps(validation)

        output_validation = self._validate_output_path(output_file)
        if not output_validation["success"]:
            return json.dumps(output_validation)

        cmd = [self.mergecap_path, "-w", output_file] + input_files
        return await self._run_command(cmd)

    async def editcap_trim(
        self,
        input_file: str,
        output_file: str,
        start_time: str = "",
        stop_time: str = "",
    ) -> str:
        """Editcap: Trim packets by timestamp window."""
        required = self._require_tool("editcap")
        if not required["success"]:
            return json.dumps(required)

        validation = self._validate_file(input_file)
        if not validation["success"]:
            return json.dumps(validation)

        output_validation = self._validate_output_path(output_file)
        if not output_validation["success"]:
            return json.dumps(output_validation)

        cmd = [self.editcap_path]
        if start_time:
            cmd.extend(["-A", start_time])
        if stop_time:
            cmd.extend(["-B", stop_time])
        cmd.extend([input_file, output_file])
        return await self._run_command(cmd)

    async def editcap_split(
        self,
        input_file: str,
        output_prefix: str,
        packets_per_file: int = 0,
        seconds_per_file: int = 0,
    ) -> str:
        """Editcap: Split a capture by packet count or interval."""
        required = self._require_tool("editcap")
        if not required["success"]:
            return json.dumps(required)

        validation = self._validate_file(input_file)
        if not validation["success"]:
            return json.dumps(validation)

        output_validation = self._validate_output_path(output_prefix)
        if not output_validation["success"]:
            return json.dumps(output_validation)

        if packets_per_file <= 0 and seconds_per_file <= 0:
            return json.dumps(
                {
                    "success": False,
                    "error": {
                        "type": "InvalidParameter",
                        "message": "Provide packets_per_file or seconds_per_file for editcap split",
                    },
                }
            )

        cmd = [self.editcap_path]
        if packets_per_file > 0:
            cmd.extend(["-c", str(packets_per_file)])
        if seconds_per_file > 0:
            cmd.extend(["-i", str(seconds_per_file)])
        cmd.extend([input_file, output_prefix])
        return await self._run_command(cmd)

    async def editcap_time_shift(self, input_file: str, output_file: str, seconds: float) -> str:
        """Editcap: Shift packet timestamps by a relative amount."""
        required = self._require_tool("editcap")
        if not required["success"]:
            return json.dumps(required)

        validation = self._validate_file(input_file)
        if not validation["success"]:
            return json.dumps(validation)

        output_validation = self._validate_output_path(output_file)
        if not output_validation["success"]:
            return json.dumps(output_validation)

        cmd = [self.editcap_path, "-t", str(seconds), input_file, output_file]
        return await self._run_command(cmd)

    async def editcap_deduplicate(self, input_file: str, output_file: str, duplicate_window: int = 5) -> str:
        """Editcap: Remove duplicate packets using a configurable packet window."""
        required = self._require_tool("editcap")
        if not required["success"]:
            return json.dumps(required)

        validation = self._validate_file(input_file)
        if not validation["success"]:
            return json.dumps(validation)

        output_validation = self._validate_output_path(output_file)
        if not output_validation["success"]:
            return json.dumps(output_validation)

        cmd = [self.editcap_path, "-D", str(duplicate_window), input_file, output_file]
        return await self._run_command(cmd)

    async def text2pcap_import(
        self,
        input_text_file: str,
        output_file: str,
        encapsulation: str = "ether",
        timestamp_format: str = "",
        ascii_mode: bool = False,
    ) -> str:
        """Text2pcap: Convert an ASCII or hex dump into a capture file."""
        required = self._require_tool("text2pcap")
        if not required["success"]:
            return json.dumps(required)

        validation = self._validate_file(input_text_file)
        if not validation["success"]:
            return json.dumps(validation)

        output_validation = self._validate_output_path(output_file)
        if not output_validation["success"]:
            return json.dumps(output_validation)

        cmd = [self.text2pcap_path]
        if timestamp_format:
            cmd.extend(["-t", timestamp_format])
        if ascii_mode:
            cmd.append("-a")
        if encapsulation:
            cmd.extend(["-E", encapsulation])
        cmd.extend([input_text_file, output_file])
        return await self._run_command(cmd)

    async def filter_and_save(self, input_file: str, output_file: str, display_filter: str) -> str:
        """
        Filter packets and save to new file.
        Uses tshark -r input -Y filter -w output.
        """
        validation = self._validate_file(input_file)
        if not validation["success"]:
            return json.dumps(validation)

        output_validation = self._validate_output_path(output_file)
        if not output_validation["success"]:
            return json.dumps(output_validation)

        cmd = [self.tshark_path, "-r", input_file, "-Y", display_filter, "-w", output_file]
        result = await self._run_command(cmd)

        if os.path.exists(output_file):
            return f"Filtered packets saved to {output_file}\n{result}"
        return result

    # --- Helper ---

    async def _run_command(
        self,
        cmd: list[str],
        limit_lines: int = 0,
        offset_lines: int = 0,
        timeout: int = 30,
    ) -> str:
        """Run command with error handling, validation, and timeout."""
        # Validate the binary being executed
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
                final_output += f"\n\n[Truncated: showing {limit_lines} of {total_lines} lines]"

            if error and not truncated:
                final_output += f"\n[Stderr]: {error}"

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
