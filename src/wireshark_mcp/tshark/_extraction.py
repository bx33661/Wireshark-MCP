"""Extraction and search mixin."""

from __future__ import annotations

import json
import os


class ExtractionMixin:
    """Field extraction, object export, packet search, stream follow, SSL decrypt."""

    tshark_path: str

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
        """Search for packets by content."""
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
        """Follow Stream (-z follow) with pagination and search."""
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
