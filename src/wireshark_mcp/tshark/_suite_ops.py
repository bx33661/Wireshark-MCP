"""Suite file operations mixin (capinfos, mergecap, editcap, text2pcap)."""

from __future__ import annotations

import json
import os


class SuiteOpsMixin:
    """File info, merge, editcap operations, text2pcap import, filter-and-save."""

    tshark_path: str

    async def get_file_info(self, pcap_file: str) -> str:
        """Capinfos: Get file metadata."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        required = self._require_tool("capinfos")
        if not required["success"]:
            return json.dumps(required)

        capinfos_path = self._get_checked_tool_path("capinfos")
        return await self._run_command([capinfos_path, pcap_file])

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

        mergecap_path = self._get_checked_tool_path("mergecap")
        cmd = [mergecap_path, "-w", output_file] + input_files
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

        editcap_path = self._get_checked_tool_path("editcap")
        cmd = [editcap_path]
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

        editcap_path = self._get_checked_tool_path("editcap")
        cmd = [editcap_path]
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

        editcap_path = self._get_checked_tool_path("editcap")
        cmd = [editcap_path, "-t", str(seconds), input_file, output_file]
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

        editcap_path = self._get_checked_tool_path("editcap")
        cmd = [editcap_path, "-D", str(duplicate_window), input_file, output_file]
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

        text2pcap_path = self._get_checked_tool_path("text2pcap")
        cmd = [text2pcap_path]
        if timestamp_format:
            cmd.extend(["-t", timestamp_format])
        if ascii_mode:
            cmd.append("-a")
        if encapsulation:
            cmd.extend(["-E", encapsulation])
        cmd.extend([input_text_file, output_file])
        return await self._run_command(cmd)

    async def filter_and_save(self, input_file: str, output_file: str, display_filter: str) -> str:
        """Filter packets and save to new file."""
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
