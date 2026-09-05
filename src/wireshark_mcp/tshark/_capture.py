"""Live capture mixin."""

from __future__ import annotations

import json
import re

from ._typing import _ClientProtocol


class CaptureMixin(_ClientProtocol):
    """Network interface listing and live packet capture."""

    MAX_CAPTURE_DURATION = 300
    MAX_CAPTURE_PACKETS = 1_000_000
    MAX_CAPTURE_KIB = 102_400
    MAX_RING_FILES = 10
    _RING_PART = re.compile(r"^(filesize|files):(\d{1,9})$")

    async def list_interfaces(self) -> str:
        """List interfaces (-D)."""
        backend = self._select_capture_backend_path()
        return await self._run_command([backend, "-D"])

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

        backend = self._select_capture_backend_path()
        cmd = [backend, "-i", interface, "-w", output_file]

        if duration < 0 or duration > self.MAX_CAPTURE_DURATION:
            return json.dumps(
                {
                    "success": False,
                    "error": {
                        "type": "InvalidParameter",
                        "message": f"duration must be between 0 and {self.MAX_CAPTURE_DURATION} seconds",
                    },
                }
            )
        if packet_count < 0 or packet_count > self.MAX_CAPTURE_PACKETS:
            return json.dumps(
                {
                    "success": False,
                    "error": {
                        "type": "InvalidParameter",
                        "message": f"packet_count must be between 0 and {self.MAX_CAPTURE_PACKETS}",
                    },
                }
            )

        if capture_filter:
            cmd.extend(["-f", capture_filter])

        ring_parts: dict[str, int] = {}
        if ring_buffer:
            for raw_part in ring_buffer.split(","):
                part = raw_part.strip()
                match = self._RING_PART.fullmatch(part)
                if not match:
                    return json.dumps(
                        {
                            "success": False,
                            "error": {
                                "type": "InvalidParameter",
                                "message": "ring_buffer accepts only 'filesize:KIB,files:COUNT'",
                            },
                        }
                    )
                key, raw_value = match.groups()
                value = int(raw_value)
                maximum = self.MAX_CAPTURE_KIB if key == "filesize" else self.MAX_RING_FILES
                if value < 1 or value > maximum or key in ring_parts:
                    return json.dumps(
                        {
                            "success": False,
                            "error": {
                                "type": "InvalidParameter",
                                "message": f"invalid or duplicate ring_buffer {key}; maximum is {maximum}",
                            },
                        }
                    )
                ring_parts[key] = value

            if set(ring_parts) != {"filesize", "files"}:
                return json.dumps(
                    {
                        "success": False,
                        "error": {
                            "type": "InvalidParameter",
                            "message": "ring_buffer requires both filesize:KIB and files:COUNT",
                        },
                    }
                )
            if ring_parts["filesize"] * ring_parts["files"] > self.MAX_CAPTURE_KIB:
                return json.dumps(
                    {
                        "success": False,
                        "error": {
                            "type": "InvalidParameter",
                            "message": f"ring_buffer total storage must not exceed {self.MAX_CAPTURE_KIB} KiB",
                        },
                    }
                )

        for key in ("filesize", "files"):
            if key in ring_parts:
                cmd.extend(["-b", f"{key}:{ring_parts[key]}"])

        if "filesize" not in ring_parts:
            cmd.extend(["-a", f"filesize:{self.MAX_CAPTURE_KIB}"])

        if duration > 0:
            cmd.extend(["-a", f"duration:{duration}"])
        if packet_count > 0:
            cmd.extend(["-c", str(packet_count)])

        return await self._run_command(cmd, timeout=max(30, duration + 10))
