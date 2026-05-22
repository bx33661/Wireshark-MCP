"""Live capture mixin."""

from __future__ import annotations

import json

from ._typing import _ClientProtocol


class CaptureMixin(_ClientProtocol):
    """Network interface listing and live packet capture."""

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
