"""Packet reading and inspection mixin."""

from __future__ import annotations

import json


class PacketsMixin:
    """JSON packet reading, packet list, details, and hex dump."""

    tshark_path: str

    async def read_packets_json(
        self,
        pcap_file: str,
        limit: int = 100,
        display_filter: str = "",
        offset: int = 0,
    ) -> str:
        """Read packets in JSON format (-T json)."""
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
        """Get summary list of packets (like Wireshark's top pane)."""
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
        """Get full JSON details for a single packet."""
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
