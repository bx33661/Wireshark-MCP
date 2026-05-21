"""Statistics mixin for tshark -z based analysis."""

from __future__ import annotations

import json


class StatsMixin:
    """Protocol hierarchy, endpoints, conversations, I/O graph, expert info."""

    tshark_path: str

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
