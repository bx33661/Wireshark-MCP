"""Statistics mixin for tshark -z based analysis."""

from __future__ import annotations

import json
import math

from ._typing import _ClientProtocol


class StatsMixin(_ClientProtocol):
    """Protocol hierarchy, endpoints, conversations, I/O graph, expert info."""

    async def get_protocol_stats(self, pcap_file: str) -> str:
        """Protocol Hierarchy (-z io,phs)."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        return await self._run_command([self.tshark_path, "-r", pcap_file, "-q", "-z", "io,phs"])

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

    async def get_io_graph(self, pcap_file: str, interval: float = 1) -> str:
        """I/O Graphs (-z io,stat,interval)."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        if not math.isfinite(interval) or interval < 0:
            return json.dumps({"success": False, "error": {"type": "InvalidParameter", "message": "Invalid interval"}})
        return await self._run_command(
            [
                self.tshark_path,
                "-r",
                pcap_file,
                "-q",
                "-z",
                f"io,stat,{interval:g}",
            ]
        )

    async def get_service_response_time(self, pcap_file: str, protocol: str = "http") -> str:
        """HTTP/DNS timing values, or a protocol's SRT statistics tap."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        if protocol in {"http", "dns"}:
            field = f"{protocol}.time"
            return await self._run_command(
                [
                    self.tshark_path,
                    "-r",
                    pcap_file,
                    "-q",
                    "-z",
                    f"io,stat,0,COUNT({field}){field},MIN({field}){field},MAX({field}){field},AVG({field}){field}",
                ]
            )
        return await self._run_command(
            [
                self.tshark_path,
                "-r",
                pcap_file,
                "-q",
                "-z",
                f"{protocol},srt",
            ]
        )

    async def get_expert_info(self, pcap_file: str) -> str:
        """Expert Information (-z expert)."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        return await self._run_command([self.tshark_path, "-r", pcap_file, "-q", "-z", "expert"])

    async def get_flow_graph(self, pcap_file: str, flow_type: str = "any") -> str:
        """Flow/Sequence graph (-z flow,type,network)."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        valid_types = {"any", "tcp", "icmp", "icmpv6"}
        if flow_type not in valid_types:
            return json.dumps(
                {"success": False, "error": f"Invalid flow type: {flow_type}. Valid: {', '.join(sorted(valid_types))}"}
            )

        return await self._run_command([self.tshark_path, "-r", pcap_file, "-q", "-z", f"flow,{flow_type},network"])

    async def get_http_stats(self, pcap_file: str) -> str:
        """HTTP statistics tree (-z http,tree)."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        return await self._run_command([self.tshark_path, "-r", pcap_file, "-q", "-z", "http,tree"])

    async def get_io_stat_filtered(self, pcap_file: str, interval: float = 1, filters: list[str] | None = None) -> str:
        """Multi-filter I/O statistics (-z io,stat,interval,filter1,filter2,...)."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        if not math.isfinite(interval) or interval < 0:
            return json.dumps({"success": False, "error": {"type": "InvalidParameter", "message": "Invalid interval"}})
        stat_arg = f"io,stat,{interval:g}"
        if filters:
            stat_arg = f"io,stat,{interval:g}," + ",".join(filters)

        return await self._run_command([self.tshark_path, "-r", pcap_file, "-q", "-z", stat_arg])

    async def get_rtp_streams(self, pcap_file: str) -> str:
        """RTP stream statistics (-z rtp,streams)."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        return await self._run_command([self.tshark_path, "-r", pcap_file, "-q", "-z", "rtp,streams"])

    async def get_smb_stats(self, pcap_file: str) -> str:
        """SMB service response time (-z smb,srt)."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        return await self._run_command([self.tshark_path, "-r", pcap_file, "-q", "-z", "smb,srt"])
