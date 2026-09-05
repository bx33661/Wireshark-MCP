"""Extraction and search mixin."""

from __future__ import annotations

import json
import os

from ._typing import FieldRowConsumer, FieldStreamResult, _ClientProtocol


class ExtractionMixin(_ClientProtocol):
    """Field extraction, object export, packet search, stream follow, SSL decrypt."""

    async def extract_fields(
        self,
        pcap_file: str,
        fields: list[str],
        display_filter: str = "",
        separator: str = "\t",
        limit: int = 100,
        offset: int = 0,
        aggregator: str = ",",
        stream_limit: bool = False,
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

        cmd.extend(
            [
                "-E",
                "header=y",
                "-E",
                f"separator={separator}",
                "-E",
                f"aggregator={aggregator}",
                "-E",
                "quote=d",
            ]
        )

        if stream_limit:
            return await self._run_command(
                cmd,
                limit_lines=limit,
                offset_lines=offset,
                stream_limit=True,
            )
        return await self._run_command(cmd, limit_lines=limit, offset_lines=offset)

    async def stream_fields(
        self,
        pcap_file: str,
        fields: list[str],
        consumer: FieldRowConsumer,
        display_filter: str = "",
        max_rows: int = 1_000_000,
        timeout: int = 30,
    ) -> FieldStreamResult:
        """Consume tshark field rows without materializing its complete stdout."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            error = validation.get("error")
            return {"success": False, "error": error if isinstance(error, dict) else {"message": str(error)}}

        cmd = [self.tshark_path, "-n", "-r", pcap_file, "-T", "fields"]
        for field in fields:
            cmd.extend(["-e", field])
        if display_filter:
            cmd.extend(["-Y", display_filter])
        cmd.extend(["-E", "header=y", "-E", "separator=/t", "-E", "aggregator=,", "-E", "quote=d"])
        return await self._stream_field_rows(cmd, consumer, max_rows=max_rows, timeout=timeout)

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
                safe_pattern = match_pattern.replace("\\", "\\\\").replace('"', '\\"')
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

        raw = await self._run_command(
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

        ok, output = self._unwrap(raw)
        if not ok:
            return raw

        lines = output.splitlines()

        if search_content:
            lines = [line for line in lines if search_content in line]
            if not lines:
                return self._ok(f"No occurrences of '{search_content}' found in stream {stream_index}.")

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

        return self._ok(final_output)

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

    async def decrypt_tls_traffic(
        self, pcap_file: str, keylog_file: str, display_filter: str = "", limit: int = 100
    ) -> str:
        """Decrypt TLS and extract decrypted HTTP/application data."""
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
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "http.request.method",
            "-e",
            "http.request.uri",
            "-e",
            "http.host",
            "-e",
            "http.response.code",
            "-e",
            "http.content_type",
            "-E",
            "header=y",
            "-E",
            "separator=\t",
        ]
        if display_filter:
            cmd.extend(["-Y", display_filter])
        else:
            cmd.extend(["-Y", "http"])
        cmd.extend(["-c", str(limit)])
        return await self._run_command(cmd)

    async def decrypt_wpa_traffic(
        self, pcap_file: str, wpa_keys: list[str], display_filter: str = "", limit: int = 100
    ) -> str:
        """Decrypt WPA/WPA2 traffic using passphrase keys."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        if not wpa_keys:
            return json.dumps(
                {
                    "success": False,
                    "error": {
                        "type": "InvalidParameter",
                        "message": "At least one WPA key required. Format: 'passphrase:SSID' or just 'passphrase'",
                    },
                }
            )

        cmd = [self.tshark_path, "-r", pcap_file, "-o", "wlan.enable_decryption:TRUE"]
        for key in wpa_keys:
            cmd.extend(["-o", f'uat:80211_keys:"wpa-pwd:{key}",1'])

        cmd.extend(
            [
                "-T",
                "fields",
                "-e",
                "frame.number",
                "-e",
                "wlan.sa",
                "-e",
                "wlan.da",
                "-e",
                "ip.src",
                "-e",
                "ip.dst",
                "-e",
                "_ws.col.Protocol",
                "-e",
                "_ws.col.Info",
                "-E",
                "header=y",
                "-E",
                "separator=\t",
            ]
        )
        if display_filter:
            cmd.extend(["-Y", display_filter])
        cmd.extend(["-c", str(limit)])
        return await self._run_command(cmd)

    async def extract_with_decode_as(
        self, pcap_file: str, decode_rules: list[str], fields: list[str], display_filter: str = "", limit: int = 100
    ) -> str:
        """Extract fields with decode-as rules applied."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        if not decode_rules:
            return json.dumps(
                {
                    "success": False,
                    "error": {
                        "type": "InvalidParameter",
                        "message": "At least one decode rule required. Format: 'tcp.port==8080,http'",
                    },
                }
            )

        cmd = [self.tshark_path, "-r", pcap_file]
        for rule in decode_rules:
            cmd.extend(["-d", rule])

        if not fields:
            fields = ["frame.number", "ip.src", "ip.dst", "_ws.col.Protocol", "_ws.col.Info"]

        cmd.extend(["-T", "fields"])
        for field in fields:
            cmd.extend(["-e", field])
        cmd.extend(["-E", "header=y", "-E", "separator=\t"])
        if display_filter:
            cmd.extend(["-Y", display_filter])
        cmd.extend(["-c", str(limit)])
        return await self._run_command(cmd)

    async def extract_with_prefs(
        self, pcap_file: str, prefs: list[str], fields: list[str], display_filter: str = "", limit: int = 100
    ) -> str:
        """Extract fields with protocol preference overrides."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        if not prefs:
            return json.dumps(
                {
                    "success": False,
                    "error": {
                        "type": "InvalidParameter",
                        "message": "At least one preference required. Format: 'tcp.desegment_tcp_streams:TRUE'",
                    },
                }
            )

        cmd = [self.tshark_path, "-r", pcap_file]
        for pref in prefs:
            cmd.extend(["-o", pref])

        if not fields:
            fields = ["frame.number", "ip.src", "ip.dst", "_ws.col.Protocol", "_ws.col.Info"]

        cmd.extend(["-T", "fields"])
        for field in fields:
            cmd.extend(["-e", field])
        cmd.extend(["-E", "header=y", "-E", "separator=\t"])
        if display_filter:
            cmd.extend(["-Y", display_filter])
        cmd.extend(["-c", str(limit)])
        return await self._run_command(cmd)

    async def extract_kerberos(self, pcap_file: str, limit: int = 100) -> str:
        """Extract Kerberos authentication data."""
        validation = self._validate_file(pcap_file)
        if not validation["success"]:
            return json.dumps(validation)

        cmd = [
            self.tshark_path,
            "-r",
            pcap_file,
            "-Y",
            "kerberos",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "kerberos.msg_type",
            "-e",
            "kerberos.CNameString",
            "-e",
            "kerberos.realm",
            "-e",
            "kerberos.SNameString",
            "-e",
            "kerberos.cipher",
            "-E",
            "header=y",
            "-E",
            "separator=\t",
            "-c",
            str(limit),
        ]
        return await self._run_command(cmd)
