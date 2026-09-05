"""Security analysis tools for Wireshark MCP."""

from typing import Any

from ..tshark.client import TSharkClient
from .envelope import envelope_response, normalize_tool_result, parse_tool_result
from .findings import Finding, FindingEvidence, mask_secret
from .formatting import CRIT, OK


def make_security_tools(client: TSharkClient) -> list[tuple[str, Any]]:
    """Build security tools."""

    async def wireshark_extract_credentials(pcap_file: str) -> str:
        """[Security] Scan for plaintext credentials (HTTP Basic Auth, FTP passwords, Telnet)."""
        evidence_list: list[FindingEvidence] = []
        warnings: list[str] = []
        limit = 50

        # 1. HTTP Basic Auth
        http_auth = await client.extract_fields(
            pcap_file,
            ["frame.number", "tcp.stream", "ip.src", "ip.dst", "http.authbasic"],
            display_filter="http.authbasic",
            limit=limit,
        )
        http_auth_wrapped = parse_tool_result(http_auth)
        if not http_auth_wrapped["success"]:
            return normalize_tool_result(http_auth_wrapped)

        http_auth_data = http_auth_wrapped.get("data")
        if http_auth_wrapped.get("truncated") is True:
            warnings.append(f"HTTP Basic Auth scan reached ceiling of {limit} entries.")

        if isinstance(http_auth_data, str) and http_auth_data.strip():
            lines = [line for line in http_auth_data.strip().splitlines() if line.strip()]
            start_idx = 1 if lines and ("http.authbasic" in lines[0] or "frame.number" in lines[0]) else 0
            for line in lines[start_idx:]:
                parts = line.split("\t")
                cred = parts[-1].strip().strip('"')
                if cred:
                    frame = (
                        int(parts[0].strip().strip('"'))
                        if len(parts) > 0 and parts[0].strip().strip('"').isdigit()
                        else None
                    )
                    stream = (
                        int(parts[1].strip().strip('"'))
                        if len(parts) > 1 and parts[1].strip().strip('"').isdigit()
                        else None
                    )
                    src_ip = parts[2].strip().strip('"') if len(parts) > 2 else "unknown"
                    evidence_list.append(
                        FindingEvidence(
                            frame=frame,
                            stream=stream,
                            protocol="HTTP",
                            field="http.authbasic",
                            value=mask_secret(cred),
                            filter="http.authbasic",
                            description=f"HTTP Basic Auth credential from {src_ip}",
                        )
                    )

        # 2. FTP Passwords
        ftp_pass = await client.extract_fields(
            pcap_file,
            ["frame.number", "tcp.stream", "ip.src", "ip.dst", "ftp.request.arg"],
            display_filter="ftp.request.command == PASS",
            limit=limit,
        )
        ftp_pass_wrapped = parse_tool_result(ftp_pass)
        if not ftp_pass_wrapped["success"]:
            return normalize_tool_result(ftp_pass_wrapped)

        ftp_pass_data = ftp_pass_wrapped.get("data")
        if ftp_pass_wrapped.get("truncated") is True:
            warnings.append(f"FTP PASS scan reached ceiling of {limit} entries.")

        if isinstance(ftp_pass_data, str) and ftp_pass_data.strip():
            lines = [line for line in ftp_pass_data.strip().splitlines() if line.strip()]
            start_idx = 1 if lines and ("ftp.request.arg" in lines[0] or "frame.number" in lines[0]) else 0
            for line in lines[start_idx:]:
                parts = line.split("\t")
                pwd = parts[-1].strip().strip('"')
                if pwd:
                    frame = (
                        int(parts[0].strip().strip('"'))
                        if len(parts) > 0 and parts[0].strip().strip('"').isdigit()
                        else None
                    )
                    stream = (
                        int(parts[1].strip().strip('"'))
                        if len(parts) > 1 and parts[1].strip().strip('"').isdigit()
                        else None
                    )
                    src_ip = parts[2].strip().strip('"') if len(parts) > 2 else "unknown"
                    evidence_list.append(
                        FindingEvidence(
                            frame=frame,
                            stream=stream,
                            protocol="FTP",
                            field="ftp.request.arg",
                            value=mask_secret(pwd),
                            filter="ftp.request.command == PASS",
                            description=f"FTP PASS command from {src_ip}",
                        )
                    )

        # 3. Telnet cleartext login search
        telnet_data = await client.search_packet_contents(pcap_file, "login", "string", limit=10)
        telnet_wrapped = parse_tool_result(telnet_data)
        if not telnet_wrapped["success"]:
            return normalize_tool_result(telnet_wrapped)
        telnet_payload = telnet_wrapped.get("data")
        if isinstance(telnet_payload, str) and (
            "Login" in telnet_payload or "Password" in telnet_payload or "login" in telnet_payload.lower()
        ):
            evidence_list.append(
                FindingEvidence(
                    protocol="Telnet",
                    filter='frame contains "login"',
                    value="Cleartext login/password prompt pattern observed",
                    description="Telnet/cleartext session with login prompt (follow stream to analyze)",
                )
            )

        if not evidence_list:
            return envelope_response(
                data={
                    "findings": [],
                    "summary": f"{OK} No plaintext credentials (HTTP Basic Auth, FTP PASS, Telnet) observed in scanned packets.",
                },
                scope={"pcap_file": pcap_file},
                coverage={"status": "complete" if not warnings else "partial", "scanned": 0, "limit": limit},
                warnings=warnings if warnings else None,
            )

        finding: Finding = {
            "observation": f"Discovered {len(evidence_list)} cleartext credential transmission(s) or login prompt(s).",
            "severity": "high",
            "confidence": "confirmed",
            "evidence": evidence_list,
            "constraints": {
                "scanned": len(evidence_list),
                "limit": limit,
                "truncated": bool(warnings),
            },
            "next_steps": [
                f"Inspect associated TCP stream {evidence_list[0].get('stream')} using wireshark_follow_stream."
                if evidence_list[0].get("stream") is not None
                else "Inspect matching frames using wireshark_get_packet_details.",
                "Enforce encrypted transport (HTTPS, SFTP, SSH) to prevent plaintext exposure.",
            ],
        }

        summary_lines = [
            f"{CRIT} Cleartext credentials / authentication signals discovered ({len(evidence_list)} total):"
        ]
        for ev in evidence_list[:10]:
            frame_str = f"Frame {ev['frame']}" if ev.get("frame") else "Frame ?"
            stream_str = f", Stream {ev['stream']}" if ev.get("stream") is not None else ""
            summary_lines.append(f"  - [{ev.get('protocol', 'Unknown')}] {frame_str}{stream_str}: {ev.get('value')}")
        if len(evidence_list) > 10:
            summary_lines.append(f"  ... +{len(evidence_list) - 10} more (see findings list)")

        return envelope_response(
            data={
                "findings": [finding],
                "summary": "\n".join(summary_lines),
            },
            scope={"pcap_file": pcap_file},
            coverage={"status": "partial" if warnings else "complete", "scanned": len(evidence_list), "limit": limit},
            warnings=warnings if warnings else None,
        )

    return [
        ("wireshark_extract_credentials", wireshark_extract_credentials),
    ]
