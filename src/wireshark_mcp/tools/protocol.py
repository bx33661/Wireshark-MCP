"""Deep protocol analysis tools for Wireshark MCP."""

import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..tshark.client import TSharkClient
from .envelope import normalize_tool_result, parse_tool_result, success_response
from .formatting import CRIT, INFO, OK, WARN

logger = logging.getLogger("wireshark_mcp")


def register_protocol_tools(mcp: FastMCP, client: TSharkClient) -> None:
    """Register core protocol analysis tools (always available)."""
    # No core protocol tools — all are contextual.
    # This function is kept for backward compatibility but does nothing.
    pass


def make_contextual_protocol_tools(client: TSharkClient) -> list[tuple[str, Any]]:
    """Create contextual protocol tools for the stable contextual catalog."""

    async def wireshark_extract_tls_handshakes(pcap_file: str, limit: int = 50) -> str:
        """[TLS] Extract TLS/SSL handshake info (version, cipher, SNI, cert issuer) as TSV."""
        fields = [
            "ip.src",
            "ip.dst",
            "tcp.dstport",
            "tls.handshake.version",
            "tls.handshake.ciphersuite",
            "tls.handshake.extensions.server_name",
        ]
        result = await client.extract_fields(
            pcap_file,
            fields,
            display_filter="tls.handshake.type == 1",
            limit=limit,
        )
        wrapped = parse_tool_result(result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        # Also try to get Server Hello info for cipher suite negotiated
        server_fields = [
            "ip.src",
            "ip.dst",
            "tls.handshake.version",
            "tls.handshake.ciphersuite",
        ]
        server_result = await client.extract_fields(
            pcap_file,
            server_fields,
            display_filter="tls.handshake.type == 2",
            limit=limit,
        )
        server_wrapped = parse_tool_result(server_result)

        output_parts = ["Client Hello (TLS Handshakes)"]
        output_parts.append(wrapped.get("data", "No data"))

        if server_wrapped["success"]:
            output_parts.append("\nServer Hello (Negotiated Parameters)")
            output_parts.append(server_wrapped.get("data", "No data"))

        return success_response("\n".join(output_parts))

    async def wireshark_analyze_tcp_health(pcap_file: str) -> str:
        """[TCP] Analyze TCP connection health (retransmissions, dup ACKs, zero window, resets)."""
        import asyncio

        checks = [
            ("Retransmissions", "tcp.analysis.retransmission"),
            ("Fast Retransmissions", "tcp.analysis.fast_retransmission"),
            ("Duplicate ACKs", "tcp.analysis.duplicate_ack"),
            ("Zero Window", "tcp.analysis.zero_window"),
            ("Window Full", "tcp.analysis.window_full"),
            ("TCP Resets", "tcp.flags.reset == 1"),
            ("Out-of-Order", "tcp.analysis.out_of_order"),
            ("Keep-Alive", "tcp.analysis.keep_alive"),
        ]

        async def _count_check(display_filter: str) -> int:
            raw = await client.get_packet_list(pcap_file, limit=10000, display_filter=display_filter)
            wrapped = parse_tool_result(raw)
            if not wrapped["success"]:
                return -1
            data = wrapped.get("data", "")
            if isinstance(data, str):
                lines = [ln for ln in data.strip().splitlines() if ln.strip()]
                return max(0, len(lines) - 1)
            return 0

        counts = await asyncio.gather(*[_count_check(f) for _, f in checks])

        retrans_conv = await client.extract_fields(
            pcap_file,
            ["ip.src", "ip.dst", "tcp.srcport", "tcp.dstport"],
            display_filter="tcp.analysis.retransmission",
            limit=20,
        )

        results: list[str] = []
        for (name, _), count in zip(checks, counts, strict=True):
            if count < 0:
                results.append(f"  [-] {name}: N/A (filter not applicable)")
                continue
            severity = OK
            if count > 0:
                severity = INFO
            if count > 50:
                severity = WARN
            if count > 200:
                severity = CRIT
            results.append(f"  {severity} {name}: {count} packets")

        results.append("\n--- Top Conversations with Issues ---")
        retrans_wrapped = parse_tool_result(retrans_conv)
        if retrans_wrapped["success"]:
            results.append(retrans_wrapped.get("data", "No retransmission data"))

        return success_response("\n".join(results))

    async def wireshark_detect_arp_spoofing(pcap_file: str) -> str:
        """[ARP] Detect potential ARP spoofing (duplicate IP-MAC, gratuitous floods, reply storms)."""
        arp_result = await client.extract_fields(
            pcap_file,
            ["arp.src.hw_mac", "arp.src.proto_ipv4", "arp.dst.proto_ipv4", "arp.opcode"],
            display_filter="arp",
            limit=5000,
        )
        wrapped = parse_tool_result(arp_result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data", "")
        if not isinstance(data, str) or len(data.strip()) < 20:
            return success_response("No ARP traffic found in this capture.")

        ip_to_macs: dict[str, set[str]] = {}
        mac_to_ips: dict[str, set[str]] = {}
        arp_reply_count = 0
        gratuitous_count = 0

        lines = data.strip().splitlines()
        for line in lines[1:]:
            parts = line.split("\t")
            if len(parts) >= 4:
                mac = parts[0].strip().strip('"')
                src_ip = parts[1].strip().strip('"')
                dst_ip = parts[2].strip().strip('"')
                opcode = parts[3].strip().strip('"')

                if mac and src_ip:
                    ip_to_macs.setdefault(src_ip, set()).add(mac)
                    mac_to_ips.setdefault(mac, set()).add(src_ip)

                if opcode == "2":
                    arp_reply_count += 1

                if src_ip == dst_ip:
                    gratuitous_count += 1

        results: list[str] = []
        results.append(f"Total ARP packets: {len(lines) - 1}")
        results.append(f"ARP replies: {arp_reply_count}")
        results.append(f"Gratuitous ARP: {gratuitous_count}")

        suspicious_ips = {ip: macs for ip, macs in ip_to_macs.items() if len(macs) > 1}
        if suspicious_ips:
            results.append(f"\n{CRIT} {len(suspicious_ips)} IP(s) have multiple MAC addresses!")
            for ip, macs in suspicious_ips.items():
                results.append(f"  IP {ip} -> MACs: {', '.join(sorted(macs))}")
        else:
            results.append(f"\n{OK} No IP-to-MAC conflicts detected.")

        multi_ip_macs = {mac: ips for mac, ips in mac_to_ips.items() if len(ips) > 3}
        if multi_ip_macs:
            results.append(f"\n{INFO} {len(multi_ip_macs)} MAC(s) claim many IPs (possible router or scanner):")
            for mac, ips in multi_ip_macs.items():
                results.append(f"  MAC {mac} -> {len(ips)} IPs")

        if arp_reply_count > 100:
            results.append(f"\n{WARN} High ARP reply count ({arp_reply_count}), possible ARP storm.")

        if gratuitous_count > 10:
            results.append(f"\n{INFO} Gratuitous ARP count is elevated ({gratuitous_count}).")

        return success_response("\n".join(results))

    async def wireshark_extract_smtp_emails(pcap_file: str, limit: int = 50) -> str:
        """[SMTP] Extract SMTP email metadata (sender, recipient, subject, mail server info)."""
        smtp_result = await client.extract_fields(
            pcap_file,
            ["ip.src", "ip.dst", "smtp.req.parameter", "smtp.rsp.parameter"],
            display_filter="smtp",
            limit=limit,
        )
        wrapped = parse_tool_result(smtp_result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data", "")
        if not isinstance(data, str) or len(data.strip()) < 20:
            return success_response("No SMTP traffic found in this capture.")

        output_parts = [data]

        mail_from = await client.extract_fields(
            pcap_file,
            ["smtp.req.parameter"],
            display_filter='smtp.req.command == "MAIL"',
            limit=limit,
        )
        from_wrapped = parse_tool_result(mail_from)
        if from_wrapped["success"]:
            from_data = from_wrapped.get("data", "")
            if isinstance(from_data, str) and len(from_data.strip()) > 20:
                output_parts.append("\n--- Senders (MAIL FROM) ---")
                output_parts.append(from_data)

        rcpt_to = await client.extract_fields(
            pcap_file,
            ["smtp.req.parameter"],
            display_filter='smtp.req.command == "RCPT"',
            limit=limit,
        )
        to_wrapped = parse_tool_result(rcpt_to)
        if to_wrapped["success"]:
            to_data = to_wrapped.get("data", "")
            if isinstance(to_data, str) and len(to_data.strip()) > 20:
                output_parts.append("\n--- Recipients (RCPT TO) ---")
                output_parts.append(to_data)

        return success_response("\n".join(output_parts))

    async def wireshark_extract_dhcp_info(pcap_file: str) -> str:
        """[DHCP] Extract DHCP lease information (IPs, hostnames, DNS servers, lease times)."""
        dhcp_result = await client.extract_fields(
            pcap_file,
            [
                "bootp.type",
                "bootp.hw.mac_addr",
                "bootp.ip.your",
                "bootp.ip.server",
                "bootp.option.hostname",
                "bootp.option.dhcp",
                "bootp.option.requested_ip_address",
                "bootp.option.domain_name_server",
            ],
            display_filter="bootp",
            limit=200,
        )
        wrapped = parse_tool_result(dhcp_result)
        if not wrapped["success"]:
            # Try the newer "dhcp" filter name
            dhcp_result = await client.extract_fields(
                pcap_file,
                [
                    "dhcp.type",
                    "dhcp.hw.mac_addr",
                    "dhcp.ip.your",
                    "dhcp.ip.server",
                    "dhcp.option.hostname",
                    "dhcp.option.dhcp",
                    "dhcp.option.requested_ip_address",
                    "dhcp.option.domain_name_server",
                ],
                display_filter="dhcp",
                limit=200,
            )
            wrapped = parse_tool_result(dhcp_result)

        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data", "")
        if not isinstance(data, str) or len(data.strip()) < 20:
            return success_response("No DHCP traffic found in this capture.")

        return success_response(data)

    async def wireshark_analyze_quic(pcap_file: str, limit: int = 100) -> str:
        """[QUIC] Analyze QUIC/HTTP3 connections (version, SNI, stream info, connection IDs)."""
        fields = [
            "ip.src",
            "ip.dst",
            "udp.dstport",
            "quic.version",
            "quic.connection.number",
            "tls.handshake.extensions.server_name",
        ]
        result = await client.extract_fields(
            pcap_file,
            fields,
            display_filter="quic",
            limit=limit,
        )
        wrapped = parse_tool_result(result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data", "")
        if not isinstance(data, str) or len(data.strip()) < 20:
            return success_response("No QUIC traffic found in this capture.")

        output_parts = [f"QUIC connections (up to {limit}):"]
        output_parts.append(data)

        h3_result = await client.extract_fields(
            pcap_file,
            ["ip.src", "ip.dst", "http3.frame_type"],
            display_filter="http3",
            limit=50,
        )
        h3_wrapped = parse_tool_result(h3_result)
        if h3_wrapped["success"]:
            h3_data = h3_wrapped.get("data", "")
            if isinstance(h3_data, str) and len(h3_data.strip()) > 20:
                output_parts.append("\nHTTP/3 frames:")
                output_parts.append(h3_data)

        return success_response("\n".join(output_parts))

    async def wireshark_analyze_websocket(pcap_file: str, limit: int = 100) -> str:
        """[WebSocket] Analyze WebSocket connections (opcode, payload length, masking)."""
        fields = [
            "ip.src",
            "ip.dst",
            "tcp.dstport",
            "websocket.opcode",
            "websocket.payload_length",
            "websocket.masked",
        ]
        result = await client.extract_fields(
            pcap_file,
            fields,
            display_filter="websocket",
            limit=limit,
        )
        wrapped = parse_tool_result(result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data", "")
        if not isinstance(data, str) or len(data.strip()) < 20:
            return success_response("No WebSocket traffic found in this capture.")

        lines = data.strip().splitlines()
        text_frames = sum(1 for row in lines[1:] if "\t1\t" in row or "\t0x1\t" in row)
        binary_frames = sum(1 for row in lines[1:] if "\t2\t" in row or "\t0x2\t" in row)
        close_frames = sum(1 for row in lines[1:] if "\t8\t" in row or "\t0x8\t" in row)

        output_parts = [
            f"Total WebSocket frames: {len(lines) - 1}",
            f"  Text: {text_frames}, Binary: {binary_frames}, Close: {close_frames}",
            "",
            data,
        ]
        return success_response("\n".join(output_parts))

    async def wireshark_analyze_mqtt(pcap_file: str, limit: int = 200) -> str:
        """[MQTT] Analyze MQTT messages (msg type, topic, QoS, client ID)."""
        fields = [
            "ip.src",
            "ip.dst",
            "mqtt.msgtype",
            "mqtt.topic",
            "mqtt.qos",
            "mqtt.clientid",
        ]
        result = await client.extract_fields(
            pcap_file,
            fields,
            display_filter="mqtt",
            limit=limit,
        )
        wrapped = parse_tool_result(result)
        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data", "")
        if not isinstance(data, str) or len(data.strip()) < 20:
            return success_response("No MQTT traffic found in this capture.")

        lines = data.strip().splitlines()
        topics: dict[str, int] = {}
        for line in lines[1:]:
            parts = line.split("\t")
            if len(parts) >= 4:
                topic = parts[3].strip().strip('"')
                if topic:
                    topics[topic] = topics.get(topic, 0) + 1

        output_parts = [f"Total MQTT messages: {len(lines) - 1}"]
        if topics:
            output_parts.append(f"Unique topics: {len(topics)}")
            output_parts.append("Top topics:")
            for topic, count in sorted(topics.items(), key=lambda x: x[1], reverse=True)[:10]:
                output_parts.append(f"  {topic} ({count})")
        output_parts.append("")
        output_parts.append(data)
        return success_response("\n".join(output_parts))

    async def wireshark_analyze_grpc(pcap_file: str, limit: int = 100) -> str:
        """[gRPC] Analyze gRPC calls (method path, message type, content-type)."""
        fields = [
            "ip.src",
            "ip.dst",
            "http2.header.value",
            "grpc.message_length",
        ]
        result = await client.extract_fields(
            pcap_file,
            fields,
            display_filter="grpc",
            limit=limit,
        )
        wrapped = parse_tool_result(result)
        if not wrapped["success"]:
            h2_result = await client.extract_fields(
                pcap_file,
                ["ip.src", "ip.dst", "http2.headers.path", "http2.headers.content_type"],
                display_filter='http2 and http2.headers.content_type contains "grpc"',
                limit=limit,
            )
            h2_wrapped = parse_tool_result(h2_result)
            if not h2_wrapped["success"]:
                return normalize_tool_result(wrapped)
            data = h2_wrapped.get("data", "")
            if not isinstance(data, str) or len(data.strip()) < 20:
                return success_response("No gRPC traffic found in this capture.")
            return success_response(f"gRPC over HTTP/2:\n{data}")

        data = wrapped.get("data", "")
        if not isinstance(data, str) or len(data.strip()) < 20:
            return success_response("No gRPC traffic found in this capture.")

        return success_response(f"gRPC messages (up to {limit}):\n{data}")

    return [
        ("wireshark_extract_tls_handshakes", wireshark_extract_tls_handshakes),
        ("wireshark_analyze_tcp_health", wireshark_analyze_tcp_health),
        ("wireshark_detect_arp_spoofing", wireshark_detect_arp_spoofing),
        ("wireshark_extract_smtp_emails", wireshark_extract_smtp_emails),
        ("wireshark_extract_dhcp_info", wireshark_extract_dhcp_info),
        ("wireshark_analyze_quic", wireshark_analyze_quic),
        ("wireshark_analyze_websocket", wireshark_analyze_websocket),
        ("wireshark_analyze_mqtt", wireshark_analyze_mqtt),
        ("wireshark_analyze_grpc", wireshark_analyze_grpc),
    ]
