"""Deep protocol analysis tools for Wireshark MCP.

Two shapes live here. `make_protocol_tools` returns tools that stay on the MCP
surface in their own right: they run several tshark passes and score the results,
so they answer a question ("is this TCP session healthy?") rather than "show me
protocol X". `make_protocol_handlers` returns per-protocol extractors that
`analyze.py` exposes through the single `wireshark_analyze_protocol` tool — the
field lists here are the reason that tool exists rather than making the caller
guess field names.
"""

import logging
from typing import Any

from ..tshark.client import TSharkClient
from .envelope import ProtocolHandler, normalize_tool_result, parse_tool_result, success_response
from .formatting import CRIT, INFO, OK, WARN

logger = logging.getLogger("wireshark_mcp")


def make_protocol_tools(client: TSharkClient) -> list[tuple[str, Any]]:
    """Build the standalone protocol tools (multi-pass diagnostics, not extractors)."""

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

    return [
        ("wireshark_analyze_tcp_health", wireshark_analyze_tcp_health),
        ("wireshark_detect_arp_spoofing", wireshark_detect_arp_spoofing),
    ]


def make_protocol_handlers(client: TSharkClient) -> dict[str, ProtocolHandler]:
    """Build per-protocol extractors for `wireshark_analyze_protocol`."""

    async def _tls_handshakes(pcap_file: str, limit: int) -> str:
        fields = [
            "ip.src",
            "ip.dst",
            "tcp.dstport",
            "tls.handshake.version",
            "tls.handshake.ciphersuite",
            "tls.handshake.extensions_server_name",
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

    async def _smtp(pcap_file: str, limit: int) -> str:
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

    async def _dhcp(pcap_file: str, limit: int) -> str:
        # Wireshark renamed the BOOTP dissector to DHCP in 3.0, so `dhcp.*` is the
        # current spelling and `bootp.*` is rejected outright by any tshark since then.
        # Current name first: the legacy pass is kept only for pre-3.0 tshark, and
        # trying it first cost every modern caller a failed subprocess.
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
            limit=limit,
        )
        wrapped = parse_tool_result(dhcp_result)
        if not wrapped["success"]:
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
                limit=limit,
            )
            wrapped = parse_tool_result(dhcp_result)

        if not wrapped["success"]:
            return normalize_tool_result(wrapped)

        data = wrapped.get("data", "")
        if not isinstance(data, str) or len(data.strip()) < 20:
            return success_response("No DHCP traffic found in this capture.")

        return success_response(data)

    async def _quic(pcap_file: str, limit: int) -> str:
        fields = [
            "ip.src",
            "ip.dst",
            "udp.dstport",
            "quic.version",
            "quic.connection.number",
            "tls.handshake.extensions_server_name",
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

    async def _websocket(pcap_file: str, limit: int) -> str:
        fields = [
            "ip.src",
            "ip.dst",
            "tcp.dstport",
            "websocket.opcode",
            "websocket.payload_length",
            "websocket.mask",
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

    async def _mqtt(pcap_file: str, limit: int) -> str:
        # Field union of the former wireshark_analyze_mqtt and wireshark_analyze_mqtt_deep,
        # which filtered on the same `mqtt` protocol and differed only in columns.
        fields = [
            "ip.src",
            "ip.dst",
            "mqtt.msgtype",
            "mqtt.topic",
            "mqtt.qos",
            "mqtt.clientid",
            "mqtt.ver",
            "mqtt.prop_key",
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
        msg_types: dict[str, int] = {}
        topics: dict[str, int] = {}
        client_ids: set[str] = set()
        versions: set[str] = set()

        for line in lines[1:]:
            parts = line.split("\t")
            if len(parts) >= 7:
                msgtype = parts[2].strip().strip('"')
                topic = parts[3].strip().strip('"')
                clientid = parts[5].strip().strip('"')
                ver = parts[6].strip().strip('"')

                if msgtype:
                    msg_types[msgtype] = msg_types.get(msgtype, 0) + 1
                if topic:
                    topics[topic] = topics.get(topic, 0) + 1
                if clientid:
                    client_ids.add(clientid)
                if ver:
                    versions.add(ver)

        output_parts = [f"Total MQTT messages: {len(lines) - 1}"]

        if msg_types:
            output_parts.append("\nMessage type distribution:")
            for mtype, count in sorted(msg_types.items(), key=lambda x: x[1], reverse=True):
                output_parts.append(f"  Type {mtype}: {count}")

        if topics:
            output_parts.append(f"\nUnique topics: {len(topics)}")
            output_parts.append("Top topics:")
            for topic, count in sorted(topics.items(), key=lambda x: x[1], reverse=True)[:10]:
                output_parts.append(f"  {topic} ({count})")

        if client_ids:
            output_parts.append(f"\n{INFO} Client IDs: {', '.join(sorted(client_ids))}")

        if versions:
            output_parts.append(f"{INFO} Protocol versions: {', '.join(sorted(versions))}")

        output_parts.append("")
        output_parts.append(data)

        sub_result = await client.extract_fields(
            pcap_file,
            ["ip.src", "mqtt.topic", "mqtt.sub.qos"],
            display_filter="mqtt.msgtype == 8",
            limit=limit,
        )
        sub_wrapped = parse_tool_result(sub_result)
        if sub_wrapped["success"]:
            sub_data = sub_wrapped.get("data", "")
            if isinstance(sub_data, str) and len(sub_data.strip()) > 20:
                output_parts.append(f"\n{INFO} SUBSCRIBE Requests (msgtype 8):")
                output_parts.append(sub_data)

        return success_response("\n".join(output_parts))

    async def _grpc(pcap_file: str, limit: int) -> str:
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

    def _make_simple_extractor(
        fields: list[str],
        display_filter: str,
        empty_msg: str,
        header_tmpl: str,
    ) -> ProtocolHandler:
        async def _extractor(pcap_file: str, limit: int) -> str:
            result = await client.extract_fields(
                pcap_file,
                fields,
                display_filter=display_filter,
                limit=limit,
            )
            wrapped = parse_tool_result(result)
            if not wrapped["success"]:
                return normalize_tool_result(wrapped)

            data = wrapped.get("data", "")
            if not isinstance(data, str) or len(data.strip()) < 20:
                return success_response(empty_msg)

            return success_response(header_tmpl.format(limit=limit, data=data))

        return _extractor

    handlers: dict[str, ProtocolHandler] = {
        "tls_handshakes": _tls_handshakes,
        "smtp": _smtp,
        "dhcp": _dhcp,
        "quic": _quic,
        "websocket": _websocket,
        "mqtt": _mqtt,
        "grpc": _grpc,
        "ble": _make_simple_extractor(
            [
                "btle.advertising_address",
                "btle.data_header.llid",
                "btle.length",
                "btatt.opcode",
                "btatt.handle",
                "btl2cap.cid",
            ],
            "btle",
            "No Bluetooth LE traffic found in this capture.",
            "Bluetooth LE packets (up to {limit}):\n{data}",
        ),
        "wifi": _make_simple_extractor(
            [
                "wlan.sa",
                "wlan.da",
                "wlan.bssid",
                "wlan.fc.type_subtype",
                "wlan.ssid",
                "wlan.rsn.akms.type",
            ],
            "wlan.fc.type == 0",
            "No 802.11 management frames found in this capture.",
            "802.11 management frames (up to {limit}):\n{data}",
        ),
        "wireguard": _make_simple_extractor(
            [
                "ip.src",
                "ip.dst",
                "udp.dstport",
                "wg.type",
                "wg.sender",
                "wg.receiver",
            ],
            "wg",
            "No WireGuard traffic found in this capture.",
            "WireGuard sessions (up to {limit}):\n{data}",
        ),
        "doh": _make_simple_extractor(
            [
                "ip.src",
                "ip.dst",
                "http2.header.value",
            ],
            'http2.header.name == "content-type" && http2.header.value contains "dns"',
            "No DNS-over-HTTPS traffic found in this capture.",
            f"{WARN} DNS-over-HTTPS detected (up to {{limit}}):\n{{data}}",
        ),
        "icmp_tunnel": _make_simple_extractor(
            [
                "ip.src",
                "ip.dst",
                "icmp.type",
                "data.len",
            ],
            "icmp && data.len > 48",
            "No large ICMP payloads found in this capture.",
            f"{WARN} ICMP tunneling indicators (up to {{limit}}):\n{{data}}",
        ),
    }
    return handlers
