"""Deep protocol analysis tools for Wireshark MCP."""

import logging
from typing import Any, List, Tuple

from mcp.server.fastmcp import FastMCP

from ..tshark.client import TSharkClient
from .envelope import error_response, normalize_tool_result, parse_tool_result, success_response

logger = logging.getLogger("wireshark_mcp")


def register_protocol_tools(mcp: FastMCP, client: TSharkClient) -> None:
    """Register core protocol analysis tools (always available)."""
    # No core protocol tools — all are contextual.
    # This function is kept for backward compatibility but does nothing.
    pass


def make_contextual_protocol_tools(client: TSharkClient) -> List[Tuple[str, Any]]:
    """Create contextual protocol tools (registered on demand by the registry)."""

    async def wireshark_extract_tls_handshakes(pcap_file: str, limit: int = 50) -> str:
        """[TLS] Extract TLS/SSL handshake information (version, cipher, SNI, cert issuer).

        Args:
            pcap_file: Path to capture file
            limit: Maximum handshakes to return (default: 50)

        Returns:
            Tabular TLS handshake data or JSON error

        Example:
            wireshark_extract_tls_handshakes("https_traffic.pcap")
        """
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

        output_parts = ["=== Client Hello (TLS Handshakes) ==="]
        output_parts.append(wrapped.get("data", "No data"))

        if server_wrapped["success"]:
            output_parts.append("\n=== Server Hello (Negotiated Parameters) ===")
            output_parts.append(server_wrapped.get("data", "No data"))

        return success_response("\n".join(output_parts))

    async def wireshark_analyze_tcp_health(pcap_file: str) -> str:
        """[TCP] Analyze TCP connection health (retransmissions, dup ACKs, zero window, resets).

        Args:
            pcap_file: Path to capture file

        Returns:
            TCP health statistics summary or JSON error

        Example:
            wireshark_analyze_tcp_health("slow_connection.pcap")
        """
        # Define the anomaly categories and their filters
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

        results: List[str] = []
        results.append("=== TCP Health Analysis ===\n")

        # Get total TCP packet count
        total_result = await client.extract_fields(
            pcap_file, ["frame.number"], display_filter="tcp", limit=1
        )
        total_list = await client.get_packet_list(pcap_file, limit=1, display_filter="tcp")
        total_wrapped = parse_tool_result(total_list)

        for name, display_filter in checks:
            count_result = await client.get_packet_list(
                pcap_file, limit=10000, display_filter=display_filter
            )
            count_wrapped = parse_tool_result(count_result)

            if count_wrapped["success"]:
                data = count_wrapped.get("data", "")
                if isinstance(data, str):
                    lines = [l for l in data.strip().splitlines() if l.strip()]
                    count = max(0, len(lines) - 1)
                else:
                    count = 0

                severity = "🟢"
                if count > 0:
                    severity = "🟡"
                if count > 50:
                    severity = "🟠"
                if count > 200:
                    severity = "🔴"

                results.append(f"  {severity} {name}: {count} packets")
            else:
                results.append(f"  ⚪ {name}: N/A (filter not applicable)")

        # Get top conversations by retransmissions
        results.append("\n--- Top Conversations with Issues ---")
        retrans_conv = await client.extract_fields(
            pcap_file,
            ["ip.src", "ip.dst", "tcp.srcport", "tcp.dstport"],
            display_filter="tcp.analysis.retransmission",
            limit=20,
        )
        retrans_wrapped = parse_tool_result(retrans_conv)
        if retrans_wrapped["success"]:
            results.append(retrans_wrapped.get("data", "No retransmission data"))

        return success_response("\n".join(results))

    async def wireshark_detect_arp_spoofing(pcap_file: str) -> str:
        """[ARP] Detect potential ARP spoofing (duplicate IP-MAC, gratuitous floods, reply storms).

        Args:
            pcap_file: Path to capture file

        Returns:
            ARP analysis results or JSON error

        Example:
            wireshark_detect_arp_spoofing("lan_traffic.pcap")
        """
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

        results: List[str] = []
        results.append("=== ARP Spoofing Analysis ===\n")
        results.append(f"Total ARP packets: {len(lines) - 1}")
        results.append(f"ARP replies: {arp_reply_count}")
        results.append(f"Gratuitous ARP: {gratuitous_count}")

        suspicious_ips = {ip: macs for ip, macs in ip_to_macs.items() if len(macs) > 1}
        if suspicious_ips:
            results.append(f"\n🔴 ALERT: {len(suspicious_ips)} IP(s) have multiple MAC addresses!")
            for ip, macs in suspicious_ips.items():
                results.append(f"  IP {ip} → MACs: {', '.join(sorted(macs))}")
        else:
            results.append("\n🟢 No IP-to-MAC conflicts detected.")

        multi_ip_macs = {mac: ips for mac, ips in mac_to_ips.items() if len(ips) > 3}
        if multi_ip_macs:
            results.append(f"\n🟡 {len(multi_ip_macs)} MAC(s) claim many IPs (possible router or scanner):")
            for mac, ips in multi_ip_macs.items():
                results.append(f"  MAC {mac} → {len(ips)} IPs")

        if arp_reply_count > 100:
            results.append(f"\n🟠 High ARP reply count ({arp_reply_count}), possible ARP storm.")

        if gratuitous_count > 10:
            results.append(f"\n🟡 Gratuitous ARP count is elevated ({gratuitous_count}).")

        return success_response("\n".join(results))

    async def wireshark_extract_smtp_emails(pcap_file: str, limit: int = 50) -> str:
        """[SMTP] Extract SMTP email metadata (sender, recipient, subject, mail server info).

        Args:
            pcap_file: Path to capture file
            limit: Maximum emails to extract (default: 50)

        Returns:
            SMTP email metadata or JSON error

        Example:
            wireshark_extract_smtp_emails("email_traffic.pcap")
        """
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

        output_parts = ["=== SMTP Email Analysis ===\n"]
        output_parts.append(data)

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
        """[DHCP] Extract DHCP lease information (IPs, hostnames, DNS servers, lease times).

        Args:
            pcap_file: Path to capture file

        Returns:
            DHCP lease information or JSON error

        Example:
            wireshark_extract_dhcp_info("network_boot.pcap")
        """
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

        return success_response(f"=== DHCP Lease Information ===\n\n{data}")

    return [
        ("wireshark_extract_tls_handshakes", wireshark_extract_tls_handshakes),
        ("wireshark_analyze_tcp_health", wireshark_analyze_tcp_health),
        ("wireshark_detect_arp_spoofing", wireshark_detect_arp_spoofing),
        ("wireshark_extract_smtp_emails", wireshark_extract_smtp_emails),
        ("wireshark_extract_dhcp_info", wireshark_extract_dhcp_info),
    ]
