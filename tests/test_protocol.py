"""Tests for deep protocol analysis tools."""

import pytest

from conftest import MockTSharkClient


class TestExtractTlsHandshakes:
    """Tests for wireshark_extract_tls_handshakes."""

    @pytest.mark.asyncio
    async def test_client_hello_query(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["ip.src", "ip.dst", "tcp.dstport", "tls.handshake.version",
             "tls.handshake.ciphersuite", "tls.handshake.extensions.server_name"],
            display_filter="tls.handshake.type == 1",
            limit=50,
        )
        assert "tls.handshake.type == 1" in result
        assert "-e tls.handshake.extensions.server_name" in result


class TestAnalyzeTcpHealth:
    """Tests for TCP health analysis queries."""

    @pytest.mark.asyncio
    async def test_retransmission_query(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_packet_list(
            "test.pcap", limit=10000, display_filter="tcp.analysis.retransmission"
        )
        assert "tcp.analysis.retransmission" in result

    @pytest.mark.asyncio
    async def test_reset_query(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_packet_list(
            "test.pcap", limit=10000, display_filter="tcp.flags.reset == 1"
        )
        assert "tcp.flags.reset == 1" in result


class TestDetectArpSpoofing:
    """Tests for ARP spoofing detection queries."""

    @pytest.mark.asyncio
    async def test_arp_extraction(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["arp.src.hw_mac", "arp.src.proto_ipv4", "arp.dst.proto_ipv4", "arp.opcode"],
            display_filter="arp",
            limit=5000,
        )
        assert "-e arp.src.hw_mac" in result
        assert "-e arp.opcode" in result


class TestExtractSmtpEmails:
    """Tests for SMTP email extraction queries."""

    @pytest.mark.asyncio
    async def test_smtp_extraction(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["ip.src", "ip.dst", "smtp.req.parameter", "smtp.rsp.parameter"],
            display_filter="smtp",
            limit=50,
        )
        assert "-e smtp.req.parameter" in result


class TestExtractDhcpInfo:
    """Tests for DHCP info extraction queries."""

    @pytest.mark.asyncio
    async def test_dhcp_extraction(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["bootp.type", "bootp.hw.mac_addr", "bootp.ip.your", "bootp.ip.server",
             "bootp.option.hostname", "bootp.option.dhcp", "bootp.option.requested_ip_address",
             "bootp.option.domain_name_server"],
            display_filter="bootp",
            limit=200,
        )
        assert "-e bootp.ip.your" in result
