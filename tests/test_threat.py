"""Tests for advanced threat detection tools."""

import pytest
from conftest import MockTSharkClient


class TestDetectPortScan:
    """Tests for port scan detection queries."""

    @pytest.mark.asyncio
    async def test_syn_scan_query(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["ip.src", "ip.dst", "tcp.dstport"],
            display_filter="tcp.flags.syn == 1 and tcp.flags.ack == 0",
            limit=10000,
        )
        assert "tcp.flags.syn == 1" in result
        assert "tcp.flags.ack == 0" in result

    @pytest.mark.asyncio
    async def test_synfin_check(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_packet_list(
            "test.pcap",
            limit=10,
            display_filter="tcp.flags.syn == 1 and tcp.flags.fin == 1",
        )
        assert "tcp.flags.fin == 1" in result

    @pytest.mark.asyncio
    async def test_null_scan_check(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_packet_list(
            "test.pcap",
            limit=10,
            display_filter="tcp.flags == 0",
        )
        assert "tcp.flags == 0" in result


class TestDetectDnsTunnel:
    """Tests for DNS tunnel detection queries."""

    @pytest.mark.asyncio
    async def test_dns_query_extraction(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["ip.src", "dns.qry.name", "dns.qry.type", "dns.resp.len"],
            display_filter="dns",
            limit=5000,
        )
        assert "-e dns.qry.name" in result
        assert "-e dns.qry.type" in result


class TestDetectDosAttack:
    """Tests for DoS detection queries."""

    @pytest.mark.asyncio
    async def test_syn_flood_check(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_packet_list(
            "test.pcap",
            limit=10000,
            display_filter="tcp.flags.syn == 1 and tcp.flags.ack == 0",
        )
        assert "tcp.flags.syn == 1" in result

    @pytest.mark.asyncio
    async def test_icmp_flood_check(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_packet_list(
            "test.pcap",
            limit=10000,
            display_filter="icmp",
        )
        assert "icmp" in result

    @pytest.mark.asyncio
    async def test_dns_amplification_check(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_packet_list(
            "test.pcap",
            limit=1000,
            display_filter="dns.flags.response == 1 and udp.length > 512",
        )
        assert "udp.length > 512" in result


class TestAnalyzeSuspiciousTraffic:
    """Tests for comprehensive suspicious traffic analysis queries."""

    @pytest.mark.asyncio
    async def test_ftp_cleartext_check(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_packet_list(
            "test.pcap",
            limit=5,
            display_filter="ftp",
        )
        assert "-Y ftp" in result

    @pytest.mark.asyncio
    async def test_expert_info_check(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_expert_info("test.pcap")
        assert "-z expert" in result
