"""Tests for forensics tools."""

import pytest
from conftest import MockTSharkClient


class TestFileCarving:
    """Tests for wireshark_carve_files."""

    @pytest.mark.asyncio
    async def test_carve_searches_magic_bytes(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.search_packet_contents(
            "test.pcap",
            "4d5a",
            search_type="hex",
            limit=50,
        )
        assert "4d5a" in result

    @pytest.mark.asyncio
    async def test_carve_searches_pdf_magic(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.search_packet_contents(
            "test.pcap",
            "255044462d",
            search_type="hex",
            limit=50,
        )
        assert "255044462d" in result


class TestJa3Fingerprints:
    """Tests for wireshark_extract_fingerprints."""

    @pytest.mark.asyncio
    async def test_ja3_field_extraction(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            [
                "ip.src",
                "ip.dst",
                "tcp.dstport",
                "tls.handshake.ja3",
                "tls.handshake.ja3s",
                "tls.handshake.extensions.server_name",
            ],
            display_filter="tls.handshake.type == 1",
            limit=100,
        )
        assert "tls.handshake.ja3" in result
        assert "tls.handshake.type == 1" in result

    @pytest.mark.asyncio
    async def test_ja3_uses_correct_filter(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            [
                "ip.src",
                "ip.dst",
                "tcp.dstport",
                "tls.handshake.ja3",
                "tls.handshake.ja3s",
                "tls.handshake.extensions.server_name",
            ],
            display_filter="tls.handshake.type == 1",
            limit=100,
        )
        assert "-Y" in result
        assert "tls.handshake.type == 1" in result
        assert "-e tls.handshake.ja3s" in result
        assert "-e tls.handshake.extensions.server_name" in result


class TestEvidenceChain:
    """Tests for wireshark_build_evidence_chain."""

    @pytest.mark.asyncio
    async def test_evidence_chain_extracts_dns(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["dns.qry.name", "dns.a", "dns.aaaa"],
            display_filter="dns.flags.response == 1",
            limit=500,
        )
        assert "dns.flags.response == 1" in result
        assert "-e dns.qry.name" in result

    @pytest.mark.asyncio
    async def test_evidence_chain_extracts_connections(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["ip.src", "ip.dst", "tcp.dstport", "frame.time_epoch"],
            display_filter="tcp.flags.syn == 1 && tcp.flags.ack == 0",
            limit=500,
        )
        assert "tcp.flags.syn == 1" in result
