"""Tests for capture tools."""

import pytest
from conftest import MockTSharkClient


class TestListInterfaces:
    """Tests for wireshark_list_interfaces."""

    @pytest.mark.asyncio
    async def test_calls_tshark_d(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.list_interfaces()
        assert "-D" in result


class TestCapturePackets:
    """Tests for capture_packets command construction."""

    @pytest.mark.asyncio
    async def test_basic_capture(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.capture_packets("eth0", "/tmp/out.pcap", duration=10)
        assert "-i eth0" in result
        assert "-w /tmp/out.pcap" in result
        assert "duration:10" in result

    @pytest.mark.asyncio
    async def test_capture_with_filter(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.capture_packets("eth0", "/tmp/out.pcap", capture_filter="port 80")
        assert "-f port 80" in result

    @pytest.mark.asyncio
    async def test_capture_with_packet_count(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.capture_packets("eth0", "/tmp/out.pcap", packet_count=100)
        assert "-c 100" in result

    @pytest.mark.asyncio
    async def test_capture_with_ring_buffer(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.capture_packets("eth0", "/tmp/out.pcap", ring_buffer="filesize:1024,files:5")
        assert "-b filesize:1024" in result
        assert "-b files:5" in result


class TestFilterAndSave:
    """Tests for filter_and_save command construction."""

    @pytest.mark.asyncio
    async def test_basic_filter(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.filter_and_save("input.pcap", "output.pcap", "http")
        assert "-r input.pcap" in result
        assert "-Y http" in result
        assert "-w output.pcap" in result
