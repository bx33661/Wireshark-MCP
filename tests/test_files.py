"""Tests for file operation tools."""

import pytest

from conftest import MockTSharkClient


class TestGetFileInfo:
    """Tests for get_file_info."""

    @pytest.mark.asyncio
    async def test_capinfos_command(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_file_info("test.pcap")
        assert "capinfos" in result
        assert "test.pcap" in result


class TestMergePcapFiles:
    """Tests for merge_pcap_files."""

    @pytest.mark.asyncio
    async def test_merge_command(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.merge_pcap_files("merged.pcap", ["a.pcap", "b.pcap"])
        assert "mergecap" in result
        assert "-w merged.pcap" in result
        assert "a.pcap" in result
        assert "b.pcap" in result
