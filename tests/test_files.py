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


class TestEditcapTools:
    """Tests for editcap-backed helpers."""

    @pytest.mark.asyncio
    async def test_editcap_trim_command(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.editcap_trim(
            "input.pcap",
            "trimmed.pcap",
            start_time="2026-03-14T10:00:00",
            stop_time="2026-03-14T10:05:00",
        )
        assert "editcap" in result
        assert "-A 2026-03-14T10:00:00" in result
        assert "-B 2026-03-14T10:05:00" in result

    @pytest.mark.asyncio
    async def test_editcap_split_command(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.editcap_split("input.pcap", "split-output", packets_per_file=500)
        assert "editcap" in result
        assert "-c 500" in result
        assert "split-output" in result

    @pytest.mark.asyncio
    async def test_editcap_time_shift_command(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.editcap_time_shift("input.pcap", "shifted.pcap", 1.5)
        assert "editcap" in result
        assert "-t 1.5" in result

    @pytest.mark.asyncio
    async def test_editcap_deduplicate_command(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.editcap_deduplicate("input.pcap", "deduped.pcap", duplicate_window=8)
        assert "editcap" in result
        assert "-D 8" in result


class TestText2PcapTools:
    """Tests for text2pcap-backed helpers."""

    @pytest.mark.asyncio
    async def test_text2pcap_import_command(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.text2pcap_import(
            "hexdump.txt",
            "imported.pcapng",
            encapsulation="ether",
            timestamp_format="%H:%M:%S.%f",
            ascii_mode=True,
        )
        assert "text2pcap" in result
        assert '-t %H:%M:%S.%f' in result
        assert "-a" in result
        assert "-E ether" in result
