"""Tests for extract tools and TSharkClient packet reading methods."""

import pytest
from conftest import MockTSharkClient


class TestGetPacketList:
    """Tests for get_packet_list command construction."""

    @pytest.mark.asyncio
    async def test_default_columns(self, mock_client: MockTSharkClient) -> None:
        res = await mock_client.get_packet_list("test.pcap")
        assert "-e frame.number" in res
        assert "-e _ws.col.Info" in res
        assert "-e _ws.col.Source" in res

    @pytest.mark.asyncio
    async def test_custom_columns(self, mock_client: MockTSharkClient) -> None:
        res = await mock_client.get_packet_list("test.pcap", custom_columns=["ip.src", "http.host"])
        assert "-e ip.src" in res
        assert "-e http.host" in res
        assert "-e _ws.col.Info" not in res

    @pytest.mark.asyncio
    async def test_display_filter(self, mock_client: MockTSharkClient) -> None:
        res = await mock_client.get_packet_list("test.pcap", display_filter="http")
        assert "-Y http" in res


class TestGetPacketDetails:
    """Tests for get_packet_details command construction."""

    @pytest.mark.asyncio
    async def test_with_layer_filter(self, mock_client: MockTSharkClient) -> None:
        res = await mock_client.get_packet_details("test.pcap", 42, included_layers=["ip", "http"])
        assert "-Y frame.number == 42" in res
        assert "-j ip http" in res

    @pytest.mark.asyncio
    async def test_without_layer_filter(self, mock_client: MockTSharkClient) -> None:
        res = await mock_client.get_packet_details("test.pcap", 42)
        assert "-Y frame.number == 42" in res
        assert "-j" not in res


class TestExtractFields:
    """Tests for extract_fields command construction."""

    @pytest.mark.asyncio
    async def test_basic_extraction(self, mock_client: MockTSharkClient) -> None:
        res = await mock_client.extract_fields("test.pcap", ["ip.src", "ip.dst"])
        assert "-e ip.src" in res
        assert "-e ip.dst" in res
        assert "header=y" in res

    @pytest.mark.asyncio
    async def test_with_filter(self, mock_client: MockTSharkClient) -> None:
        res = await mock_client.extract_fields("test.pcap", ["http.host"], display_filter="http.request")
        assert "-Y http.request" in res


class TestSearchPacketContents:
    """Tests for search_packet_contents filter construction."""

    @pytest.mark.asyncio
    async def test_string_search_bytes_scope(self, mock_client: MockTSharkClient) -> None:
        res = await mock_client.search_packet_contents("test.pcap", "password", scope="bytes")
        assert 'frame contains "password"' in res

    @pytest.mark.asyncio
    async def test_regex_search_details_scope(self, mock_client: MockTSharkClient) -> None:
        res = await mock_client.search_packet_contents("test.pcap", "pass.*word", search_type="regex", scope="details")
        assert 'frame matches "pass.*word"' in res

    @pytest.mark.asyncio
    async def test_filter_scope(self, mock_client: MockTSharkClient) -> None:
        res = await mock_client.search_packet_contents("test.pcap", "http.response.code == 200", scope="filter")
        assert "http.response.code == 200" in res
