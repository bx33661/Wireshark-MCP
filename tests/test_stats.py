"""Tests for stats tools."""

import pytest

from conftest import MockTSharkClient


class TestProtocolHierarchy:
    """Tests for get_protocol_stats."""

    @pytest.mark.asyncio
    async def test_phs_command(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_protocol_stats("test.pcap")
        assert "-z io,phs" in result
        assert "-q" in result


class TestEndpoints:
    """Tests for get_endpoints."""

    @pytest.mark.asyncio
    async def test_default_ip_type(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_endpoints("test.pcap")
        assert "-z endpoints,ip" in result

    @pytest.mark.asyncio
    async def test_tcp_type(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_endpoints("test.pcap", type="tcp")
        assert "-z endpoints,tcp" in result


class TestConversations:
    """Tests for get_conversations."""

    @pytest.mark.asyncio
    async def test_default_type(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_conversations("test.pcap")
        assert "-z conv,ip" in result


class TestIOGraph:
    """Tests for get_io_graph."""

    @pytest.mark.asyncio
    async def test_default_interval(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_io_graph("test.pcap")
        assert "-z io,stat,1" in result

    @pytest.mark.asyncio
    async def test_custom_interval(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_io_graph("test.pcap", interval=5)
        assert "-z io,stat,5" in result


class TestExpertInfo:
    """Tests for get_expert_info."""

    @pytest.mark.asyncio
    async def test_expert_command(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_expert_info("test.pcap")
        assert "-z expert" in result


class TestServiceResponseTime:
    """Tests for get_service_response_time."""

    @pytest.mark.asyncio
    async def test_http_srt(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_service_response_time("test.pcap", protocol="http")
        assert "-z http,tree" in result
