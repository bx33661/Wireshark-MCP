"""Tests for new protocol analysis tools (QUIC, WebSocket, MQTT, gRPC)."""

import pytest
from conftest import MockTSharkClient


class TestAnalyzeQuic:
    """Tests for wireshark_analyze_quic."""

    @pytest.mark.asyncio
    async def test_quic_field_extraction(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            [
                "ip.src",
                "ip.dst",
                "udp.dstport",
                "quic.version",
                "quic.connection.number",
                "tls.handshake.extensions.server_name",
            ],
            display_filter="quic",
            limit=100,
        )
        assert "quic" in result
        assert "-e quic.version" in result
        assert "-e tls.handshake.extensions.server_name" in result

    @pytest.mark.asyncio
    async def test_http3_field_extraction(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["ip.src", "ip.dst", "http3.frame_type"],
            display_filter="http3",
            limit=50,
        )
        assert "http3" in result
        assert "-e http3.frame_type" in result


class TestAnalyzeWebSocket:
    """Tests for wireshark_analyze_websocket."""

    @pytest.mark.asyncio
    async def test_websocket_field_extraction(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["ip.src", "ip.dst", "tcp.dstport", "websocket.opcode", "websocket.payload_length", "websocket.masked"],
            display_filter="websocket",
            limit=100,
        )
        assert "websocket" in result
        assert "-e websocket.opcode" in result
        assert "-e websocket.payload_length" in result


class TestAnalyzeMqtt:
    """Tests for wireshark_analyze_mqtt."""

    @pytest.mark.asyncio
    async def test_mqtt_field_extraction(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["ip.src", "ip.dst", "mqtt.msgtype", "mqtt.topic", "mqtt.qos", "mqtt.clientid"],
            display_filter="mqtt",
            limit=200,
        )
        assert "mqtt" in result
        assert "-e mqtt.topic" in result
        assert "-e mqtt.qos" in result


class TestAnalyzeGrpc:
    """Tests for wireshark_analyze_grpc."""

    @pytest.mark.asyncio
    async def test_grpc_field_extraction(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["ip.src", "ip.dst", "http2.header.value", "grpc.message_length"],
            display_filter="grpc",
            limit=100,
        )
        assert "grpc" in result
        assert "-e grpc.message_length" in result

    @pytest.mark.asyncio
    async def test_grpc_http2_fallback_query(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["ip.src", "ip.dst", "http2.headers.path", "http2.headers.content_type"],
            display_filter='http2 and http2.headers.content_type contains "grpc"',
            limit=100,
        )
        assert "http2" in result
        assert "grpc" in result
