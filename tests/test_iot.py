"""Tests for IoT protocol analysis tools."""

import pytest
from conftest import MockTSharkClient


class TestCoap:
    """Tests for wireshark_analyze_coap."""

    @pytest.mark.asyncio
    async def test_coap_request_extraction(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            [
                "ip.src",
                "ip.dst",
                "udp.srcport",
                "udp.dstport",
                "coap.type",
                "coap.code",
                "coap.opt.uri_path",
                "coap.token",
            ],
            display_filter="coap",
            limit=100,
        )
        assert "coap" in result
        assert "-e coap.code" in result
        assert "-e coap.opt.uri_path" in result


class TestMqtt5Deep:
    """Tests for wireshark_analyze_mqtt_deep."""

    @pytest.mark.asyncio
    async def test_mqtt5_connect_extraction(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            [
                "ip.src",
                "ip.dst",
                "mqtt.msgtype",
                "mqtt.topic",
                "mqtt.clientid",
                "mqtt.ver",
                "mqtt.prop.id",
            ],
            display_filter="mqtt",
            limit=100,
        )
        assert "mqtt" in result
        assert "-e mqtt.msgtype" in result
        assert "-e mqtt.prop.id" in result

    @pytest.mark.asyncio
    async def test_mqtt5_subscribe_extraction(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            [
                "ip.src",
                "mqtt.topic",
                "mqtt.sub.qos",
            ],
            display_filter="mqtt.msgtype == 8",
            limit=100,
        )
        assert "mqtt.msgtype == 8" in result
        assert "-e mqtt.topic" in result
        assert "-e mqtt.sub.qos" in result


class TestZigbee:
    """Tests for wireshark_analyze_zigbee."""

    @pytest.mark.asyncio
    async def test_zigbee_network_extraction(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            [
                "zbee_nwk.src",
                "zbee_nwk.dst",
                "zbee_nwk.frame_type",
                "zbee_aps.profile",
                "zbee_aps.cluster",
                "zbee_zcl.cmd.id",
            ],
            display_filter="zbee_nwk",
            limit=100,
        )
        assert "zbee_nwk" in result
        assert "-e zbee_nwk.src" in result
        assert "-e zbee_aps.cluster" in result
