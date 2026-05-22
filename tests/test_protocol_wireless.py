"""Tests for wireless and tunneling protocol analysis tools."""

import pytest
from conftest import MockTSharkClient


class TestBluetoothLE:
    @pytest.mark.asyncio
    async def test_ble_hci_extraction(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["btle.advertising_address", "btle.data_header.llid", "btle.length", "btatt.opcode", "btatt.handle", "btl2cap.cid"],
            display_filter="btle",
            limit=100,
        )
        assert "btle" in result
        assert "-e btle.advertising_address" in result


class TestWifi80211:
    @pytest.mark.asyncio
    async def test_wifi_management_frames(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["wlan.sa", "wlan.da", "wlan.bssid", "wlan.fc.type_subtype", "wlan.ssid", "wlan.rsn.akms.type"],
            display_filter="wlan.fc.type == 0",
            limit=100,
        )
        assert "wlan.fc.type == 0" in result
        assert "-e wlan.ssid" in result


class TestWireGuard:
    @pytest.mark.asyncio
    async def test_wireguard_handshake_extraction(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["ip.src", "ip.dst", "udp.dstport", "wg.type", "wg.sender", "wg.receiver"],
            display_filter="wg",
            limit=100,
        )
        assert "wg" in result
        assert "-e wg.type" in result


class TestDnsOverHttps:
    @pytest.mark.asyncio
    async def test_doh_detection(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["ip.src", "ip.dst", "http2.header.value"],
            display_filter='http2.header.name == "content-type" && http2.header.value contains "dns"',
            limit=100,
        )
        assert "dns" in result


class TestIcmpTunnel:
    @pytest.mark.asyncio
    async def test_icmp_payload_size_extraction(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["ip.src", "ip.dst", "icmp.type", "data.len"],
            display_filter="icmp && data.len > 48",
            limit=100,
        )
        assert "icmp" in result
        assert "data.len > 48" in result
