"""Tests for ICS/SCADA protocol analysis tools."""

import pytest
from conftest import MockTSharkClient


class TestModbusTcp:
    """Tests for wireshark_analyze_modbus."""

    @pytest.mark.asyncio
    async def test_modbus_function_code_extraction(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            [
                "ip.src",
                "ip.dst",
                "tcp.srcport",
                "tcp.dstport",
                "mbtcp.trans_id",
                "mbtcp.unit_id",
                "modbus.func_code",
                "modbus.exception_code",
            ],
            display_filter="modbus",
            limit=100,
        )
        assert "modbus" in result
        assert "-e modbus.func_code" in result
        assert "-e mbtcp.trans_id" in result

    @pytest.mark.asyncio
    async def test_modbus_write_operations(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            [
                "ip.src",
                "ip.dst",
                "modbus.func_code",
                "modbus.reference_num",
                "modbus.data",
            ],
            display_filter="modbus.func_code in {5 6 15 16}",
            limit=100,
        )
        assert "modbus.func_code in {5 6 15 16}" in result
        assert "-e modbus.reference_num" in result
        assert "-e modbus.data" in result
