"""Tests for anomaly detection tools."""

import pytest
from conftest import MockTSharkClient

from wireshark_mcp.tools.anomaly import _compute_jitter, _parse_tsv_rows


class TestBeaconDetection:
    """Tests for wireshark_detect_beaconing."""

    @pytest.mark.asyncio
    async def test_beacon_extracts_connection_timing(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["ip.src", "ip.dst", "tcp.dstport", "frame.time_epoch"],
            display_filter="tcp.flags.syn == 1 && tcp.flags.ack == 0",
            limit=10000,
        )
        assert "frame.time_epoch" in result
        assert "tcp.flags.syn == 1" in result

    @pytest.mark.asyncio
    async def test_beacon_uses_correct_fields(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["ip.src", "ip.dst", "tcp.dstport", "frame.time_epoch"],
            display_filter="tcp.flags.syn == 1 && tcp.flags.ack == 0",
            limit=10000,
        )
        assert "-e ip.src" in result
        assert "-e ip.dst" in result
        assert "-e tcp.dstport" in result
        assert "-e frame.time_epoch" in result


class TestComputeJitter:
    """Tests for _compute_jitter helper."""

    def test_perfectly_periodic(self) -> None:
        intervals = [1.0, 1.0, 1.0, 1.0, 1.0]
        assert _compute_jitter(intervals) == 0.0

    def test_high_jitter(self) -> None:
        intervals = [0.1, 10.0, 0.5, 8.0, 0.2]
        jitter = _compute_jitter(intervals)
        assert jitter > 0.5

    def test_single_interval(self) -> None:
        assert _compute_jitter([1.0]) == 1.0

    def test_empty_intervals(self) -> None:
        assert _compute_jitter([]) == 1.0

    def test_zero_mean(self) -> None:
        assert _compute_jitter([0.0, 0.0, 0.0]) == 1.0


class TestParseTsvRows:
    """Tests for _parse_tsv_rows helper."""

    def test_basic_parsing(self) -> None:
        data = "col1\tcol2\tcol3\nval1\tval2\tval3\nval4\tval5\tval6"
        rows = _parse_tsv_rows(data)
        assert len(rows) == 3
        assert rows[0] == ["col1", "col2", "col3"]
        assert rows[1] == ["val1", "val2", "val3"]

    def test_skips_comments(self) -> None:
        data = "# comment\ncol1\tcol2\nval1\tval2"
        rows = _parse_tsv_rows(data)
        assert len(rows) == 2

    def test_skips_empty_lines(self) -> None:
        data = "col1\tcol2\n\nval1\tval2\n\n"
        rows = _parse_tsv_rows(data)
        assert len(rows) == 2


class TestExfiltrationDetection:
    """Tests for wireshark_detect_exfiltration."""

    @pytest.mark.asyncio
    async def test_exfil_extracts_outbound_volumes(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["ip.src", "ip.dst", "tcp.dstport", "tcp.len"],
            display_filter="tcp && !ip.dst == 10.0.0.0/8 && !ip.dst == 172.16.0.0/12 && !ip.dst == 192.168.0.0/16",
            limit=10000,
        )
        assert "tcp.len" in result
        assert "10.0.0.0/8" in result

    @pytest.mark.asyncio
    async def test_exfil_checks_dns_length(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_fields(
            "test.pcap",
            ["ip.src", "dns.qry.name", "dns.qry.name.len"],
            display_filter="dns.qry.name.len > 50",
            limit=1000,
        )
        assert "dns.qry.name.len > 50" in result
