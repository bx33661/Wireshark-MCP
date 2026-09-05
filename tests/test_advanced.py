"""Tests for advanced analysis tools (decode-as, decryption, stats, forensics)."""

import pytest
from conftest import MockTSharkClient

from wireshark_mcp.tools.envelope import parse_tool_result


class TestDecodeAs:
    @pytest.mark.asyncio
    async def test_builds_correct_command(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_with_decode_as(
            "/tmp/test.pcap",
            decode_rules=["tcp.port==8080,http"],
            fields=["frame.number", "ip.src"],
            display_filter="http",
            limit=50,
        )
        assert "-d" in result
        assert "tcp.port==8080,http" in result
        assert "-e" in result
        assert "frame.number" in result

    @pytest.mark.asyncio
    async def test_rejects_empty_rules(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_with_decode_as("/tmp/test.pcap", decode_rules=[], fields=[])
        assert "InvalidParameter" in result


class TestProtocolPrefs:
    @pytest.mark.asyncio
    async def test_builds_correct_command(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_with_prefs(
            "/tmp/test.pcap",
            prefs=["tcp.desegment_tcp_streams:TRUE"],
            fields=["frame.number", "ip.src"],
        )
        assert "-o" in result
        assert "tcp.desegment_tcp_streams:TRUE" in result

    @pytest.mark.asyncio
    async def test_rejects_empty_prefs(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_with_prefs("/tmp/test.pcap", prefs=[], fields=[])
        assert "InvalidParameter" in result


class TestDecryptTls:
    @pytest.mark.asyncio
    async def test_builds_correct_command(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.decrypt_tls_traffic("/tmp/test.pcap", "/tmp/keylog.txt")
        assert "tls.keylog_file:/tmp/keylog.txt" in result
        assert "http.request.method" in result


class TestDecryptWpa:
    @pytest.mark.asyncio
    async def test_builds_correct_command(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.decrypt_wpa_traffic("/tmp/test.pcap", wpa_keys=["mypassword:MySSID"])
        assert "wlan.enable_decryption:TRUE" in result
        assert "wpa-pwd:mypassword:MySSID" in result

    @pytest.mark.asyncio
    async def test_rejects_empty_keys(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.decrypt_wpa_traffic("/tmp/test.pcap", wpa_keys=[])
        assert "InvalidParameter" in result


class TestExtractFrames:
    @pytest.mark.asyncio
    async def test_rejects_empty_ranges(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.editcap_extract_frames("/tmp/test.pcap", "/tmp/out.pcap", "")
        assert "InvalidParameter" in result

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "ranges",
        ["-F pcap", "1-", "0", "1;touch /tmp/pwned", "10-2", "1000000001", "9" * 10000],
    )
    async def test_rejects_option_injection(self, mock_client: MockTSharkClient, ranges: str) -> None:
        result = await mock_client.editcap_extract_frames("/tmp/test.pcap", "/tmp/out.pcap", ranges)
        assert "InvalidParameter" in result

    @pytest.mark.asyncio
    async def test_accepts_positive_frames_and_ranges(self, mock_client: MockTSharkClient) -> None:
        await mock_client.editcap_extract_frames("/tmp/test.pcap", "/tmp/out.pcap", "1-10 15 20-30")
        assert mock_client._last_cmd[-3:] == ["1-10", "15", "20-30"]


class TestFlowGraph:
    @pytest.mark.asyncio
    async def test_builds_correct_command(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_flow_graph("/tmp/test.pcap", "tcp")
        assert "flow,tcp,network" in result

    @pytest.mark.asyncio
    async def test_rejects_invalid_type(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_flow_graph("/tmp/test.pcap", "invalid")
        assert "Invalid" in result or "error" in result.lower()


class TestIoStatFiltered:
    @pytest.mark.asyncio
    async def test_with_filters(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_io_stat_filtered("/tmp/test.pcap", interval=1, filters=["tcp", "udp"])
        assert "io,stat,1" in result
        assert '"tcp"' in parse_tool_result(result)["data"]
        assert '"udp"' in parse_tool_result(result)["data"]

    @pytest.mark.asyncio
    async def test_no_filters(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_io_stat_filtered("/tmp/test.pcap", interval=5)
        assert "io,stat,5" in result


class TestRtpStreams:
    @pytest.mark.asyncio
    async def test_builds_correct_command(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_rtp_streams("/tmp/test.pcap")
        assert "rtp,streams" in result


class TestSmbStats:
    @pytest.mark.asyncio
    async def test_builds_correct_command(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.get_smb_stats("/tmp/test.pcap")
        assert "smb,srt" in result


class TestKerberos:
    @pytest.mark.asyncio
    async def test_builds_correct_command(self, mock_client: MockTSharkClient) -> None:
        result = await mock_client.extract_kerberos("/tmp/test.pcap")
        assert "kerberos.msg_type" in result
        assert "kerberos.CNameString" in result
        assert "kerberos.realm" in result
