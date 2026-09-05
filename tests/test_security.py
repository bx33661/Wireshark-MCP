"""Tests for security tools and credential extraction."""

from unittest.mock import AsyncMock

import pytest

from wireshark_mcp.tools.envelope import parse_tool_result, success_response
from wireshark_mcp.tools.findings import mask_secret
from wireshark_mcp.tools.security import make_security_tools


class TestSecretMasking:
    def test_mask_secret_with_user_pass(self) -> None:
        masked = mask_secret("admin:secret123")
        assert masked.startswith("admin:s")
        assert "secret123" not in masked
        assert "*" in masked

    def test_mask_short_password(self) -> None:
        masked = mask_secret("123456")
        assert masked == "1*****"
        assert "123456" not in masked

    def test_mask_very_short_secret(self) -> None:
        masked = mask_secret("ab")
        assert masked == "**"


class TestExtractCredentials:
    @pytest.mark.asyncio
    async def test_extract_short_credentials_not_dropped(self) -> None:
        mock_client = AsyncMock()

        # Simulate TSV with short credentials: frame, stream, src, dst, cred
        mock_client.extract_fields.side_effect = [
            # HTTP Basic Auth: short credentials admin:pw (8 chars!)
            success_response("1\t0\t192.168.1.10\t192.168.1.1\tadmin:pw\n"),
            # FTP PASS: short password 123 (3 chars!)
            success_response("5\t1\t192.168.1.10\t192.168.1.2\t123\n"),
        ]
        mock_client.search_packet_contents.return_value = success_response("")

        tools = dict(make_security_tools(mock_client))
        raw_result = await tools["wireshark_extract_credentials"]("test.pcap")
        parsed = parse_tool_result(raw_result)

        assert parsed["success"] is True
        data = parsed["data"]
        assert "findings" in data
        assert len(data["findings"]) == 1

        finding = data["findings"][0]
        assert finding["severity"] == "high"
        assert finding["confidence"] == "confirmed"

        evidence = finding["evidence"]
        # Both HTTP and FTP credentials MUST be present, despite being < 20 chars!
        protocols = [e["protocol"] for e in evidence]
        assert "HTTP" in protocols
        assert "FTP" in protocols

        # Check evidence anchors
        http_ev = next(e for e in evidence if e["protocol"] == "HTTP")
        assert http_ev["frame"] == 1
        assert http_ev["stream"] == 0
        assert "admin:" in http_ev["value"]
        assert "admin:pw" not in http_ev["value"]  # masked!

        ftp_ev = next(e for e in evidence if e["protocol"] == "FTP")
        assert ftp_ev["frame"] == 5
        assert ftp_ev["stream"] == 1
        assert ftp_ev["value"] == "1**"

    @pytest.mark.asyncio
    async def test_no_credentials_returns_clean_coverage(self) -> None:
        mock_client = AsyncMock()
        mock_client.extract_fields.return_value = success_response("")
        mock_client.search_packet_contents.return_value = success_response("")

        tools = dict(make_security_tools(mock_client))
        raw_result = await tools["wireshark_extract_credentials"]("test.pcap")
        parsed = parse_tool_result(raw_result)

        assert parsed["success"] is True
        assert parsed["data"]["findings"] == []
        assert "No plaintext credentials" in parsed["data"]["summary"]
        assert parsed["coverage"]["status"] == "complete"
