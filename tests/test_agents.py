"""Tests for Agentic Workflow super tools."""

import json

import pytest

from conftest import MockTSharkClient
from wireshark_mcp.tools.agents import _count_lines, _extract_data, _run_security_audit, _run_quick_analysis
from wireshark_mcp.tools.envelope import success_response, normalize_tool_result


class TestHelpers:
    """Tests for shared helper functions."""

    def test_count_lines_with_header(self) -> None:
        data = "header\nline1\nline2\nline3"
        assert _count_lines(data) == 3

    def test_count_lines_empty(self) -> None:
        assert _count_lines("") == 0
        assert _count_lines("\n\n") == 0

    def test_extract_data_success(self) -> None:
        result = success_response("some meaningful data here")
        assert _extract_data(result) == "some meaningful data here"

    def test_extract_data_failure(self) -> None:
        result = json.dumps({"success": False, "error": {"type": "FileNotFound"}})
        assert _extract_data(result) is None

    def test_extract_data_short(self) -> None:
        result = success_response("tiny")
        assert _extract_data(result) is None


class TestSecurityAudit:
    """Tests for security audit super tool."""

    @pytest.mark.asyncio
    async def test_returns_risk_level(self, mock_client: MockTSharkClient) -> None:
        result = await _run_security_audit(mock_client, "test.pcap")
        data = json.loads(result)
        assert data["success"]
        output = data["data"]
        assert "SECURITY AUDIT REPORT" in output
        assert "RISK LEVEL" in output

    @pytest.mark.asyncio
    async def test_contains_all_sections(self, mock_client: MockTSharkClient) -> None:
        result = await _run_security_audit(mock_client, "test.pcap")
        data = json.loads(result)
        output = data["data"]
        assert "File Summary" in output
        assert "Protocol Overview" in output
        assert "Threat Intelligence" in output
        assert "Credential Exposure" in output
        assert "Port Scanning" in output
        assert "DNS Anomaly" in output
        assert "Cleartext Protocol" in output
        assert "Protocol Anomalies" in output
        assert "Recommendations" in output

    @pytest.mark.asyncio
    async def test_returns_valid_json(self, mock_client: MockTSharkClient) -> None:
        result = await _run_security_audit(mock_client, "test.pcap")
        data = json.loads(result)
        assert "success" in data
        assert data["success"] is True


class TestQuickAnalysis:
    """Tests for quick analysis super tool."""

    @pytest.mark.asyncio
    async def test_returns_report(self, mock_client: MockTSharkClient) -> None:
        result = await _run_quick_analysis(mock_client, "test.pcap")
        data = json.loads(result)
        assert data["success"]
        output = data["data"]
        assert "QUICK ANALYSIS REPORT" in output

    @pytest.mark.asyncio
    async def test_contains_all_sections(self, mock_client: MockTSharkClient) -> None:
        result = await _run_quick_analysis(mock_client, "test.pcap")
        data = json.loads(result)
        output = data["data"]
        assert "Capture File Info" in output
        assert "Protocol Distribution" in output
        assert "Top Talkers" in output
        assert "Top Conversations" in output
        assert "Key Hostnames" in output
        assert "Anomaly Summary" in output
        assert "Suggested Next Steps" in output

    @pytest.mark.asyncio
    async def test_returns_valid_json(self, mock_client: MockTSharkClient) -> None:
        result = await _run_quick_analysis(mock_client, "test.pcap")
        data = json.loads(result)
        assert "success" in data
        assert data["success"] is True
