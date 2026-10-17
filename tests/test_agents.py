"""Tests for Agentic Workflow super tools."""

import json

import pytest
from conftest import MockTSharkClient

from wireshark_mcp.tools.agents import _extract_data, _run_quick_analysis
from wireshark_mcp.tools.envelope import success_response


class TestHelpers:
    """Tests for shared helper functions."""

    def test_extract_data_success(self) -> None:
        result = success_response("some meaningful data here")
        assert _extract_data(result) == "some meaningful data here"

    def test_extract_data_failure(self) -> None:
        result = json.dumps({"success": False, "error": {"type": "FileNotFound"}})
        assert _extract_data(result) is None

    def test_extract_data_short(self) -> None:
        result = success_response("tiny")
        assert _extract_data(result) is None


class TestQuickAnalysis:
    """Tests for quick analysis super tool."""

    @pytest.mark.asyncio
    async def test_returns_report(self, mock_client: MockTSharkClient) -> None:
        result = await _run_quick_analysis(mock_client, "test.pcap")
        data = json.loads(result)
        assert data["success"]
        output = data["data"]["report"]
        assert "## Quick Analysis" in output

    @pytest.mark.asyncio
    async def test_contains_all_sections(self, mock_client: MockTSharkClient) -> None:
        result = await _run_quick_analysis(mock_client, "test.pcap")
        data = json.loads(result)
        output = data["data"]["report"]
        assert "File Info" in output
        assert "Protocols" in output
        assert "Top Talkers" in output
        assert "Conversations" in output
        assert "Hostnames" in output
        assert "Anomalies" in output

    @pytest.mark.asyncio
    async def test_returns_valid_json(self, mock_client: MockTSharkClient) -> None:
        result = await _run_quick_analysis(mock_client, "test.pcap")
        data = json.loads(result)
        assert "success" in data
        assert data["success"] is True
