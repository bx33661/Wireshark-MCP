"""Tests for TSharkClient core functionality."""

import json
from pathlib import Path

import pytest

from wireshark_mcp.tshark.client import TSharkClient


class TestValidation:
    """Tests for file and protocol validation."""

    def test_validate_file_not_found(self, real_client: TSharkClient) -> None:
        result = real_client._validate_file("/nonexistent/file.pcap")
        assert not result["success"]
        assert result["error"]["type"] == "FileNotFound"

    def test_validate_file_empty_path(self, real_client: TSharkClient) -> None:
        result = real_client._validate_file("")
        assert not result["success"]
        assert result["error"]["type"] == "InvalidParameter"

    def test_validate_file_exists(self, tmp_pcap: str, real_client: TSharkClient) -> None:
        result = real_client._validate_file(tmp_pcap)
        assert result["success"]

    def test_validate_file_is_directory(self, tmp_dir: str, real_client: TSharkClient) -> None:
        result = real_client._validate_file(tmp_dir)
        assert not result["success"]
        assert result["error"]["type"] == "InvalidParameter"

    def test_validate_protocol_valid(self, real_client: TSharkClient) -> None:
        result = real_client._validate_protocol("tcp", TSharkClient.VALID_ENDPOINT_TYPES)
        assert result["success"]

    def test_validate_protocol_invalid(self, real_client: TSharkClient) -> None:
        result = real_client._validate_protocol("invalid", TSharkClient.VALID_ENDPOINT_TYPES)
        assert not result["success"]
        assert result["error"]["type"] == "InvalidParameter"

    def test_validate_protocol_case_insensitive(self, real_client: TSharkClient) -> None:
        result = real_client._validate_protocol("TCP", TSharkClient.VALID_ENDPOINT_TYPES)
        assert result["success"]


class TestSandbox:
    """Tests for path sandbox enforcement."""

    def test_sandbox_allows_file_in_allowed_dir(self, tmp_dir: str, tmp_pcap: str) -> None:
        client = TSharkClient(allowed_dirs=[tmp_dir])
        result = client._validate_file(tmp_pcap)
        assert result["success"]

    def test_sandbox_blocks_file_outside_allowed_dir(self, tmp_dir: str) -> None:
        client = TSharkClient(allowed_dirs=[tmp_dir])
        result = client._validate_file("/etc/passwd")
        assert not result["success"]
        assert result["error"]["type"] == "PermissionDenied"

    def test_sandbox_blocks_path_traversal(self, tmp_dir: str) -> None:
        client = TSharkClient(allowed_dirs=[tmp_dir])
        malicious_path = f"{tmp_dir}/../../../etc/passwd"
        result = client._validate_file(malicious_path)
        assert not result["success"]
        assert result["error"]["type"] == "PermissionDenied"

    def test_no_sandbox_allows_any_path(self, tmp_pcap: str) -> None:
        client = TSharkClient()
        result = client._validate_file(tmp_pcap)
        assert result["success"]

    def test_sandbox_output_path_validation(self, tmp_dir: str) -> None:
        client = TSharkClient(allowed_dirs=[tmp_dir])
        result = client._validate_output_path(f"{tmp_dir}/output.pcap")
        assert result["success"]

        result = client._validate_output_path("/tmp/evil/output.pcap")
        assert not result["success"]


class TestCapabilities:
    """Tests for check_capabilities."""

    @pytest.mark.asyncio
    async def test_check_capabilities(self, real_client: TSharkClient) -> None:
        result = await real_client.check_capabilities()
        assert result["success"]
        assert "tshark" in result["data"]
        assert "capinfos" in result["data"]


class TestRunCommand:
    """Tests for _run_command error handling."""

    @pytest.mark.asyncio
    async def test_file_not_found_returns_error(self, real_client: TSharkClient) -> None:
        result_str = await real_client.get_protocol_stats("/nonexistent.pcap")
        result = json.loads(result_str)
        assert not result["success"]
        assert result["error"]["type"] == "FileNotFound"

    @pytest.mark.asyncio
    async def test_binary_whitelist_blocks_unknown(self, real_client: TSharkClient) -> None:
        result_str = await real_client._run_command(["curl", "http://evil.com"])
        result = json.loads(result_str)
        assert not result["success"]
        assert result["error"]["type"] == "SecurityError"
