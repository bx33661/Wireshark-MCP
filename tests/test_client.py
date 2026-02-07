"""
Basic test suite for Wireshark MCP.
Run with: pytest tests/test_client.py
"""
import pytest
import asyncio
from pathlib import Path
from src.wireshark_mcp.tshark.client import TSharkClient

@pytest.fixture
def client():
    return TSharkClient()

@pytest.fixture
def sample_pcap(tmp_path):
    """Create a dummy pcap file for testing."""
    pcap = tmp_path / "test.pcap"
    pcap.write_bytes(b"")  # Empty file for validation tests
    return str(pcap)

class TestValidation:
    """Test parameter validation"""
    
    @pytest.mark.asyncio
    async def test_validate_file_not_found(self, client):
        result = client._validate_file("/nonexistent/file.pcap")
        assert result["success"] == False
        assert result["error"]["type"] == "FileNotFound"
        
    @pytest.mark.asyncio
    async def test_validate_file_exists(self, client, sample_pcap):
        result = client._validate_file(sample_pcap)
        assert result["success"] == True
        
    @pytest.mark.asyncio
    async def test_validate_protocol_valid(self, client):
        result = client._validate_protocol("tcp", client.VALID_ENDPOINT_TYPES)
        assert result["success"] == True
        
    @pytest.mark.asyncio
    async def test_validate_protocol_invalid(self, client):
        result = client._validate_protocol("invalid", client.VALID_ENDPOINT_TYPES)
        assert result["success"] == False
        assert result["error"]["type"] == "InvalidParameter"

class TestCapabilities:
    """Test capability detection"""
    
    @pytest.mark.asyncio
    async def test_check_capabilities(self, client):
        result = await client.check_capabilities()
        assert result["success"] == True
        assert "tshark" in result["data"]
        assert "available" in result["data"]["tshark"]

class TestErrorHandling:
    """Test error responses"""
    
    @pytest.mark.asyncio
    async def test_file_not_found_error(self, client):
        result = await client.get_protocol_stats("/nonexistent.pcap")
        import json
        error = json.loads(result)
        assert error["success"] == False
        assert error["error"]["type"] == "FileNotFound"
