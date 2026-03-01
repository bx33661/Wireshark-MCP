"""Shared fixtures for Wireshark MCP tests."""

import shutil
import tempfile
from pathlib import Path
from typing import Any

import pytest

from wireshark_mcp.tshark.client import TSharkClient


class MockTSharkClient(TSharkClient):
    """TSharkClient that returns predictable results without calling real tshark."""

    def __init__(self, allowed_dirs: list[str] | None = None) -> None:
        self.tshark_path = "tshark"
        self.capinfos_path = "capinfos"
        self.mergecap_path = "mergecap"
        self.editcap_path = "editcap"
        self._version: str | None = None
        self._allowed_dirs = [Path(d).resolve() for d in allowed_dirs] if allowed_dirs else None
        self._last_cmd: list[str] = []

    def _validate_file(self, filepath: str) -> dict[str, Any]:
        """Always succeed for mock, unless sandbox is enabled."""
        if self._allowed_dirs:
            return super()._validate_file(filepath)
        return {"success": True}

    async def _run_command(
        self,
        cmd: list[str],
        limit_lines: int = 0,
        offset_lines: int = 0,
        timeout: int = 30,
    ) -> str:
        self._last_cmd = cmd
        return "CMD: " + " ".join(cmd)


@pytest.fixture
def mock_client() -> MockTSharkClient:
    """Provide a MockTSharkClient instance."""
    return MockTSharkClient()


@pytest.fixture
def tmp_dir():
    """Provide a temporary directory that is cleaned up after the test."""
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d)


@pytest.fixture
def tmp_pcap(tmp_dir: str) -> str:
    """Provide a temporary empty pcap file path."""
    pcap_path = Path(tmp_dir) / "test.pcap"
    pcap_path.write_bytes(b"")
    return str(pcap_path)


@pytest.fixture
def real_client() -> TSharkClient:
    """Provide a real TSharkClient (for integration tests)."""
    return TSharkClient()


@pytest.fixture
def sandboxed_client(tmp_dir: str) -> TSharkClient:
    """Provide a TSharkClient with sandbox restricted to tmp_dir."""
    return TSharkClient(allowed_dirs=[tmp_dir])
