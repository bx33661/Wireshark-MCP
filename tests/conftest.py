"""Shared fixtures for Wireshark MCP tests."""

import shutil
import tempfile
from pathlib import Path
from typing import Any

import pytest
from mcp.server import MCPServer
from mcp.types import CallToolResult, TextContent

from wireshark_mcp.tshark.client import TSharkClient


async def call_tool_text(mcp: MCPServer, name: str, arguments: dict[str, Any]) -> str:
    """Invoke a tool through the public MCPServer v2 API and return its text block."""
    result = await mcp.call_tool(name, arguments)
    assert isinstance(result, CallToolResult)
    assert len(result.content) == 1
    content = result.content[0]
    assert isinstance(content, TextContent)
    return content.text


class MockTSharkClient(TSharkClient):
    """TSharkClient that returns predictable results without calling real tshark."""

    def __init__(self, allowed_dirs: list[str] | None = None) -> None:
        self.tshark_path = "tshark"
        self.capinfos_path = "capinfos"
        self.mergecap_path = "mergecap"
        self.editcap_path = "editcap"
        self.dumpcap_path = "dumpcap"
        self.text2pcap_path = "text2pcap"
        self._tool_paths = {
            "tshark": self.tshark_path,
            "capinfos": self.capinfos_path,
            "mergecap": self.mergecap_path,
            "editcap": self.editcap_path,
            "dumpcap": self.dumpcap_path,
            "text2pcap": self.text2pcap_path,
        }
        self._version: str | None = None
        self._allowed_dirs = [Path(d).resolve() for d in allowed_dirs] if allowed_dirs else None
        self._last_cmd: list[str] = []
        # Line capping is applied by the runner rather than argv, so tests that need to
        # assert a caller's `limit` reached tshark have to read it from here.
        self._last_limit_lines: int = 0
        # Every command, in order. Tools that make several tshark passes (a request plus
        # its response, a summary plus a breakout) would otherwise only expose the last.
        self._commands: list[list[str]] = []

    def fields_requested(self) -> set[str]:
        """Every `-e` field across all recorded commands, as exact tokens.

        Tests assert against this rather than searching the echoed command string:
        `"-e foo.bar" in cmd_text` is also true when the tool asked for `foo.barbaz`,
        so a mistyped field name would pass.
        """
        fields: set[str] = set()
        for cmd in self._commands:
            fields.update(arg for prev, arg in zip(cmd, cmd[1:], strict=False) if prev == "-e")
        return fields

    def filters_applied(self) -> set[str]:
        """Every `-Y` display filter across all recorded commands."""
        filters: set[str] = set()
        for cmd in self._commands:
            filters.update(arg for prev, arg in zip(cmd, cmd[1:], strict=False) if prev == "-Y")
        return filters

    def _validate_file(self, filepath: str) -> dict[str, Any]:
        """Always succeed for mock, unless sandbox is enabled."""
        if self._allowed_dirs:
            return super()._validate_file(filepath)
        return {"success": True}

    def _validate_output_path(self, filepath: str) -> dict[str, Any]:
        """Allow command-construction tests to write nowhere; real clients stay fail-closed."""
        if self._allowed_dirs:
            return super()._validate_output_path(filepath)
        return {"success": True}

    @staticmethod
    def _tool_is_available(tool_path: str | None) -> bool:
        """Treat any configured mock command name as available."""
        return bool(tool_path)

    async def _run_command(
        self,
        cmd: list[str],
        limit_lines: int = 0,
        offset_lines: int = 0,
        timeout: int = 30,
        stream_limit: bool = False,
    ) -> str:
        self._last_cmd = cmd
        self._last_limit_lines = limit_lines
        self._last_stream_limit = stream_limit
        self._commands.append(list(cmd))
        # Mirror the real client's contract: always return a success envelope.
        return self._ok("CMD: " + " ".join(cmd))


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
