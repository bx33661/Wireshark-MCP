"""Tests verifying concurrent execution in agents and TCP health."""

import asyncio
import json
import time
from unittest.mock import AsyncMock

import pytest
from conftest import MockTSharkClient

from wireshark_mcp.tools.agents import _run_quick_analysis


class SlowMockClient(MockTSharkClient):
    """Mock client that adds a small delay to simulate I/O."""

    def __init__(self, delay: float = 0.05) -> None:
        super().__init__()
        self._delay = delay
        self._call_count = 0
        self._active = 0
        self._peak = 0

    async def _run_command(self, cmd: list[str], limit_lines: int = 0, offset_lines: int = 0, timeout: int = 30) -> str:
        self._call_count += 1
        await asyncio.sleep(self._delay)
        return "CMD: " + " ".join(cmd)

    async def stream_fields(self, *args, **kwargs):
        self._call_count += 1
        self._active += 1
        self._peak = max(self._peak, self._active)
        try:
            await asyncio.sleep(self._delay)
        finally:
            self._active -= 1
        return {"success": True, "rows": 0}


class TestConcurrentQuickAnalysis:
    @pytest.mark.asyncio
    async def test_udp_overview_skips_absent_protocol_scans(self) -> None:
        client = MockTSharkClient()
        client.get_protocol_stats = AsyncMock(return_value=client._ok(
            "frame frames:20 bytes:1000\n  ip frames:20 bytes:1000\n    udp frames:20 bytes:1000"
        ))
        client.get_conversations = AsyncMock()
        client.extract_fields = AsyncMock()
        result = json.loads(await _run_quick_analysis(client, "udp.pcap"))
        assert result["success"]
        client.get_conversations.assert_not_awaited()
        client.extract_fields.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_quick_analysis_runs_concurrently(self) -> None:
        client = SlowMockClient(delay=0.02)
        start = time.monotonic()
        result = await _run_quick_analysis(client, "test.pcap")
        elapsed = time.monotonic() - start
        data = json.loads(result)
        assert data["success"]
        # 7 concurrent fetches at 0.02s each: sequential ~0.14s, concurrent ~0.04s
        assert elapsed < 0.12, f"Took {elapsed:.2f}s — likely not concurrent"


class TestConcurrentTcpHealth:
    @pytest.mark.asyncio
    async def test_tcp_health_concurrent_checks(self) -> None:
        from wireshark_mcp.tools.protocol import make_protocol_tools

        client = SlowMockClient(delay=0.02)
        tools = make_protocol_tools(client)
        tcp_health_fn = next(fn for name, fn in tools if name == "wireshark_analyze_tcp_health")

        start = time.monotonic()
        result = await tcp_health_fn("test.pcap")
        elapsed = time.monotonic() - start

        data = json.loads(result)
        assert data["success"]
        assert 1 < client._peak <= 3
        assert elapsed < 0.3, f"Took {elapsed:.2f}s — unexpected scheduling delay"
