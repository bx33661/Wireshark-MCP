"""Tests for the ResultCache layer."""

import tempfile
import time
from pathlib import Path

import pytest

from wireshark_mcp.tshark.cache import ResultCache


@pytest.fixture
def cache() -> ResultCache:
    return ResultCache(max_entries=10, max_bytes=10000, ttl_seconds=2)


@pytest.fixture
def pcap_file() -> str:
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        f.write(b"\x00" * 100)
        return f.name


class TestCacheBasics:
    def test_put_and_get(self, cache: ResultCache, pcap_file: str) -> None:
        cmd = ["tshark", "-r", pcap_file, "-T", "fields"]
        cache.put(pcap_file, cmd, "result data")
        assert cache.get(pcap_file, cmd) == "result data"

    def test_miss_on_empty(self, cache: ResultCache, pcap_file: str) -> None:
        cmd = ["tshark", "-r", pcap_file]
        assert cache.get(pcap_file, cmd) is None

    def test_different_commands_different_keys(self, cache: ResultCache, pcap_file: str) -> None:
        cmd1 = ["tshark", "-r", pcap_file, "-Y", "tcp"]
        cmd2 = ["tshark", "-r", pcap_file, "-Y", "udp"]
        cache.put(pcap_file, cmd1, "tcp result")
        cache.put(pcap_file, cmd2, "udp result")
        assert cache.get(pcap_file, cmd1) == "tcp result"
        assert cache.get(pcap_file, cmd2) == "udp result"

    def test_nonexistent_file_returns_none(self, cache: ResultCache) -> None:
        cmd = ["tshark", "-r", "/nonexistent.pcap"]
        cache.put("/nonexistent.pcap", cmd, "data")
        assert cache.get("/nonexistent.pcap", cmd) is None


class TestCacheEviction:
    def test_ttl_expiry(self, cache: ResultCache, pcap_file: str) -> None:
        cmd = ["tshark", "-r", pcap_file]
        cache.put(pcap_file, cmd, "data")
        assert cache.get(pcap_file, cmd) == "data"
        time.sleep(2.1)
        assert cache.get(pcap_file, cmd) is None

    def test_max_entries_eviction(self, pcap_file: str) -> None:
        cache = ResultCache(max_entries=3, max_bytes=100000, ttl_seconds=60)
        for i in range(5):
            cache.put(pcap_file, ["cmd", str(i)], f"result_{i}")
        assert cache.stats["entries"] == 3
        assert cache.get(pcap_file, ["cmd", "4"]) == "result_4"
        assert cache.get(pcap_file, ["cmd", "0"]) is None

    def test_max_bytes_eviction(self, pcap_file: str) -> None:
        cache = ResultCache(max_entries=100, max_bytes=500, ttl_seconds=60)
        cache.put(pcap_file, ["cmd", "1"], "x" * 100)
        cache.put(pcap_file, ["cmd", "2"], "y" * 100)
        cache.put(pcap_file, ["cmd", "3"], "z" * 100)
        assert cache.stats["bytes"] <= 500

    def test_oversized_result_not_cached(self, pcap_file: str) -> None:
        cache = ResultCache(max_entries=10, max_bytes=400, ttl_seconds=60)
        cache.put(pcap_file, ["cmd"], "x" * 200)
        assert cache.get(pcap_file, ["cmd"]) is None


class TestCacheInvalidation:
    def test_clear(self, cache: ResultCache, pcap_file: str) -> None:
        cache.put(pcap_file, ["cmd"], "data")
        cache.clear()
        assert cache.get(pcap_file, ["cmd"]) is None
        assert cache.stats["entries"] == 0

    def test_invalidate_file(self, cache: ResultCache, pcap_file: str) -> None:
        cache.put(pcap_file, ["cmd1"], "data1")
        cache.put(pcap_file, ["cmd2"], "data2")
        cache.invalidate_file(pcap_file)
        assert cache.get(pcap_file, ["cmd1"]) is None

    def test_file_modification_invalidates(self, cache: ResultCache, pcap_file: str) -> None:
        cmd = ["tshark", "-r", pcap_file]
        cache.put(pcap_file, cmd, "old data")
        assert cache.get(pcap_file, cmd) == "old data"
        time.sleep(0.01)
        Path(pcap_file).write_bytes(b"\x01" * 200)
        assert cache.get(pcap_file, cmd) is None


class TestCacheStats:
    def test_hit_miss_tracking(self, cache: ResultCache, pcap_file: str) -> None:
        cmd = ["tshark", "-r", pcap_file]
        cache.put(pcap_file, cmd, "data")
        cache.get(pcap_file, cmd)  # hit
        cache.get(pcap_file, ["other"])  # miss
        stats = cache.stats
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["hit_rate_pct"] == 50
