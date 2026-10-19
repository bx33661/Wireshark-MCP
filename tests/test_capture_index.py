"""Capture index: build, freshness, filter translation, SQL sandbox, and tshark equivalence."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest
from conftest import call_tool_text
from mcp.server import MCPServer

from wireshark_mcp.index.filter_sql import UnsupportedFilter, translate_filter
from wireshark_mcp.index.schema import INDEX_FIELDS
from wireshark_mcp.index.store import CaptureIndexStore
from wireshark_mcp.tools.envelope import parse_tool_result
from wireshark_mcp.tools.index import register_index_tools
from wireshark_mcp.tools.stats import register_stats_tools
from wireshark_mcp.tshark.client import TSharkClient

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "pcaps"
COLUMNS = set(INDEX_FIELDS)
PROTOCOLS = {"eth", "ethertype", "ip", "tcp", "udp", "dns", "http"}

duckdb = pytest.importorskip("duckdb")
needs_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")


# ── filter translation (no tshark needed) ─────────────────────────────────


@pytest.mark.parametrize(
    "display_filter",
    [
        "",
        "dns",
        "tcp && http",
        "ip.src == 10.0.0.1",
        "ip.addr == 10.0.0.1",
        "tcp.flags.syn == 1 and tcp.flags.ack == 0",
        "tcp.port in {80, 443, 8080}",
        "!(udp.dstport == 53)",
        'http.user_agent contains "curl"',
        "frame.len >= 100",
        "dns.flags.response eq 0",
        "tcp.flags == 0x0002",
        "eth.src == AA:BB:CC:DD:EE:FF",
        "ip.dst != 10.0.0.1",
        "(dns or http) and frame.len > 60",
    ],
)
def test_supported_filters_translate(display_filter: str) -> None:
    translated = translate_filter(display_filter, COLUMNS, PROTOCOLS)
    assert translated.sql
    assert translated.sql.count("?") == len(translated.params)


@pytest.mark.parametrize(
    "display_filter",
    [
        "dns or http and tcp",  # precedence must be explicit
        "ip.src == 10.0.0.0/8",
        "ipv6.src == ::1",
        'http.host matches "x"',
        "tcp.port in {1..1024}",
        "tcp.port in {80 443}",  # tshark 4.2+ needs commas
        "frame[0:2] == 00:01",
        "smtp.req.command == MAIL",  # field not indexed
        "nosuchproto",
        "ip.src > 10.0.0.1",
        "dns.qry.type == A",
        "tcp.flags.syn == 2",
        'http.host contains "\\x41"',
        "len(http.host) > 3",
    ],
)
def test_unsupported_filters_fall_back(display_filter: str) -> None:
    with pytest.raises(UnsupportedFilter):
        translate_filter(display_filter, COLUMNS, PROTOCOLS)


def _evaluate(display_filter: str, rows: list[dict[str, str]]) -> list[int]:
    connection = duckdb.connect()
    columns = ", ".join(f'"{name}" VARCHAR' for name in INDEX_FIELDS)
    connection.execute(f"CREATE TABLE packets ({columns})")
    for row in rows:
        names = ", ".join(f'"{name}"' for name in row)
        connection.execute(f"INSERT INTO packets ({names}) VALUES ({', '.join('?' * len(row))})", list(row.values()))
    translated = translate_filter(display_filter, COLUMNS, PROTOCOLS)
    result = connection.execute(
        f'SELECT CAST("frame.number" AS INTEGER) FROM packets WHERE {translated.sql} ORDER BY 1', translated.params
    ).fetchall()
    return [value for (value,) in result]


def test_filter_semantics_follow_wireshark_occurrence_rules() -> None:
    rows = [
        {"frame.number": "1", "ip.src": "10.0.0.1", "ip.dst": "10.0.0.2", "frame.protocols": "eth:ip:udp:dns"},
        {"frame.number": "2", "ip.src": "10.0.0.1,192.0.2.9", "ip.dst": "10.0.0.3", "frame.protocols": "eth:ip:ip"},
        {"frame.number": "3", "frame.protocols": "eth:arp"},
        {"frame.number": "4", "tcp.flags.syn": "True", "tcp.flags.ack": "False", "frame.protocols": "eth:ip:tcp"},
        {"frame.number": "5", "tcp.flags": "0x0012", "frame.protocols": "eth:ip:tcp"},
    ]
    assert _evaluate("ip.src == 192.0.2.9", rows) == [2]  # any occurrence
    assert _evaluate("ip.src != 10.0.0.1", rows) == []  # all differ, and absent is false
    assert _evaluate("!(ip.src == 10.0.0.1)", rows) == [3, 4, 5]
    assert _evaluate("ip.addr == 10.0.0.3", rows) == [2]
    assert _evaluate("dns", rows) == [1]
    assert _evaluate("ip", rows) == [1, 2, 4, 5]
    assert _evaluate("tcp.flags.syn == 1 && tcp.flags.ack == 0", rows) == [4]
    assert _evaluate("tcp.flags == 0x12", rows) == [5]
    assert _evaluate("tcp.flags", rows) == [5]


# ── real tshark ───────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def pcap_fixtures() -> dict[str, str]:
    from fixtures.generate_pcaps import build_all_fixtures

    paths = build_all_fixtures(FIXTURES_DIR)
    return {k: str(v) for k, v in paths.items()}


@pytest.fixture
def merged_capture(pcap_fixtures: dict[str, str], tmp_path: Path) -> str:
    """One capture mixing every IP fixture, so filters see several protocols."""
    import subprocess

    target = tmp_path / "merged.pcap"
    sources = [pcap_fixtures[name] for name in ("credentials", "syn_scan", "dns_tunnel", "multivalue")]
    subprocess.run(["mergecap", "-F", "pcap", "-w", str(target), *sources], check=True)
    return str(target)


def _servers(tmp_path: Path) -> tuple[MCPServer, MCPServer, CaptureIndexStore]:
    client = TSharkClient()
    store = CaptureIndexStore(client, index_dir=tmp_path / "index")
    indexed = MCPServer("indexed")
    register_stats_tools(indexed, client, store)
    register_index_tools(indexed, client, store)
    plain = MCPServer("plain")
    register_stats_tools(plain, client)
    return indexed, plain, store


async def _call(mcp: MCPServer, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return parse_tool_result(await call_tool_text(mcp, name, arguments))


AGGREGATE_CASES: list[dict[str, Any]] = [
    {},
    {"group_by": "ip.src"},
    {"display_filter": "tcp.flags.syn == 1 and tcp.flags.ack == 0", "group_by": "ip.src", "distinct": "tcp.dstport"},
    {"display_filter": "dns.flags.response == 0", "group_by": "ip.src", "distinct": "dns.qry.name"},
    {"display_filter": "dns", "group_by": "dns.qry.name", "top_k": 5},
    {"display_filter": "http", "group_by": "http.host", "distinct": "http.user_agent"},
    {"display_filter": "ip", "group_by": "ip.src", "time_bucket_seconds": 1},
    {"group_by": "ip.proto", "sum_fields": "frame.len", "avg_fields": "frame.len", "max_fields": "tcp.len"},
    {"display_filter": "tcp.port in {21, 23, 80}", "group_by": "tcp.dstport,ip.dst"},
    {"display_filter": "!(udp.port == 53)", "group_by": "frame.protocols"},
    {"display_filter": "ip.addr == 10.1.1.5", "group_by": "ip.dst"},
    {
        "display_filter": "frame.len > 80 && tcp",
        "sum_fields": "tcp.len",
        "sort_by": "numeric_desc",
        "sort_numeric": "tcp.len",
        "group_by": "ip.src",
    },
]


@needs_tshark
@pytest.mark.asyncio
@pytest.mark.parametrize("arguments", AGGREGATE_CASES)
async def test_indexed_aggregate_matches_tshark(merged_capture: str, tmp_path: Path, arguments: dict[str, Any]) -> None:
    indexed, plain, _ = _servers(tmp_path)
    built = await _call(indexed, "wireshark_index", {"pcap_file": merged_capture})
    assert built["success"] is True, built

    call = {"pcap_file": merged_capture, **arguments}
    from_index = await _call(indexed, "wireshark_aggregate", call)
    from_tshark = await _call(plain, "wireshark_aggregate", call)

    assert from_index["success"] is True, from_index
    assert from_index["coverage"]["source"] == "index", from_index["coverage"]
    assert from_tshark["coverage"]["source"] == "tshark"
    assert from_index["data"] == from_tshark["data"]
    assert from_index.get("warnings") == from_tshark.get("warnings")


@needs_tshark
@pytest.mark.asyncio
async def test_untranslatable_filter_falls_back_to_tshark(merged_capture: str, tmp_path: Path) -> None:
    indexed, _, _ = _servers(tmp_path)
    await _call(indexed, "wireshark_index", {"pcap_file": merged_capture})

    result = await _call(
        indexed, "wireshark_aggregate", {"pcap_file": merged_capture, "display_filter": "ip.src == 10.0.0.0/8"}
    )
    assert result["success"] is True
    assert result["coverage"]["source"] == "tshark"
    assert "filter not translatable" in result["coverage"]["index_unused"]

    result = await _call(
        indexed, "wireshark_aggregate", {"pcap_file": merged_capture, "group_by": "ftp.request.command"}
    )
    assert result["coverage"]["source"] == "tshark"
    assert "ftp.request.command" in result["coverage"]["index_unused"]


@needs_tshark
@pytest.mark.asyncio
async def test_build_reuse_status_and_staleness(merged_capture: str, tmp_path: Path) -> None:
    indexed, _, store = _servers(tmp_path)

    status = await _call(indexed, "wireshark_index", {"pcap_file": merged_capture, "action": "status"})
    assert status["data"]["state"] == "missing"

    built = await _call(indexed, "wireshark_index", {"pcap_file": merged_capture})
    index = built["data"]["index"]
    assert built["data"]["reused"] is False
    assert index["packets"] > 0
    assert len(index["capture_sha256"]) == 64
    assert built["coverage"]["status"] == "complete"

    again = await _call(indexed, "wireshark_index", {"pcap_file": merged_capture})
    assert again["data"]["reused"] is True

    # Any change to the capture makes the index stale; aggregate must not use it.
    stat = os.stat(merged_capture)
    os.utime(merged_capture, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
    status = await _call(indexed, "wireshark_index", {"pcap_file": merged_capture, "action": "status"})
    assert status["data"]["state"] == "stale"
    result = await _call(indexed, "wireshark_aggregate", {"pcap_file": merged_capture})
    assert result["coverage"]["source"] == "tshark"

    dropped = await _call(indexed, "wireshark_index", {"pcap_file": merged_capture, "action": "drop"})
    assert dropped["data"]["removed"] is True
    assert not store.index_path(Path(merged_capture).resolve()).exists()


@needs_tshark
@pytest.mark.asyncio
async def test_index_query_flows_and_sandbox(merged_capture: str, tmp_path: Path) -> None:
    indexed, _, _ = _servers(tmp_path)

    missing = await _call(
        indexed, "wireshark_index", {"pcap_file": merged_capture, "action": "query", "sql": "SELECT 1"}
    )
    assert missing["success"] is False
    assert missing["error"]["type"] == "IndexMissing"

    await _call(indexed, "wireshark_index", {"pcap_file": merged_capture})
    flows = await _call(
        indexed,
        "wireshark_index",
        {
            "pcap_file": merged_capture,
            "action": "query",
            "sql": "SELECT transport, src, dport, packets, syn FROM flows ORDER BY packets DESC, stream LIMIT 3",
        },
    )
    assert flows["success"] is True, flows
    assert flows["data"]["columns"] == ["transport", "src", "dport", "packets", "syn"]
    assert 0 < flows["data"]["row_count"] <= 3
    assert flows["coverage"]["source"] == "index"

    joined = await _call(
        indexed,
        "wireshark_index",
        {
            "pcap_file": merged_capture,
            "action": "query",
            "sql": 'SELECT frame, src, "dns.qry.name" FROM pkt WHERE "dns.qry.name" <> \'\'',
        },
    )
    assert joined["success"] is True, joined
    assert all(isinstance(row[0], int) for row in joined["data"]["rows"])

    for sql in (
        "SELECT * FROM read_csv('/etc/passwd')",
        "COPY packets TO 'out.csv'",
        "ATTACH 'other.duckdb'",
        "SELECT 1; SELECT 2",
        "DELETE FROM packets",
        "INSTALL httpfs",
    ):
        refused = await _call(indexed, "wireshark_index", {"pcap_file": merged_capture, "action": "query", "sql": sql})
        assert refused["success"] is False, sql
        assert refused["error"]["type"] in {"InvalidParameter", "QueryError"}, refused


@needs_tshark
@pytest.mark.asyncio
async def test_index_respects_allowed_directories(merged_capture: str, tmp_path: Path) -> None:
    (tmp_path / "elsewhere").mkdir()
    client = TSharkClient(allowed_dirs=[str(tmp_path / "elsewhere")])
    store = CaptureIndexStore(client, index_dir=tmp_path / "index")
    mcp = MCPServer("sandboxed")
    register_index_tools(mcp, client, store)

    for name, arguments in (
        ("wireshark_index", {"pcap_file": merged_capture}),
        ("wireshark_index", {"pcap_file": merged_capture, "action": "query", "sql": "SELECT 1"}),
    ):
        result = await _call(mcp, name, arguments)
        assert result["success"] is False
        assert result["error"]["type"] == "PermissionDenied"
    assert not (tmp_path / "index").exists() or not any((tmp_path / "index").iterdir())


@needs_tshark
@pytest.mark.asyncio
async def test_empty_capture_indexes_cleanly(pcap_fixtures: dict[str, str], tmp_path: Path) -> None:
    indexed, _, _ = _servers(tmp_path)
    built = await _call(indexed, "wireshark_index", {"pcap_file": pcap_fixtures["empty"]})
    assert built["success"] is True, built
    assert built["data"]["index"]["packets"] == 0
    result = await _call(indexed, "wireshark_aggregate", {"pcap_file": pcap_fixtures["empty"]})
    assert result["coverage"]["source"] == "index"
    assert result["data"]["matched_packets"] == 0
    assert json.dumps(result)


@pytest.mark.asyncio
async def test_missing_duckdb_reports_the_install_hint(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import wireshark_mcp.tools.index as index_tools

    monkeypatch.setattr(index_tools, "duckdb_available", lambda: False)
    client = TSharkClient()
    mcp = MCPServer("no-duckdb")
    register_index_tools(mcp, client, CaptureIndexStore(client, index_dir=tmp_path / "index"))
    result = await _call(mcp, "wireshark_index", {"pcap_file": str(tmp_path / "x.pcap")})
    assert result["success"] is False
    assert result["error"]["type"] == "DependencyMissing"
    assert "wireshark-mcp[index]" in result["error"]["message"]
