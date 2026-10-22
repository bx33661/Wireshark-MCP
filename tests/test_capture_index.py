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

from wireshark_mcp.index.compare import available_kinds
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


@pytest.fixture
def layered_capture(tmp_path: Path) -> str:
    """IP-in-IP and QinQ frames, so fields repeat within a packet (comma-joined values)."""
    import struct

    from fixtures.generate_pcaps import (
        make_ethernet_frame,
        make_ipv4_packet,
        make_pcap_header,
        make_pcap_packet,
        make_tcp_packet,
        make_udp_packet,
    )

    data = bytearray(make_pcap_header())
    inner = make_tcp_packet("10.9.9.1", "10.9.9.2", 40000, 443, flags=0x02)
    data.extend(make_pcap_packet(make_ethernet_frame(make_ipv4_packet("172.16.0.1", "172.16.0.2", 4, inner)), sec=10))
    udp = make_udp_packet("10.9.9.3", "10.9.9.4", 5000, 5001, b"payload")
    qinq = struct.pack("!HH", 100, 0x8100) + struct.pack("!HH", 200, 0x0800) + udp
    data.extend(make_pcap_packet(make_ethernet_frame(qinq, ethertype=0x8100), sec=11, usec=500000))
    plain = make_tcp_packet("10.9.9.1", "10.9.9.2", 40001, 443, flags=0x12)
    data.extend(make_pcap_packet(make_ethernet_frame(plain), sec=12))
    target = tmp_path / "layered.pcap"
    target.write_bytes(data)
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
    {"group_by": "ip.src", "distinct": "tcp.flags,ip.ttl", "sum_fields": "tcp.len,ip.ttl", "min_fields": "ip.ttl"},
    {"time_bucket_seconds": 0.1, "group_by": "ip.proto", "distinct": "ip.dst", "min_fields": "frame.len"},
    {"time_bucket_seconds": 2.5, "group_by": "dns.qry.name", "distinct": "dns.a", "avg_fields": "udp.length"},
    {"display_filter": "http", "distinct": "http.request.uri,http.host,frame.protocols"},
    {"distinct": "frame.protocols,eth.src", "sum_fields": "ip.ttl", "max_fields": "ip.len"},
]

# The SQL pushdown must refuse these and stream rows into the accumulator instead.
STREAMED_CASES: list[dict[str, Any]] = [
    {"group_by": "ip.src", "max_fields": "tcp.flags"},  # hex text: float() and SQL disagree on parsing
    {"group_by": "ip.src", "sum_fields": "frame.time_relative"},  # fractional sums depend on order
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
    assert from_index["coverage"]["pushdown"] is True, from_index["coverage"]
    assert from_index["data"] == from_tshark["data"]
    assert from_index.get("warnings") == from_tshark.get("warnings")


@needs_tshark
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("arguments", "warning"),
    [
        ({"group_by": "ip.proto", "sum_fields": "ip.ttl", "max_fields": "ip.len"}, "ip.ttl"),
        ({"distinct": "vlan.id", "group_by": "eth.src"}, "comma delimiters"),
        ({"group_by": "ip.src", "distinct": "ip.dst,tcp.dstport", "time_bucket_seconds": 0.5}, None),
    ],
)
async def test_pushdown_matches_tshark_on_repeated_fields(
    layered_capture: str, tmp_path: Path, arguments: dict[str, Any], warning: str | None
) -> None:
    indexed, plain, _ = _servers(tmp_path)
    await _call(indexed, "wireshark_index", {"pcap_file": layered_capture})

    call = {"pcap_file": layered_capture, **arguments}
    from_index = await _call(indexed, "wireshark_aggregate", call)
    from_tshark = await _call(plain, "wireshark_aggregate", call)

    assert from_index["coverage"]["pushdown"] is True, from_index["coverage"]
    assert from_index["data"] == from_tshark["data"]
    assert from_index.get("warnings") == from_tshark.get("warnings")
    if warning:
        assert any(warning in text for text in from_index["warnings"]), from_index
    else:
        assert not from_index.get("warnings")


@needs_tshark
@pytest.mark.asyncio
@pytest.mark.parametrize("arguments", STREAMED_CASES)
async def test_pushdown_gates_stream_rows_and_still_match(
    merged_capture: str, tmp_path: Path, arguments: dict[str, Any]
) -> None:
    indexed, plain, _ = _servers(tmp_path)
    await _call(indexed, "wireshark_index", {"pcap_file": merged_capture})

    call = {"pcap_file": merged_capture, **arguments}
    from_index = await _call(indexed, "wireshark_aggregate", call)
    from_tshark = await _call(plain, "wireshark_aggregate", call)

    assert from_index["coverage"]["source"] == "index"
    assert from_index["coverage"]["pushdown"] is False
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


@needs_tshark
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("ceiling", "arguments"),
    [
        ("MAX_AGGREGATE_GROUPS", {"group_by": "ip.src"}),
        ("MAX_DISTINCT_PER_GROUP", {"group_by": "ip.proto", "distinct": "ip.dst"}),
        ("MAX_TOTAL_DISTINCT_ITEMS", {"group_by": "ip.proto", "distinct": "ip.dst"}),
    ],
)
async def test_pushdown_leaves_ceilings_to_the_accumulator(
    merged_capture: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ceiling: str, arguments: dict[str, Any]
) -> None:
    """Which rows survive a ceiling depends on arrival order, so pushdown must not decide it."""
    import wireshark_mcp.index.pushdown as pushdown

    monkeypatch.setattr(pushdown, ceiling, 2)
    indexed, _, _ = _servers(tmp_path)
    await _call(indexed, "wireshark_index", {"pcap_file": merged_capture})
    result = await _call(indexed, "wireshark_aggregate", {"pcap_file": merged_capture, **arguments})
    assert result["coverage"]["source"] == "index"
    assert result["coverage"]["pushdown"] is False


# ── collections, timeline, diff, export ───────────────────────────────────


@needs_tshark
@pytest.mark.asyncio
async def test_collection_query_labels_each_capture(pcap_fixtures: dict[str, str], tmp_path: Path) -> None:
    indexed, _, _ = _servers(tmp_path)
    first, second = pcap_fixtures["credentials"], pcap_fixtures["dns_tunnel"]
    copy = tmp_path / "copy" / Path(first).name
    copy.parent.mkdir()
    shutil.copy(first, copy)

    missing = await _call(
        indexed, "wireshark_index", {"pcap_file": first, "more_files": second, "action": "query", "sql": "SELECT 1"}
    )
    assert missing["error"]["type"] == "IndexMissing"
    assert second in missing["error"]["message"]

    files = f"{second}, {copy}, {first}"  # the duplicate of pcap_file is ignored
    built = await _call(indexed, "wireshark_index", {"pcap_file": first, "more_files": files})
    assert built["success"] is True, built
    assert len(built["data"]["captures"]) == 3

    counts = await _call(
        indexed,
        "wireshark_index",
        {
            "pcap_file": first,
            "more_files": files,
            "action": "query",
            "sql": "SELECT capture_id, count(*) AS n, min(frame) AS first FROM pkt GROUP BY ALL ORDER BY capture_id",
        },
    )
    assert counts["success"] is True, counts
    name = Path(first).name
    assert counts["data"]["rows"] == [
        [Path(second).name, 27, 1],
        [name, 3, 1],
        [f"{name}~2", 3, 1],
    ]
    assert [item["capture_id"] for item in counts["coverage"]["captures"]] == [name, Path(second).name, f"{name}~2"]

    flows = await _call(
        indexed,
        "wireshark_index",
        {
            "pcap_file": first,
            "more_files": files,
            "action": "query",
            "sql": "SELECT count(DISTINCT capture_id) FROM flows JOIN captures USING (capture_id)",
        },
    )
    assert flows["data"]["rows"] == [[3]]

    status = await _call(indexed, "wireshark_index", {"pcap_file": first, "more_files": second, "action": "status"})
    assert [item["state"] for item in status["data"]["captures"]] == ["fresh", "fresh"]


def _rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    return [dict(zip(data["columns"], item, strict=True)) for item in data["items"]]


@needs_tshark
@pytest.mark.asyncio
async def test_timeline_reports_first_and_last_frames(merged_capture: str, tmp_path: Path) -> None:
    indexed, plain, _ = _servers(tmp_path)
    await _call(indexed, "wireshark_index", {"pcap_file": merged_capture})

    result = await _call(indexed, "wireshark_index", {"pcap_file": merged_capture, "action": "timeline"})
    assert result["success"] is True, result
    data = result["data"]
    events = _rows(data)
    assert data["kinds"]["dns_name"] == 27
    assert data["truncated"] is True and len(events) == data["items_returned"] <= 60
    assert sum(1 for e in events if e["kind"] == "dns_name") <= 20
    order = [(e["first_time"], e["first_frame"], e["kind"], e["value"]) for e in events]
    assert order == sorted(order)
    assert "first_capture_id" not in data["columns"]

    # Every DNS name's first/last frame and packet count must agree with tshark.
    expected = await _call(
        plain,
        "wireshark_aggregate",
        {
            "pcap_file": merged_capture,
            "display_filter": "dns",
            "group_by": "dns.qry.name",
            "top_k": 200,
            "min_fields": "frame.number",
            "max_fields": "frame.number",
        },
    )
    by_name = {
        group["key"]["dns.qry.name"]: (
            group["count"],
            int(group["numeric"]["frame.number"]["min"]),
            int(group["numeric"]["frame.number"]["max"]),
        )
        for group in expected["data"]["groups"]
    }
    window = await _call(
        indexed,
        "wireshark_index",
        {"pcap_file": merged_capture, "action": "timeline", "display_filter": "dns"},
    )
    assert window["data"]["selected_packets"] == sum(count for count, _, _ in by_name.values())
    assert set(window["data"]["kinds"]) >= {"host", "conversation", "protocol", "dns_name"}
    assert "http_host" not in window["data"]["kinds"]
    dns = {
        e["value"]: (e["packets"], e["first_frame"], e["last_frame"])
        for e in _rows(window["data"])
        if e["kind"] == "dns_name"
    }
    assert len(dns) == 20
    assert dns == {name: by_name[name] for name in dns}
    earliest = sorted(by_name.items(), key=lambda item: item[1][1])[:20]
    assert set(dns) == {name for name, _ in earliest}

    refused = await _call(
        indexed,
        "wireshark_index",
        {"pcap_file": merged_capture, "action": "timeline", "display_filter": "ip.src == 10.0.0.0/8"},
    )
    assert refused["error"]["type"] == "InvalidParameter"


@needs_tshark
@pytest.mark.asyncio
async def test_timeline_over_a_collection_names_the_capture(pcap_fixtures: dict[str, str], tmp_path: Path) -> None:
    indexed, _, _ = _servers(tmp_path)
    files = {"pcap_file": pcap_fixtures["credentials"], "more_files": pcap_fixtures["dns_tunnel"]}
    await _call(indexed, "wireshark_index", files)
    result = await _call(indexed, "wireshark_index", {**files, "action": "timeline", "display_filter": "udp"})
    events = _rows(result["data"])
    assert result["data"]["columns"][-2:] == ["first_capture_id", "last_capture_id"]
    assert {e["first_capture_id"] for e in events} == {"dns_tunnel_candidate.pcap"}


@needs_tshark
@pytest.mark.asyncio
async def test_diff_returns_only_differences(
    pcap_fixtures: dict[str, str], merged_capture: str, tmp_path: Path
) -> None:
    indexed, _, _ = _servers(tmp_path)
    baseline, compare = pcap_fixtures["credentials"], merged_capture
    await _call(indexed, "wireshark_index", {"pcap_file": baseline, "more_files": compare})

    result = await _call(indexed, "wireshark_index", {"pcap_file": baseline, "more_files": compare, "action": "diff"})
    assert result["success"] is True, result
    data = result["data"]
    rows = _rows(data)
    assert data["baseline"]["capture_id"] == Path(baseline).name
    assert data["compare"]["capture_id"] == "merged.pcap"
    # merged.pcap contains the baseline capture, so nothing is gone and the DNS tunnel is new.
    assert {row["change"] for row in rows} == {"new"}
    assert data["summary"]["dns_name"]["new"] == 27
    assert sum(1 for row in rows if row["kind"] == "dns_name") == 10
    assert data["truncated"] is True
    assert data["summary"]["host"]["common"] == data["summary"]["host"]["baseline"]
    new_hosts = {row["value"] for row in rows if row["kind"] == "host"}
    assert "8.8.8.8" in new_hosts and "192.168.1.10" not in new_hosts
    udp_only = await _call(
        indexed,
        "wireshark_index",
        {"pcap_file": baseline, "more_files": compare, "action": "diff", "compare_filter": "udp"},
    )
    tunnel = next(row for row in _rows(udp_only["data"]) if row["value"] == "udp 192.168.1.20 -> 8.8.8.8:53")
    assert (tunnel["change"], tunnel["packets"], tunnel["first_frame"]) == (
        "new",
        27,
        29,
    )  # tshark -Y "udp" puts the first query at frame 29
    kinds_in_order = [row["kind"] for row in rows]
    assert kinds_in_order == sorted(kinds_in_order, key=available_kinds(COLUMNS).index)

    windows = await _call(
        indexed,
        "wireshark_index",
        {"pcap_file": compare, "action": "diff", "display_filter": "tcp", "compare_filter": "udp"},
    )
    assert windows["success"] is True, windows
    assert windows["data"]["selected_packets"] == {"baseline": 29, "compare": 27}
    gone = {row["value"] for row in _rows(windows["data"]) if row["change"] == "gone" and row["kind"] == "protocol"}
    assert {"tcp", "http"} <= gone
    changes = [row["change"] for row in _rows(windows["data"])]
    assert changes == sorted(changes, key=["new", "gone"].index)

    same = await _call(indexed, "wireshark_index", {"pcap_file": compare, "action": "diff"})
    assert same["error"]["type"] == "InvalidParameter"


@needs_tshark
@pytest.mark.asyncio
async def test_index_views_fit_the_default_result_cap(
    pcap_fixtures: dict[str, str], merged_capture: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Through the real server the result cap must trim items, never empty the payload."""
    from wireshark_mcp.server import _build_server

    monkeypatch.setenv("WIRESHARK_MCP_INDEX_DIR", str(tmp_path / "index"))
    server = _build_server(host="127.0.0.1", port=8080, log_level="ERROR")
    files = {"pcap_file": pcap_fixtures["credentials"], "more_files": merged_capture}
    await _call(server, "wireshark_index", files)
    for arguments in ({"action": "timeline"}, {"action": "diff"}):
        result = await _call(server, "wireshark_index", {**files, **arguments})
        assert result["success"] is True
        assert result["data"]["items"], result
        assert result["data"]["summary" if arguments["action"] == "diff" else "kinds"]


@needs_tshark
@pytest.mark.asyncio
async def test_export_writes_parquet_into_the_index_directory(
    pcap_fixtures: dict[str, str], merged_capture: str, tmp_path: Path
) -> None:
    indexed, _, store = _servers(tmp_path)
    await _call(indexed, "wireshark_index", {"pcap_file": merged_capture, "more_files": pcap_fixtures["credentials"]})

    result = await _call(
        indexed,
        "wireshark_index",
        {
            "pcap_file": merged_capture,
            "more_files": pcap_fixtures["credentials"],
            "action": "export",
            "display_filter": "tcp",
        },
    )
    assert result["success"] is True, result
    files = result["data"]["files"]
    directory = Path(result["data"]["directory"])
    assert directory.parent == store.index_dir / "exports"
    packets = duckdb.sql(f"SELECT capture_id, count(*) FROM '{files['packets']['path']}' GROUP BY ALL ORDER BY 1")
    assert packets.fetchall() == [("merged.pcap", 29), ("plaintext_credentials.pcap", 3)]
    assert files["packets"]["rows"] == 32
    flows = duckdb.sql(f"SELECT DISTINCT transport FROM '{files['flows']['path']}'").fetchall()
    assert flows == [("tcp",)]
    columns = {
        name for (name,) in duckdb.sql(f"SELECT name FROM parquet_schema('{files['packets']['path']}')").fetchall()
    }
    assert {"capture_id", "frame", "epoch", "ip.src", "dns.qry.name"} <= columns
    captures = duckdb.sql(f"SELECT count(*) FROM '{files['captures']['path']}'").fetchone()
    assert captures == (2,)

    again = await _call(
        indexed,
        "wireshark_index",
        {
            "pcap_file": merged_capture,
            "more_files": pcap_fixtures["credentials"],
            "action": "export",
            "display_filter": "tcp",
        },
    )
    assert again["data"]["directory"] == str(directory)
    assert sorted(path.name for path in directory.parent.iterdir()) == [directory.name]


EXTRACT_CASES: list[dict[str, Any]] = [
    {"fields": "frame.number,ip.src,ip.dst,tcp.dstport"},
    {"fields": "ip.src,http.user_agent,http.host", "display_filter": "http"},
    {"fields": "dns.qry.name,dns.a,dns.flags.response", "display_filter": "dns", "limit": 5},
    {"fields": "dns.qry.name", "display_filter": "dns", "limit": 5, "offset": 5},
    {"fields": "dns.qry.name", "display_filter": "dns", "limit": 10, "offset": 25},
    {"fields": "frame.time_epoch,frame.time_relative,frame.len,eth.src,frame.protocols", "limit": 1},
    {"fields": "tcp.flags,tcp.flags.syn,tcp.flags.ack", "display_filter": "tcp.flags.syn == 1", "limit": 7},
    {"fields": "ip.src", "display_filter": "ip.src == 203.0.113.250"},
    {"fields": "ip.src", "limit": 3, "offset": 100},
]


@needs_tshark
@pytest.mark.asyncio
@pytest.mark.parametrize("arguments", EXTRACT_CASES)
async def test_indexed_extract_fields_matches_tshark(
    merged_capture: str, layered_capture: str, tmp_path: Path, arguments: dict[str, Any]
) -> None:
    from wireshark_mcp.tools.extract import register_extract_tools

    client = TSharkClient()
    store = CaptureIndexStore(client, index_dir=tmp_path / "index")
    indexed = MCPServer("indexed")
    register_index_tools(indexed, client, store)
    register_extract_tools(indexed, client, store)
    plain = MCPServer("plain")
    register_extract_tools(plain, TSharkClient())

    for capture in (merged_capture, layered_capture):
        await _call(indexed, "wireshark_index", {"pcap_file": capture})
        call = {"pcap_file": capture, **arguments}
        from_index = await _call(indexed, "wireshark_extract_fields", call)
        from_tshark = await _call(plain, "wireshark_extract_fields", call)
        if capture == merged_capture:  # layered.pcap lacks some filtered protocols, so tshark answers there
            assert from_index["coverage"]["source"] == "index", from_index
        assert from_index["data"] == from_tshark["data"]
        assert from_index.get("truncated") == from_tshark.get("truncated")


@needs_tshark
@pytest.mark.asyncio
async def test_extract_fields_falls_back_when_the_index_cannot_answer(merged_capture: str, tmp_path: Path) -> None:
    from wireshark_mcp.tools.extract import register_extract_tools

    client = TSharkClient()
    store = CaptureIndexStore(client, index_dir=tmp_path / "index")
    mcp = MCPServer("indexed")
    register_index_tools(mcp, client, store)
    register_extract_tools(mcp, client, store)
    await _call(mcp, "wireshark_index", {"pcap_file": merged_capture})

    for arguments in (
        {"fields": "ftp.request.command"},  # not indexed
        {"fields": "ip.src", "display_filter": "ip.src == 10.0.0.0/8"},  # not translatable
        {"fields": "http.user_agent", "display_filter": "http", "limit": 0},  # unbounded
    ):
        result = await _call(mcp, "wireshark_extract_fields", {"pcap_file": merged_capture, **arguments})
        assert result["success"] is True, result
        assert "coverage" not in result, arguments

    store._version = "TShark (Wireshark) 0.0.0"  # index built by a different tshark
    result = await _call(mcp, "wireshark_extract_fields", {"pcap_file": merged_capture, "fields": "ip.src"})
    assert "coverage" not in result
