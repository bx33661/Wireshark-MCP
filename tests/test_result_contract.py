"""Tests for the 3.0 stable result contract and MCP isError synchronization."""

import json

import pytest
from mcp.types import CallToolResult

from wireshark_mcp.mcp_app import WiresharkMCP, cap_result_text
from wireshark_mcp.tools.envelope import (
    envelope_response,
    error_response,
    parse_tool_result,
    success_response,
)


def test_envelope_response_retains_rich_metadata() -> None:
    scope = {"pcap_file": "sample.pcap", "filter": "tcp.port == 80"}
    coverage = {"status": "complete", "scanned": 1000, "limit": 5000}
    pagination = {"returned": 50, "total": 200, "has_more": True}
    warnings = ["Vantage point may miss retransmissions"]

    raw = envelope_response(
        data={"items": [1, 2, 3]},
        scope=scope,
        coverage=coverage,
        pagination=pagination,
        warnings=warnings,
        truncated=False,
    )
    parsed = json.loads(raw)
    assert parsed["success"] is True
    assert parsed["data"] == {"items": [1, 2, 3]}
    assert parsed["scope"] == scope
    assert parsed["coverage"] == coverage
    assert parsed["pagination"] == pagination
    assert parsed["warnings"] == warnings
    assert parsed["truncated"] is False


def test_normalize_dict_payload_preserves_contract_fields() -> None:
    incoming = {
        "success": True,
        "data": "some data",
        "scope": {"pcap_file": "test.pcap"},
        "coverage": {"status": "partial", "reason": "limit_reached"},
        "pagination": {"returned": 10, "has_more": True},
        "warnings": ["Warning note"],
        "truncated": True,
        "stderr": "tshark stderr",
    }
    normalized = parse_tool_result(incoming)
    assert normalized["success"] is True
    assert normalized["data"] == "some data"
    assert normalized["scope"] == {"pcap_file": "test.pcap"}
    assert normalized["coverage"]["status"] == "partial"
    assert normalized["pagination"]["has_more"] is True
    assert normalized["warnings"] == ["Warning note"]
    assert normalized["truncated"] is True
    assert normalized["stderr"] == "tshark stderr"


def test_cap_result_text_preserves_list_type_on_truncation() -> None:
    # 200 items, each around 50 chars => >10,000 chars total
    records = [{"id": i, "name": f"record_{i}", "detail": "detail_" * 5} for i in range(200)]
    raw = success_response(records)
    assert len(raw) > 5000

    capped = cap_result_text(raw, max_chars=1000)
    assert len(capped) <= 1000

    parsed = json.loads(capped)
    assert parsed["success"] is True
    # The return type MUST REMAIN A LIST, not a sliced string!
    assert isinstance(parsed["data"], list)
    assert len(parsed["data"]) < 200
    assert parsed["truncated"] is True
    assert parsed["pagination"]["has_more"] is True
    assert parsed["pagination"]["returned"] == len(parsed["data"])
    assert parsed["pagination"]["total"] == 200


def test_cap_result_text_preserves_dict_with_groups_type_on_truncation() -> None:
    groups = [{"key": {"ip.src": f"192.168.1.{i % 255}", "tcp.dstport": 80 + i}, "count": i * 10} for i in range(300)]
    data = {
        "matched_packets": 10000,
        "groups_total": 300,
        "groups_returned": 300,
        "groups": groups,
    }
    raw = success_response(data)
    assert len(raw) > 8000

    capped = cap_result_text(raw, max_chars=2000)
    assert len(capped) <= 2000

    parsed = json.loads(capped)
    assert parsed["success"] is True
    # data MUST REMAIN A DICT, and groups MUST REMAIN A LIST!
    assert isinstance(parsed["data"], dict)
    assert isinstance(parsed["data"]["groups"], list)
    assert parsed["data"]["groups_returned"] == len(parsed["data"]["groups"])
    assert parsed["data"]["groups_returned"] < 300
    assert parsed["truncated"] is True
    assert parsed["data"]["truncated"] is True
    assert parsed["pagination"]["has_more"] is True


def test_cap_result_text_on_freeform_text_marks_truncated() -> None:
    raw = success_response("A" * 5000)
    capped = cap_result_text(raw, max_chars=500)
    assert len(capped) <= 500

    parsed = json.loads(capped)
    assert parsed["success"] is True
    assert isinstance(parsed["data"], str)
    assert parsed["truncated"] is True


def _tsv_rows(count: int) -> str:
    """A line-oriented payload shaped like the packet-list and field-extraction tools."""
    header = "frame.number\t_ws.col.cls_time\t_ws.col.def_src\t_ws.col.def_dst\t_ws.col.protocol\t_ws.col.info"
    rows = [
        f'"{i}"\t"0.000000"\t"192.168.1.{i % 200}"\t"8.8.8.8"\t"DNS"\t"Standard query A host{i}.example.com"'
        for i in range(1, count + 1)
    ]
    return "\n".join([header, *rows])


def test_cap_result_text_keeps_line_oriented_text_contiguous() -> None:
    """A capped page must be a prefix, not head-and-tail with a hole in the middle.

    Callers page with offset/limit, so rows removed from the middle are
    unreachable by every later page while the tool's own footer still reports
    the requested page size.
    """
    raw = json.dumps({"success": True, "data": _tsv_rows(200)})
    capped = cap_result_text(raw, max_chars=16_000)
    assert len(capped) <= 16_000

    delivered = json.loads(capped)["data"]
    frame_numbers = [
        int(line.split("\t")[0].strip('"')) for line in delivered.split("\n") if line.startswith('"')
    ]

    assert frame_numbers, "expected delivered rows"
    assert frame_numbers == list(range(1, len(frame_numbers) + 1)), (
        "rows must stay a contiguous prefix starting at the first row"
    )
    assert "withheld" in delivered, "the caller needs to know rows were withheld"


def test_cap_result_text_still_uses_head_and_tail_for_prose() -> None:
    """Text without line structure keeps the head-plus-tail form; nothing pages it."""
    raw = json.dumps({"success": True, "data": "A" * 20_000})
    capped = cap_result_text(raw, max_chars=2_000)
    assert len(capped) <= 2_000

    delivered = json.loads(capped)["data"]
    assert delivered.startswith("A" * 100)
    assert delivered.endswith("A" * 100)
    assert "omitted" in delivered


def test_cap_result_text_line_oriented_stays_under_the_ceiling_at_any_size() -> None:
    for ceiling in (1_000, 4_000, 8_000, 16_000):
        raw = json.dumps({"success": True, "data": _tsv_rows(500)})
        capped = cap_result_text(raw, max_chars=ceiling)
        assert len(capped) <= ceiling, f"ceiling {ceiling} exceeded"


@pytest.mark.asyncio
async def test_call_tool_synchronizes_is_error_flag() -> None:
    mcp = WiresharkMCP("test_mcp")

    async def tool_failing() -> str:
        return error_response("File not found or invalid permissions", "FileNotFound")

    async def tool_succeeding() -> str:
        return success_response({"status": "ok"})

    mcp.add_tool(tool_failing, name="tool_failing")
    mcp.add_tool(tool_succeeding, name="tool_succeeding")

    # Failing tool
    res_fail = await mcp.call_tool("tool_failing", {})
    assert isinstance(res_fail, CallToolResult)
    assert res_fail.is_error is True
    # Verify MCP protocol serialization contains camelCase "isError": true
    assert res_fail.model_dump(by_alias=True)["isError"] is True
    content_fail = json.loads(res_fail.content[0].text)
    assert content_fail["success"] is False
    assert content_fail["error"]["type"] == "FileNotFound"

    # Succeeding tool
    res_ok = await mcp.call_tool("tool_succeeding", {})
    assert isinstance(res_ok, CallToolResult)
    assert res_ok.is_error is False
    assert res_ok.model_dump(by_alias=True)["isError"] is False


def test_cap_result_text_long_error_preserves_valid_json() -> None:
    raw_error = error_response(
        "Fatal syntax error in filter: tcp.port == 80 and invalid",
        details="A" * 3000,
        scope={"pcap_file": "/path/to/capture.pcap" * 50, "extra": "B" * 2000},
    )
    capped = cap_result_text(raw_error, max_chars=250)
    assert len(capped) <= 250
    # Crucial: Must parse as valid JSON!
    parsed = json.loads(capped)
    assert parsed["success"] is False
    assert "Fatal syntax error" in parsed["error"]["message"]
    assert parsed["truncated"] is True


@pytest.mark.asyncio
async def test_call_tool_preserves_is_error_even_when_error_is_heavily_capped() -> None:
    mcp = WiresharkMCP("test_mcp")
    # Set a tiny ceiling to force heavy capping
    mcp._max_result_chars = 200

    async def tool_giant_error() -> str:
        return error_response(
            "Fatal syntax error in filter: tcp.port == 80 and invalid",
            details="A" * 3000,
            scope={"pcap_file": "/path/to/capture.pcap" * 50, "extra": "B" * 2000},
        )

    mcp.add_tool(tool_giant_error, name="tool_giant_error")
    res = await mcp.call_tool("tool_giant_error", {})
    assert isinstance(res, CallToolResult)
    assert res.is_error is True
    assert res.model_dump(by_alias=True)["isError"] is True
    parsed = json.loads(res.content[0].text)
    assert parsed["success"] is False


def test_cap_result_text_preserves_global_total_and_updates_next_offset() -> None:
    data = [{"id": i, "name": f"item_{i}", "desc": "long descriptive string for each item" * 5} for i in range(50)]
    raw = envelope_response(
        data=data,
        pagination={
            "total": 1000,
            "offset": 0,
            "limit": 50,
            "returned": 50,
            "next_offset": 50,
            "has_more": True,
        },
    )
    # Cap to 800 chars so only a few items fit
    capped = cap_result_text(raw, max_chars=800)
    assert len(capped) <= 800

    parsed = json.loads(capped)
    assert parsed["success"] is True
    assert isinstance(parsed["data"], list)
    k = len(parsed["data"])
    assert 0 < k < 50

    pag = parsed["pagination"]
    # Global total MUST NOT be corrupted to batch size 50!
    assert pag["total"] == 1000
    assert pag["returned"] == k
    # next_offset MUST be offset + k so continuation does not skip items k..49!
    assert pag["next_offset"] == k
    assert pag["has_more"] is True
