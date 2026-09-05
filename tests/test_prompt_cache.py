"""Guard tests for the client's cached prompt prefix.

The `tools/list` payload is re-sent in the prefix of every request, so its size
is a fixed per-request cost and its byte-stability decides whether the client's
cache survives a server restart. These tests pin both, plus the ceiling that
keeps one oversized result from inflating the rest of a session.

50,325 bytes before this work; 21,438 after consolidating the tool surface.
Bump MAX_WIRE_BYTES deliberately — the slack is there to absorb a schema change,
not a new tool.
"""

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

from wireshark_mcp.mcp_app import WiresharkMCP, cap_result_text
from wireshark_mcp.server import _build_server
from wireshark_mcp.tool_annotations import OUTPUT_PATH_PARAMS, WRITE_TOOLS

MAX_WIRE_BYTES = 22_500
REPO_ROOT = Path(__file__).parent.parent


def _tool_dicts() -> list[dict]:
    """The tool list exactly as it goes over the wire."""
    mcp = _build_server(host="127.0.0.1", port=8080, log_level="ERROR")
    tools = asyncio.run(mcp.list_tools())
    return [t.model_dump(exclude_none=True, by_alias=True) for t in tools]


def test_tool_list_stays_within_prefix_budget() -> None:
    payload = json.dumps(_tool_dicts())
    assert len(payload) < MAX_WIRE_BYTES, (
        f"tools/list is {len(payload)} bytes, over the {MAX_WIRE_BYTES} budget. "
        "Every request pays this. Trim descriptions or schemas rather than raising the cap."
    )


def test_no_tool_declares_an_output_schema() -> None:
    """An auto-derived {"result": string} schema says nothing and doubles every result."""
    offenders = [t["name"] for t in _tool_dicts() if "outputSchema" in t]
    assert not offenders, f"Tools emitting outputSchema: {offenders}"


def test_no_schema_titles() -> None:
    """Pydantic titles duplicate the field name; they are pure prefix weight."""
    offenders = [t["name"] for t in _tool_dicts() if '"title"' in json.dumps(t["inputSchema"])]
    assert not offenders, f"Tools with title keys in inputSchema: {offenders}"


def test_surface_is_byte_identical_across_builds() -> None:
    """Two builds in one process must agree, or ordering depends on something mutable."""
    assert json.dumps(_tool_dicts()) == json.dumps(_tool_dicts())


def test_surface_is_byte_identical_across_hash_seeds() -> None:
    """A surface that shifts with PYTHONHASHSEED means set/dict iteration leaked into it.

    That would silently invalidate the client's cached prefix on every restart, so
    this runs in subprocesses where the seed can actually differ.
    """
    script = (
        "import asyncio,json,sys;"
        "sys.path.insert(0,'src');"
        "from wireshark_mcp.server import _build_server;"
        "m=_build_server(host='127.0.0.1',port=8080,log_level='ERROR');"
        "ts=asyncio.run(m.list_tools());"
        "print(json.dumps([t.model_dump(exclude_none=True,by_alias=True) for t in ts]))"
    )
    outputs = []
    for seed in ("0", "1", "424242"):
        env = os.environ.copy()
        env["PYTHONHASHSEED"] = seed
        proc = subprocess.run(
            [sys.executable, "-c", script],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            env=env,
            check=True,
        )
        outputs.append(proc.stdout.strip())

    assert outputs[0], "subprocess produced no tool list"
    assert outputs[0] == outputs[1] == outputs[2], "tool surface varies with PYTHONHASHSEED"


# ── Result ceiling ──────────────────────────────────────────────────────────


def test_ceiling_truncates_inside_the_envelope() -> None:
    """Cutting the JSON string itself would corrupt it; only `data` may be trimmed."""
    payload = json.dumps({"success": True, "data": "A" * 50_000})
    capped = json.loads(cap_result_text(payload, 2_000))

    assert capped["success"] is True
    assert len(json.dumps(capped, separators=(",", ":"))) <= 2_000
    assert "omitted" in capped["data"], "expected a truncation marker the model can act on"


def test_ceiling_leaves_small_results_untouched() -> None:
    payload = json.dumps({"success": True, "data": "tiny"})
    assert cap_result_text(payload, 8_000) == payload


def test_ceiling_applies_to_non_envelope_text() -> None:
    """Six tool modules bypass the envelope helpers, so bare text must be capped too."""
    assert len(cap_result_text("B" * 50_000, 2_000)) <= 2_000


def test_ceiling_handles_small_limits_without_expanding_output() -> None:
    payload = json.dumps({"success": True, "data": "A" * 50_000})
    assert len(cap_result_text(payload, 500)) <= 500


def test_ceiling_applies_to_structured_data() -> None:
    payload = json.dumps({"success": True, "data": {"items": ["A" * 5_000] * 20}})
    capped = cap_result_text(payload, 2_000)
    assert len(capped) <= 2_000
    assert json.loads(capped)["success"] is True


def test_ceiling_is_enforced_through_call_tool() -> None:
    mcp = WiresharkMCP("t", max_result_chars=2_000)

    async def flood(pcap_file: str) -> str:
        """Returns far more than the ceiling."""
        return json.dumps({"success": True, "data": "C" * 50_000})

    mcp.add_tool(flood, name="flood")
    result = asyncio.run(mcp.call_tool("flood", {"pcap_file": "x.pcap"}))
    assert hasattr(result, "content")
    assert len(result.content) == 1
    assert len(result.content[0].text) <= 2_000, "call_tool did not apply the ceiling"


# ── Annotations ─────────────────────────────────────────────────────────────


def test_every_tool_carries_annotations() -> None:
    """Unannotated tools are treated as destructive, so clients would prompt for every tool."""
    missing = [t["name"] for t in _tool_dicts() if "annotations" not in t]
    assert not missing, f"Tools without annotations: {missing}"


def test_writers_are_never_marked_read_only() -> None:
    """The dangerous direction: a read-only hint on a writer invites auto-approval."""
    mislabelled = [
        t["name"]
        for t in _tool_dicts()
        if t["name"] in WRITE_TOOLS and t["annotations"].get("readOnlyHint") is not False
    ]
    assert not mislabelled, f"Writers marked read-only: {mislabelled}"


def test_write_allowlist_has_no_stale_names() -> None:
    registered = {t["name"] for t in _tool_dicts()}
    stale = sorted(WRITE_TOOLS - registered)
    assert not stale, f"WRITE_TOOLS names no longer registered: {stale}"


def test_a_new_writer_cannot_slip_past_the_allowlist() -> None:
    """Catch a tool that grows an output-path parameter without being declared a writer.

    Without this, adding such a tool would silently make it auto-approvable.
    """
    unlisted = sorted(
        t["name"]
        for t in _tool_dicts()
        if (set(t["inputSchema"].get("properties") or {}) & OUTPUT_PATH_PARAMS) and t["name"] not in WRITE_TOOLS
    )
    assert not unlisted, (
        f"Tools take an output path but are not in WRITE_TOOLS: {unlisted}. "
        "Add them there so clients stop treating them as read-only."
    )
