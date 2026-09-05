"""Guard test: every field name the server sends must exist in tshark's registry.

`tshark -T fields -e <name>` does not degrade when a name is wrong — it refuses the
whole command with `Some fields aren't valid` and exit code 1. A single mistyped name
therefore breaks the entire tool, not one column of its output.

Tests that assert "the tool asked for field X" cannot catch this, because the expected
value is copied from the same implementation being tested: both copies agree, and both
are wrong. This test compares against `tshark -G fields` instead — the authority the
command is actually validated against at runtime.

It found four live breakages when introduced:

  tls.handshake.extensions.server_name  ->  tls.handshake.extensions_server_name
  s7comm.param.item.dbnum               ->  s7comm.param.item.db
  websocket.masked                      ->  websocket.mask
  mqtt.prop.id                          ->  mqtt.prop_key

The first appeared in three places, so `analyze_protocol` for tls_handshakes and quic,
plus `extract_fingerprints`, all failed outright against real tshark.

Skipped when tshark is unavailable, since there is nothing to validate against.
"""

import json
import os
import shutil
import subprocess

import pytest
from conftest import MockTSharkClient, call_tool_text
from mcp.server import MCPServer

from wireshark_mcp.tools.analyze import make_analyze_tools, supported_protocols
from wireshark_mcp.tools.registry import ToolRegistry

pytestmark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")


@pytest.fixture(scope="module")
def tshark_fields() -> frozenset[str]:
    """Every field name tshark will accept after `-e`."""
    out = subprocess.run(["tshark", "-G", "fields"], capture_output=True, text=True, timeout=120).stdout
    names: set[str] = set()
    for line in out.splitlines():
        parts = line.split("\t")
        # 'F' rows are fields, 'P' rows are protocols; both are usable with -e.
        if parts and parts[0] in {"F", "P"} and len(parts) > 2:
            names.add(parts[2])
    assert len(names) > 10_000, f"only parsed {len(names)} field names; the -G format may have changed"

    # Column pseudo-fields are accepted by `-e` but are not dissector fields, so
    # `-G fields` does not list them. Verified against the running tshark below
    # rather than assumed, so this allowance cannot hide a real breakage.
    column_fields = {
        "_ws.col.Time",
        "_ws.col.Source",
        "_ws.col.Destination",
        "_ws.col.Protocol",
        "_ws.col.Length",
        "_ws.col.Info",
    }
    probe = subprocess.run(
        ["tshark", "-r", os.devnull, "-T", "fields", *[a for f in sorted(column_fields) for a in ("-e", f)]],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert "aren't valid" not in probe.stderr, f"tshark rejected a column pseudo-field: {probe.stderr.strip()}"

    return frozenset(names | column_fields)


# Field names kept only to support tshark older than the rename that removed them.
# Each must be paired with a current name that the tool tries first, so the legacy
# pass only ever runs where the current one is unavailable.
LEGACY_FALLBACK_FIELDS = {
    # Wireshark 3.0 renamed the BOOTP dissector to DHCP.
    "bootp.type",
    "bootp.hw.mac_addr",
    "bootp.ip.your",
    "bootp.ip.server",
    "bootp.option.hostname",
    "bootp.option.dhcp",
    "bootp.option.requested_ip_address",
    "bootp.option.domain_name_server",
}


def _fields_emitted_by(coro_factory) -> set[str]:
    """Run a tool against the mock and collect the `-e` arguments it produced."""
    client = MockTSharkClient()
    import asyncio

    asyncio.run(coro_factory(client))
    return client.fields_requested()


@pytest.mark.parametrize("protocol", supported_protocols())
def test_analyze_protocol_fields_are_valid(protocol: str, tshark_fields: frozenset[str]) -> None:
    async def run(client: MockTSharkClient) -> None:
        tool = dict(make_analyze_tools(client))["wireshark_analyze_protocol"]
        await tool("demo.pcap", protocol)

    invalid = sorted(_fields_emitted_by(run) - tshark_fields - LEGACY_FALLBACK_FIELDS)
    assert not invalid, (
        f"analyze_protocol(protocol={protocol!r}) sends field names tshark does not know: {invalid}. "
        "tshark rejects the whole command, so this protocol is completely broken."
    )


def test_all_registry_tool_fields_are_valid(tshark_fields: frozenset[str]) -> None:
    """Sweep the tools that hardcode field lists but take only a pcap path."""

    async def run(client: MockTSharkClient) -> None:
        mcp = MCPServer("test")
        registry = ToolRegistry(mcp, client)
        names = registry.register()
        for name in names:
            tool = mcp._tool_manager.get_tool(name)
            if tool is None:
                continue
            required = set(tool.parameters.get("required", []))
            # Only tools whose sole required argument is the capture can be driven blind.
            if required - {"pcap_file"}:
                continue
            try:
                await call_tool_text(mcp, name, {"pcap_file": "demo.pcap"})
            except Exception:
                # A tool may reject the mock's canned output; its fields were still recorded.
                continue

    invalid = sorted(_fields_emitted_by(run) - tshark_fields - LEGACY_FALLBACK_FIELDS)
    assert not invalid, f"registry tools send field names tshark does not know: {invalid}"


def test_the_check_would_notice_a_bad_name(tshark_fields: frozenset[str]) -> None:
    """Prove the registry lookup is strict rather than vacuously true."""
    assert "tls.handshake.extensions_server_name" in tshark_fields
    assert "tls.handshake.extensions.server_name" not in tshark_fields
    assert "not.a.real.field" not in tshark_fields


def test_legacy_fallbacks_are_genuinely_unavailable(tshark_fields: frozenset[str]) -> None:
    """The allowance above is for removed names only, not a hole to park typos in.

    If one of these becomes valid again, it no longer needs the exemption; if a name
    is added that this tshark accepts, the exemption is hiding it from the real check.
    """
    still_valid = sorted(LEGACY_FALLBACK_FIELDS & tshark_fields)
    assert not still_valid, f"exempted as legacy but this tshark accepts them: {still_valid}"


def test_dhcp_tries_the_current_field_names_first() -> None:
    """The legacy pass must be the fallback, not the default.

    `bootp.*` has been rejected by every tshark since 3.0, so trying it first made the
    first subprocess of every DHCP call a guaranteed failure.
    """
    import asyncio

    client = MockTSharkClient()
    tool = dict(make_analyze_tools(client))["wireshark_analyze_protocol"]
    asyncio.run(tool("demo.pcap", "dhcp"))

    assert client._commands, "no command was run"
    first = client._commands[0]
    assert "dhcp" in first, "the first DHCP pass should use the current dissector name"
    assert "bootp" not in " ".join(first), "the first DHCP pass still uses the removed bootp names"


def test_display_filters_are_accepted_by_tshark(tshark_fields: frozenset[str]) -> None:
    """A bad display filter fails the command too, so compile every one we send."""
    client = MockTSharkClient()
    import asyncio

    async def run() -> None:
        tool = dict(make_analyze_tools(client))["wireshark_analyze_protocol"]
        for protocol in supported_protocols():
            await tool("demo.pcap", protocol)

    asyncio.run(run())

    bad: list[str] = []
    for display_filter in sorted(client.filters_applied()):
        probe = subprocess.run(
            ["tshark", "-Y", display_filter, "-r", os.devnull],
            capture_output=True,
            text=True,
            timeout=30,
        )
        # An unparseable filter is reported before the (invalid) capture file is read.
        if "isn't a valid display filter" in probe.stderr or "Unexpected end of filter" in probe.stderr:
            bad.append(f"{display_filter}: {probe.stderr.strip().splitlines()[0]}")
    assert not bad, "display filters tshark cannot compile: " + json.dumps(bad, indent=2)
