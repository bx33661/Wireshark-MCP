"""Guard tests for opt-in tool profiles.

The risk a profile introduces is not a missing tool — it is a *reachable* missing
tool. The shipped prompts, resources, and skill files name tools for the model to
call, and `PROTOCOL_TOOL_MAP` recommends more at runtime. If a profile drops one of
those, a user on that profile is told to call something they do not have, and nothing
in the code links the prose back to the exclusion list. That invariant is the reason
these tests exist; the byte and subset checks are secondary.
"""

import asyncio
import json
from pathlib import Path

import pytest

from wireshark_mcp.mcp_app import WiresharkMCP
from wireshark_mcp.profiles import (
    DEFAULT_PROFILE,
    PROFILE_NAMES,
    excluded_tools,
    profile_description,
)
from wireshark_mcp.server import _build_server
from wireshark_mcp.tools.registry import ToolRegistry

REPO_ROOT = Path(__file__).parent.parent


def _tools(profile: str) -> set[str]:
    mcp = _build_server(host="127.0.0.1", port=8080, log_level="ERROR", profile=profile)
    return {t.name for t in asyncio.run(mcp.list_tools())}


def _payload(profile: str) -> str:
    mcp = _build_server(host="127.0.0.1", port=8080, log_level="ERROR", profile=profile)
    tools = asyncio.run(mcp.list_tools())
    return json.dumps([t.model_dump(exclude_none=True, by_alias=True) for t in tools])


def _reachable_tool_names() -> set[str]:
    """Every tool the shipped guidance can point a caller at."""
    import sys

    sys.path.insert(0, str(Path(__file__).parent))
    from test_tool_references import NON_TOOL_NAMES, PROSE_SOURCES, TOOL_NAME_RE

    from wireshark_mcp.tools.registry import PROTOCOL_TOOL_MAP

    cited: set[str] = set()
    for source in PROSE_SOURCES:
        text = (REPO_ROOT / source).read_text(encoding="utf-8")
        cited |= set(TOOL_NAME_RE.findall(text)) - NON_TOOL_NAMES
    cited |= {rec.tool for recs in PROTOCOL_TOOL_MAP.values() for rec in recs}
    return cited


def test_default_profile_is_full() -> None:
    """Profiles must be opt-in: shipping this may not change any existing surface."""
    assert DEFAULT_PROFILE == "full"
    assert excluded_tools("full") == frozenset()
    assert _tools("full") == _tools(DEFAULT_PROFILE)


@pytest.mark.parametrize("profile", PROFILE_NAMES)
def test_profile_is_a_subset_of_full(profile: str) -> None:
    full = _tools("full")
    assert _tools(profile) <= full


def test_every_documented_or_recommended_tool_exists_in_full_profile() -> None:
    """Guidance may qualify profile-specific tools, but every named tool must exist."""
    available = _tools("full")
    stranded = sorted(_reachable_tool_names() - available)
    assert not stranded, (
        f"shipped prompts, resources, skills, or protocol recommendations name missing tools: {stranded}"
    )


@pytest.mark.parametrize("profile", PROFILE_NAMES)
def test_exclusion_names_all_exist(profile: str) -> None:
    """A typo in an exclusion set would silently exclude nothing."""
    full = _tools("full")
    unknown = sorted(excluded_tools(profile) - full)
    assert not unknown, f"profile {profile!r} excludes names that are not tools: {unknown}"


@pytest.mark.parametrize("profile", PROFILE_NAMES)
def test_profile_payload_is_byte_identical_across_builds(profile: str) -> None:
    """Each profile's prefix must be stable, or the client's cache is invalidated."""
    assert _payload(profile) == _payload(profile)


def test_reduced_profiles_actually_reduce() -> None:
    """Guard against an exclusion set that has quietly stopped matching anything."""
    full = _tools("full")
    analysis = _tools("analysis")
    core = _tools("core")
    assert core < analysis < full, f"expected core < analysis < full, got {len(core)}/{len(analysis)}/{len(full)}"


@pytest.mark.parametrize("profile", PROFILE_NAMES)
def test_excluded_tools_are_uncallable_not_merely_hidden(profile: str) -> None:
    """An excluded tool must be absent from the manager, not just from tools/list."""
    mcp = _build_server(host="127.0.0.1", port=8080, log_level="ERROR", profile=profile)
    for name in excluded_tools(profile):
        assert mcp._tool_manager.get_tool(name) is None, f"{name} is excluded but still callable"


def test_registry_reports_only_tools_it_actually_registered(mock_client) -> None:
    """Profile exclusions must not appear in the registry result or registration log count."""
    excluded = frozenset({"wireshark_scan_file_signatures"})
    mcp = WiresharkMCP("test", excluded_tools=excluded)
    reported = set(ToolRegistry(mcp, mock_client).register())
    actual = set(mcp._tool_manager._tools)

    assert reported == actual
    assert reported.isdisjoint(excluded)


def test_every_profile_has_a_description() -> None:
    for profile in PROFILE_NAMES:
        assert profile_description(profile) != "unknown profile"


def test_unknown_profile_falls_back_to_full_surface() -> None:
    """A bad name must not silently hand the caller an arbitrarily reduced surface."""
    assert excluded_tools("nonsense") == frozenset()


def test_profile_is_exposed_on_the_cli() -> None:
    from wireshark_mcp.server import _build_parser

    args = _build_parser().parse_args(["serve", "--profile", "core"])
    assert args.profile == "core"

    default_args = _build_parser().parse_args(["serve"])
    assert default_args.profile == DEFAULT_PROFILE
