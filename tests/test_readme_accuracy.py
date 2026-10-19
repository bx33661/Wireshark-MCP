"""Guard tests: the README's numbers must match the server it documents.

Counting tools by hand goes stale the first time one is added or removed, and a
stale count in the README is the kind of error a reader trusts. These tests read
the numbers back out of the prose and compare them to the live surface.

Both languages are checked. The patterns are per-language rather than shared: an
English-only regex silently matches nothing in README_zh.md, which would leave the
translation free to drift while the suite stayed green.
"""

import asyncio
import json
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

from wireshark_mcp.profiles import PROFILE_NAMES
from wireshark_mcp.server import _build_server
from wireshark_mcp.tool_annotations import CACHE_WRITE_TOOLS, WRITE_TOOLS

REPO_ROOT = Path(__file__).parent.parent


@dataclass(frozen=True)
class ReadmeSpec:
    """Where each number lives in one language's README."""

    path: str
    table_header: str
    headline: str  # captures the tool count
    read_write: str  # captures (read-only count, writer count)


SPECS = [
    ReadmeSpec(
        path="README.md",
        table_header="| Category |",
        headline=r"(\d+)\s+tools, each backed by",
        read_write=r"auto-approve the (\d+) read-only[^.]*?prompt for the (\d+)",
    ),
    ReadmeSpec(
        path="README_zh.md",
        table_header="| 类别 |",
        headline=r"(\d+)\s*个工具，每个都由真实",
        read_write=r"自动放行\s*(\d+)\s*个只读分析工具.*?会创建文件的\s*(\d+)\s*个工具",
    ),
]
IDS = [s.path for s in SPECS]


def _surface(profile: str = "full") -> tuple[int, int]:
    """(tool count, payload bytes) for a profile."""
    mcp = _build_server(host="127.0.0.1", port=8080, log_level="ERROR", profile=profile)
    tools = asyncio.run(mcp.list_tools())
    payload = json.dumps([t.model_dump(exclude_none=True, by_alias=True) for t in tools])
    return len(tools), len(payload)


def _text(spec: ReadmeSpec) -> str:
    return (REPO_ROOT / spec.path).read_text(encoding="utf-8")


@pytest.mark.parametrize("spec", SPECS, ids=IDS)
def test_category_counts_sum_to_the_real_tool_count(spec: ReadmeSpec) -> None:
    _, _, after = _text(spec).partition(spec.table_header)
    block, _, _ = after.partition("\n\n")
    counts = [int(m) for m in re.findall(r"\|\s*(\d+)\s*\|\s*$", block, re.M)]
    assert counts, f"{spec.path}: could not find the category table"

    total, _ = _surface()
    assert sum(counts) == total, (
        f"{spec.path} category counts sum to {sum(counts)} but the server registers {total} tools"
    )


@pytest.mark.parametrize("spec", SPECS, ids=IDS)
def test_headline_tool_count_is_accurate(spec: ReadmeSpec) -> None:
    total, _ = _surface()
    match = re.search(spec.headline, _text(spec))
    assert match, f"{spec.path}: could not find the headline tool count"
    assert int(match.group(1)) == total, f"{spec.path} claims {match.group(1)} tools; the server registers {total}"


@pytest.mark.parametrize("spec", SPECS, ids=IDS)
def test_profile_table_matches_the_real_profiles(spec: ReadmeSpec) -> None:
    text = _text(spec)
    for profile in PROFILE_NAMES:
        row = re.search(rf"^\|\s*`{profile}`[^|]*\|\s*(\d+)\s*\|\s*~(\d+)\s*KB", text, re.M)
        assert row, f"{spec.path}: no profile table row for {profile!r}"

        documented_tools, documented_kb = int(row.group(1)), int(row.group(2))
        actual_tools, actual_bytes = _surface(profile)
        assert documented_tools == actual_tools, (
            f"{spec.path}: profile {profile!r} documented as {documented_tools} tools, actually {actual_tools}"
        )
        # Rounded to the nearest KB in prose, so allow the rounding but not drift.
        assert abs(documented_kb - actual_bytes / 1000) < 1.0, (
            f"{spec.path}: profile {profile!r} documented as ~{documented_kb} KB, actually {actual_bytes} B"
        )


@pytest.mark.parametrize("spec", SPECS, ids=IDS)
def test_read_write_split_is_accurate(spec: ReadmeSpec) -> None:
    mcp = _build_server(host="127.0.0.1", port=8080, log_level="ERROR")
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    writers = len(names & set(WRITE_TOOLS))
    # Cache writers (the capture index) are neither read-only nor file-creating.
    readers = len(names) - writers - len(names & set(CACHE_WRITE_TOOLS))

    match = re.search(spec.read_write, _text(spec), re.S)
    assert match, f"{spec.path}: could not find the read/write split sentence"
    assert (int(match.group(1)), int(match.group(2))) == (readers, writers), (
        f"{spec.path} claims {match.group(1)} read-only / {match.group(2)} writers; actual {readers}/{writers}"
    )
