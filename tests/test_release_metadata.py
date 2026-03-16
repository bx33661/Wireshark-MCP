"""Tests that keep release metadata and support policy aligned."""

import json
import re
from pathlib import Path

from wireshark_mcp import __version__

ROOT = Path(__file__).resolve().parents[1]


def _project_version() -> str:
    text = (ROOT / "pyproject.toml").read_text()
    match = re.search(r'^version = "([^"]+)"', text, re.MULTILINE)
    assert match is not None
    return match.group(1)


def test_release_versions_match_across_metadata_files() -> None:
    server_manifest = json.loads((ROOT / "server.json").read_text())
    package = server_manifest["packages"][0]
    project_version = _project_version()

    assert __version__ == project_version
    assert server_manifest["version"] == project_version
    assert package["version"] == project_version


def test_security_policy_targets_the_active_major_line() -> None:
    text = (ROOT / "SECURITY.md").read_text()

    assert "| 1.x" in text
    assert "| < 1.0" in text
    assert "0.4.x" not in text
