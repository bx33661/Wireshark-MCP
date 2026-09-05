"""Keep current user documentation aligned with the public product surface."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

from wireshark_mcp.server import _build_server

ROOT = Path(__file__).resolve().parents[1]
CURRENT_DOCS = (
    ROOT / "README.md",
    ROOT / "README_zh.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "SECURITY.md",
    ROOT / "CHANGELOG.md",
    ROOT / "ROADMAP.md",
    ROOT / "ROADMAP_zh.md",
    ROOT / "docs" / "README.md",
    ROOT / "docs" / "README_zh.md",
    ROOT / "docs" / "aggregation.md",
    ROOT / "docs" / "aggregation_zh.md",
    ROOT / "docs" / "architecture.md",
    ROOT / "docs" / "architecture_zh.md",
    ROOT / "docs" / "deployment-scenarios.md",
    ROOT / "docs" / "deployment-scenarios_zh.md",
    ROOT / "docs" / "manual-configuration.md",
    ROOT / "docs" / "manual-configuration_zh.md",
    ROOT / "docs" / "platform-validation.md",
    ROOT / "docs" / "platform-validation_zh.md",
    ROOT / "docs" / "prompt-engineering.md",
    ROOT / "docs" / "prompt-engineering_zh.md",
    ROOT / "docs" / "release-checklist.md",
    ROOT / "skills" / "wireshark-traffic-analysis" / "SKILL.md",
    ROOT / "skills" / "wireshark-traffic-analysis" / "references" / "playbooks.md",
)


def _text(path: Path) -> str:
    assert path.exists(), f"document is missing: {path.relative_to(ROOT)}"
    return path.read_text(encoding="utf-8")


def test_current_documentation_has_no_broken_local_links() -> None:
    missing: list[str] = []
    markdown_link = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
    html_link = re.compile(r'href="([^"]+)"')

    for document in CURRENT_DOCS:
        targets = markdown_link.findall(_text(document)) + html_link.findall(_text(document))
        for raw_target in targets:
            target = raw_target.strip().strip("<>").split("#", 1)[0]
            if not target or re.match(r"^(?:https?://|mailto:)", target):
                continue
            if not (document.parent / target).resolve().exists():
                missing.append(f"{document.relative_to(ROOT)} -> {raw_target}")

    assert not missing, "broken local documentation links:\n" + "\n".join(missing)


def test_current_documentation_names_only_registered_tools() -> None:
    mcp = _build_server(host="127.0.0.1", port=8080, log_level="ERROR")
    registered = {tool.name for tool in asyncio.run(mcp.list_tools())}
    references = {
        name for document in CURRENT_DOCS for name in re.findall(r"\bwireshark_[a-z0-9_]+\b", _text(document))
    }

    # The package/module name is not an MCP tool.
    unknown = references - registered - {"wireshark_mcp"}
    assert not unknown, f"documentation references unknown tools: {sorted(unknown)}"


def test_current_documentation_does_not_restore_removed_interfaces() -> None:
    forbidden = {
        "wireshark_decode_payload": "removed MCP tool",
        "wireshark_security_audit": "removed MCP tool; security_audit is a prompt",
        "--dry-run": "unsupported installer option",
        "--no-backup": "unsupported installer option",
        "wireshark-mcp rollback": "unsupported command",
        "spec/changes": "removed change-record directory",
    }
    offenders: list[str] = []

    for document in CURRENT_DOCS:
        content = _text(document)
        for value, reason in forbidden.items():
            if value in content:
                offenders.append(f"{document.relative_to(ROOT)}: {value} ({reason})")

    assert not offenders, "stale documentation interfaces:\n" + "\n".join(offenders)
