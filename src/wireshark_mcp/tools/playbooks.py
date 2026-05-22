"""Playbook engine for Wireshark MCP — YAML-based investigation workflows."""

import logging
from importlib import resources as importlib_resources
from pathlib import Path
from typing import Any

import yaml

from ..tshark.client import TSharkClient
from .envelope import success_response
from .formatting import INFO

logger = logging.getLogger("wireshark_mcp")

_PLAYBOOKS: list[dict[str, Any]] | None = None


def load_playbooks() -> list[dict[str, Any]]:
    """Load all playbooks from bundled + user directories."""
    global _PLAYBOOKS
    if _PLAYBOOKS is not None:
        return _PLAYBOOKS

    playbooks: list[dict[str, Any]] = []

    # Load bundled playbooks
    try:
        data_dir = importlib_resources.files("wireshark_mcp") / "data" / "playbooks"
        for item in data_dir.iterdir():
            if str(item).endswith(".yaml"):
                with importlib_resources.as_file(item) as fp:
                    pb = yaml.safe_load(fp.read_text())
                    if pb and "name" in pb:
                        playbooks.append(pb)
    except Exception:
        logger.warning("Could not load bundled playbooks")

    # Load user custom playbooks
    user_dir = Path.home() / ".wireshark-mcp" / "playbooks"
    if user_dir.exists():
        for f in user_dir.glob("*.yaml"):
            try:
                pb = yaml.safe_load(f.read_text())
                if pb and "name" in pb:
                    playbooks.append(pb)
            except Exception:
                logger.warning("Could not load user playbook: %s", f)

    _PLAYBOOKS = playbooks
    return _PLAYBOOKS


def get_playbook(name: str) -> dict[str, Any] | None:
    """Get a playbook by name."""
    for pb in load_playbooks():
        if pb["name"] == name:
            return pb
    return None


def list_playbook_names() -> list[str]:
    """List all available playbook names."""
    return [pb["name"] for pb in load_playbooks()]


def make_contextual_playbook_tools(client: TSharkClient) -> list[tuple[str, Any]]:
    """Create contextual playbook tools."""

    async def wireshark_list_playbooks(pcap_file: str = "") -> str:
        """[Investigation] List all available investigation playbooks."""
        playbooks = load_playbooks()
        output_parts = [f"{INFO} Available Investigation Playbooks ({len(playbooks)})"]
        for pb in playbooks:
            steps_str = " → ".join(s.get("tool", "?") for s in pb.get("steps", []))
            output_parts.append(f"\n  {pb['name']}: {pb['description']}")
            output_parts.append(f"    Steps: {steps_str}")
        return success_response("\n".join(output_parts))

    return [
        ("wireshark_list_playbooks", wireshark_list_playbooks),
    ]
