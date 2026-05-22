"""Natural language query engine for Wireshark MCP — maps intent to tshark operations."""

import json
import logging
from importlib import resources as importlib_resources
from pathlib import Path
from typing import Any

import yaml

from ..tshark.client import TSharkClient
from .envelope import success_response
from .formatting import INFO, WARN

logger = logging.getLogger("wireshark_mcp")

_TEMPLATES: list[dict[str, Any]] | None = None


def _load_templates() -> list[dict[str, Any]]:
    """Load intent templates from bundled + user custom YAML."""
    global _TEMPLATES
    if _TEMPLATES is not None:
        return _TEMPLATES

    templates: list[dict[str, Any]] = []

    try:
        data_ref = importlib_resources.files("wireshark_mcp") / "data" / "nl_templates.yaml"
        with importlib_resources.as_file(data_ref) as fp:
            data = yaml.safe_load(fp.read_text(encoding="utf-8"))
            templates.extend(data.get("templates", []))
    except Exception:
        logger.warning("Could not load bundled NL templates")

    user_file = Path.home() / ".wireshark-mcp" / "nl_templates.yaml"
    if user_file.exists():
        try:
            data = yaml.safe_load(user_file.read_text(encoding="utf-8"))
            templates.extend(data.get("templates", []))
        except Exception:
            logger.warning("Could not load user NL templates")

    _TEMPLATES = templates
    return _TEMPLATES


def _match_intent(query: str) -> dict[str, Any] | None:
    """Match a natural language query to an intent template."""
    templates = _load_templates()
    query_lower = query.lower()

    best_match = None
    best_score = 0

    for template in templates:
        score = 0
        all_keywords = template.get("keywords", []) + template.get("keywords_zh", [])
        for keyword in all_keywords:
            if keyword.lower() in query_lower:
                score += len(keyword)

        if score > best_score:
            best_score = score
            best_match = template

    return best_match if best_score > 0 else None


def make_contextual_nl_tools(client: TSharkClient) -> list[tuple[str, Any]]:
    """Create contextual NL query tools."""

    async def wireshark_nl_query(pcap_file: str, query: str) -> str:
        """[AI] Natural language query — describe what you're looking for and get matched to the right analysis tools."""
        matched = _match_intent(query)

        if matched is None:
            output_parts = [
                f"{WARN} Could not interpret query: '{query}'",
                "",
                f"{INFO} Try describing what you're looking for using keywords like:",
                "  - C2, beacon, command and control",
                "  - lateral movement, pivot, spread",
                "  - exfiltration, data leak, large transfer",
                "  - malware, trojan, backdoor",
                "  - suspicious DNS, tunnel, DGA",
                "  - credential, password, login",
                "  - investigate, full analysis",
                "",
                "Or use standard Wireshark display filter syntax directly.",
            ]
            return success_response("\n".join(output_parts))

        operations = matched.get("operations", [])
        tool_names = [op["tool"] for op in operations]

        output = {
            "interpreted_as": matched["description"],
            "intent": matched["intent"],
            "tools_to_invoke": tool_names,
            "suggested_workflow": f"Run these tools in sequence on '{pcap_file}': {', '.join(tool_names)}",
        }

        output_parts = [
            f"{INFO} Query interpreted as: {matched['description']}",
            "",
            f"{INFO} Recommended tools to run:",
        ]
        for tool_name in tool_names:
            output_parts.append(f"  - {tool_name}")
        output_parts.append("")
        output_parts.append(f"{INFO} Structured response:")
        output_parts.append(json.dumps(output, indent=2))

        return success_response("\n".join(output_parts))

    return [
        ("wireshark_nl_query", wireshark_nl_query),
    ]
