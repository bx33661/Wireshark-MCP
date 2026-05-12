"""Report generation engine for Wireshark MCP — multi-format investigation reports."""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

from ..tshark.client import TSharkClient
from .envelope import error_response, success_response
from .formatting import INFO, OK
from .investigator import get_session

logger = logging.getLogger("wireshark_mcp")


def _extract_ips_from_text(text: str) -> list[str]:
    """Extract IPv4 addresses from text."""
    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    matches = re.findall(pattern, text)
    private_prefixes = ("10.", "192.168.", "127.", "0.")
    return [ip for ip in set(matches) if not any(ip.startswith(p) for p in private_prefixes)]


def _extract_domains_from_text(text: str) -> list[str]:
    """Extract domain names from text."""
    pattern = r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b"
    matches = re.findall(pattern, text.lower())
    return list(set(matches))


def extract_iocs(session_id: str) -> list[dict[str, str]]:
    """Extract IOCs (Indicators of Compromise) from session findings."""
    session = get_session(session_id)
    if session is None:
        return []

    iocs: list[dict[str, str]] = []
    all_text = ""

    for finding in session.get("findings", []):
        desc = finding.get("description", "")
        all_text += " " + desc

    for h in session.get("hypotheses", []):
        all_text += " " + h.get("description", "")

    if session.get("initial_lead"):
        all_text += " " + session["initial_lead"]

    for ip in _extract_ips_from_text(all_text):
        iocs.append({"type": "ipv4", "value": ip, "source": "investigation"})

    for domain in _extract_domains_from_text(all_text):
        iocs.append({"type": "domain", "value": domain, "source": "investigation"})

    return iocs


def generate_detection_rules(session_id: str) -> dict[str, str]:
    """Generate detection rule suggestions from session findings."""
    session = get_session(session_id)
    if session is None:
        return {}

    rules: dict[str, str] = {}
    iocs = extract_iocs(session_id)
    findings = session.get("findings", [])

    # Snort rules
    snort_rules = []
    for ioc in iocs:
        if ioc["type"] == "ipv4":
            snort_rules.append(
                f'alert ip any any -> {ioc["value"]} any '
                f'(msg:"Suspicious traffic to {ioc["value"]}"; sid:1000001; rev:1;)'
            )
    if snort_rules:
        rules["snort"] = "\n".join(snort_rules)

    # Sigma rule
    sigma_parts = [
        "title: Wireshark-MCP Investigation Finding",
        "status: experimental",
        "description: Auto-generated from investigation session",
        "logsource:",
        "    category: network_connection",
        "detection:",
        "    selection:",
    ]
    ip_iocs = [i["value"] for i in iocs if i["type"] == "ipv4"]
    if ip_iocs:
        sigma_parts.append("        DestinationIp|contains:")
        for ip in ip_iocs[:5]:
            sigma_parts.append(f"            - '{ip}'")
        sigma_parts.append("    condition: selection")
        sigma_parts.append("level: high")
        rules["sigma"] = "\n".join(sigma_parts)

    # YARA rule
    if findings:
        yara_parts = [
            "rule investigation_finding {",
            "    meta:",
            '        description = "Auto-generated from investigation"',
            f'        date = "{datetime.now(timezone.utc).strftime("%Y-%m-%d")}"',
            "    strings:",
        ]
        for i, ioc in enumerate(iocs[:10]):
            if ioc["type"] == "ipv4":
                yara_parts.append(f'        $ip{i} = "{ioc["value"]}"')
            elif ioc["type"] == "domain":
                yara_parts.append(f'        $domain{i} = "{ioc["value"]}"')
        yara_parts.append("    condition:")
        yara_parts.append("        any of them")
        yara_parts.append("}")
        rules["yara"] = "\n".join(yara_parts)

    return rules


def generate_report(session_id: str, fmt: str = "markdown") -> str | None:
    """Generate an investigation report in the specified format."""
    session = get_session(session_id)
    if session is None:
        return None

    if fmt == "json":
        return _generate_json_report(session)
    return _generate_markdown_report(session)


def _generate_json_report(session: dict[str, Any]) -> str:
    """Generate JSON format report."""
    iocs = extract_iocs(session["session_id"])
    rules = generate_detection_rules(session["session_id"])

    report = {
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "pcap_file": session["pcap_file"],
        "initial_lead": session.get("initial_lead"),
        "playbook": session.get("playbook"),
        "status": session["status"],
        "hypotheses": session["hypotheses"],
        "findings": session["findings"],
        "iocs": iocs,
        "detection_rules": rules,
    }
    return json.dumps(report, indent=2)


def _generate_markdown_report(session: dict[str, Any]) -> str:
    """Generate Markdown format report."""
    iocs = extract_iocs(session["session_id"])
    rules = generate_detection_rules(session["session_id"])
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    parts = [
        "# Investigation Report",
        f"\n**Generated:** {now}",
        f"**PCAP:** {session['pcap_file']}",
        f"**Session:** {session['session_id']}",
    ]

    if session.get("initial_lead"):
        parts.append(f"**Initial Lead:** {session['initial_lead']}")
    if session.get("playbook"):
        parts.append(f"**Playbook:** {session['playbook']}")

    # Executive Summary
    confirmed = [h for h in session["hypotheses"] if h["status"] == "confirmed"]
    critical_findings = [f for f in session["findings"] if f.get("severity") == "critical"]
    high_findings = [f for f in session["findings"] if f.get("severity") == "high"]

    parts.append("\n## Executive Summary")
    parts.append(
        f"Investigation analyzed {session['pcap_file']} with "
        f"{len(session['findings'])} findings "
        f"({len(critical_findings)} critical, {len(high_findings)} high). "
        f"{len(confirmed)} hypothesis confirmed."
    )

    # Hypotheses
    if session["hypotheses"]:
        parts.append("\n## Hypotheses")
        for i, h in enumerate(session["hypotheses"]):
            status_icon = {"confirmed": "CONFIRMED", "refuted": "REFUTED"}.get(
                h["status"], "PENDING"
            )
            parts.append(f"\n### Hypothesis #{i}: {h['description']}")
            parts.append(f"- **Status:** {status_icon}")
            parts.append(f"- **Confidence:** {h['confidence']:.0%}")

    # Findings
    if session["findings"]:
        parts.append("\n## Findings")
        for f in session["findings"]:
            parts.append(f"\n### [{f.get('severity', 'medium').upper()}] {f['type']}")
            parts.append(f"- **Confidence:** {f.get('confidence', 0):.0%}")
            parts.append(f"- **Description:** {f.get('description', 'N/A')}")
            if f.get("evidence_frames"):
                parts.append(f"- **Evidence Frames:** {f['evidence_frames']}")

    # IOCs
    if iocs:
        parts.append("\n## Indicators of Compromise (IOCs)")
        parts.append("\n| Type | Value | Source |")
        parts.append("|------|-------|--------|")
        for ioc in iocs:
            parts.append(f"| {ioc['type']} | `{ioc['value']}` | {ioc['source']} |")

    # Detection Rules
    if rules:
        parts.append("\n## Detection Rules")
        for rule_type, rule_content in rules.items():
            parts.append(f"\n### {rule_type.upper()}")
            parts.append(f"```\n{rule_content}\n```")

    return "\n".join(parts)


def make_contextual_reporter_tools(client: TSharkClient) -> list[tuple[str, Any]]:
    """Create contextual report generation tools."""

    async def wireshark_generate_report(
        session_id: str, format: str = "markdown"
    ) -> str:
        """[Investigation] Generate an investigation report (markdown or json) from a session."""
        session = get_session(session_id)
        if session is None:
            return error_response(f"Session '{session_id}' not found")

        report = generate_report(session_id, fmt=format)
        if report is None:
            return error_response("Failed to generate report")

        return success_response(report)

    async def wireshark_extract_iocs(session_id: str) -> str:
        """[Investigation] Extract IOCs (IPs, domains, hashes) from investigation findings."""
        session = get_session(session_id)
        if session is None:
            return error_response(f"Session '{session_id}' not found")

        iocs = extract_iocs(session_id)
        if not iocs:
            return success_response(f"{INFO} No IOCs extracted from session findings.")

        output_parts = [f"{OK} Extracted {len(iocs)} IOCs:"]
        for ioc in iocs:
            output_parts.append(f"  [{ioc['type']}] {ioc['value']}")

        return success_response("\n".join(output_parts))

    async def wireshark_suggest_rules(session_id: str) -> str:
        """[Investigation] Generate Snort/Sigma/YARA detection rule suggestions from investigation."""
        session = get_session(session_id)
        if session is None:
            return error_response(f"Session '{session_id}' not found")

        rules = generate_detection_rules(session_id)
        if not rules:
            return success_response(
                f"{INFO} No detection rules generated (insufficient IOCs or findings)."
            )

        output_parts = [f"{OK} Generated detection rules:"]
        for rule_type, content in rules.items():
            output_parts.append(f"\n--- {rule_type.upper()} ---")
            output_parts.append(content)

        return success_response("\n".join(output_parts))

    return [
        ("wireshark_generate_report", wireshark_generate_report),
        ("wireshark_extract_iocs", wireshark_extract_iocs),
        ("wireshark_suggest_rules", wireshark_suggest_rules),
    ]
