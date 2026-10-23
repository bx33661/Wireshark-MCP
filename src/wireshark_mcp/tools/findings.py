"""Finding schema shared by every security and anomaly tool.

A finding is the unit an investigation keeps: a calibrated observation plus the
packet-level anchors that let anyone re-check it. Tools build findings, then call
``finalize_findings`` so each one carries the same identity and replay data no
matter which detector produced it. Markdown summaries are rendered from the same
list, so the human-readable and machine-readable outputs cannot drift apart.
"""

import hashlib
import json
import shlex
from typing import Any, Literal, TypedDict

Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["candidate", "likely", "confirmed"]

SEVERITY_ORDER: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Candidate MITRE ATT&CK techniques per finding category. These are hints for
# triage and reporting, not attribution: a mapping says what the observed
# behaviour is consistent with, never that the technique was used.
ATTACK_TECHNIQUES: dict[str, list[str]] = {
    "port_scan": ["T1046"],
    "dns_tunnel": ["T1071.004", "T1048"],
    "dos": ["T1498", "T1499"],
    "cleartext_credentials": ["T1040", "T1552"],
    "beaconing": ["T1071", "T1573"],
    "exfiltration": ["T1048", "T1041"],
    "non_standard_port": ["T1571"],
    "arp_spoofing": ["T1557.002"],
    "yara_match": ["T1105"],
}


class FindingEvidence(TypedDict, total=False):
    frame: int | None
    stream: int | None
    protocol: str | None
    filter: str | None
    field: str | None
    value: str | None
    description: str | None


class FindingConstraints(TypedDict, total=False):
    scanned: int
    limit: int
    truncated: bool
    time_window_seconds: float | None
    single_sided: bool | None
    threshold: Any


class Finding(TypedDict, total=False):
    # Identity and provenance, filled by finalize_findings.
    id: str
    tool: str
    category: str
    mitre_attack: list[str]
    reproduce: list[str]
    # The calibrated claim itself.
    observation: str
    severity: Severity
    confidence: Confidence
    evidence: list[FindingEvidence]
    constraints: FindingConstraints
    next_steps: list[str]
    # Detector-specific structured values (counts, intervals, rule names).
    details: dict[str, Any]


def finding_id(tool: str, finding: Finding) -> str:
    """Stable content hash: the same detector seeing the same evidence yields the same id."""
    anchors = [
        [item.get("frame"), item.get("stream"), item.get("filter"), item.get("field"), item.get("value")]
        for item in finding.get("evidence", [])
    ]
    material = json.dumps(
        [tool, finding.get("category"), finding.get("observation"), anchors],
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )
    return "wf-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def reproduce_commands(pcap_file: str, evidence: list[FindingEvidence], max_commands: int = 3) -> list[str]:
    """Native tshark commands that re-derive the evidence without this server."""
    commands: list[str] = []
    capture = shlex.quote(pcap_file)
    for item in evidence:
        display_filter = item.get("filter")
        frame = item.get("frame")
        if display_filter:
            command = f"tshark -n -r {capture} -Y {shlex.quote(display_filter)}"
        elif isinstance(frame, int):
            command = f"tshark -n -r {capture} -Y {shlex.quote(f'frame.number == {frame}')} -V"
        else:
            continue
        if command not in commands:
            commands.append(command)
        if len(commands) >= max_commands:
            break
    return commands


def finalize_findings(tool: str, pcap_file: str, findings: list[Finding], category: str | None = None) -> list[Finding]:
    """Attach id, tool, ATT&CK candidates and replay commands to each finding, in place."""
    for finding in findings:
        finding.setdefault("evidence", [])
        if category:
            finding.setdefault("category", category)
        finding["tool"] = tool
        category = finding.get("category")
        if category and category in ATTACK_TECHNIQUES and finding.get("severity") != "info":
            finding.setdefault("mitre_attack", list(ATTACK_TECHNIQUES[category]))
        commands = reproduce_commands(pcap_file, finding["evidence"])
        if commands:
            finding["reproduce"] = commands
        finding["id"] = finding_id(tool, finding)
    return findings


def render_findings_markdown(findings: list[Finding], max_evidence: int = 5) -> str:
    """Render findings as Markdown from the same data the JSON output carries."""
    if not findings:
        return "No findings."
    lines: list[str] = []
    ordered = sorted(findings, key=lambda item: SEVERITY_ORDER.get(str(item.get("severity", "info")), 5))
    for finding in ordered:
        severity = str(finding.get("severity", "info")).upper()
        confidence = finding.get("confidence", "candidate")
        lines.append(
            f"- [{severity}/{confidence}] {finding.get('observation', '')} ({finding.get('id', 'unidentified')})"
        )
        evidence = finding.get("evidence", [])
        for item in evidence[:max_evidence]:
            anchors = []
            if item.get("frame") is not None:
                anchors.append(f"frame {item['frame']}")
            if item.get("stream") is not None:
                anchors.append(f"stream {item['stream']}")
            if item.get("filter"):
                anchors.append(f"filter `{item['filter']}`")
            text = item.get("description") or item.get("value") or ""
            lines.append(f"  - {text}" + (f" [{', '.join(anchors)}]" if anchors else ""))
        if len(evidence) > max_evidence:
            lines.append(f"  - ... +{len(evidence) - max_evidence} more evidence item(s)")
        if finding.get("mitre_attack"):
            lines.append(f"  - ATT&CK candidates: {', '.join(finding['mitre_attack'])}")
    return "\n".join(lines)


def mask_secret(secret: str, keep_chars: int = 1) -> str:
    """Mask sensitive credentials while preserving structure for investigation."""
    s = secret.strip()
    if not s:
        return ""
    if ":" in s:
        user, passw = s.split(":", 1)
        return f"{user}:{mask_secret(passw, keep_chars=keep_chars)}"
    if len(s) <= 2:
        return "**"
    visible = min(keep_chars, max(1, len(s) // 3))
    return s[:visible] + "*" * (len(s) - visible)
