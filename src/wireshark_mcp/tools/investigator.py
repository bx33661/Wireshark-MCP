"""Investigation engine for Wireshark MCP — stateful session management."""

import logging
import uuid
from typing import Any

from ..tshark.client import TSharkClient
from .envelope import error_response, success_response
from .formatting import CRIT, INFO, OK
from .playbooks import get_playbook, list_playbook_names

logger = logging.getLogger("wireshark_mcp")

_SESSIONS: dict[str, dict[str, Any]] = {}


def create_session(
    pcap_file: str,
    initial_lead: str | None = None,
    playbook: str | None = None,
) -> dict[str, Any]:
    """Create a new investigation session."""
    session_id = str(uuid.uuid4())[:8]
    session: dict[str, Any] = {
        "session_id": session_id,
        "pcap_file": pcap_file,
        "status": "active",
        "initial_lead": initial_lead,
        "playbook": playbook,
        "hypotheses": [],
        "findings": [],
        "next_steps": [],
        "executed_steps": [],
        "evidence_summary": [],
    }
    _SESSIONS[session_id] = session
    return session


def get_session(session_id: str) -> dict[str, Any] | None:
    """Get a session by ID."""
    return _SESSIONS.get(session_id)


def list_sessions() -> list[dict[str, Any]]:
    """List all active sessions."""
    return list(_SESSIONS.values())


def add_hypothesis(
    session_id: str, description: str, confidence: float = 0.5
) -> None:
    """Add a hypothesis to a session."""
    session = _SESSIONS.get(session_id)
    if session is None:
        return
    session["hypotheses"].append(
        {"description": description, "confidence": confidence, "status": "pending"}
    )


def update_hypothesis(
    session_id: str,
    index: int,
    status: str | None = None,
    confidence: float | None = None,
) -> None:
    """Update a hypothesis status or confidence."""
    session = _SESSIONS.get(session_id)
    if session is None:
        return
    if index < 0 or index >= len(session["hypotheses"]):
        return
    if status is not None:
        session["hypotheses"][index]["status"] = status
    if confidence is not None:
        session["hypotheses"][index]["confidence"] = confidence


def add_finding(session_id: str, finding: dict[str, Any]) -> None:
    """Add a finding to a session."""
    session = _SESSIONS.get(session_id)
    if session is None:
        return
    session["findings"].append(finding)


def make_contextual_investigator_tools(client: TSharkClient) -> list[tuple[str, Any]]:
    """Create contextual investigation tools."""

    async def wireshark_investigate(
        pcap_file: str,
        initial_lead: str = "",
        playbook: str = "",
    ) -> str:
        """[Investigation] Start an investigation session. Optionally provide an initial lead (suspect IP, alert) or a playbook name (malware_c2, lateral_movement, data_exfil, initial_access)."""
        pb = None
        if playbook:
            pb = get_playbook(playbook)
            if pb is None:
                available = ", ".join(list_playbook_names())
                return error_response(
                    f"Playbook '{playbook}' not found. Available: {available}"
                )

        session = create_session(
            pcap_file,
            initial_lead=initial_lead or None,
            playbook=playbook or None,
        )

        output_parts = [
            f"{OK} Investigation session started: {session['session_id']}",
            f"  PCAP: {pcap_file}",
        ]

        if initial_lead:
            output_parts.append(f"  Lead: {initial_lead}")

        if pb:
            output_parts.append(f"  Playbook: {pb['name']} — {pb['description']}")
            steps_str = " → ".join(s.get("tool", "?") for s in pb.get("steps", []))
            output_parts.append(f"  Steps: {steps_str}")
            output_parts.append(
                f"\n{INFO} Execute playbook steps with wireshark_execute_playbook_step"
            )
        else:
            output_parts.append(f"\n{INFO} Suggested next steps:")
            output_parts.append("  1. Run wireshark_quick_analysis for overview")
            output_parts.append("  2. Run wireshark_detect_anomalies for anomaly scan")
            output_parts.append("  3. Add hypotheses with wireshark_add_hypothesis")
            output_parts.append("  4. Verify hypotheses with targeted tools")

        return success_response("\n".join(output_parts))

    async def wireshark_execute_playbook_step(
        session_id: str, step_index: int = -1
    ) -> str:
        """[Investigation] Execute the next (or specified) step in the active playbook for a session."""
        session = get_session(session_id)
        if session is None:
            return error_response(f"Session '{session_id}' not found")

        playbook_name = session.get("playbook")
        if not playbook_name:
            return error_response("No playbook attached to this session")

        pb = get_playbook(playbook_name)
        if pb is None:
            return error_response(f"Playbook '{playbook_name}' no longer available")

        steps = pb.get("steps", [])
        executed = session.get("executed_steps", [])

        if step_index < 0:
            step_index = len(executed)

        if step_index >= len(steps):
            return success_response(
                f"{OK} All playbook steps completed ({len(steps)} steps). "
                f"Use wireshark_generate_report to create the investigation report."
            )

        step = steps[step_index]
        tool_name = step.get("tool", "unknown")
        description = step.get("description", "")

        output_parts = [
            f"{INFO} Executing playbook step {step_index + 1}/{len(steps)}",
            f"  Tool: {tool_name}",
            f"  Description: {description}",
        ]

        # Record step execution
        executed.append({"step_index": step_index, "tool": tool_name, "status": "done"})
        session["executed_steps"] = executed

        remaining = len(steps) - len(executed)
        if remaining > 0:
            next_step = steps[step_index + 1]
            output_parts.append(
                f"\n{INFO} Next step ({step_index + 2}/{len(steps)}): "
                f"{next_step.get('tool', '?')} — {next_step.get('description', '')}"
            )
        else:
            output_parts.append(
                f"\n{OK} Playbook complete. Generate report with wireshark_generate_report."
            )

        return success_response("\n".join(output_parts))

    async def wireshark_add_hypothesis(
        session_id: str, description: str, confidence: float = 0.5
    ) -> str:
        """[Investigation] Add a hypothesis to an investigation session (e.g., 'Host X has C2 implant')."""
        session = get_session(session_id)
        if session is None:
            return error_response(f"Session '{session_id}' not found")

        add_hypothesis(session_id, description, confidence)
        idx = len(session["hypotheses"]) - 1
        return success_response(
            f"{OK} Hypothesis #{idx} added: {description} (confidence: {confidence:.0%})\n"
            f"  Status: pending — verify with targeted analysis tools"
        )

    async def wireshark_update_hypothesis(
        session_id: str,
        hypothesis_index: int,
        status: str = "",
        confidence: float = -1.0,
    ) -> str:
        """[Investigation] Update a hypothesis status (pending/confirmed/refuted) and confidence."""
        session = get_session(session_id)
        if session is None:
            return error_response(f"Session '{session_id}' not found")

        if hypothesis_index < 0 or hypothesis_index >= len(session["hypotheses"]):
            return error_response(
                f"Hypothesis index {hypothesis_index} out of range "
                f"(0-{len(session['hypotheses']) - 1})"
            )

        update_hypothesis(
            session_id,
            hypothesis_index,
            status=status if status else None,
            confidence=confidence if confidence >= 0 else None,
        )

        h = session["hypotheses"][hypothesis_index]
        icon = OK if h["status"] == "confirmed" else (CRIT if h["status"] == "refuted" else INFO)
        return success_response(
            f"{icon} Hypothesis #{hypothesis_index} updated:\n"
            f"  {h['description']}\n"
            f"  Status: {h['status']} | Confidence: {h['confidence']:.0%}"
        )

    async def wireshark_add_finding(
        session_id: str,
        finding_type: str,
        severity: str = "medium",
        confidence: float = 0.5,
        description: str = "",
        evidence_frames: str = "",
    ) -> str:
        """[Investigation] Record a finding in the investigation session."""
        session = get_session(session_id)
        if session is None:
            return error_response(f"Session '{session_id}' not found")

        frames = []
        if evidence_frames:
            frames = [int(f.strip()) for f in evidence_frames.split(",") if f.strip().isdigit()]

        finding = {
            "type": finding_type,
            "severity": severity,
            "confidence": confidence,
            "description": description,
            "evidence_frames": frames,
        }
        add_finding(session_id, finding)

        return success_response(
            f"{OK} Finding recorded:\n"
            f"  Type: {finding_type} | Severity: {severity} | Confidence: {confidence:.0%}\n"
            f"  {description}"
        )

    async def wireshark_session_status(session_id: str) -> str:
        """[Investigation] Get the current status of an investigation session."""
        session = get_session(session_id)
        if session is None:
            return error_response(f"Session '{session_id}' not found")

        output_parts = [
            f"{INFO} Investigation Session: {session_id}",
            f"  PCAP: {session['pcap_file']}",
            f"  Status: {session['status']}",
        ]

        if session.get("playbook"):
            pb = get_playbook(session["playbook"])
            total_steps = len(pb["steps"]) if pb else 0
            done_steps = len(session.get("executed_steps", []))
            output_parts.append(f"  Playbook: {session['playbook']} ({done_steps}/{total_steps} steps)")

        if session["hypotheses"]:
            output_parts.append(f"\n  Hypotheses ({len(session['hypotheses'])}):")
            for i, h in enumerate(session["hypotheses"]):
                icon = OK if h["status"] == "confirmed" else (CRIT if h["status"] == "refuted" else "[ ]")
                output_parts.append(f"    {icon} #{i}: {h['description']} ({h['confidence']:.0%})")

        if session["findings"]:
            output_parts.append(f"\n  Findings ({len(session['findings'])}):")
            for f in session["findings"]:
                output_parts.append(f"    [{f['severity'].upper()}] {f['type']}: {f['description']}")

        return success_response("\n".join(output_parts))

    return [
        ("wireshark_investigate", wireshark_investigate),
        ("wireshark_execute_playbook_step", wireshark_execute_playbook_step),
        ("wireshark_add_hypothesis", wireshark_add_hypothesis),
        ("wireshark_update_hypothesis", wireshark_update_hypothesis),
        ("wireshark_add_finding", wireshark_add_finding),
        ("wireshark_session_status", wireshark_session_status),
    ]
