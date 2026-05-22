"""Integration tests for Phase 3 — full investigation workflow."""

import json


class TestInvestigationWorkflow:
    """End-to-end investigation workflow test."""

    def test_full_workflow_without_pcap(self) -> None:
        """Test session lifecycle without actual pcap (unit-level integration)."""
        from wireshark_mcp.tools.investigator import (
            _SESSIONS,
            add_finding,
            add_hypothesis,
            create_session,
            update_hypothesis,
        )
        from wireshark_mcp.tools.reporter import (
            extract_iocs,
            generate_detection_rules,
            generate_report,
        )

        _SESSIONS.clear()

        # 1. Create session
        session = create_session("evidence.pcap", initial_lead="Alert: beacon to 45.33.32.156")
        assert session["status"] == "active"

        # 2. Add hypotheses
        add_hypothesis(session["session_id"], "Host 192.168.1.50 has C2 implant to 45.33.32.156", confidence=0.7)
        add_hypothesis(session["session_id"], "DNS tunneling for data exfiltration", confidence=0.5)

        # 3. Add findings
        add_finding(
            session["session_id"],
            {
                "type": "beacon",
                "severity": "high",
                "confidence": 0.87,
                "description": "Periodic connection to 45.33.32.156:443 every 60s",
                "evidence_frames": [100, 200, 300, 400],
            },
        )
        add_finding(
            session["session_id"],
            {
                "type": "dns_tunnel",
                "severity": "critical",
                "confidence": 0.72,
                "description": "High-entropy DNS queries to evil.example.com",
                "evidence_frames": [500, 600, 700],
            },
        )

        # 4. Update hypotheses
        update_hypothesis(session["session_id"], 0, status="confirmed", confidence=0.95)
        update_hypothesis(session["session_id"], 1, status="confirmed", confidence=0.8)

        # 5. Generate report
        md_report = generate_report(session["session_id"], fmt="markdown")
        assert "# Investigation Report" in md_report
        assert "45.33.32.156" in md_report
        assert "CONFIRMED" in md_report

        json_report = generate_report(session["session_id"], fmt="json")
        parsed = json.loads(json_report)
        assert parsed["pcap_file"] == "evidence.pcap"
        assert len(parsed["findings"]) == 2
        assert len(parsed["hypotheses"]) == 2

        # 6. Extract IOCs
        iocs = extract_iocs(session["session_id"])
        ip_iocs = [i for i in iocs if i["type"] == "ipv4"]
        assert any(i["value"] == "45.33.32.156" for i in ip_iocs)

        domain_iocs = [i for i in iocs if i["type"] == "domain"]
        assert any("evil.example.com" in i["value"] for i in domain_iocs)

        # 7. Generate detection rules
        rules = generate_detection_rules(session["session_id"])
        assert "snort" in rules
        assert "45.33.32.156" in rules["snort"]

    def test_playbook_session(self) -> None:
        """Test creating a session with a playbook."""
        from wireshark_mcp.tools.investigator import _SESSIONS, create_session
        from wireshark_mcp.tools.playbooks import get_playbook

        _SESSIONS.clear()
        session = create_session("malware.pcap", playbook="malware_c2")
        assert session["playbook"] == "malware_c2"

        pb = get_playbook("malware_c2")
        assert pb is not None
        assert len(pb["steps"]) >= 3

    def test_all_phase3_tools_registered(self) -> None:
        """Verify all Phase 3 tool factories produce tools."""
        from unittest.mock import MagicMock

        from wireshark_mcp.tools.investigator import make_contextual_investigator_tools
        from wireshark_mcp.tools.playbooks import make_contextual_playbook_tools
        from wireshark_mcp.tools.reporter import make_contextual_reporter_tools

        mock_client = MagicMock()

        investigator_tools = make_contextual_investigator_tools(mock_client)
        assert len(investigator_tools) >= 5
        tool_names = [name for name, _ in investigator_tools]
        assert "wireshark_investigate" in tool_names
        assert "wireshark_session_status" in tool_names

        reporter_tools = make_contextual_reporter_tools(mock_client)
        assert len(reporter_tools) >= 3
        tool_names = [name for name, _ in reporter_tools]
        assert "wireshark_generate_report" in tool_names
        assert "wireshark_extract_iocs" in tool_names

        playbook_tools = make_contextual_playbook_tools(mock_client)
        assert len(playbook_tools) >= 1
        tool_names = [name for name, _ in playbook_tools]
        assert "wireshark_list_playbooks" in tool_names
