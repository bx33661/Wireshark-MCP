"""Tests for report generation engine."""

import json

import pytest


class TestReportGeneration:
    """Tests for generating investigation reports."""

    def _make_session(self) -> dict:
        from wireshark_mcp.tools.investigator import (
            _SESSIONS,
            add_finding,
            add_hypothesis,
            create_session,
            update_hypothesis,
        )

        _SESSIONS.clear()
        session = create_session("test.pcap", initial_lead="suspect 1.2.3.4")
        add_hypothesis(session["session_id"], "Host has C2 implant", confidence=0.9)
        update_hypothesis(session["session_id"], 0, status="confirmed", confidence=0.95)
        add_finding(
            session["session_id"],
            {
                "type": "beacon",
                "severity": "high",
                "confidence": 0.87,
                "description": "Periodic C2 communication to 1.2.3.4:443 every 60s",
                "evidence_frames": [100, 200, 300],
            },
        )
        add_finding(
            session["session_id"],
            {
                "type": "exfiltration",
                "severity": "critical",
                "confidence": 0.72,
                "description": "Large outbound transfer via DNS tunneling",
                "evidence_frames": [500, 600],
            },
        )
        return session

    def test_generate_markdown_report(self) -> None:
        from wireshark_mcp.tools.reporter import generate_report

        session = self._make_session()
        report = generate_report(session["session_id"], fmt="markdown")
        assert report is not None
        assert "# Investigation Report" in report
        assert "test.pcap" in report
        assert "C2 implant" in report
        assert "beacon" in report

    def test_generate_json_report(self) -> None:
        from wireshark_mcp.tools.reporter import generate_report

        session = self._make_session()
        report = generate_report(session["session_id"], fmt="json")
        assert report is not None
        parsed = json.loads(report)
        assert parsed["pcap_file"] == "test.pcap"
        assert len(parsed["findings"]) == 2
        assert len(parsed["hypotheses"]) == 1

    def test_extract_iocs(self) -> None:
        from wireshark_mcp.tools.reporter import extract_iocs

        session = self._make_session()
        iocs = extract_iocs(session["session_id"])
        assert isinstance(iocs, list)

    def test_generate_detection_rules(self) -> None:
        from wireshark_mcp.tools.reporter import generate_detection_rules

        session = self._make_session()
        rules = generate_detection_rules(session["session_id"])
        assert isinstance(rules, dict)
        assert "snort" in rules or "sigma" in rules or "yara" in rules

    def test_report_nonexistent_session(self) -> None:
        from wireshark_mcp.tools.reporter import generate_report

        report = generate_report("nonexistent")
        assert report is None
