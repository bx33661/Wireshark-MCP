"""Tests for investigation engine."""

import pytest


class TestInvestigationSession:
    """Tests for session creation and state management."""

    def test_create_session(self) -> None:
        from wireshark_mcp.tools.investigator import create_session
        session = create_session("test.pcap")
        assert session["pcap_file"] == "test.pcap"
        assert session["status"] == "active"
        assert session["hypotheses"] == []
        assert session["findings"] == []
        assert session["next_steps"] == []
        assert "session_id" in session

    def test_create_session_with_lead(self) -> None:
        from wireshark_mcp.tools.investigator import create_session
        session = create_session("test.pcap", initial_lead="suspect IP 1.2.3.4")
        assert session["initial_lead"] == "suspect IP 1.2.3.4"

    def test_create_session_with_playbook(self) -> None:
        from wireshark_mcp.tools.investigator import create_session
        session = create_session("test.pcap", playbook="malware_c2")
        assert session["playbook"] == "malware_c2"

    def test_get_session(self) -> None:
        from wireshark_mcp.tools.investigator import create_session, get_session
        session = create_session("test.pcap")
        retrieved = get_session(session["session_id"])
        assert retrieved is not None
        assert retrieved["session_id"] == session["session_id"]

    def test_get_nonexistent_session(self) -> None:
        from wireshark_mcp.tools.investigator import get_session
        assert get_session("nonexistent-id") is None

    def test_list_sessions(self) -> None:
        from wireshark_mcp.tools.investigator import (
            _SESSIONS,
            create_session,
            list_sessions,
        )
        _SESSIONS.clear()
        create_session("a.pcap")
        create_session("b.pcap")
        sessions = list_sessions()
        assert len(sessions) == 2


class TestHypothesisManagement:
    """Tests for hypothesis add/update."""

    def test_add_hypothesis(self) -> None:
        from wireshark_mcp.tools.investigator import (
            add_hypothesis,
            create_session,
            get_session,
        )
        session = create_session("test.pcap")
        add_hypothesis(session["session_id"], "Host X has C2 implant", confidence=0.7)
        s = get_session(session["session_id"])
        assert len(s["hypotheses"]) == 1
        assert s["hypotheses"][0]["description"] == "Host X has C2 implant"
        assert s["hypotheses"][0]["confidence"] == 0.7
        assert s["hypotheses"][0]["status"] == "pending"

    def test_update_hypothesis_status(self) -> None:
        from wireshark_mcp.tools.investigator import (
            add_hypothesis,
            create_session,
            get_session,
            update_hypothesis,
        )
        session = create_session("test.pcap")
        add_hypothesis(session["session_id"], "Test hypothesis", confidence=0.5)
        update_hypothesis(session["session_id"], 0, status="confirmed", confidence=0.95)
        s = get_session(session["session_id"])
        assert s["hypotheses"][0]["status"] == "confirmed"
        assert s["hypotheses"][0]["confidence"] == 0.95


class TestFindingsManagement:
    """Tests for adding findings to session."""

    def test_add_finding(self) -> None:
        from wireshark_mcp.tools.investigator import (
            add_finding,
            create_session,
            get_session,
        )
        session = create_session("test.pcap")
        finding = {
            "type": "beacon",
            "severity": "high",
            "confidence": 0.87,
            "description": "Periodic C2 communication detected",
        }
        add_finding(session["session_id"], finding)
        s = get_session(session["session_id"])
        assert len(s["findings"]) == 1
        assert s["findings"][0]["type"] == "beacon"
