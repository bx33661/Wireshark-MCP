"""Tests for playbook engine."""



class TestPlaybookLoader:
    """Tests for playbook loading."""

    def test_load_bundled_playbooks(self) -> None:
        import wireshark_mcp.tools.playbooks as pb_mod
        from wireshark_mcp.tools.playbooks import load_playbooks

        # Reset cache to force reload
        pb_mod._PLAYBOOKS = None
        playbooks = load_playbooks()
        assert len(playbooks) >= 4
        names = [p["name"] for p in playbooks]
        assert "malware_c2" in names
        assert "lateral_movement" in names
        assert "data_exfil" in names
        assert "initial_access" in names

    def test_playbook_has_required_fields(self) -> None:
        from wireshark_mcp.tools.playbooks import load_playbooks

        playbooks = load_playbooks()
        for pb in playbooks:
            assert "name" in pb
            assert "description" in pb
            assert "steps" in pb
            assert len(pb["steps"]) > 0

    def test_get_playbook_by_name(self) -> None:
        from wireshark_mcp.tools.playbooks import get_playbook

        pb = get_playbook("malware_c2")
        assert pb is not None
        assert pb["name"] == "malware_c2"

    def test_get_nonexistent_playbook(self) -> None:
        from wireshark_mcp.tools.playbooks import get_playbook

        pb = get_playbook("nonexistent")
        assert pb is None

    def test_list_playbook_names(self) -> None:
        from wireshark_mcp.tools.playbooks import list_playbook_names

        names = list_playbook_names()
        assert "malware_c2" in names
        assert "lateral_movement" in names
        assert "data_exfil" in names
        assert "initial_access" in names

    def test_playbook_steps_have_tool_field(self) -> None:
        from wireshark_mcp.tools.playbooks import load_playbooks

        playbooks = load_playbooks()
        for pb in playbooks:
            for step in pb["steps"]:
                assert "tool" in step
                assert "description" in step
