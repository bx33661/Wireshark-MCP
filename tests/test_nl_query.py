"""Tests for natural language query engine."""

import pytest
from conftest import MockTSharkClient


class TestIntentMatching:
    def test_matches_c2_keywords(self) -> None:
        from wireshark_mcp.tools.nl_query import _match_intent

        result = _match_intent("find all hosts connecting to C2 servers")
        assert result is not None
        assert result["intent"] == "c2_detection"

    def test_matches_lateral_movement(self) -> None:
        from wireshark_mcp.tools.nl_query import _match_intent

        result = _match_intent("is there any lateral movement")
        assert result is not None
        assert result["intent"] == "lateral_movement"

    def test_matches_chinese_keywords(self) -> None:
        from wireshark_mcp.tools.nl_query import _match_intent

        result = _match_intent("检测DNS隧道")
        assert result is not None
        assert result["intent"] == "dns_suspicious"

    def test_returns_none_for_unknown(self) -> None:
        from wireshark_mcp.tools.nl_query import _match_intent

        result = _match_intent("what is the meaning of life")
        assert result is None

    def test_matches_data_exfiltration(self) -> None:
        from wireshark_mcp.tools.nl_query import _match_intent

        result = _match_intent("detect data leak or exfil attempts")
        assert result is not None
        assert result["intent"] == "data_exfiltration"

    def test_matches_malware(self) -> None:
        from wireshark_mcp.tools.nl_query import _match_intent

        result = _match_intent("is there any malware or trojan traffic")
        assert result is not None
        assert result["intent"] == "malware_analysis"

    def test_matches_credential_theft(self) -> None:
        from wireshark_mcp.tools.nl_query import _match_intent

        result = _match_intent("look for exposed credentials or password")
        assert result is not None
        assert result["intent"] == "credential_theft"

    def test_matches_full_investigation(self) -> None:
        from wireshark_mcp.tools.nl_query import _match_intent

        result = _match_intent("investigate what happened on this network")
        assert result is not None
        assert result["intent"] == "full_investigation"


class TestNlQueryTool:
    @pytest.mark.asyncio
    async def test_nl_query_tool_exists(self, mock_client: MockTSharkClient) -> None:
        from wireshark_mcp.tools.nl_query import make_contextual_nl_tools

        tools = make_contextual_nl_tools(mock_client)
        tool_names = [name for name, _ in tools]
        assert "wireshark_nl_query" in tool_names

    @pytest.mark.asyncio
    async def test_nl_query_returns_tools_for_match(self, mock_client: MockTSharkClient) -> None:
        from wireshark_mcp.tools.nl_query import make_contextual_nl_tools

        tools = make_contextual_nl_tools(mock_client)
        nl_query_fn = tools[0][1]
        result = await nl_query_fn(pcap_file="/tmp/test.pcap", query="detect C2 beacon")
        assert "wireshark_detect_beaconing" in result

    @pytest.mark.asyncio
    async def test_nl_query_returns_help_for_no_match(self, mock_client: MockTSharkClient) -> None:
        from wireshark_mcp.tools.nl_query import make_contextual_nl_tools

        tools = make_contextual_nl_tools(mock_client)
        nl_query_fn = tools[0][1]
        result = await nl_query_fn(pcap_file="/tmp/test.pcap", query="random gibberish xyz")
        assert "Could not interpret" in result
