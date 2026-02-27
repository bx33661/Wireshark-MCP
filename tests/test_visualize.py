"""Tests for visualization tools (pure parsing functions)."""

import pytest

from wireshark_mcp.tools.visualize import (
    _parse_io_graph,
    _parse_protocol_hierarchy,
    _render_ascii_bar_chart,
    _render_ascii_tree,
)


class TestParseIOGraph:
    """Tests for I/O graph output parsing."""

    def test_parses_standard_output(self) -> None:
        output = """
===================================================================
IO Statistics
Interval: 1.000 secs
Column #0: Frames and bytes
                |    Column #0   |
Time            |Frames|  Bytes  |
000.000-001.000     154     12345
001.000-002.000      20      1200
===================================================================
        """
        data = _parse_io_graph(output)
        assert len(data) == 2
        assert data[0] == (0.0, 154)
        assert data[1] == (1.0, 20)

    def test_empty_output(self) -> None:
        data = _parse_io_graph("")
        assert data == []


class TestRenderAsciiBarChart:
    """Tests for ASCII bar chart rendering."""

    def test_basic_chart(self) -> None:
        data = [(0.0, 100), (1.0, 50), (2.0, 0)]
        chart = _render_ascii_bar_chart(data, height=5)
        assert "Max: 100" in chart
        assert "█" in chart
        assert "_" in chart

    def test_no_data(self) -> None:
        result = _render_ascii_bar_chart([])
        assert "No traffic data" in result

    def test_all_zero(self) -> None:
        result = _render_ascii_bar_chart([(0.0, 0), (1.0, 0)])
        assert "No packets" in result


class TestParseProtocolHierarchy:
    """Tests for protocol hierarchy parsing."""

    def test_nested_protocols(self) -> None:
        output = """
===================================================================
Protocol Hierarchy Statistics
Filter:
protocol        frames:bytes
eth             100:1000
  ip            100:1000
    tcp          50:500
    udp          50:500
===================================================================
        """
        root = _parse_protocol_hierarchy(output)
        assert root["children"][0]["name"] == "eth"
        eth = root["children"][0]
        ip = eth["children"][0]
        assert ip["name"] == "ip"
        assert len(ip["children"]) == 2

    def test_empty_output(self) -> None:
        root = _parse_protocol_hierarchy("")
        assert root["children"] == []


class TestRenderAsciiTree:
    """Tests for ASCII tree rendering."""

    def test_basic_tree(self) -> None:
        root = {
            "name": "root", "frames": 100, "bytes": 0, "children": [
                {"name": "eth", "frames": 100, "bytes": 0, "children": [
                    {"name": "ip", "frames": 50, "bytes": 0, "children": []},
                ]},
            ],
        }
        lines = _render_ascii_tree(root, total_frames=100)
        assert any("eth (100.0%)" in line for line in lines)
        assert any("└── " in line for line in lines)

    def test_empty_tree(self) -> None:
        root = {"name": "root", "frames": 0, "bytes": 0, "children": []}
        lines = _render_ascii_tree(root, total_frames=0)
        assert lines == []
