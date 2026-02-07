import unittest
import sys
import os

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from wireshark_mcp.tools.visualize import (
    _parse_io_graph, 
    _render_ascii_bar_chart, 
    _parse_protocol_hierarchy,
    _render_ascii_tree
)

class TestVisualize(unittest.TestCase):
    
    def test_parse_io_graph(self):
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
        self.assertEqual(len(data), 2)
        self.assertEqual(data[0], (0.0, 154))
        self.assertEqual(data[1], (1.0, 20))

    def test_render_ascii_bar_chart(self):
        data = [(0.0, 100), (1.0, 50), (2.0, 0)]
        chart = _render_ascii_bar_chart(data, height=5)
        self.assertIn("Max: 100", chart)
        # Should contain full block for 100
        self.assertIn("█", chart)
        # Should contain baseline
        self.assertIn("_", chart)

    def test_parse_protocol_hierarchy(self):
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
        self.assertEqual(root["children"][0]["name"], "eth")
        eth = root["children"][0]
        self.assertEqual(len(eth["children"]), 1)
        ip = eth["children"][0]
        self.assertEqual(ip["name"], "ip")
        self.assertEqual(len(ip["children"]), 2) # tcp, udp

    def test_render_ascii_tree(self):
        root = {
            "name": "root", "frames": 100, "children": [
                {"name": "eth", "frames": 100, "children": [
                    {"name": "ip", "frames": 50, "children": []}
                ]}
            ]
        }
        lines = _render_ascii_tree(root, total_frames=100)
        self.assertTrue(any("eth (100.0%)" in line for line in lines))
        # Check hierarchy connector
        self.assertTrue(any("└── " in line for line in lines))

if __name__ == '__main__':
    unittest.main()
