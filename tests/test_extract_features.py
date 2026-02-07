import unittest
import sys
import os
import asyncio

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from wireshark_mcp.tshark.client import TSharkClient

class MockTSharkClient(TSharkClient):
    def __init__(self):
        self.tshark_path = "tshark"
        self.capinfos_path = "capinfos"
        self.mergecap_path = "mergecap"
        self.editcap_path = "editcap"
        self._version = None

    def _validate_file(self, filepath):
        return {"success": True}

    async def _run_command(self, cmd, limit_lines=0, offset_lines=0, timeout=30):
        # Just return the command arguments joined by space
        return "CMD: " + " ".join(cmd)

class TestExtractFeatures(unittest.TestCase):
    
    def setUp(self):
        self.client = MockTSharkClient()

    def run_async(self, coro):
        return asyncio.run(coro)

    def test_get_packet_list_default(self):
        res = self.run_async(self.client.get_packet_list("test.pcap"))
        self.assertIn("-e frame.number", res)
        self.assertIn("-e _ws.col.Info", res)

    def test_get_packet_list_custom_columns(self):
        res = self.run_async(self.client.get_packet_list("test.pcap", custom_columns=["ip.src", "http.host"]))
        self.assertIn("-e ip.src", res)
        self.assertIn("-e http.host", res)
        self.assertNotIn("-e _ws.col.Info", res) # Default columns should be gone

    def test_get_packet_details_j_flag(self):
        res = self.run_async(self.client.get_packet_details("test.pcap", 42, included_layers=["ip", "http"]))
        self.assertIn("-Y frame.number == 42", res)
        self.assertIn("-j ip http", res)

    def test_get_packet_details_no_j_flag(self):
        res = self.run_async(self.client.get_packet_details("test.pcap", 42))
        self.assertIn("-Y frame.number == 42", res)
        self.assertNotIn("-j", res)

if __name__ == '__main__':
    unittest.main()
