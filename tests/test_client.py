import unittest
import sys
import os
import json
import asyncio
from pathlib import Path
import tempfile
import shutil

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from wireshark_mcp.tshark.client import TSharkClient

class TestClient(unittest.TestCase):
    
    def setUp(self):
        self.client = TSharkClient()
        self.test_dir = tempfile.mkdtemp()
        self.pcap_path = os.path.join(self.test_dir, "test.pcap")
        # Create empty file
        with open(self.pcap_path, 'wb') as f:
            f.write(b"")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def run_async(self, coro):
        return asyncio.run(coro)

    def test_validate_file_not_found(self):
        result = self.client._validate_file("/nonexistent/file.pcap")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"]["type"], "FileNotFound")
        
    def test_validate_file_exists(self):
        result = self.client._validate_file(self.pcap_path)
        self.assertTrue(result["success"])
        
    def test_validate_protocol_valid(self):
        result = self.client._validate_protocol("tcp", self.client.VALID_ENDPOINT_TYPES)
        self.assertTrue(result["success"])
        
    def test_validate_protocol_invalid(self):
        result = self.client._validate_protocol("invalid", self.client.VALID_ENDPOINT_TYPES)
        self.assertFalse(result["success"])
        self.assertEqual(result["error"]["type"], "InvalidParameter")

    def test_check_capabilities(self):
        # This runs real command which might fail if tshark not installed, but we should handle it gracefully
        result = self.run_async(self.client.check_capabilities())
        self.assertTrue(result["success"])
        self.assertIn("tshark", result["data"])

    def test_file_not_found_error(self):
        result_str = self.run_async(self.client.get_protocol_stats("/nonexistent.pcap"))
        result = json.loads(result_str)
        self.assertFalse(result["success"])
        self.assertEqual(result["error"]["type"], "FileNotFound")

if __name__ == '__main__':
    unittest.main()
