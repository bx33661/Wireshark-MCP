import unittest
import gzip
import base64
import sys
import os

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from wireshark_mcp.tools.decode import _try_decode, _calculate_score

class TestDecode(unittest.TestCase):
    def test_base64(self):
        success, res, err = _try_decode("SGVsbG8gV29ybGQ=", "base64")
        self.assertTrue(success)
        self.assertEqual(res, b"Hello World")

    def test_hex(self):
        success, res, err = _try_decode("48656c6c6f", "hex")
        self.assertTrue(success)
        self.assertEqual(res, b"Hello")

    def test_url(self):
        success, res, err = _try_decode("Hello%20World", "url")
        self.assertTrue(success)
        self.assertEqual(res, b"Hello World")

    def test_rot13(self):
        success, res, err = _try_decode("Uryyb", "rot13")
        self.assertTrue(success)
        self.assertEqual(res, b"Hello")

    def test_html(self):
        success, res, err = _try_decode("&lt;div&gt;", "html")
        self.assertTrue(success)
        self.assertEqual(res, b"<div>")

    def test_gzip(self):
        # Gzip encoding of "Hello World"
        data = b"Hello World"
        compressed = gzip.compress(data)
        # _try_decode expects string input (latin-1 decoded bytes)
        input_str = compressed.decode('latin-1')
        
        success, res, err = _try_decode(input_str, "gzip")
        self.assertTrue(success)
        self.assertEqual(res, data)

    def test_score(self):
        self.assertGreater(_calculate_score(b"Hello World"), 0.9)
        self.assertLess(_calculate_score(b"\x00\x01\x02"), 0.1)

if __name__ == '__main__':
    unittest.main()
