"""Tests for decode tools (pure functions, no tshark dependency)."""

import base64
import gzip

import pytest

from wireshark_mcp.tools.decode import _calculate_score, _try_decode


class TestTryDecode:
    """Tests for individual encoding decoders."""

    def test_base64(self) -> None:
        success, res, err = _try_decode("SGVsbG8gV29ybGQ=", "base64")
        assert success
        assert res == b"Hello World"

    def test_base64_missing_padding(self) -> None:
        success, res, err = _try_decode("SGVsbG8", "base64")
        assert success
        assert res == b"Hello"

    def test_hex(self) -> None:
        success, res, err = _try_decode("48656c6c6f", "hex")
        assert success
        assert res == b"Hello"

    def test_hex_with_separators(self) -> None:
        success, res, err = _try_decode("48:65:6c:6c:6f", "hex")
        assert success
        assert res == b"Hello"

    def test_url(self) -> None:
        success, res, err = _try_decode("Hello%20World", "url")
        assert success
        assert res == b"Hello World"

    def test_rot13(self) -> None:
        success, res, err = _try_decode("Uryyb", "rot13")
        assert success
        assert res == b"Hello"

    def test_html(self) -> None:
        success, res, err = _try_decode("&lt;div&gt;", "html")
        assert success
        assert res == b"<div>"

    def test_gzip(self) -> None:
        data = b"Hello World"
        compressed = gzip.compress(data)
        input_str = compressed.decode("latin-1")

        success, res, err = _try_decode(input_str, "gzip")
        assert success
        assert res == data

    def test_unknown_encoding(self) -> None:
        success, res, err = _try_decode("test", "nonexistent")
        assert not success
        assert err == "Unknown encoding"


class TestCalculateScore:
    """Tests for readability scoring."""

    def test_printable_text_scores_high(self) -> None:
        assert _calculate_score(b"Hello World") > 0.9

    def test_binary_scores_low(self) -> None:
        assert _calculate_score(b"\x00\x01\x02") < 0.1

    def test_empty_scores_zero(self) -> None:
        assert _calculate_score(b"") == 0.0
