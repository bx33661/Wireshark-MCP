"""Tests for response envelope normalization."""

import json

from wireshark_mcp.tools.envelope import (
    error_response,
    normalize_tool_result,
    parse_tool_result,
    success_response,
)


class TestSuccessResponse:
    """Tests for success_response helper."""

    def test_wraps_string(self) -> None:
        result = json.loads(success_response("hello"))
        assert result["success"] is True
        assert result["data"] == "hello"

    def test_wraps_dict(self) -> None:
        result = json.loads(success_response({"key": "value"}))
        assert result["success"] is True
        assert result["data"] == {"key": "value"}

    def test_wraps_none(self) -> None:
        result = json.loads(success_response(None))
        assert result["success"] is True
        assert result["data"] is None


class TestErrorResponse:
    """Tests for error_response helper."""

    def test_basic_error(self) -> None:
        result = json.loads(error_response("something broke"))
        assert result["success"] is False
        assert result["error"]["type"] == "ToolError"
        assert result["error"]["message"] == "something broke"

    def test_custom_type(self) -> None:
        result = json.loads(error_response("not found", error_type="FileNotFound"))
        assert result["error"]["type"] == "FileNotFound"

    def test_with_details(self) -> None:
        result = json.loads(error_response("fail", details={"code": 42}))
        assert result["error"]["details"] == {"code": 42}


class TestNormalizeToolResult:
    """Tests for normalize_tool_result."""

    def test_plain_text_becomes_success(self) -> None:
        payload = parse_tool_result("ok")
        assert payload["success"]
        assert payload["data"] == "ok"

    def test_json_error_string_is_normalized(self) -> None:
        raw = json.dumps({"success": False, "error": "boom"})
        payload = parse_tool_result(raw)
        assert not payload["success"]
        assert payload["error"]["type"] == "ToolError"
        assert payload["error"]["message"] == "boom"

    def test_json_list_becomes_success(self) -> None:
        payload = parse_tool_result('[{"a": 1}, {"a": 2}]')
        assert payload["success"]
        assert len(payload["data"]) == 2

    def test_existing_success_with_data_is_preserved(self) -> None:
        raw = {"success": True, "data": {"k": "v"}}
        payload = parse_tool_result(raw)
        assert payload["success"]
        assert payload["data"] == {"k": "v"}

    def test_empty_string_becomes_success(self) -> None:
        payload = parse_tool_result("")
        assert payload["success"]
        assert payload["data"] == ""

    def test_normalize_returns_valid_json(self) -> None:
        result = normalize_tool_result("hello")
        payload = json.loads(result)
        assert payload["data"] == "hello"
