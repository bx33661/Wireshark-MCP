import json
from typing import Any


def _error_object(error: Any) -> dict[str, Any]:
    if isinstance(error, dict):
        error_type = error.get("type")
        message = error.get("message")
        details = error.get("details")
        normalized: dict[str, Any] = {
            "type": error_type if isinstance(error_type, str) and error_type else "ToolError",
            "message": message if isinstance(message, str) and message else "Tool failed",
        }
        if details is not None:
            normalized["details"] = details
        for key, value in error.items():
            if key not in normalized and key not in {"type", "message", "details"}:
                normalized[key] = value
        return normalized

    if isinstance(error, str) and error.strip():
        return {"type": "ToolError", "message": error.strip()}

    return {"type": "ToolError", "message": "Tool failed"}


def success_response(data: Any) -> str:
    return json.dumps({"success": True, "data": data})


def error_response(message: str, error_type: str = "ToolError", details: Any = None) -> str:
    error: dict[str, Any] = {
        "type": error_type,
        "message": message,
    }
    if details is not None:
        error["details"] = details
    return json.dumps({"success": False, "error": error})


def _normalize_dict_payload(payload: dict[str, Any]) -> str:
    if "success" in payload and isinstance(payload["success"], bool):
        if payload["success"]:
            if "data" in payload:
                return success_response(payload["data"])

            extra = {k: v for k, v in payload.items() if k != "success"}
            return success_response(extra if extra else None)

        return json.dumps({"success": False, "error": _error_object(payload.get("error"))})

    if "error" in payload:
        return json.dumps({"success": False, "error": _error_object(payload.get("error"))})

    return success_response(payload)


def normalize_tool_result(result: Any) -> str:
    if isinstance(result, str):
        stripped = result.strip()
        if not stripped:
            return success_response("")
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            return success_response(result)
        return normalize_tool_result(parsed)

    if isinstance(result, dict):
        return _normalize_dict_payload(result)

    if isinstance(result, list):
        return success_response(result)

    return success_response(result)


def parse_tool_result(result: Any) -> dict[str, Any]:
    return json.loads(normalize_tool_result(result))
