import json
from collections.abc import Awaitable, Callable
from typing import Any, cast

# A protocol analysis handler: (pcap_file, limit) -> envelope JSON string.
# Handlers live in the domain modules (protocol/ics/iot) that own their field
# knowledge; `analyze.py` collects them into one dispatching tool. Every handler
# takes `limit` even when the underlying tshark facility has nothing to cap, so
# the dispatcher can call them uniformly.
ProtocolHandler = Callable[[str, int], Awaitable[str]]


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


def success_response(data: Any, compact: bool = False) -> str:
    if compact and isinstance(data, str):
        return data
    return json.dumps({"success": True, "data": data})


def envelope_response(
    data: Any,
    *,
    scope: dict[str, Any] | None = None,
    coverage: dict[str, Any] | None = None,
    pagination: dict[str, Any] | None = None,
    warnings: list[str] | None = None,
    truncated: bool | None = None,
    stderr: str | None = None,
    compact: bool = False,
) -> str:
    """Construct a standardized successful response envelope.

    Ensures top-level consistency for structured findings, scopes, coverage,
    and pagination across all Wireshark MCP tools.
    """
    if compact and isinstance(data, str) and not (scope or coverage or pagination or warnings or truncated or stderr):
        return data

    payload: dict[str, Any] = {
        "success": True,
        "data": data,
    }
    if scope is not None:
        payload["scope"] = scope
    if coverage is not None:
        payload["coverage"] = coverage
    if pagination is not None:
        payload["pagination"] = pagination
    if warnings is not None:
        payload["warnings"] = warnings
    if truncated is not None:
        payload["truncated"] = truncated
    if stderr is not None:
        payload["stderr"] = stderr

    return json.dumps(payload, ensure_ascii=False)


def error_response(
    message: str,
    error_type: str = "ToolError",
    details: Any = None,
    *,
    scope: dict[str, Any] | None = None,
    coverage: dict[str, Any] | None = None,
    warnings: list[str] | None = None,
) -> str:
    error: dict[str, Any] = {
        "type": error_type,
        "message": message,
    }
    if details is not None:
        error["details"] = details
    payload: dict[str, Any] = {"success": False, "error": error}
    if scope is not None:
        payload["scope"] = scope
    if coverage is not None:
        payload["coverage"] = coverage
    if warnings is not None:
        payload["warnings"] = warnings
    return json.dumps(payload, ensure_ascii=False)


def _normalize_dict_payload(payload: dict[str, Any]) -> str:
    if "success" in payload and isinstance(payload["success"], bool):
        if payload["success"]:
            envelope: dict[str, Any] = {"success": True, "data": payload.get("data")}
            for extra_key in ("scope", "coverage", "pagination", "warnings", "truncated", "stderr"):
                if extra_key in payload:
                    envelope[extra_key] = payload[extra_key]
            if "data" not in payload:
                extra = {k: v for k, v in payload.items() if k != "success" and k not in envelope}
                envelope["data"] = extra if extra else None
            return json.dumps(envelope, ensure_ascii=False)

        normalized_err = _error_object(payload.get("error"))
        err_envelope: dict[str, Any] = {"success": False, "error": normalized_err}
        for extra_key in ("scope", "coverage", "warnings", "stderr"):
            if extra_key in payload:
                err_envelope[extra_key] = payload[extra_key]
        return json.dumps(err_envelope, ensure_ascii=False)

    if "error" in payload:
        return json.dumps({"success": False, "error": _error_object(payload.get("error"))}, ensure_ascii=False)

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
    return cast("dict[str, Any]", json.loads(normalize_tool_result(result)))
