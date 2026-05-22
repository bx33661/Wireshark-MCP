"""Doctor diagnostics — health-check for Python, Wireshark tools, and client configs."""

from __future__ import annotations

import json
from typing import Any, cast

from ..toolchain import (
    WIRESHARK_TOOL_ENV_VARS,
    WIRESHARK_TOOL_ORDER,
    WIRESHARK_TOOL_PURPOSES,
    WIRESHARK_TOOL_REQUIREMENTS,
)
from ._detection import _detect_wireshark_tool_paths, _get_python_executable
from ._writer import _build_client_targets_payload, _print_rows, _print_title


def _build_doctor_payload(selected_clients: list[str] | None = None) -> dict[str, Any]:
    """Build a machine-readable payload for doctor diagnostics."""
    detected_tools = _detect_wireshark_tool_paths()
    tools: dict[str, dict[str, Any]] = {}
    for tool_name in WIRESHARK_TOOL_ORDER:
        env_var = WIRESHARK_TOOL_ENV_VARS[tool_name]
        tool_path = detected_tools.get(env_var)
        tools[tool_name] = {
            "available": bool(tool_path),
            "path": tool_path,
            "requirement": WIRESHARK_TOOL_REQUIREMENTS[tool_name],
            "purpose": WIRESHARK_TOOL_PURPOSES[tool_name],
        }

    warnings: list[str] = []
    capture_backend: str | None = None
    if not detected_tools["WIRESHARK_MCP_TSHARK_PATH"]:
        warnings.append(
            "tshark was not found. Install Wireshark CLI tools or set WIRESHARK_MCP_TSHARK_PATH before starting the MCP server."
        )
    else:
        capture_backend = "dumpcap" if detected_tools.get("WIRESHARK_MCP_DUMPCAP_PATH") else "tshark"

    client_payload = _build_client_targets_payload(selected_clients)
    return {
        "python_executable": _get_python_executable(),
        "wireshark_tools": tools,
        "capture_backend": capture_backend,
        "warnings": warnings,
        "clients": client_payload["clients"],
        "client_summary": client_payload["summary"],
    }


def print_install_doctor(*, selected_clients: list[str] | None = None, output_format: str = "text") -> None:
    """Print install diagnostics for Python, Wireshark tools, and client configs."""
    payload = _build_doctor_payload(selected_clients)
    if output_format == "json":
        print(json.dumps(payload, indent=2))
        return

    _print_title("Wireshark MCP doctor")
    print(f"Python executable : {payload['python_executable']}")
    print()
    print("Wireshark suite tools")
    print("---------------------")

    tools = cast("dict[str, dict[str, Any]]", payload["wireshark_tools"])
    for requirement in ("required", "recommended", "optional"):
        print(f"{requirement.title()}:")
        for tool_name in WIRESHARK_TOOL_ORDER:
            if WIRESHARK_TOOL_REQUIREMENTS[tool_name] != requirement:
                continue
            tool_path = cast("str | None", tools[tool_name]["path"])
            marker = "[OK]" if tool_path else "[MISS]"
            print(f"  {marker:<6} {tool_name:<10} {tool_path or 'not found'}")

    print()
    warnings = cast("list[str]", payload["warnings"])
    if warnings:
        print("[WARN] tshark was not found.")
        print("       Install Wireshark CLI tools or set WIRESHARK_MCP_TSHARK_PATH before starting the MCP server.")
    else:
        capture_backend = cast("str", payload["capture_backend"])
        print(f"Preferred capture backend : {capture_backend}")

    print()
    print("MCP client targets")
    print("------------------")
    client_rows = cast("list[dict[str, str]]", payload["clients"])
    _print_rows(client_rows)

    summary = [f"{count} {status}" for status, count in cast("dict[str, int]", payload["client_summary"]).items()]
    if summary:
        print()
        print("Summary: " + ", ".join(summary))
