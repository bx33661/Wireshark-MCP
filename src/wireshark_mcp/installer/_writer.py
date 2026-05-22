"""Config file read/write operations and CLI output helpers."""

from __future__ import annotations

import json
import os
import re
import tempfile
from typing import Any, cast

from ._clients import _OPENCODE_STYLE_CLIENTS, _SPECIAL_JSON_STRUCTURES, get_client_configs
from ._config_gen import SERVER_NAME, _render_codex_toml_block


def _read_json_config(path: str) -> dict[str, Any]:
    """Read a JSON config file, returning {} for missing/empty/invalid files."""
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        data = f.read().strip()
        if not data:
            return {}
        try:
            parsed = json.loads(data)
            return cast("dict[str, Any]", parsed) if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}


def _write_json_config(path: str, config: dict[str, Any]) -> None:
    """Atomically write a JSON config file."""
    config_dir = os.path.dirname(path)
    fd, temp_path = tempfile.mkstemp(dir=config_dir, prefix=".tmp_", suffix=".json", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
            f.write("\n")
        os.replace(temp_path, path)
    except Exception:
        os.unlink(temp_path)
        raise


def _write_text_config(path: str, text: str, suffix: str) -> None:
    """Atomically write a text config file."""
    config_dir = os.path.dirname(path)
    fd, temp_path = tempfile.mkstemp(dir=config_dir, prefix=".tmp_", suffix=suffix, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.replace(temp_path, path)
    except Exception:
        os.unlink(temp_path)
        raise


def _get_mcp_servers_dict(config: dict[str, Any], client_name: str) -> dict[str, Any]:
    """Navigate into the correct nesting level for the mcpServers dict."""
    if client_name in _OPENCODE_STYLE_CLIENTS:
        top_level = config.get("mcp")
        if not isinstance(top_level, dict):
            top_level = {}
            config["mcp"] = top_level
        return top_level

    if client_name in _SPECIAL_JSON_STRUCTURES:
        top_key, nested_key = _SPECIAL_JSON_STRUCTURES[client_name]
        top_level = config.get(top_key)
        if not isinstance(top_level, dict):
            top_level = {}
            config[top_key] = top_level

        nested = top_level.get(nested_key)
        if not isinstance(nested, dict):
            nested = {}
            top_level[nested_key] = nested

        return nested

    if not isinstance(config.get("mcpServers"), dict):
        config["mcpServers"] = {}
    return cast("dict[str, Any]", config["mcpServers"])


def _has_server_entry_in_json_config(config: dict[str, Any], client_name: str) -> bool:
    """Check whether a JSON config already contains this MCP server."""
    if client_name in _OPENCODE_STYLE_CLIENTS:
        return SERVER_NAME in config.get("mcp", {})
    if client_name in _SPECIAL_JSON_STRUCTURES:
        top_key, nested_key = _SPECIAL_JSON_STRUCTURES[client_name]
        return SERVER_NAME in config.get(top_key, {}).get(nested_key, {})
    return SERVER_NAME in config.get("mcpServers", {})


def _has_server_entry(config_path: str, client_name: str) -> bool:
    """Check whether a client config contains this MCP server."""
    if not os.path.exists(config_path):
        return False

    if config_path.endswith(".toml"):
        with open(config_path, encoding="utf-8") as f:
            content = f.read()
        return f"[mcp_servers.{SERVER_NAME}]" in content

    return _has_server_entry_in_json_config(_read_json_config(config_path), client_name)


def _status_marker(status: str) -> str:
    """Return a short ASCII status label for CLI output."""
    return {
        "configured": "[OK]",
        "installed": "[OK]",
        "uninstalled": "[OK]",
        "config file found": "[INFO]",
        "client detected": "[INFO]",
        "already configured": "[SKIP]",
        "not installed": "[SKIP]",
        "not detected": "[MISS]",
    }.get(status, "[INFO]")


def _print_title(title: str) -> None:
    """Print a simple section header."""
    print(title)
    print("=" * len(title))


def _print_rows(rows: list[dict[str, str]]) -> None:
    """Print aligned status rows with optional paths."""
    if not rows:
        return

    width = max(len(row["name"]) for row in rows)
    for row in rows:
        marker = row.get("marker") or _status_marker(row.get("status", ""))
        detail = row.get("detail", "")
        print(f"  {marker:<6} {row['name']:<{width}} {detail}")
        path = row.get("path")
        if path:
            print(f"         {path}")


def _summarize_status_rows(rows: list[dict[str, str]], statuses: tuple[str, ...]) -> dict[str, int]:
    """Summarize row counts for the requested statuses."""
    return {
        status: sum(row["status"] == status for row in rows)
        for status in statuses
        if any(row["status"] == status for row in rows)
    }


def _collect_client_rows(selected_clients: list[str] | None = None) -> list[dict[str, str]]:
    """Collect client detection/configuration status rows."""
    rows: list[dict[str, str]] = []
    for name, (config_dir, config_file) in get_client_configs(selected_clients).items():
        config_path = os.path.join(config_dir, config_file)
        if os.path.exists(config_path):
            status = "configured" if _has_server_entry(config_path, name) else "config file found"
        elif os.path.exists(config_dir):
            status = "client detected"
        else:
            status = "not detected"
        rows.append({"name": name, "status": status, "detail": status, "path": config_path})
    return rows


def _build_client_targets_payload(selected_clients: list[str] | None = None) -> dict[str, Any]:
    """Build a machine-readable payload for client detection status."""
    rows = _collect_client_rows(selected_clients)
    summary_order = ("configured", "config file found", "client detected", "not detected")
    return {
        "clients": rows,
        "summary": _summarize_status_rows(rows, summary_order),
    }


def print_client_targets(*, selected_clients: list[str] | None = None, output_format: str = "text") -> None:
    """Print supported client targets and detection status."""
    payload = _build_client_targets_payload(selected_clients)
    rows = cast("list[dict[str, str]]", payload["clients"])
    if output_format == "json":
        print(json.dumps(payload, indent=2))
        return

    _print_title("Wireshark MCP clients")
    _print_rows(rows)

    summary = [f"{count} {status}" for status, count in cast("dict[str, int]", payload["summary"]).items()]
    if summary:
        print()
        print("Summary: " + ", ".join(summary))


def _upsert_named_toml_block(content: str, section_name: str, block: str) -> str:
    """Replace an existing TOML table block or append it if missing."""
    lines = content.splitlines()
    output: list[str] = []
    section_header = f"[{section_name}]"
    section_prefix = f"[{section_name}."
    skip_mode = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if stripped == section_header or stripped.startswith(section_prefix):
                skip_mode = True
                continue
            if skip_mode:
                skip_mode = False
        if not skip_mode:
            output.append(line)

    rendered = "\n".join(output).rstrip()
    if rendered:
        rendered += "\n\n"
    rendered += block.rstrip() + "\n"
    return rendered


def _remove_named_toml_block(content: str, section_name: str) -> tuple[str, bool]:
    """Remove a TOML table block and any nested subtables."""
    pattern = re.compile(rf"(?ms)^\[{re.escape(section_name)}\]\n.*?(?=^\[(?!{re.escape(section_name)}(?:\.|\]))|\Z)")
    updated, count = pattern.subn("", content)
    updated = updated.rstrip()
    if updated:
        updated += "\n"
    return updated, count > 0


def _install_codex_config(config_path: str, *, uninstall: bool) -> bool:
    """Install or uninstall the Codex TOML configuration."""
    content = ""
    if os.path.exists(config_path):
        with open(config_path, encoding="utf-8") as f:
            content = f.read()

    section_name = f"mcp_servers.{SERVER_NAME}"
    if uninstall:
        updated, changed = _remove_named_toml_block(content, section_name)
        if not changed:
            return False
        _write_text_config(config_path, updated, ".toml")
        return True

    updated = _upsert_named_toml_block(content, section_name, _render_codex_toml_block())
    if updated == content:
        return False
    _write_text_config(config_path, updated, ".toml")
    return True
