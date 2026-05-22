"""Top-level install orchestrator and CLI dispatcher."""

from __future__ import annotations

import os
import sys

from ._clients import _OPENCODE_STYLE_CLIENTS, get_client_configs
from ._config_gen import SERVER_NAME, _generate_opencode_config, generate_mcp_config, print_mcp_config
from ._detection import _detect_wireshark_tool_paths
from ._doctor import print_install_doctor
from ._tui import _interactive_select_clients
from ._writer import (
    _get_mcp_servers_dict,
    _has_server_entry,
    _install_codex_config,
    _print_rows,
    _print_title,
    _read_json_config,
    _write_json_config,
    print_client_targets,
)


def install_mcp_servers(
    *, uninstall: bool = False, update: bool = False, selected_clients: list[str] | None = None
) -> int:
    """Install, update, or uninstall wireshark-mcp from detected MCP clients.

    update=True  — only touch clients that already have a wireshark-mcp entry;
                   skip clients where it is not yet installed.
    uninstall=True — remove the entry from every matched client.
    Neither flag  — write/overwrite the entry (install or re-install).

    When no clients are explicitly selected and stdin is a TTY, an interactive
    checklist is shown so the user can pick which clients to configure.
    """
    all_configs = get_client_configs()
    if not all_configs:
        print(f"Unsupported platform: {sys.platform}")
        return 0

    if selected_clients:
        configs = get_client_configs(selected_clients)
    else:
        chosen = _interactive_select_clients(all_configs)
        if chosen is None:
            # Non-interactive: fall back to all clients (original behaviour).
            configs = all_configs
        elif not chosen:
            print("No clients selected. Nothing to do.")
            return 0
        else:
            configs = {name: all_configs[name] for name in chosen}

    installed = 0
    skipped = 0
    action_word = "uninstall" if uninstall else ("update" if update else "installation")
    result_rows: list[dict[str, str]] = []

    if uninstall:
        title = "Wireshark MCP uninstall"
    elif update:
        title = "Wireshark MCP update"
    else:
        title = "Wireshark MCP install"
    _print_title(title)

    if not uninstall:
        detected_tools = _detect_wireshark_tool_paths()
        if not detected_tools["WIRESHARK_MCP_TSHARK_PATH"]:
            print("[WARN] tshark was not found. Client configs can still be written,")
            print("       but packet analysis will fail until Wireshark CLI tools are available.")
            print("       Run `wireshark-mcp doctor` after installing Wireshark to verify the tool paths.")
            print()

    for name, (config_dir, config_file) in configs.items():
        config_path = os.path.join(config_dir, config_file)

        if not os.path.exists(config_dir):
            result_rows.append(
                {
                    "marker": "[SKIP]",
                    "name": name,
                    "detail": f"{action_word} skipped (config dir not found)",
                    "path": config_path,
                }
            )
            skipped += 1
            continue

        if config_file.endswith(".toml"):
            # For update mode, skip if the server block is not already present.
            if update and not _has_server_entry(config_path, name):
                result_rows.append({"marker": "[SKIP]", "name": name, "detail": "not installed", "path": config_path})
                skipped += 1
                continue

            changed = _install_codex_config(config_path, uninstall=uninstall)
            if not changed:
                reason = "not installed" if uninstall else ("already up to date" if update else "already configured")
                result_rows.append({"marker": "[SKIP]", "name": name, "detail": reason, "path": config_path})
                skipped += 1
                continue

            done_word = "uninstalled" if uninstall else "updated" if update else "installed"
            result_rows.append(
                {"marker": "[OK]", "name": name, "detail": f"{done_word} (restart required)", "path": config_path}
            )
            installed += 1
            continue

        config = _read_json_config(config_path)
        mcp_servers = _get_mcp_servers_dict(config, name)

        if uninstall:
            if SERVER_NAME not in mcp_servers:
                result_rows.append({"marker": "[SKIP]", "name": name, "detail": "not installed", "path": config_path})
                skipped += 1
                continue
            del mcp_servers[SERVER_NAME]
        elif update:
            if SERVER_NAME not in mcp_servers:
                result_rows.append({"marker": "[SKIP]", "name": name, "detail": "not installed", "path": config_path})
                skipped += 1
                continue
            entry_config = _generate_opencode_config() if name in _OPENCODE_STYLE_CLIENTS else generate_mcp_config()
            mcp_servers[SERVER_NAME] = entry_config
        else:
            entry_config = _generate_opencode_config() if name in _OPENCODE_STYLE_CLIENTS else generate_mcp_config()
            mcp_servers[SERVER_NAME] = entry_config

        _write_json_config(config_path, config)

        done_word = "uninstalled" if uninstall else "updated" if update else "installed"
        result_rows.append(
            {"marker": "[OK]", "name": name, "detail": f"{done_word} (restart required)", "path": config_path}
        )
        installed += 1

    _print_rows(result_rows)

    if not uninstall and not update and installed == 0:
        print()
        print("No MCP clients detected. For unsupported clients, use the following config:\n")
        print_mcp_config()
    else:
        if uninstall:
            action_done = "uninstalled"
        elif update:
            action_done = "updated"
        else:
            action_done = "configured"
        print(f"\nSummary: {installed} client(s) {action_done}, {skipped} skipped.")

    return installed


def run_install(
    *,
    install: bool = False,
    update: bool = False,
    uninstall: bool = False,
    config: bool = False,
    doctor: bool = False,
    list_clients: bool = False,
    selected_clients: list[str] | None = None,
    config_format: str = "json",
    output_format: str = "text",
) -> None:
    """Dispatcher called from the CLI entry point."""
    if sum(bool(flag) for flag in (install, update, uninstall, config, doctor, list_clients)) > 1:
        print("Choose only one action at a time: install, update, uninstall, config, doctor, or clients.")
        sys.exit(1)

    if install:
        install_mcp_servers(uninstall=False, update=False, selected_clients=selected_clients)
        return

    if update:
        install_mcp_servers(uninstall=False, update=True, selected_clients=selected_clients)
        return

    if uninstall:
        install_mcp_servers(uninstall=True, update=False, selected_clients=selected_clients)
        return

    if config:
        print_mcp_config(output_format=config_format)
        return

    if doctor:
        print_install_doctor(selected_clients=selected_clients, output_format=output_format)
        return

    if list_clients:
        print_client_targets(selected_clients=selected_clients, output_format=output_format)
        return
