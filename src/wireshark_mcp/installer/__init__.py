"""Auto-configuration installer for Wireshark MCP."""

from ._clients import (  # noqa: F401
    _OPENCODE_STYLE_CLIENTS,
    _SPECIAL_JSON_STRUCTURES,
    _get_client_configs,
    get_client_configs,
)
from ._config_gen import (  # noqa: F401
    SERVER_NAME,
    _generate_opencode_config,
    _render_codex_toml_block,
    generate_mcp_config,
    print_mcp_config,
)
from ._detection import (  # noqa: F401
    _collect_python_env,
    _collect_runtime_env,
    _detect_wireshark_tool_paths,
    _get_linux_config_home,
    _get_python_executable,
    _iter_wireshark_search_dirs,
    _join_path,
)
from ._doctor import print_install_doctor  # noqa: F401
from ._orchestrator import install_mcp_servers, run_install  # noqa: F401
from ._tui import _interactive_select_clients  # noqa: F401
from ._writer import (  # noqa: F401
    _build_client_targets_payload,
    _get_mcp_servers_dict,
    _read_json_config,
    _write_json_config,
    print_client_targets,
)

__all__ = [
    "SERVER_NAME",
    "generate_mcp_config",
    "get_client_configs",
    "install_mcp_servers",
    "print_client_targets",
    "print_install_doctor",
    "print_mcp_config",
    "run_install",
]
