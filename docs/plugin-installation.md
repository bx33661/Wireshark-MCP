# AI client plugin distribution

This route does not run the traditional `wireshark-mcp install`. The client installs the source project, MCP launcher and both canonical skills; uv prepares the locked Python environment and the client starts the stdio subprocess.

## Prerequisites

Use a Codex/Claude Code version supporting plugin commands, with `uv` available to the client process and Wireshark CLI/TShark installed. GUI PATH can differ from terminal PATH. The plugin does not install Wireshark, capture drivers or permissions. First launch needs package-source access. The project's `.python-version` pins 3.13; uv can prepare that interpreter unless downloads are disabled, in which case provide it beforehand.

## Local install

From a clean checkout containing the manifests, or an unpacked source plugin ZIP, choose your client:

```sh
# Codex
codex plugin marketplace add .
codex plugin add wireshark-mcp@wireshark-mcp

# Claude Code
claude plugin marketplace add .
claude plugin install wireshark-mcp@wireshark-mcp
```

Refresh/restart the session and inspect the client's plugin list. Both skills come directly from `skills/`, not duplicated plugin copies. Root `CLAUDE.md` is repository guidance, not plugin context. Do not distribute a developer `.venv`, caches or personal configuration.

## Actual launchers

Codex declares the plugin root as `cwd`:

```sh
uv run --locked --no-dev --extra index wireshark-mcp serve --transport stdio
```

Claude explicitly selects its own project from any session directory:

```sh
uv run --project "${CLAUDE_PLUGIN_ROOT}" --locked --no-dev --extra index wireshark-mcp serve --transport stdio
```

`--locked` rejects stale metadata rather than modifying the lockfile; `--no-dev` excludes development/test dependencies, and `--extra index` adds DuckDB for the capture index. Setup logs use stderr, leaving stdout for MCP. No maintainer-specific Python/Wireshark paths are embedded.

Codex forwards the declared `WIRESHARK_MCP_ALLOWED_DIRS`, tool-path and result-limit variables. Claude uses its client launch environment. Configure directory/permission requirements as for the existing server; installing a plugin does not automatically authorize writes or capture. A GUI only inherits the environment of its launcher.

## Refresh and removal

Skip removal on first installation. To clear an old plugin cache and reinstall:

```sh
codex plugin remove wireshark-mcp@wireshark-mcp
codex plugin add wireshark-mcp@wireshark-mcp

claude plugin uninstall wireshark-mcp@wireshark-mcp
claude plugin install wireshark-mcp@wireshark-mcp
```

For Git sources, refresh the marketplace before reinstalling. Keep package and plugin manifest versions aligned when releasing. Choose plugin or traditional registration, not both, to avoid duplicate tools. Client removal does not uninstall Wireshark.

## Hosted source after publication

These manifests/source must first be committed and published. Only then use the repository source instead of the local path:

```sh
codex plugin marketplace add bx33661/Wireshark-MCP
codex plugin add wireshark-mcp@wireshark-mcp

claude plugin marketplace add bx33661/Wireshark-MCP
claude plugin install wireshark-mcp@wireshark-mcp
```

A Git marketplace is not approval/listing in a universal public directory. This working-tree implementation does not claim either a remote publication or public-directory acceptance.

## Verify and package

```sh
python scripts/check_plugin_package.py --build /absolute/path/new-plugin.zip
python scripts/smoke_plugin_runtime.py --plugin-zip /absolute/path/new-plugin.zip --output plugin-smoke.json
claude plugin validate . --json
```

The ZIP excludes environments, caches and root maintenance instructions. Runtime checks unpack separate fresh projects for both launchers, run uv over actual stdio, negotiate MCP, list tools and query a synthetic frame. They do not borrow the developer environment or modify user client settings. Isolated native-client install/discovery checks are separate from actual GUI-session acceptance.

References: [ida-pro-mcp Codex launcher](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/.codex-plugin/mcp.json), [official OpenAI packaging](https://developers.openai.com/plugins/build/plugins), [Claude manifest reference](https://code.claude.com/docs/en/plugins-reference).
