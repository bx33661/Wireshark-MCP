# Manual Configuration

Use this guide when:

- your MCP client is not in the auto-install list
- you prefer to manage config files directly
- you want to compare the generated config with your current setup

## Generate the Exact Config for This Machine

For JSON-based MCP clients:

```sh
wireshark-mcp config
```

For Codex TOML:

```sh
wireshark-mcp config --format codex-toml
```

`wireshark-mcp config` generates local stdio configuration only. To run a separate Streamable HTTP server:

```sh
wireshark-mcp serve --transport streamable-http --host 127.0.0.1 --port 8080
```

Add `http://127.0.0.1:8080/mcp` as a remote MCP URL in the client. Remote server configuration differs by client and is not emitted by the `config` command. Legacy SSE uses `--transport sse` and an endpoint ending in `/sse`.

The generated config uses the current Python interpreter, forwards the current runtime environment, and includes detected absolute Wireshark tool paths when available.

## Restrict Paths and Tools

Set `WIRESHARK_MCP_ALLOWED_DIRS` in the server environment to a comma-separated list of capture and output roots:

```sh
export WIRESHARK_MCP_ALLOWED_DIRS=/srv/pcaps,/srv/wireshark-results
```

The directories must already exist. In 3.0, all file-creating tools fail closed
when this variable is absent; once present, it constrains reads and writes. See
the [3.0 security migration guide](security-hardening-v3.md).

When a client only needs offline read-only analysis, add the core profile to its server arguments:

```json
{
  "mcpServers": {
    "wireshark-mcp": {
      "command": "wireshark-mcp",
      "args": ["serve", "--profile", "core"],
      "env": {
        "WIRESHARK_MCP_ALLOWED_DIRS": "/srv/pcaps"
      }
    }
  }
}
```

Environment-field names vary by client. Use `wireshark-mcp config` as the base when a client expects `environment` instead of `env` or uses an array command.

## Common Clients

### Claude Desktop

Config file:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

Example:

```json
{
  "mcpServers": {
    "wireshark-mcp": {
      "command": "wireshark-mcp",
      "args": []
    }
  }
}
```

### Claude Code

```bash
claude mcp add wireshark-mcp -- wireshark-mcp
```

Or edit `~/.claude.json`.

### Cursor

Use the MCP server UI, or edit `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "wireshark-mcp": {
      "command": "wireshark-mcp",
      "args": []
    }
  }
}
```

### VS Code / VS Code Insiders

Add to `settings.json`:

```json
{
  "mcp": {
    "servers": {
      "wireshark-mcp": {
        "command": "wireshark-mcp",
        "args": []
      }
    }
  }
}
```

### OpenAI Codex CLI

```bash
codex mcp add wireshark-mcp -- wireshark-mcp
```

Or edit `~/.codex/config.toml`:

```toml
[mcp_servers.wireshark-mcp]
command = "wireshark-mcp"
args = []
```

### OpenCode

Config file:

- macOS / Linux: `~/.config/opencode/opencode.json` (respects `$XDG_CONFIG_HOME`)
- Windows: `%APPDATA%\opencode\opencode.json`

Example:

```json
{
  "mcp": {
    "wireshark-mcp": {
      "type": "local",
      "command": ["<path-to-python>", "-u", "-m", "wireshark_mcp.server"]
    }
  }
}
```

Use `wireshark-mcp config` to get the exact command path for your machine, then paste the `command` value into the config above.

### Kimi Code

The installer writes the standard `mcpServers` entry to `~/.kimi-code/mcp.json`, or to
`$KIMI_CODE_HOME/mcp.json` when that environment variable is set.

### Grok Build

The installer writes a TOML server block to `~/.grok/config.toml`, or to
`$GROK_HOME/config.toml` when that environment variable is set:

```toml
[mcp_servers.wireshark-mcp]
command = "<path-to-python>"
args = ["-u", "-m", "wireshark_mcp.server"]
```

### Qwen Code

The installer writes the standard `mcpServers` entry to `~/.qwen/settings.json`.

### Auggie

The installer writes the standard `mcpServers` entry to `~/.augment/settings.json`.

### Factory Droid

The installer writes the standard `mcpServers` entry to `~/.factory/mcp.json`.

### Amp

The installer writes the server under the `amp.mcpServers` key in
`~/.config/amp/settings.json`.

### Pi Agent

Pi uses extensions for MCP connectivity rather than a built-in MCP config registry.
Select **Pi Agent (manual extension)** in `wireshark-mcp install`, install an MCP
extension for Pi, and copy the generated stdio server values into that extension's
documented settings.

## Other Clients

Select **Other / Manual setup** at the bottom of `wireshark-mcp install`. The installer
prints both JSON and TOML snippets plus the steps for adding a local stdio server.
You can also generate the JSON directly with:

```sh
wireshark-mcp config
```

Then paste the output into your client's MCP config file.
