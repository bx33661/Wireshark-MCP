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

The generated config uses the current Python interpreter, forwards the current runtime environment, and includes detected absolute Wireshark tool paths when available.

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

## Other Clients

If your client is not listed above, use:

```sh
wireshark-mcp config
```

Then paste the output into your client's MCP config file.

## Docker / SSE Mode

```sh
docker compose up -d
```

Then point your client to:

```text
http://localhost:8080/sse
```
