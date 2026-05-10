---
title: MCP Clients
description: Configure Wireshark MCP in common AI clients.
---

## Auto configure

For supported clients, use:

```sh
wireshark-mcp install
```

This scans known client config files and injects the `wireshark-mcp` server entry without replacing unrelated settings.

## Claude Desktop

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

## Claude Code

```sh
claude mcp add wireshark-mcp -- wireshark-mcp
```

## Cursor

Edit `~/.cursor/mcp.json` or use the MCP server UI:

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

## VS Code

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

## Codex CLI

```sh
codex mcp add wireshark-mcp -- wireshark-mcp
```

Or edit `~/.codex/config.toml`:

```toml
[mcp_servers.wireshark-mcp]
command = "wireshark-mcp"
args = []
```
