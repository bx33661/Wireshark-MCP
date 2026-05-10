---
title: Manual Configuration
description: Configure Wireshark MCP manually when auto-install is not the right fit.
---

Use this guide when your MCP client is not in the auto-install list, you manage config files directly, or you want to compare generated config with existing settings.

## Generate config

For JSON-based MCP clients:

```sh
wireshark-mcp config
```

For Codex TOML:

```sh
wireshark-mcp config --format codex-toml
```

## Minimal server entry

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

## Docker SSE mode

```sh
docker compose up -d
```

Then point the client to:

```text
http://localhost:8080/sse
```
