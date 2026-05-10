---
title: MCP 客户端
description: 在常见 AI 客户端中配置 Wireshark MCP。
---

## 自动配置

支持的客户端可以直接执行：

```sh
wireshark-mcp install
```

该命令会扫描已知客户端配置文件，注入 `wireshark-mcp` 服务配置，不会替换无关设置。

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

编辑 `~/.cursor/mcp.json`，或使用 MCP server UI：

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

添加到 `settings.json`：

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

或编辑 `~/.codex/config.toml`：

```toml
[mcp_servers.wireshark-mcp]
command = "wireshark-mcp"
args = []
```
