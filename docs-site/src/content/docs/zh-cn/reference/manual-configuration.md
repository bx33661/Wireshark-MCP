---
title: 手动配置
description: 当自动安装不适合时，手动配置 Wireshark MCP。
---

当 MCP 客户端不在自动安装列表中、你想直接管理配置文件，或需要对比生成配置和现有配置时，使用本页。

## 生成配置

JSON 类型 MCP 客户端：

```sh
wireshark-mcp config
```

Codex TOML：

```sh
wireshark-mcp config --format codex-toml
```

## 最小服务配置

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

## Docker SSE 模式

```sh
docker compose up -d
```

然后把客户端指向：

```text
http://localhost:8080/sse
```
