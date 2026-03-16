# 手动配置指南

当你处于下面这些场景时，适合看这份文档：

- 你的 MCP 客户端不在自动安装支持列表里
- 你希望手动维护配置文件
- 你想把自动生成的配置和当前环境做对比

## 先生成当前机器的精确配置

面向 JSON 类 MCP 客户端：

```sh
wireshark-mcp config
```

面向 Codex TOML：

```sh
wireshark-mcp config --format codex-toml
```

自动生成的配置会固定使用当前 Python 解释器，透传当前运行环境，并在可探测到时附带 Wireshark 工具的绝对路径。

## 常见客户端

### Claude Desktop

配置文件位置：

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

示例：

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

或者直接编辑 `~/.claude.json`。

### Cursor

可以直接用 MCP Server UI，也可以编辑 `~/.cursor/mcp.json`：

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

在 `settings.json` 中加入：

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

或者编辑 `~/.codex/config.toml`：

```toml
[mcp_servers.wireshark-mcp]
command = "wireshark-mcp"
args = []
```

## 其他客户端

如果你的客户端不在上面的列表里，先运行：

```sh
wireshark-mcp config
```

然后把输出结果粘贴到对应客户端的 MCP 配置文件中。

## Docker / SSE 模式

```sh
docker compose up -d
```

然后让客户端连接：

```text
http://localhost:8080/sse
```
