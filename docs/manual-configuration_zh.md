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

`wireshark-mcp config` 只生成本地 stdio 配置。需要单独运行 Streamable HTTP 服务时：

```sh
wireshark-mcp serve --transport streamable-http --host 127.0.0.1 --port 8080
```

在客户端中把 `http://127.0.0.1:8080/mcp` 添加为远程 MCP 地址。不同客户端的远程服务配置格式不同，`config` 命令不会生成这类配置。兼容旧式 SSE 时使用 `--transport sse`，端点以 `/sse` 结尾。

自动生成的配置会固定使用当前 Python 解释器，透传当前运行环境，并在可探测到时附带 Wireshark 工具的绝对路径。

## 限制路径与工具面

在服务端环境中设置 `WIRESHARK_MCP_ALLOWED_DIRS`，用逗号分隔抓包目录与输出目录：

```sh
export WIRESHARK_MCP_ALLOWED_DIRS=/srv/pcaps,/srv/wireshark-results
```

这些目录必须已经存在。3.0 中，未设置该变量时所有写文件工具都会失败关闭；设置后，
它会同时约束读取和写入。详见 [3.0 安全迁移指南](security-hardening-v3_zh.md)。

客户端只需离线只读分析时，可以在服务参数中启用 core profile：

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

不同客户端使用的环境变量字段名可能不同，有的写作 `environment`，有的使用数组命令。遇到这类差异时，以 `wireshark-mcp config` 生成的结构为基础调整。

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

### OpenCode

配置文件位置：

- macOS / Linux: `~/.config/opencode/opencode.json`（遵循 `$XDG_CONFIG_HOME`）
- Windows: `%APPDATA%\opencode\opencode.json`

示例：

```json
{
  "mcp": {
    "wireshark-mcp": {
      "type": "local",
      "command": ["<python路径>", "-u", "-m", "wireshark_mcp.server"]
    }
  }
}
```

运行 `wireshark-mcp config` 获取当前机器的精确命令路径，将其中的 `command` 值填入上方配置即可。

### Kimi Code

安装器会把标准 `mcpServers` 配置写入 `~/.kimi-code/mcp.json`。如果设置了
`$KIMI_CODE_HOME`，则写入该目录下的 `mcp.json`。

### Grok Build

安装器会把 TOML 服务配置写入 `~/.grok/config.toml`。如果设置了 `$GROK_HOME`，
则写入该目录下的 `config.toml`：

```toml
[mcp_servers.wireshark-mcp]
command = "<python路径>"
args = ["-u", "-m", "wireshark_mcp.server"]
```

### Qwen Code

安装器会把标准 `mcpServers` 配置写入 `~/.qwen/settings.json`。

### Auggie

安装器会把标准 `mcpServers` 配置写入 `~/.augment/settings.json`。

### Factory Droid

安装器会把标准 `mcpServers` 配置写入 `~/.factory/mcp.json`。

### Amp

安装器会把服务写入 `~/.config/amp/settings.json` 的 `amp.mcpServers` 字段。

### Pi Agent

Pi 通过扩展接入 MCP，而不是使用内置的 MCP 配置注册表。在 `wireshark-mcp install`
中选择 **Pi Agent (manual extension)**，安装适合 Pi 的 MCP 扩展，然后把安装器生成的
stdio 服务参数填入该扩展文档指定的配置位置。

## 其他客户端

在 `wireshark-mcp install` 列表末尾选择 **Other / Manual setup**，安装器会同时输出
JSON、TOML 配置和本地 stdio 服务的接入步骤。也可以直接生成 JSON：

```sh
wireshark-mcp config
```

然后把输出结果粘贴到对应客户端的 MCP 配置文件中。
