# [Unreleased] - OpenCode client support / OpenCode 客户端支持

Date / 日期: 2026-04-17

---

## English

### Added

#### OpenCode MCP client support (`src/wireshark_mcp/installer.py`)

OpenCode uses a different config schema from other JSON-based MCP clients: servers live under a flat `"mcp"` key (no nested `"servers"` sub-key), `command` must be an array, and environment variables go under `"environment"` rather than `"env"`. The following changes implement full support:

- **`_generate_opencode_config()`** — New helper that produces an OpenCode-compatible server entry:
  ```json
  {
    "type": "local",
    "command": ["/path/to/python3", "-u", "-m", "wireshark_mcp.server"],
    "environment": { "PATH": "...", "PYTHONIOENCODING": "utf-8", ... }
  }
  ```
- **`_OPENCODE_STYLE_CLIENTS` frozenset** — Identifies clients that use the flat-under-`"mcp"` structure so routing logic stays explicit and easy to extend.
- **`_get_mcp_servers_dict()` updated** — OpenCode requests are routed to `config["mcp"]` (flat dict) instead of `config["mcpServers"]` or `config["mcp"]["servers"]`.
- **`_has_server_entry_in_json_config()` updated** — Detects existing `wireshark-mcp` entries inside `config["mcp"]` for OpenCode configs.
- **`install_mcp_servers()` updated** — Calls `_generate_opencode_config()` when writing an OpenCode entry.
- **Client registry updated for all three platforms**:
  - macOS: `~/.config/opencode/opencode.json` (respects `$XDG_CONFIG_HOME`)
  - Linux: `$XDG_CONFIG_HOME/opencode/opencode.json`
  - Windows: `%APPDATA%\opencode\opencode.json`

#### Documentation (`docs/manual-configuration.md`, `docs/manual-configuration_zh.md`)

- Added an **OpenCode** section to both the English and Chinese manual-configuration guides with the correct config file location per platform and an annotated example snippet.

### How to use

**Auto-install** (if OpenCode config dir exists):
```sh
wireshark-mcp install
```

**Manual** — run `wireshark-mcp config` to get the exact Python path, then add to `~/.config/opencode/opencode.json`:
```json
{
  "mcp": {
    "wireshark-mcp": {
      "type": "local",
      "command": ["/path/to/python3", "-u", "-m", "wireshark_mcp.server"],
      "environment": {
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```

---

## 中文

### 新增

#### OpenCode MCP 客户端支持（`src/wireshark_mcp/installer.py`）

OpenCode 的配置结构与其他 JSON 类 MCP 客户端不同：服务端条目直接位于顶层 `"mcp"` 键下（没有嵌套的 `"servers"` 子键），`command` 必须是数组，环境变量放在 `"environment"` 而非 `"env"` 下。以下改动实现了完整支持：

- **`_generate_opencode_config()`** — 新增辅助函数，生成 OpenCode 格式的服务端条目：
  ```json
  {
    "type": "local",
    "command": ["/path/to/python3", "-u", "-m", "wireshark_mcp.server"],
    "environment": { "PATH": "...", "PYTHONIOENCODING": "utf-8", ... }
  }
  ```
- **`_OPENCODE_STYLE_CLIENTS` frozenset** — 标识使用扁平 `"mcp"` 结构的客户端，使路由逻辑清晰且易于扩展。
- **`_get_mcp_servers_dict()` 更新** — OpenCode 请求现在路由到 `config["mcp"]`（扁平字典），而非 `config["mcpServers"]` 或 `config["mcp"]["servers"]`。
- **`_has_server_entry_in_json_config()` 更新** — 可检测 OpenCode 配置中 `config["mcp"]` 下是否已存在 `wireshark-mcp` 条目。
- **`install_mcp_servers()` 更新** — 写入 OpenCode 条目时调用 `_generate_opencode_config()`。
- **三平台客户端注册表更新**：
  - macOS: `~/.config/opencode/opencode.json`（遵循 `$XDG_CONFIG_HOME`）
  - Linux: `$XDG_CONFIG_HOME/opencode/opencode.json`
  - Windows: `%APPDATA%\opencode\opencode.json`

#### 文档（`docs/manual-configuration.md`、`docs/manual-configuration_zh.md`）

- 在英文和中文手动配置文档中均新增了 **OpenCode** 章节，包含各平台配置文件路径和带注释的示例。

### 使用方式

**自动安装**（前提：OpenCode 配置目录已存在）：
```sh
wireshark-mcp install
```

**手动配置** — 先运行 `wireshark-mcp config` 获取当前机器的 Python 路径，然后写入 `~/.config/opencode/opencode.json`：
```json
{
  "mcp": {
    "wireshark-mcp": {
      "type": "local",
      "command": ["/path/to/python3", "-u", "-m", "wireshark_mcp.server"],
      "environment": {
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```
