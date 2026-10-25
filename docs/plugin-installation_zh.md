# 作为 AI 客户端插件分发

这条路线不运行传统 `wireshark-mcp install`。客户端安装插件，取得项目源码、启动声明与两个 Skills；uv 准备锁定的 Python 环境，客户端启动 MCP stdio 子进程。

## 前置条件

- 支持插件命令的 Codex 或 Claude Code。
- 客户端进程能找到 `uv`；终端能运行不一定表示 GUI 的 PATH 相同。
- 已安装 Wireshark CLI/TShark；插件不安装 Wireshark、驱动或抓包权限。
- 首次启动可访问 Python 包源。项目沿用 `.python-version` 的 3.13，uv 可准备该解释器；禁用自动下载时须事先提供兼容解释器。

## 本地安装

从包含插件清单的干净仓库根目录执行；也可以解压源插件 ZIP 后执行。不要把已有 `.venv`、缓存或个人配置复制进分发包。

```sh
# Codex
codex plugin marketplace add .
codex plugin add wireshark-mcp@wireshark-mcp

# Claude Code（选择这一组或上面一组）
claude plugin marketplace add .
claude plugin install wireshark-mcp@wireshark-mcp
```

查看客户端插件列表并刷新/重启会话。两个 Skill 直接来自 `skills/`，没有另一套插件专用副本。仓库维护用的根 `CLAUDE.md` 不是插件上下文；工作流由已声明的 Skills 提供。

## 实际启动链

Codex 配置使用插件根目录作为 `cwd`：

```sh
uv run --locked --no-dev --extra index wireshark-mcp serve --transport stdio
```

Claude Code 显式选择插件项目，即使会话工作目录不在插件中也使用正确依赖：

```sh
uv run --project "${CLAUDE_PLUGIN_ROOT}" --locked --no-dev --extra index wireshark-mcp serve --transport stdio
```

`--locked` 在项目和锁文件不匹配时失败，不静默改锁；`--no-dev` 不安装测试/开发工具，`--extra index` 带上抓包索引所需的 DuckDB。首次环境准备日志走 stderr，stdout 留给 MCP。配置没有硬编码维护者的 Python 或 Wireshark 绝对路径。

Codex 声明转发 `WIRESHARK_MCP_ALLOWED_DIRS`、各 Wireshark 工具路径和结果限额变量；Claude 启动环境沿用客户端环境。按现有服务约束设置目录与权限：安装插件不会自动开放文件写入或抓包权限。GUI 从哪里启动，决定它能继承哪些环境变量。

## 刷新旧版本与卸载

首次安装跳过移除命令。已装旧版、需要清空插件缓存重装时：

```sh
codex plugin remove wireshark-mcp@wireshark-mcp
codex plugin add wireshark-mcp@wireshark-mcp

claude plugin uninstall wireshark-mcp@wireshark-mcp
claude plugin install wireshark-mcp@wireshark-mcp
```

对于 Git 来源，先用客户端的 marketplace 刷新命令取得新提交，再重装；发布新版本时同步 Python 包与两个插件清单的版本。不要同时保留插件 MCP 和传统安装器写入的同一服务，以免重复工具。移除插件由客户端管理，不删除 Wireshark。

## GitHub 入口与发布状态

本轮交付的是本地可分发源码及市场清单。提交/发布这些文件到仓库后，用户可改用以下来源；当前工作区未推送不等于远端已有该市场：

```sh
codex plugin marketplace add bx33661/Wireshark-MCP
codex plugin add wireshark-mcp@wireshark-mcp

claude plugin marketplace add bx33661/Wireshark-MCP
claude plugin install wireshark-mcp@wireshark-mcp
```

Git 仓库市场与 OpenAI/Anthropic 的公共目录收录是两件事；本轮不宣称公共目录已审核上架。

## 验证与打包

```sh
python scripts/check_plugin_package.py --build /absolute/path/new-plugin.zip
python scripts/smoke_plugin_runtime.py --plugin-zip /absolute/path/new-plugin.zip --output plugin-smoke.json
claude plugin validate . --json
```

打包器排除虚拟环境、缓存和维护用根指令。运行测试分别在两个全新解压目录中使用真实声明启动 uv、完成 MCP 握手、列工具并查询合成帧；不依赖开发目录的 `.venv`，不改用户客户端配置。客户端插件安装/识别另在隔离配置目录验证；它不替代具体 GUI 会话验收。

参考：[ida-pro-mcp 的 Codex 配置](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/.codex-plugin/mcp.json)、[OpenAI 官方插件打包说明](https://developers.openai.com/plugins/build/plugins)、[Claude 插件清单](https://code.claude.com/docs/en/plugins-reference)。
