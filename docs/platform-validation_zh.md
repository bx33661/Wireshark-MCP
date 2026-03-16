# 平台验收清单

这份清单是 `v1.0` “稳态承诺”的人工验收依据：

- Windows 可用
- Linux 可用
- macOS 可用
- 安装路径足够简单
- 文档里的验证步骤和真实产品行为一致

## 自动化证据

仓库里已经有这些自动化验证：

- `ubuntu-latest`、`windows-latest`、`macos-latest` 三个平台都跑测试
- `ubuntu-latest`、`windows-latest`、`macos-latest` 三个平台都跑打包后 CLI 冒烟
- Linux 额外跑真实 `tshark` 集成冒烟

但在正式发大版本前，仍然建议做人工验收，因为 GUI MCP 客户端和本地 Wireshark 安装环境会因机器而异。

## 核心验收标准

每个平台至少要完成下面这些检查：

1. `wireshark-mcp --version`
2. `wireshark-mcp doctor`
3. `wireshark-mcp clients`
4. `wireshark-mcp config`
5. `wireshark-mcp install`
6. `wireshark-mcp doctor --format json`
7. `wireshark-mcp clients --format json`
8. 在 MCP 客户端里打开一个小型 `.pcap`，执行：

```text
先对这个抓包运行 wireshark_open_file，总结看到的协议，再运行 wireshark_quick_analysis。
```

预期结果：

- 服务能正常启动
- `doctor` 能识别到 `tshark`
- `clients` 能反映本机真实客户端配置状态
- `doctor` 和 `clients` 的 JSON 输出可以直接用于自动验收或问题排查
- `config` 能输出当前机器可直接使用的配置片段
- MCP 客户端能成功调用 `wireshark_open_file` 和 `wireshark_quick_analysis`

## macOS 验收

1. 安装 Python `3.10+`。
2. 安装 Wireshark，并确认 `tshark` 可用。
3. 执行：

```sh
pip install wireshark-mcp
wireshark-mcp --version
wireshark-mcp doctor
wireshark-mcp clients
wireshark-mcp install
wireshark-mcp config
```

4. 重启目标 MCP 客户端。
5. 打开一个示例 `.pcap`，执行上面的验收提示词。

可选项：

- 如果这次发布要求覆盖实时抓包，再确认 `dumpcap` 被识别到，并且可以完成一次短时抓包

## Linux 验收

1. 安装 Python `3.10+`。
2. 安装 Wireshark，或安装提供 `tshark` 的发行版包。
3. 执行：

```sh
pip install wireshark-mcp
wireshark-mcp --version
wireshark-mcp doctor
wireshark-mcp clients
wireshark-mcp install
wireshark-mcp config
```

4. 重启目标 MCP 客户端。
5. 打开一个示例 `.pcap`，执行上面的验收提示词。

可选项：

- 如果这次发布要求覆盖实时抓包，再确认当前主机已经具备对应抓包权限

## Windows 验收

1. 安装 Python `3.10+`。
2. 安装 Wireshark，并确保安装器里勾选 `TShark` 组件。
3. 在 PowerShell 或命令提示符里执行：

```powershell
py -m pip install wireshark-mcp
wireshark-mcp --version
wireshark-mcp doctor
wireshark-mcp clients
wireshark-mcp install
wireshark-mcp config --format codex-toml
```

4. 重启目标 MCP 客户端。
5. 打开一个示例 `.pcap`，执行上面的验收提示词。

Windows 特别注意：

- 很多 GUI 客户端不会完整继承终端里的 `PATH`，所以发版前必须同时确认 `doctor` 和 `install` 的结果

## 发布签收标准

不要在下面这些条件缺失时就认定大版本可发：

- 所有自动化 CI 全绿
- 三大系统族至少各完成过一次人工验收
- 文档中的命令和当前 CLI 实际输出一致
