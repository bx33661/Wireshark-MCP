# Wireshark MCP v1.0.0

Wireshark MCP `v1.0.0` 现已发布。

这次版本的目标，是把项目从“快速迭代中的工具集”收口成一个稳定的 `1.x` 基线：明确支持 Windows、Linux、macOS，安装更简单，诊断更完整，文档也和真实工作流彻底对齐。

## 短公告版

`Wireshark MCP v1.0.0` 正式发布。

- `1.0` 稳态基线覆盖 Windows、Linux、macOS
- `tshark` 仍然是唯一必需的 Wireshark 依赖
- `capinfos`、`mergecap`、`editcap`、`dumpcap`、`text2pcap` 等可选工具会自动探测并启用增强能力
- `install`、`doctor`、`clients`、`config` 的安装和诊断链路更完整
- 新增 `doctor --format json` 和 `clients --format json`
- 文档已经按真实 `1.0` 使用流程重新整理

GitHub Release: <https://github.com/bx33661/Wireshark-MCP/releases/tag/v1.0.0>  
PyPI: <https://pypi.org/project/wireshark-mcp/>

## 完整公告版

`v1.0.0` 是我们定义里的“可以稳定一段时间”的版本。

这次发布并不是单纯堆新功能，而是把项目的产品面、发布面和文档面一起做扎实：安装路径更清晰，CLI 行为更稳定，平台支持更明确，版本元数据更一致，用户第一次接触项目时也不需要靠猜来理解怎么用。

`1.0` 的核心变化包括：

- 项目正式承诺 Windows、Linux、macOS 三大平台的 `1.0` 基线支持。
- MCP 会在整个会话中保持稳定的工具面，`wireshark_open_file` 负责针对当前抓包推荐最相关的工具。
- 威胁情报匹配现在基于抓包中的 HTTP URL、DNS 主机名和 TLS 主机名，分析链路更可复现。
- CLI 更像成熟产品，子命令更清晰，诊断体验更完整。
- `doctor` 和 `clients` 新增 JSON 输出，更适合自动验收、故障单收集和 CI 场景。
- README 被进一步收成 landing page，详细配置和提示词指导拆到了独立 `docs/` 页面里。

对 `v1.0` 来说，“稳态”不是一句口号。如果文档里承诺的基线能力失效，我们会把它视为 `1.0.x` 需要修复的问题，而不是“以后再增强”。

## 升级建议

- 通过 PyPI 安装或升级：

```sh
pip install --upgrade wireshark-mcp
```

- 验证本机环境：

```sh
wireshark-mcp doctor
wireshark-mcp clients
```

- 如果你需要机器可读输出做验收或排障：

```sh
wireshark-mcp doctor --format json
wireshark-mcp clients --format json
```

## 关键链接

- GitHub Release: <https://github.com/bx33661/Wireshark-MCP/releases/tag/v1.0.0>
- PyPI: <https://pypi.org/project/wireshark-mcp/>
- 更新日志: <https://github.com/bx33661/Wireshark-MCP/blob/main/CHANGELOG.md>
- 项目说明: <https://github.com/bx33661/Wireshark-MCP/blob/main/README_zh.md>
