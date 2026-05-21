<div align="center">
<!-- mcp-name: io.github.bx33661/wireshark-mcp -->

<img src="Logo.png" width="150" alt="Wireshark MCP" style="margin-top: 20px; margin-bottom: 20px;">

<h1>Wireshark MCP</h1>

**给你的 AI 助手一个数据包分析器。**

*丢入一个 `.pcap` 文件，用自然语言提问 — 获得基于真实 `tshark` 数据的回答。*

<p style="margin-top: 15px;">
  <a href="https://github.com/bx33661/Wireshark-MCP/actions/workflows/ci.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/bx33661/Wireshark-MCP/ci.yml?style=flat-square&logo=github&label=CI" alt="CI">
  </a>
  <a href="https://github.com/bx33661/Wireshark-MCP/releases/latest">
    <img src="https://img.shields.io/github/v/release/bx33661/Wireshark-MCP?style=flat-square&logo=github&color=24292f" alt="GitHub Release">
  </a>
  <a href="https://pypi.org/project/wireshark-mcp/">
    <img src="https://img.shields.io/pypi/v/wireshark-mcp?style=flat-square&logo=pypi&color=0066cc" alt="PyPI">
  </a>
  <a href="https://pypi.org/project/wireshark-mcp/">
    <img src="https://img.shields.io/pypi/pyversions/wireshark-mcp?style=flat-square&logo=python" alt="Python">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square" alt="MIT License">
  </a>
</p>

<p>
  <a href="README.md"><b>English</b></a> •
  <a href="README_zh.md"><b>中文</b></a> •
  <a href="CHANGELOG.md"><b>Changelog</b></a> •
  <a href="CONTRIBUTING.md"><b>Contributing</b></a>
</p>
</div>

---

## 这是什么？

一个 [MCP 服务器](https://modelcontextprotocol.io/introduction)，将 `tshark`（及可选的 Wireshark 套件工具）封装为结构化分析接口。支持 Claude Desktop、Claude Code、Cursor、VS Code 等 [18+ MCP 客户端](docs/manual-configuration.md)。

```
你：    "找出这个抓包中所有访问可疑域名的 DNS 查询。"
Claude: [调用 wireshark_extract_dns_queries → wireshark_check_threats]
        "发现 3 条命中 URLhaus 威胁情报的域名查询：..."
```

---

## 安装

**前置条件：** Python 3.10+ 和 [Wireshark](https://www.wireshark.org/)（`tshark` 需在 PATH 中）。

```sh
pip install wireshark-mcp
wireshark-mcp install   # 自动配置所有检测到的 MCP 客户端
```

重启你的 AI 客户端即可。

如有问题运行 `wireshark-mcp doctor` 诊断。手动配置或平台特定说明见 [docs/manual-configuration.md](docs/manual-configuration.md)。

---

## 快速开始

将 AI 客户端指向一个 `.pcap` 文件，尝试：

```
使用 Wireshark MCP 工具分析 capture.pcap。
先用 wireshark_open_file 打开，然后运行 wireshark_security_audit。
将发现写入 report.md。
```

---

## 工具

40+ 工具，按类别组织：

| 类别 | 亮点 | 数量 |
|------|------|:----:|
| **智能工作流** | `wireshark_security_audit`、`wireshark_quick_analysis`、`wireshark_open_file` | 4 |
| **数据包分析** | 数据包列表、详情、字节、上下文、流追踪、搜索 | 7 |
| **数据提取** | HTTP 请求、DNS 查询、TLS 握手、字段提取 | 6 |
| **统计** | 协议层次、端点、会话、I/O 图、专家信息 | 6 |
| **安全分析** | 威胁情报、凭据扫描、端口扫描、DNS 隧道、DoS 检测 | 6 |
| **协议深入** | TCP 健康、ARP 欺骗、SMTP、DHCP | 5 |
| **文件操作与抓包** | 实时抓包、合并、过滤保存、文件信息 | 5 |
| **套件工具** | editcap 裁剪/分割/去重、text2pcap 导入 | 5 |
| **解码与可视化** | 载荷解码、流量图、协议树 | 3 |

服务器仅需 `tshark` 即可启动。可选工具（`capinfos`、`mergecap`、`editcap`、`dumpcap`、`text2pcap`）自动检测，存在时启用额外功能。

---

## 文档

| 主题 | 链接 |
|------|------|
| 平台配置（macOS/Linux/Windows） | [docs/platform-validation.md](docs/platform-validation.md) |
| 手动客户端配置 | [docs/manual-configuration.md](docs/manual-configuration.md) |
| Prompt 模板 | [docs/prompt-engineering.md](docs/prompt-engineering.md) |
| 发布清单 | [docs/release-checklist.md](docs/release-checklist.md) |
| 贡献指南 | [CONTRIBUTING.md](CONTRIBUTING.md) |
| 更新日志 | [CHANGELOG.md](CHANGELOG.md) |
| 安全策略 | [SECURITY.md](SECURITY.md) |

---

## 开发

```sh
pip install -e ".[dev]"
pytest tests/ -v
ruff check src/ tests/
```

完整指南见 [CONTRIBUTING.md](CONTRIBUTING.md)。

---

<div align="center">
<sub><a href="LICENSE">MIT License</a> · <a href="https://github.com/bx33661/Wireshark-MCP/issues">报告 Bug</a></sub>
</div>
