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
  <a href="docs/README_zh.md"><b>文档</b></a> •
  <a href="CHANGELOG.md"><b>更新日志</b></a> •
  <a href="ROADMAP_zh.md"><b>路线图</b></a> •
  <a href="CONTRIBUTING.md"><b>Contributing</b></a>
</p>
</div>

---

## 这是什么？

一个 [MCP 服务器](https://modelcontextprotocol.io/introduction)，将 `tshark`（及可选的 Wireshark 套件工具）封装为结构化分析接口。支持 Claude Desktop、Claude Code、Cursor、VS Code 等 18+ MCP 客户端。

```
你：    "找出这个抓包中所有访问可疑域名的 DNS 查询。"
Claude: [调用 wireshark_extract_dns_queries → wireshark_detect_dns_tunnel]
        "发现重复的高熵 DNS 查询，行为与隧道流量一致：..."
```

---

## 安装

**前置条件：** Python 3.10+ 和 [Wireshark](https://www.wireshark.org/)（`tshark` 需在 PATH 中）。

Wireshark MCP 3.0 基于稳定版 MCP Python SDK 2.x（`mcp>=2.1.1,<3`）。

```sh
pip install wireshark-mcp
wireshark-mcp install   # 从检测到的 MCP 客户端中选择并配置
```

重启你的 AI 客户端即可。

如有问题运行 `wireshark-mcp doctor` 诊断。手动配置或平台特定说明见 [docs/manual-configuration_zh.md](docs/manual-configuration_zh.md)。

---

## 快速开始

将 AI 客户端指向一个 `.pcap` 文件，尝试：

```
使用 Wireshark MCP 工具分析 capture.pcap。
先用 wireshark_open_file 打开，然后运行 wireshark_quick_analysis。
涉及全量计数或分布时使用 wireshark_aggregate。
将发现写入 report.md。
```

---

## 工具

52 个工具，每个都由真实 `tshark` 输出支撑，按类别组织：

| 类别 | 亮点 | 数量 |
|------|------|:----:|
| **入口与工作流** | `wireshark_open_file`、`wireshark_quick_analysis` | 2 |
| **数据包分析** | 数据包列表、详情、字节、上下文、流追踪、搜索、文件信息 | 8 |
| **数据提取** | HTTP 请求、DNS 查询、任意字段提取、对象导出 | 4 |
| **统计** | 聚合/分组/去重计数/Top-K/时间分桶、协议层次、端点、会话、I/O 图、专家信息、服务响应时间、流图 | 8 |
| **安全与异常** | 凭据扫描、端口扫描、DNS 隧道、DoS、信标、外泄、协议异常、YARA | 8 |
| **协议分析** | `wireshark_analyze_protocol`（20 种协议）、TCP 健康、ARP 欺骗 | 3 |
| **解密与解析** | TLS/WPA 解密、解密校验、decode-as、协议偏好设置 | 5 |
| **取证与富化** | TLS 指纹、文件特征扫描、GeoIP | 3 |
| **文件操作、抓包与套件** | 实时抓包、接口列表、合并、过滤保存、editcap 裁剪/分割/去重/时移、帧提取、text2pcap、能力查询 | 11 |

20 种协议由一个工具覆盖，而不是 20 个工具各覆盖一种：`wireshark_analyze_protocol` 接受 `protocol` 参数（`tls_handshakes`、`mqtt`、`modbus`、`s7comm`、`zigbee`、`wifi`、`rtp`、`kerberos` 等），并为其套用正确的字段与显示过滤器。字段名正是关键——`s7comm.param.item.dbnum` 不该由调用方去猜，而猜错时返回的空结果看起来和"干净的流量"没有区别。

服务器仅需 `tshark` 即可启动。可选工具（`capinfos`、`mergecap`、`editcap`、`dumpcap`、`text2pcap`）自动检测，存在时启用额外功能。

### 上下文开销

工具列表会随客户端的每一次请求进入 prompt 前缀，因此它的体积是每请求的固定成本。默认表面约为 22 KB——其中参数 schema 约 9 KB、描述约 5 KB、读写 annotations 约 3 KB；并且它在重启之间逐字节一致，客户端可以缓存该前缀，而不必每个会话重新读取。

如果你的客户端从不实时抓包、也不写入 pcap，可以用 `--profile` 暴露更小的表面：

| Profile | 工具数 | 载荷 | 移除的内容 |
|---------|:-----:|:----:|-----------|
| `full`（默认） | 52 | ~22 KB | 无 |
| `analysis` | 40 | ~17 KB | 实时抓包、接口列表、以及全部写文件的工具 |
| `core` | 32 | ~14 KB | 以上全部，再加解密、解析覆写与底层视图 |

```bash
wireshark-mcp serve --profile core
```

运行时 prompts 和协议推荐会遵循当前 profile。静态指南可能介绍仅限 `full` 的流程，但打开抓包时，服务器不会推荐已被当前 profile 移除的工具。

工具结果同样有上限，因为一条结果会在会话余下的全部轮次里一直留在上下文中。超过 8000 字符的输出会保留首尾并标注截断位置，其余部分请用工具自带的 `offset` / `limit` / `display_filter` 参数翻页。调整上限：

```bash
export WIRESHARK_MCP_MAX_RESULT_CHARS=16000
```

每个工具都声明了自己是只读还是写入，因此客户端可以自动放行 41 个只读分析工具，同时仍然对会创建文件的 11 个工具（实时抓包、合并、过滤保存、editcap、text2pcap、帧提取、对象导出）进行确认。

3.0 中，这 11 个工具在 `WIRESHARK_MCP_ALLOWED_DIRS` 未指向现有目录时一律失败关闭。HTTP/SSE 默认也只能监听回环地址；只有放在可信、带认证的 TLS 反向代理后，才应显式传入 `--allow-insecure-http`。迁移说明见 [3.0 安全加固指南](docs/security-hardening-v3_zh.md)。

---

## 文档

| 主题 | 链接 |
|------|------|
| 文档索引 | [docs/README_zh.md](docs/README_zh.md) |
| 全量聚合指南 | [docs/aggregation_zh.md](docs/aggregation_zh.md) |
| 平台配置（macOS/Linux/Windows） | [docs/platform-validation_zh.md](docs/platform-validation_zh.md) |
| 手动客户端配置 | [docs/manual-configuration_zh.md](docs/manual-configuration_zh.md) |
| 部署场景 | [docs/deployment-scenarios_zh.md](docs/deployment-scenarios_zh.md) |
| 3.0 安全迁移 | [docs/security-hardening-v3_zh.md](docs/security-hardening-v3_zh.md) |
| Prompt 模板 | [docs/prompt-engineering_zh.md](docs/prompt-engineering_zh.md) |
| 架构说明 | [docs/architecture_zh.md](docs/architecture_zh.md) |
| 发布清单 | [docs/release-checklist.md](docs/release-checklist.md) |
| 贡献指南 | [CONTRIBUTING.md](CONTRIBUTING.md) |
| 更新日志 | [CHANGELOG.md](CHANGELOG.md) |
| 功能路线图 | [ROADMAP_zh.md](ROADMAP_zh.md) |
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
