<div align="center">
<!-- mcp-name: io.github.bx33661/wireshark-mcp -->

<br>

<img src="Logo.png" width="120" alt="Wireshark MCP">

<h1>Wireshark MCP</h1>

<p><strong>给你的 AI 助手一个数据包分析器。</strong><br>
丢入一个 <code>.pcap</code> 文件，用自然语言提问 —— 获得基于真实 <code>tshark</code> 数据的回答。</p>

<p>
  <a href="https://github.com/bx33661/Wireshark-MCP/actions/workflows/ci.yml">
    <img src="https://github.com/bx33661/Wireshark-MCP/actions/workflows/ci.yml/badge.svg" alt="CI">
  </a>
  <a href="https://github.com/bx33661/Wireshark-MCP/releases/latest">
    <img src="https://img.shields.io/github/v/release/bx33661/Wireshark-MCP?label=GitHub%20Release&color=24292f" alt="GitHub Release">
  </a>
  <a href="https://pypi.org/project/wireshark-mcp/">
    <img src="https://img.shields.io/pypi/v/wireshark-mcp?label=PyPI&color=0066cc" alt="PyPI">
  </a>
  <a href="https://pypi.org/project/wireshark-mcp/">
    <img src="https://img.shields.io/pypi/pyversions/wireshark-mcp?label=Python" alt="Python">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License">
  </a>
</p>

<p>
  <a href="README.md">English</a> ·
  <a href="README_zh.md">中文</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

<br>

</div>

---

## 这是什么？

Wireshark MCP 是一个 [MCP 服务器](https://modelcontextprotocol.io/introduction)，以 `tshark` 为基础提供结构化分析接口，并在宿主机可用时自动接入 `capinfos`、`mergecap`、`editcap`、`dumpcap`、`text2pcap` 等 Wireshark 伴随工具。也就是说，只安装 `tshark` 就能工作；安装得更完整时，MCP 会自动获得更强的能力。

```
你:     "分析这个抓包里有没有可疑的 DNS 查询。"
Claude: [调用 wireshark_extract_dns_queries → wireshark_check_threats]
        "发现 3 条查询指向 URLhaus 标记的恶意域名: ..."
```

---

## 环境要求

- **Python 3.10+**
- **Wireshark** 已安装并包含 `tshark`
- `tshark` 是唯一必需的 Wireshark CLI 依赖
- `capinfos`、`mergecap`、`editcap`、`dumpcap`、`text2pcap` 等工具都按可选增强能力处理，探测到后会自动启用对应 MCP 功能
- 实时抓包在可用时会优先使用 `dumpcap`，缺失时自动回退到 `tshark`，因此最小安装仍然可用
- 最好让 `tshark` 出现在 `PATH` 中，但 `wireshark-mcp install` 也会尽量把探测到的 Wireshark 绝对路径写入 GUI 客户端配置
- 任意 [MCP 客户端](https://modelcontextprotocol.io/clients): Claude Desktop、Claude Code、Cursor、Codex 等

---

## 1.0 支持矩阵

对 `v1.0` 来说，“稳态”指的是项目明确承诺下面这组基线能力：

| 维度 | v1.0 基线 |
|---|---|
| 操作系统 | Windows、Linux、macOS |
| CI 验证 | 三大平台都跑测试；三大平台都跑打包后 CLI 冒烟测试；Linux 额外跑真实 `tshark` 集成冒烟 |
| Python 版本 | 3.10、3.11、3.12、3.13 |
| 必需 Wireshark 依赖 | `tshark` |
| 可选 Wireshark suite 工具 | `capinfos`、`mergecap`、`editcap`、`dumpcap`、`text2pcap`，探测到即自动启用 |
| 支持的安装路径 | `pip install wireshark-mcp`、源码安装、手动粘贴 MCP 配置 |
| 用户可执行的验收方式 | `wireshark-mcp doctor`、`wireshark-mcp clients`、`wireshark-mcp config` |

如果这些基线能力里有哪一项失效，那在 1.0 语义里它属于 `1.0.x` 需要修复的问题，不是“以后再增强”。

---

## 安装

### 安装演示视频

<video src="docs/install.mp4" controls muted playsinline preload="metadata" width="100%">
  当前环境不支持内嵌视频播放，可直接打开 <a href="docs/install.mp4">docs/install.mp4</a> 查看。
</video>

[下载或播放安装演示视频](docs/install.mp4)

### 方式一 — Cursor 一键安装（无需提前安装包）

[![在 Cursor 中安装](https://cursor.com/deeplink/mcp-install-dark.png)](cursor://anysphere.cursor-deeplink/mcp/install?name=wireshark-mcp&config=eyJjb21tYW5kIjoidXZ4IiwiYXJncyI6WyJ3aXJlc2hhcmstbWNwIl19)

需要提前安装 [uv](https://docs.astral.sh/uv/getting-started/installation/) 和 [Wireshark](https://www.wireshark.org/)。

### 方式二 — pip 安装 + 一键配置

```sh
pip install wireshark-mcp
```

然后一键配置 **所有** MCP 客户端：

```sh
wireshark-mcp install
```

搞定！重启你的 AI 客户端即可使用。 🎉

如果装完还是不对劲，可以继续执行：

```sh
wireshark-mcp doctor
```

> **`install` 做了什么？** 它会扫描系统中所有已知的 MCP 客户端配置文件（Claude、Cursor、VS Code 等），自动注入 `wireshark-mcp` 服务器配置。已有配置不会被覆盖。完整列表见 [支持的客户端](#支持的客户端)。

<details>
<summary>从源码安装</summary>

```sh
pip install git+https://github.com/bx33661/Wireshark-MCP.git
wireshark-mcp install
```

</details>

<details>
<summary>从所有客户端卸载</summary>

```sh
wireshark-mcp uninstall
```

</details>

---

## 三大平台安装建议

如果你想走最短、最稳的安装路径，可以直接按下面做。

<details>
<summary><b>macOS</b></summary>

1. 安装 Python 3.10+。
2. 安装 Wireshark，并确认 `tshark` 可用。
3. 执行：

```sh
pip install wireshark-mcp
wireshark-mcp install
wireshark-mcp doctor
```

如果你要用实时抓包，探测到 `dumpcap` 时会优先使用它。

</details>

<details>
<summary><b>Linux</b></summary>

1. 安装 Python 3.10+。
2. 安装 Wireshark，或安装能提供 `tshark` 的发行版包。
3. 执行：

```sh
pip install wireshark-mcp
wireshark-mcp install
wireshark-mcp doctor
```

实时抓包在部分发行版上可能需要额外的抓包权限；只要 `tshark` 可用，离线 `.pcap` 分析可以先稳定工作。

</details>

<details>
<summary><b>Windows</b></summary>

1. 安装 Python 3.10+。
2. 安装 Wireshark，并在安装器里保留 `TShark` 组件。
3. 在 PowerShell 或命令提示符里执行：

```powershell
py -m pip install wireshark-mcp
wireshark-mcp install
wireshark-mcp doctor
```

自动安装器会把 Python 和 Wireshark 工具的绝对路径写入 GUI MCP 客户端配置，这对 Windows 特别重要，因为很多 GUI 应用不会完整继承终端里的环境变量。

</details>

---

## 支持的客户端

`wireshark-mcp install` 会在 macOS、Linux 和 Windows 上自动配置以下客户端：

| 客户端 | 配置文件 |
|--------|--------|
| **Claude Desktop** | `claude_desktop_config.json` |
| **Claude Code** | `~/.claude.json` |
| **Cursor** | `~/.cursor/mcp.json` |
| **VS Code** | `settings.json`（通过 `mcp.servers`）|
| **VS Code Insiders** | `settings.json`（通过 `mcp.servers`）|
| **Windsurf** | `mcp_config.json` |
| **Cline** | `cline_mcp_settings.json` |
| **Roo Code** | `mcp_settings.json` |
| **Kilo Code** | `mcp_settings.json` |
| **Antigravity IDE** | `mcp_config.json` |
| **Zed** | `settings.json`（通过 `mcp.servers`）|
| **LM Studio** | `mcp.json` |
| **Warp** | `mcp_config.json` |
| **Trae** | `mcp_config.json` |
| **Gemini CLI** | `settings.json` |
| **Copilot CLI** | `mcp-config.json` |
| **Amazon Q** | `mcp_config.json` |
| **Codex** | `config.toml` |

不在列表中的客户端？运行 `wireshark-mcp config` 获取 JSON 配置片段，手动粘贴即可。

---

## 配置

### 推荐：一键自动配置

```sh
pip install wireshark-mcp
wireshark-mcp install
```

自动检测已安装的 MCP 客户端并写入配置，不会覆盖已有设置。
自动生成的配置会固定使用当前 Python 解释器（`python -u -m wireshark_mcp.server`），同时透传当前 `PATH`，并在可探测到时写入 Wireshark 工具绝对路径，因此 GUI MCP 客户端不需要自己再去猜 `wireshark-mcp` 或 `tshark` 在哪里。

> 如果分析工具依然无法启动，运行 `wireshark-mcp doctor` 检查 Python、必需/可选 Wireshark CLI 工具以及客户端配置探测结果。

### 手动配置

如果你需要手动配置，先运行：

```sh
wireshark-mcp config
```

如果你主要使用 Codex：

```sh
wireshark-mcp config --format codex-toml
```

更完整的客户端逐项配置说明已经拆到 [docs/manual-configuration_zh.md](docs/manual-configuration_zh.md)，包括 Claude Desktop、Claude Code、Cursor、VS Code、Codex、通用 JSON 客户端，以及 Docker / SSE 模式。

---

## 5 分钟验收

安装完成后，推荐用下面这组步骤快速确认当前机器已经达到可用的 1.0 状态：

1. 先看入口命令是否正常：

```sh
wireshark-mcp --version
```

2. 再看 Python 和 Wireshark 工具探测是否正常：

```sh
wireshark-mcp doctor
```

如果你要做自动验收，也可以用：

```sh
wireshark-mcp doctor --format json
```

3. 确认客户端目标是否被发现：

```sh
wireshark-mcp clients
```

如果你要做自动验收，也可以用：

```sh
wireshark-mcp clients --format json
```

4. 打印当前机器的精确手动配置：

```sh
wireshark-mcp config
```

如果你主要用 Codex，也可以直接输出 TOML：

```sh
wireshark-mcp config --format codex-toml
```

5. 在 MCP 客户端里打开一个小型 `.pcap`，然后执行：

```text
先对这个抓包运行 wireshark_open_file，总结看到的协议，再运行 wireshark_quick_analysis。
```

如果这 5 步都通过，说明当前安装已经达到预期的 `v1.0` 稳态。

---

## 运行与发布文档

更详细的稳态验证和发版文档现在放在 `docs/` 目录：

- [平台验收清单](docs/platform-validation_zh.md)
- [发版清单](docs/release-checklist.md)
- [手动配置指南](docs/manual-configuration_zh.md)
- [提示词工程](docs/prompt-engineering_zh.md)

---

## 快速开始

将以下提示词粘贴到你的 AI 客户端中：

```
使用 Wireshark MCP 工具分析 <path/to/file.pcap>。

- 先用 wireshark_open_file 获取抓包全局画像和推荐工具
- 使用 wireshark_security_audit 一键安全审计
- 或用 wireshark_quick_analysis 快速了解流量概况
- 需要细节时使用 wireshark_follow_stream 或 wireshark_get_packet_details
- 不要猜测 — 始终用工具验证
- 将分析结果写入 report.md
```

---

## 内置 Codex Skill

这个仓库现在也自带一个 Codex skill，位置在 `skills/wireshark-traffic-analysis/`。
它不是简单的提示词集合，而是一套更稳的流量分析工作流：先建立全局画像，再选择分析模式，用数据包证据确认结论，最后给出可执行的下一步。
这次也补进了基于 Wireshark 官方文档整理的关键规则，包括 Protocol Hierarchy、Endpoints、Conversations、Expert Info、Display Filters 和 Follow Stream 的使用边界。
为了兼容更多应用，同一套 skill 也镜像到了 `.github/skills/` 和 `.claude/skills/`，并补了根级入口文件（`AGENTS.md`、`CLAUDE.md`、`GEMINI.md`）、GitHub Copilot 指令以及机器可读目录 `skills/manifest.json`。

支持的模式：

- `triage`
- `security`
- `incident-response`
- `troubleshoot`
- `ctf`

示例调用：

```text
Use $wireshark-traffic-analysis to investigate <file.pcap>.
Start in triage mode, escalate if you find suspicious behavior, and produce a concise report with exact filters, streams, frames, confidence, and next steps.
```

---

## 兼容性策略

- `1.x` 的稳定 CLI 以子命令接口为准：`serve`、`install`、`uninstall`、`doctor`、`config`、`clients`。
- `--install`、`--doctor`、`--config` 这类旧参数形式会在整个 `1.x` 周期内继续兼容。
- `wireshark_read_packets` 会在整个 `1.x` 周期内保留，用于兼容旧调用，但它已经处于 deprecated 状态，不建议新工作流继续使用。
- 新的数据包明细工作流应优先使用 `wireshark_get_packet_list` 和 `wireshark_get_packet_details`。

---

## Prompt Engineering（提示词工程）

LLM 在下面这种提示方式下表现最好：

- 先用 `wireshark_open_file`
- 先做宏观分析，再逐步深挖
- 不猜，直接用工具验证
- 明确要求结构化输出

安全审计、CTF、性能排查的可直接粘贴模板现在放在 [docs/prompt-engineering_zh.md](docs/prompt-engineering_zh.md)。

## 工具集

<details>
<summary><b>⚡ Agentic Workflows</b> — 一键综合分析</summary>

<br>

| 工具 | 描述 |
|---|---|
| `wireshark_security_audit` | **一键安全审计**：8 阶段分析（威胁情报、凭证扫描、端口扫描、DNS 隧道、明文协议、异常检测），输出风险评分（0-100）和修复建议 |
| `wireshark_quick_analysis` | **一键流量概览**：文件信息、协议分布、Top Talkers、会话统计、域名/主机名、异常摘要、下一步建议 |
| `wireshark_open_file` | **智能打开文件**：分析 pcap 内容并推荐最相关的工具，同时保持 MCP 工具面稳定 |
| `wireshark_get_capabilities` | **工具链能力视图**：显示当前 MCP 服务可见的必需、推荐和可选 Wireshark suite 工具 |

> 💡 这些工具替代了手动串联 5-10 次 tool call。只需一次调用即可获得完整报告。

</details>

<details>
<summary><b>数据包分析</b> — 检查、浏览、搜索数据包</summary>

<br>

| 工具 | 描述 |
|---|---|
| `wireshark_get_packet_list` | 分页数据包列表，支持显示过滤器和自定义列 |
| `wireshark_get_packet_details` | 单帧完整 JSON 解析，支持按层过滤以减少 Token 消耗 |
| `wireshark_get_packet_bytes` | 原始 Hex + ASCII 转储（Wireshark "分组字节流"视图）|
| `wireshark_get_packet_context` | 查看某帧前后 N 个数据包，便于上下文调试 |
| `wireshark_read_packets` | 为 `1.x` 兼容保留的 deprecated 工具；新流程请改用 `wireshark_get_packet_list` 和 `wireshark_get_packet_details` |
| `wireshark_follow_stream` | 重组完整 TCP/UDP/HTTP 流会话，支持分页和搜索 |
| `wireshark_search_packets` | 跨原始字节或解码字段搜索（支持正则表达式）|

</details>

<details>
<summary><b>数据提取</b> — 从抓包中提取结构化数据</summary>

<br>

| 工具 | 描述 |
|---|---|
| `wireshark_extract_fields` | 提取任意 tshark 字段为表格 |
| `wireshark_extract_http_requests` | HTTP 请求的方法、URI、主机名 |
| `wireshark_extract_dns_queries` | 抓包中的所有 DNS 查询 |
| `wireshark_list_ips` | 所有唯一的源、目的 IP 地址 |
| `wireshark_export_objects` | 提取嵌入文件（HTTP、SMB、TFTP 等）|
| `wireshark_verify_ssl_decryption` | 使用密钥日志文件验证 TLS 解密 |

</details>

<details>
<summary><b>统计分析</b> — 流量模式和异常检测</summary>

<br>

| 工具 | 描述 |
|---|---|
| `wireshark_stats_protocol_hierarchy` | 协议分层统计 — 查看协议占比 |
| `wireshark_stats_endpoints` | 所有端点按流量排序 |
| `wireshark_stats_conversations` | 通信对及其字节/包数统计 |
| `wireshark_stats_io_graph` | 流量随时间变化（发现 DDoS、扫描、突发）|
| `wireshark_stats_expert_info` | Wireshark 专家分析：错误、警告、提示 |
| `wireshark_stats_service_response_time` | HTTP、DNS 等协议的服务响应时间 |

</details>

<details>
<summary><b>文件操作与实时抓包</b></summary>

<br>

| 工具 | 描述 |
|---|---|
| `wireshark_get_file_info` | 通过 `capinfos` 获取文件元数据（时长、包数、链路类型）|
| `wireshark_merge_pcaps` | 合并多个抓包文件 |
| `wireshark_filter_save` | 按过滤器筛选并保存到新文件 |
| `wireshark_list_interfaces` | 列出可用网络接口 |
| `wireshark_capture` | 实时抓包（时长、包数、BPF 过滤器、环形缓冲区）|

</details>

<details>
<summary><b>Suite Utilities</b> — 可选 Wireshark 伴随工具</summary>

<br>

这些工具都属于增强项。即使只有 `tshark`，服务也可以正常启动；只有在检测到对应 Wireshark 伴随二进制时，下面这些额外工作流才会被暴露和使用。

| 工具 | 描述 |
|---|---|
| `wireshark_editcap_trim` | 使用 `editcap` 按时间窗口裁剪抓包 |
| `wireshark_editcap_split` | 使用 `editcap` 按包数或时间间隔拆分抓包 |
| `wireshark_editcap_time_shift` | 使用 `editcap` 按相对偏移调整时间戳 |
| `wireshark_editcap_deduplicate` | 使用 `editcap` 按重复窗口去重 |
| `wireshark_text2pcap_import` | 使用 `text2pcap` 将 ASCII 或十六进制转储导入为抓包文件 |

</details>

<details>
<summary><b>安全分析</b></summary>

<br>

| 工具 | 描述 |
|---|---|
| `wireshark_check_threats` | 对照 [URLhaus](https://urlhaus.abuse.ch/) 威胁情报检查抓包里出现的 URL 和主机名 |
| `wireshark_extract_credentials` | 检测 HTTP Basic Auth、FTP、Telnet 中的明文凭证 |
| `wireshark_detect_port_scan` | 检测 SYN/FIN/NULL/Xmas 端口扫描，可配置阈值 |
| `wireshark_detect_dns_tunnel` | 检测 DNS 隧道（长查询、TXT 滥用、子域名熵）|
| `wireshark_detect_dos_attack` | 检测 DoS/DDoS 模式（SYN 洪泛、ICMP/UDP 洪泛、DNS 放大）|
| `wireshark_analyze_suspicious_traffic` | 综合异常分析：明文协议、异常端口、专家警告 |

</details>

<details>
<summary><b>协议深度分析</b> — TLS、TCP、ARP、SMTP、DHCP</summary>

<br>

| 工具 | 描述 |
|---|---|
| `wireshark_extract_tls_handshakes` | 从 Client/Server Hello 提取 TLS 版本、密码套件、SNI、证书 |
| `wireshark_analyze_tcp_health` | TCP 重传、重复 ACK、零窗口、RST、乱序分析 |
| `wireshark_detect_arp_spoofing` | ARP 欺骗检测：IP-MAC 冲突、gratuitous ARP 洪泛 |
| `wireshark_extract_smtp_emails` | SMTP 邮件元数据：发件人、收件人、邮件服务器 |
| `wireshark_extract_dhcp_info` | DHCP 租约信息：分配 IP、主机名、DNS 服务器 |

</details>

<details>
<summary><b>解码与可视化</b></summary>

<br>

| 工具 | 描述 |
|---|---|
| `wireshark_decode_payload` | 自动检测并解码 Base64、Hex、URL 编码、Gzip、Deflate、Rot13 等 |
| `wireshark_plot_traffic` | ASCII 流量波形图 — 一眼发现 DDoS 或扫描模式 |
| `wireshark_plot_protocols` | ASCII 协议分层树 — 直观查看抓包中的协议分布 |

</details>

> **注意**：安全分析、协议分析、威胁检测工具在整个会话里都可用。`wireshark_open_file` 的作用是根据当前抓包推荐最值得先用的工具。

---

## MCP Resources

| 资源 URI | 描述 |
|---|---|
| `wireshark://reference/display-filters` | 完整的显示过滤器语法速查表 |
| `wireshark://reference/protocol-fields` | 常用协议字段名参考 |
| `wireshark://guide/usage` | 推荐的分析工作流和使用技巧 |
| `wireshark://capabilities` | 当前 Wireshark suite 的必需、推荐与可选能力概览 |

## MCP Prompts

| Prompt | 描述 |
|---|---|
| `security_audit` | 完整安全审计流程：威胁情报、凭证扫描、攻击检测 |
| `performance_analysis` | 网络性能分析：TCP 健康、响应时间、瓶颈定位 |
| `ctf_solve` | CTF 解题流程：flag 搜索、流分析、隐写检查 |
| `incident_response` | 应急响应流程：分诊、IOC 提取、攻击时间线、遏制 |
| `traffic_overview` | 快速流量摘要，含协议分布和可视化 |

## 为什么选择 Wireshark MCP？

市面上有其他网络分析 MCP 服务器，但 Wireshark MCP 在以下方面具有优势：

| 特性 | Wireshark MCP | 其他方案 |
|------|:---:|:---:|
| 一键安装（`install`） | ✅ | ❌ |
| Agentic Workflows（一键安全审计） | ✅ | ❌ |
| 抓包感知推荐 + 稳定工具面 | ✅ | ❌ |
| 40+ 专业分析工具 | ✅ | 5-10 |
| 威胁情报集成 | ✅ | ❌ |
| Python 环境智能检测 | ✅ | ❌ |
| 18+ MCP 客户端支持 | ✅ | 手动 |

---

## 常见故障排查

| 现象 | 常见原因 | 建议处理 |
|---|---|---|
| `doctor` 里看不到 `tshark` | Wireshark 或 CLI 组件没装好，或者路径不可发现 | 安装带 `tshark` 的 Wireshark，然后重新运行 `wireshark-mcp doctor` |
| MCP 客户端能看到服务，但 tool call 启动失败 | GUI 客户端缺少运行时环境变量或绝对工具路径 | 重新执行 `wireshark-mcp install`，重启客户端，再跑一次 `wireshark-mcp doctor` |
| 实时抓包失败，但离线 `.pcap` 分析正常 | 问题通常在抓包权限或 `dumpcap` 可用性，不在核心服务本身 | 先用离线抓包文件；如果确实需要实时抓包，再补对应系统上的抓包权限 |
| `capinfos`、`editcap`、`text2pcap` 缺失 | 这些是可选增强工具，不是必需依赖 | 不影响 `tshark` 基础能力，只是对应增强工作流不会出现 |
| 你的客户端不在支持列表里 | 自动安装目前只覆盖已知配置格式 | 运行 `wireshark-mcp config` 或 `wireshark-mcp config --format codex-toml`，手动粘贴配置即可 |

---

## 开发

**安装开发依赖：**

```sh
pip install -e ".[dev]"
```

**使用 MCP Inspector 测试**（打开 Web UI 直接调用工具）：

```sh
npx -y @modelcontextprotocol/inspector uv run wireshark-mcp
```

**运行测试套件：**

```sh
uv run python -m pytest tests/ -v
```

**代码检查 & 类型检查：**

```sh
uv run python -m ruff check src/ tests/
uv run python -m mypy --package wireshark_mcp --ignore-missing-imports --no-namespace-packages
```

**Docker：**

```sh
docker compose up -d
# Pcap 文件放在 ./pcaps/（挂载为 /data）
```

**命令行选项：**

```sh
wireshark-mcp                          # 启动 stdio MCP 服务
wireshark-mcp serve --transport sse --host 0.0.0.0 --port 8080
wireshark-mcp install                  # 一键配置所有检测到的 MCP 客户端
wireshark-mcp install --client codex   # 仅配置指定客户端
wireshark-mcp uninstall
wireshark-mcp doctor                   # 人类可读诊断
wireshark-mcp doctor --format json     # 机器可读诊断
wireshark-mcp clients                  # 人类可读客户端探测结果
wireshark-mcp clients --format json    # 机器可读客户端探测结果
wireshark-mcp config                   # 打印 JSON 配置供手动设置
wireshark-mcp config --format codex-toml
wireshark-mcp --version
```

为了兼容旧用法，`--install`、`--doctor`、`--config` 这些参数形式仍然可继续使用。

参阅 [CONTRIBUTING.md](CONTRIBUTING.md) 获取完整的开发环境搭建指南。

---

<div align="center">
<sub><a href="LICENSE">MIT License</a> · <a href="https://github.com/bx33661/Wireshark-MCP/issues">报告 Bug</a></sub>
</div>
