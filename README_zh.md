<div align="center">

<br>

<img src="Logo.png" width="120" alt="Wireshark MCP">

<h1>Wireshark MCP</h1>

<p><strong>给你的 AI 助手一个数据包分析器。</strong><br>
丢入一个 <code>.pcap</code> 文件，用自然语言提问 —— 获得基于真实 <code>tshark</code> 数据的回答。</p>

<p>
  <a href="https://github.com/bx33661/Wireshark-MCP/actions/workflows/ci.yml">
    <img src="https://github.com/bx33661/Wireshark-MCP/actions/workflows/ci.yml/badge.svg" alt="CI">
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

Wireshark MCP 是一个 [MCP 服务器](https://modelcontextprotocol.io/introduction)，将 `tshark` 封装为结构化工具，让 Claude、Cursor 等 AI 助手无需命令行即可执行深度数据包分析。

```
你:     "分析这个抓包里有没有可疑的 DNS 查询。"
Claude: [调用 wireshark_extract_dns_queries → wireshark_check_threats]
        "发现 3 条查询指向 URLhaus 标记的恶意域名: ..."
```

---

## 环境要求

- **Python 3.10+**
- **Wireshark** 已安装且 `tshark` 在 PATH 中
- 任意 [MCP 客户端](https://modelcontextprotocol.io/clients): Claude Desktop、Claude Code、Cursor、Codex 等

---

## 安装

```sh
pip install wireshark-mcp
```

<details>
<summary>从源码安装</summary>

```sh
pip install git+https://github.com/bx33661/Wireshark-MCP.git
```

</details>

---

## 配置

<details>
<summary><b>Claude Desktop</b></summary>

编辑 `claude_desktop_config.json`：

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "uv",
      "args": ["tool", "run", "wireshark-mcp"]
    }
  }
}
```

</details>

<details>
<summary><b>Claude Code (CLI)</b></summary>

```bash
claude mcp add wireshark -- uv tool run wireshark-mcp
```

也可以编辑 `~/.claude/claude_desktop_config.json`，格式同上。

</details>

<details>
<summary><b>Cursor</b></summary>

进入 **Settings → Features → MCP Servers → Add new MCP server**：

- **Name**: `wireshark`
- **Type**: `command`
- **Command**: `uv tool run wireshark-mcp`

或在项目根目录编辑 `.cursor/mcp.json`：

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "uv",
      "args": ["tool", "run", "wireshark-mcp"]
    }
  }
}
```

</details>

<details>
<summary><b>OpenAI Codex CLI</b></summary>

```bash
codex mcp add wireshark -- uv tool run wireshark-mcp
```

或编辑 `~/.codex/config.toml`：

```toml
[mcp_servers.wireshark]
command = "uv"
args = ["tool", "run", "wireshark-mcp"]
```

</details>

<details>
<summary><b>Trae AI IDE</b></summary>

进入 **Settings → MCP → Add MCP Server → Manual**，粘贴：

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "uv",
      "args": ["tool", "run", "wireshark-mcp"]
    }
  }
}
```

或在项目根目录编辑 `.trae/mcp.json`。

</details>

> **Docker / SSE 模式**: `docker compose up -d`，然后客户端连接 `http://localhost:8080/sse`

---

## 快速开始

将以下提示词粘贴到你的 AI 客户端中：

```
使用 Wireshark MCP 工具分析 <path/to/file.pcap>。

- 先用 wireshark_get_packet_list 获取流量概览
- 对感兴趣的帧使用 wireshark_get_packet_details 查看详情
- 对于 TCP/HTTP 会话，使用 wireshark_follow_stream 查看完整对话
- 不要猜测 — 始终用工具验证
- 将分析结果写入 report.md
```

---

## 工具集

<details>
<summary><b>数据包分析</b> — 检查、浏览、搜索数据包</summary>

<br>

| 工具 | 描述 |
|---|---|
| `wireshark_get_packet_list` | 分页数据包列表，支持显示过滤器和自定义列 |
| `wireshark_get_packet_details` | 单帧完整 JSON 解析，支持按层过滤以减少 Token 消耗 |
| `wireshark_get_packet_bytes` | 原始 Hex + ASCII 转储（Wireshark "分组字节流"视图）|
| `wireshark_get_packet_context` | 查看某帧前后 N 个数据包，便于上下文调试 |
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
<summary><b>安全分析</b></summary>

<br>

| 工具 | 描述 |
|---|---|
| `wireshark_check_threats` | 对照 [URLhaus](https://urlhaus.abuse.ch/) 威胁情报检查 IP |
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

---

## MCP Resources

| 资源 URI | 描述 |
|---|---|
| `wireshark://reference/display-filters` | 完整的显示过滤器语法速查表 |
| `wireshark://reference/protocol-fields` | 常用协议字段名参考 |
| `wireshark://guide/usage` | 推荐的分析工作流和使用技巧 |

## MCP Prompts

| Prompt | 描述 |
|---|---|
| `security_audit` | 完整安全审计流程：威胁情报、凭证扫描、攻击检测 |
| `performance_analysis` | 网络性能分析：TCP 健康、响应时间、瓶颈定位 |
| `ctf_solve` | CTF 解题流程：flag 搜索、流分析、隐写检查 |
| `incident_response` | 应急响应流程：分诊、IOC 提取、攻击时间线、遏制 |
| `traffic_overview` | 快速流量摘要，含协议分布和可视化 |

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
pytest tests/ -v
```

**代码检查 & 类型检查：**

```sh
ruff check src/ tests/
mypy src/wireshark_mcp/
```

**Docker：**

```sh
docker compose up -d
# Pcap 文件放在 ./pcaps/（挂载为 /data）
```

**命令行选项：**

```sh
wireshark-mcp --version
wireshark-mcp --transport sse --port 8080 --log-level INFO
```

参阅 [CONTRIBUTING.md](CONTRIBUTING.md) 获取完整的开发环境搭建指南。

---

<div align="center">
<sub><a href="LICENSE">MIT License</a> · <a href="https://github.com/bx33661/Wireshark-MCP/issues">报告 Bug</a></sub>
</div>
