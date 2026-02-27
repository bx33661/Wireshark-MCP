# Wireshark MCP

<div align="center">
<img src="Logo.png" width="200" alt="Wireshark MCP">
</div>

一个简单的 [MCP 服务器](https://modelcontextprotocol.io/introduction)，让您可以在 Wireshark 中进行智能数据包分析。

[![CI](https://github.com/bx33661/Wireshark-MCP/actions/workflows/ci.yml/badge.svg)](https://github.com/bx33661/Wireshark-MCP/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/wireshark-mcp)](https://pypi.org/project/wireshark-mcp/)
[![Python Versions](https://img.shields.io/pypi/pyversions/wireshark-mcp)](https://pypi.org/project/wireshark-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[English](README.md) | [中文](README_zh.md)

---

- [Python](https://www.python.org/downloads/) (**3.10 或更高版本**)
- [Wireshark](https://www.wireshark.org/) (确保 `tshark` 已添加到您的 PATH 环境变量中)
- 支持的 MCP 客户端 (任选其一)
  - [Claude Code](https://www.anthropic.com/code)
  - [Claude](https://claude.ai/download)
  - [Cursor](https://cursor.com)
  - [VS Code](https://code.visualstudio.com/) (配合通用 MCP 客户端扩展)
  - [其他 MCP 客户端](https://modelcontextprotocol.io/clients#example-clients)

## 安装

安装最新版本的 Wireshark MCP 包：

```sh
pip install wireshark-mcp
```

或者直接从源码安装：

```sh
pip install git+https://github.com/bx33661/Wireshark-MCP.git
```

## 配置

将服务器添加到您的 MCP 客户端配置中 (例如 `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "uv",
      "args": [
        "tool",
        "run",
        "wireshark-mcp"
      ]
    }
  }
}
```

_注意_: 如果已安装在环境中，您也可以直接运行 `python -m wireshark_mcp`。

## 提示词工程 (Prompt Engineering)

大语言模型 (LLM) 擅长通用分析，但在数据包解析的细节上可能会遇到困难。以下是一个最小化的示例提示词策略：

```md
Your task is to analyze a pcap file using Wireshark MCP tools.
- Start by getting a packet list summary to understand the traffic flow (`wireshark_get_packet_list`).
- If you see interesting packets, get full details for that specific frame (`wireshark_get_packet_details`).
- For TCP/HTTP flows, use `wireshark_follow_stream` to see the full conversation.
- Use `wireshark_extract_http_requests` or `wireshark_extract_dns_queries` for quick high-level overviews.
- NEVER try to guess packet contents; always verify with the tools.
- Create a report.md with your findings.
```

## 可用工具 (Available Tools)

### 数据包分析 (Packet Analysis)
- `wireshark_get_packet_list(pcap_file, limit=20, offset=0, display_filter="", custom_columns="")`:
    获取数据包摘要列表。**新增支持自定义列** (如 "ip.src,http.host")，可替代默认视图。
- `wireshark_get_packet_details(pcap_file, frame_number, layers="")`:
    获取单个数据包的完整详情。**新增支持层级过滤** (如 "ip,tcp,http")，大幅减少 Token 消耗。
- `wireshark_get_packet_bytes(pcap_file, frame_number)`: 
    **[新增]** 获取原始 Hex/ASCII 转储 (类似 Wireshark '分组字节流' 窗格)。
- `wireshark_get_packet_context(pcap_file, frame_number, count=5)`:
    **[新增]** 查看上下文数据包 (前后 N 个包)，便于理解故障现场。
- `wireshark_follow_stream(pcap_file, stream_index, protocol="tcp", output_mode="ascii", limit_lines=500, offset_lines=0, search_content="")`: 重组并查看完整的流内容 (支持**分页**和**搜索**)。
- `wireshark_search_packets(pcap_file, match_pattern, search_type="string", limit=50, scope="bytes")`: 
    **[增强]** 搜索数据包。
    *   `scope="bytes"`: 搜索原始载荷 (Hex/字符串)。
    *   `scope="details"`: 搜索解码后的文本层 (支持 Regex)。
- `wireshark_read_packets(...)`: [**已弃用**] 请使用 `get_packet_details`。

### 数据提取 (Data Extraction)
- `wireshark_extract_fields(pcap_file, fields, display_filter="", limit=100, offset=0)`: 提取特定字段为表格数据。
- `wireshark_extract_http_requests(pcap_file, limit=100)`: 提取 HTTP 请求详情 (方法, URI, 主机名) 的便捷工具。
- `wireshark_extract_dns_queries(pcap_file, limit=100)`: 提取 DNS 查询的便捷工具。
- `wireshark_list_ips(pcap_file, type="both")`: 列出所有唯一的 IP 地址 (源,目的,或两者)。
- `wireshark_export_objects(pcap_file, protocol, dest_dir)`: 从流量中提取嵌入的文件 (http, smb 等)。
- `wireshark_verify_ssl_decryption(pcap_file, keylog_file)`: 使用密钥日志文件验证 TLS 解密。

### 统计 (Statistics)
- `wireshark_stats_protocol_hierarchy(pcap_file)`: 获取协议分级统计 (PHS)。
- `wireshark_stats_endpoints(pcap_file, type="ip")`: 列出所有端点及其流量统计。
- `wireshark_stats_conversations(pcap_file, type="ip")`: 显示通信对及其统计信息。
- `wireshark_stats_io_graph(pcap_file, interval=1)`: 获取随时间变化的流量 (I/O 图表)。
- `wireshark_stats_expert_info(pcap_file)`: 获取专家信息 (异常, 警告)。
- `wireshark_stats_service_response_time(pcap_file, protocol="http")`: 服务响应时间 (SRT) 统计。

### 文件操作 (File Operations)
- `wireshark_get_file_info(pcap_file)`: 获取关于捕获文件的详细元数据 (capinfos)。
- `wireshark_merge_pcaps(output_file, input_files)`: 将多个捕获文件合并为一个。
- `wireshark_list_interfaces()`: 列出可用于捕获的网络接口。
- `wireshark_capture(interface, output_file, duration_seconds=10, packet_count=0, capture_filter="", ring_buffer="")`: 捕获实时网络流量。
- `wireshark_filter_save(input_file, output_file, display_filter)`: 从 pcap 中过滤数据包并保存到新文件。

### 安全 (Security)
- `wireshark_check_threats(pcap_file)`: 对照 URLhaus 威胁情报检查捕获的 IP。
- `wireshark_extract_credentials(pcap_file)`: 扫描明文凭证 (HTTP Auth, FTP, Telnet)。

### 解码工具 (Decoding)
- `wireshark_decode_payload(data, encoding="auto")`: 智能解码常见编码 (Base64, Hex, URL, Gzip, Deflate, Rot13 等)。

### 可视化工具 (Visualization)
- `wireshark_plot_traffic(pcap_file, interval=1)`: 生成 ASCII 字符画形式的流量波峰图 (可识别 DDoS/扫描)。
- `wireshark_plot_protocols(pcap_file)`: 生成 ASCII 字符画形式的协议分级树 (直观查看协议占比)。

## 开发

测试 MCP 服务器本身：

```sh
npx -y @modelcontextprotocol/inspector uv run wireshark-mcp
```

这将打开一个 Web 界面，您可以在其中直接与工具进行交互。
