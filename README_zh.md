# Wireshark MCP

一个简单的 [MCP 服务器](https://modelcontextprotocol.io/introduction)，让您可以在 Wireshark 中进行智能数据包分析。

[English](README.md) | [中文](README_zh.md)

## 先决条件

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

## 核心功能

### 数据包分析 (Packet Analysis)
- `wireshark_get_packet_list(pcap_file, limit, offset, display_filter)`: 获取数据包摘要列表 (类似 Wireshark 上方窗格)。
- `wireshark_get_packet_details(pcap_file, frame_number)`: 获取**单个**数据包的完整详情 (类似 Wireshark 下方窗格)。
- `wireshark_follow_stream(pcap_file, stream_index, protocol, ...)`: 重组并查看完整的流内容 (支持**分页**和**搜索**)。

### 数据提取 (Data Extraction)
- `wireshark_extract_fields(pcap_file, fields, ...)`:这也是一个表格形式的字段提取工具。
- `wireshark_extract_http_requests(pcap_file)`: 便捷工具，提取 HTTP 方法、URI、主机名。
- `wireshark_extract_dns_queries(pcap_file)`: 便捷工具，提取 DNS 查询。
- `wireshark_list_ips(pcap_file)`: 列出捕获文件中的所有唯一 IP 地址。

### 统计与捕获 (Stats & Capture)
- `wireshark_stats_protocol_hierarchy(pcap_file)`: 协议分布统计。
- `wireshark_stats_conversations(pcap_file, type)`: 端点之间的流量统计。
- `wireshark_filter_save(input_file, output_file, display_filter)`: 将过滤后的数据包保存为新文件。

### 安全 (Security)
- `wireshark_check_threats(pcap_file)`: 对照威胁情报源检查 IP。
- `wireshark_extract_credentials(pcap_file)`: 扫描明文凭证。

## 开发

测试 MCP 服务器本身：

```sh
npx -y @modelcontextprotocol/inspector uv run wireshark-mcp
```

这将打开一个 Web 界面，您可以在其中直接与工具进行交互。
