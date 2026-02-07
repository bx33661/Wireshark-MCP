# Wireshark MCP (Production Edition) 🦈

```text
 __      __ _               _                _      __  __  _____ _____  
 \ \    / /(_)             | |              | |    |  \/  |/ ____|  __ \ 
  \ \  / /  _ _ __ ___  ___| |__   __ _ _ __| | __ | \  / | |    | |__) |
   \ \/ /  | | '__/ _ \/ __| '_ \ / _` | '__| |/ / | |\/| | |    |  ___/ 
    \  /   | | | |  __/\__ \ | | | (_| | |  |   <  | |  | | |____| |     
     \/    |_|_|  \___||___/_| |_|\__,_|_|  |_|\_\ |_|  |_|\_____|_|     
```

基于 Python 的 **生产级** Model Context Protocol (MCP) 服务器。

**工程化架构**: `src-layout` 模块化结构，对标 `ida-pro-mcp`。
**生产特性**: JSON输出、参数验证、标准化错误处理、完整文档、测试覆盖。

## 🎯 核心原则

1. **工具原子性** - 每个工具只做一件事
2. **JSON优先** - 结构化输出，便于AI解析
3. **参数验证** - 文件存在性、协议白名单检查
4. **错误规范** - 统一JSON错误格式
5. **完整文档** - 每个工具包含返回值、错误类型、使用示例

## 🚀 核心能力

| 类别 | 工具 | 说明 |
| :--- | :--- | :--- |
| **JSON读取** | `wireshark_read_packets` | 返回结构化JSON数据包 |
| **抓包管理** | `wireshark_capture` | 环形缓冲区、BPF过滤器 |
| | `wireshark_filter_save` | **[New]** 按条件筛选并保存新pcap |
| **统计分析** | `wireshark_stats_*` | 协议层级、端点、会话、IO图表、专家信息 |
| **数据提取** | `wireshark_extract_fields` | 字段提取（分页支持） |
| | `wireshark_extract_http_requests` | **[New]** HTTP请求便捷提取 |
| | `wireshark_extract_dns_queries` | **[New]** DNS查询便捷提取 |
| | `wireshark_list_ips` | **[New]** 列出所有唯一IP |
| **流追踪** | `wireshark_follow_stream` | TCP/UDP/TLS/HTTP流重组（支持**分页**与**内容搜索**） |
| **安全审计** | `wireshark_extract_credentials` | 明文凭证扫描 |
| | `wireshark_check_threats` | URLhaus威胁情报检测（改进错误处理） |
| **文件操作** | `wireshark_get_file_info` | Capinfos元数据（含版本检测） |
| | `wireshark_merge_pcaps` | 合并多个pcap文件 |
| | `wireshark_export_objects` | HTTP/SMB对象导出 |

## 🛠️ 安装与运行

### 环境准备
确保系统已安装 Wireshark (且 `tshark` 在 PATH 中)。

### 安装步骤
```powershell
# 1. 安装依赖
uv sync

# 2. 安装项目（注册命令）
uv pip install -e .

# 3. (可选) 运行测试
pytest tests/

# 4. 启动服务器
uv run wireshark-mcp
```

### Claude Desktop 配置
```json
{
  "mcpServers": {
    "wireshark": {
      "command": "uv",
      "args": [
        "--directory",
        "C:\\Users\\bx336\\Desktop\\wireshark\\wireshark-mcp",
        "run",
        "wireshark-mcp"
      ]
    }
  }
}
```

## 📝 错误处理

所有工具在参数无效或执行失败时返回标准JSON错误：

```json
{
  "success": false,
  "error": {
    "type": "FileNotFound|InvalidParameter|ExecutionError|ToolNotFound|DependencyError|NetworkError",
    "message": "Human readable error message",
    "details": "Technical details (optional)"
  }
}
```

## 📖 使用示例

### 过滤并保存
```python
wireshark_filter_save(
    input_file="big.pcap",
    output_file="http_only.pcap",
    display_filter="http"
)
```

### JSON数据包分析
```python
data = wireshark_read_packets(
    pcap_file="traffic.pcap",
    limit=50,
    display_filter="tcp.flags.syn == 1"
)
```

### 便捷HTTP分析
```python
http_requests = wireshark_extract_http_requests("web.pcap", limit=100)
# 返回: method | uri | host | user_agent 表格
```

### 威胁检测
```python
threats = wireshark_check_threats("suspicious.pcap")
# 返回: {"success": true, "data": {"ips_checked": 142, "threats_found": 3, "malicious_ips": [...]}}
```

## 🏗️ 项目结构

```text
src/wireshark_mcp/
├── server.py           # FastMCP入口
├── tshark/
│   └── client.py       # 核心驱动（带验证、版本检测）
└── tools/
    ├── __init__.py
    ├── capture.py      # 抓包、过滤
    ├── stats.py        # 统计
    ├── extract.py      # 提取（JSON + 便捷工具）
    ├── files.py        # 文件
    └── security.py     # 安全（改进错误处理）
tests/
└── test_client.py      # 单元测试
```

## 🧪 测试

运行测试套件:
```powershell
pytest tests/ -v
```

测试覆盖:
- 参数验证（文件存在性、协议白名单）
- 错误处理（JSON格式、错误类型）
- 能力检测（版本信息）

---
*Production-ready for CTF competitions and security research. Fully documented and tested.*
