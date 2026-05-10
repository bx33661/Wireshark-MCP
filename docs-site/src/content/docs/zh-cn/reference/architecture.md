---
title: 架构
description: 内部设计 — 并发执行、结果缓存、Token 优化和上下文工具注册。
---

本页记录 Wireshark MCP 中影响工具执行方式和结果交付方式的性能与架构决策。

## 并发执行

Wireshark MCP 使用 `asyncio.gather` 在可能的情况下并行运行独立的 tshark 查询。

| 工具 | 并发阶段 | 加速比 |
| --- | --- | --- |
| `wireshark_security_audit` | 6 个独立分析阶段（威胁情报、凭据、端口扫描、DNS、明文、专家信息） | ~3x |
| `wireshark_quick_analysis` | 7 个数据获取（文件信息、协议、端点、会话、HTTP 主机、DNS、专家信息） | ~3x |
| `wireshark_analyze_tcp_health` | 8 个健康检查（重传、重复 ACK、零窗口等） | ~4x |

安全审计分两轮执行：第一轮 `gather` 获取文件信息 + 协议层级（后续阶段需要），第二轮 `gather` 运行 6 个独立分析阶段。

## 结果缓存

内置 LRU 缓存避免对同一文件重复运行相同的 tshark 命令。

| 属性 | 值 |
| --- | --- |
| 最大条目数 | 128 |
| 最大总大小 | 50 MB |
| TTL | 5 分钟 |
| 失效机制 | 文件 mtime + size（自动） |
| 作用范围 | 仅只读命令（通过 `-r` 标志检测） |

缓存行为：
- 超过最大大小 25% 的结果不缓存（避免单条目占满）
- 被截断的结果不缓存（避免提供不完整数据）
- 文件修改自动使该文件的所有缓存结果失效
- 写操作（capture、filter_save、editcap）永不缓存

## Token 优化

工具描述和输出经过优化，以最小化 LLM 对话中的 token 消耗。

### Docstring 预算

全部 51 个工具的 docstring 总计约 4400 字符（约 1100 tokens）。CI 测试（`test_token_budget.py`）强制上限为 8000 字符。

### 输出格式

- 严重性指示器使用文本标签：`[!]`（严重）、`[W]`（警告）、`[i]`（信息）、`[OK]`（正常）
- 无 ASCII 框线或装饰边框
- 使用 Markdown 标题（`###`）作为章节结构
- 表格数据超过 50 行自动截断并提示分页

### 智能截断

`smart_truncate` 工具保留长输出的头部和尾部，在中间插入省略提示。统计工具（`endpoints`、`conversations`、`io_graph`、`expert_info`、`service_response_time`）自动应用此功能。

## 上下文工具注册

并非所有工具在启动时注册。上下文工具注册表根据 `wireshark_open_file` 检测到的内容激活协议特定工具。

流程：
1. `wireshark_open_file` 运行 `tshark -z io,phs` 获取协议层级
2. 检测到的协议与 `PROTOCOL_TOOL_MAP` 匹配
3. 匹配的工具在响应中推荐给 LLM

这使活跃的工具面保持聚焦且与当前抓包相关。
