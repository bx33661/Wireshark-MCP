# 架构说明

[English](architecture.md)

Wireshark MCP 是 Wireshark 命令行套件之上的本地编排层。数据包事实来自 `tshark` 及相关工具；MCP 服务负责选择命令、校验路径与参数、统一响应，并限制进入模型上下文的数据量。

## 请求链路

```text
MCP 客户端
  → WiresharkMCP（工具 schema、profile、annotations、结果上限）
    → 工具函数（工作流与领域语义）
      → WiresharkSuiteClient（校验、命令构造、缓存）
        → tshark / capinfos / editcap / mergecap / dumpcap / text2pcap
```

`src/wireshark_mcp/server.py` 创建一个服务和一个套件客户端，再注册工具、prompts 与 resources。会话中的公开工具列表保持静态。`wireshark_open_file` 读取协议层次并推荐已经注册的工具，不会在运行时修改工具目录。

## MCP SDK 兼容性

服务端使用稳定版 Python SDK 2.x（`mcp>=2.1.1,<3`），并继承 `MCPServer`。按照 v2 的要求，HTTP 监听参数在传输启动时传入；旧有 `--mount-path` CLI 参数会转换为明确的 SSE 与消息端点路径。协议模型在 Python 中使用 snake_case 属性，在线路 JSON 中仍使用 camelCase 别名。内存客户端测试会完成一次完整的 v2 协议协商，核对服务版本，并通过协议接口读取公开工具列表，不再依赖私有 manager。

## 主要模块

| 区域 | 位置 | 职责 |
|------|------|------|
| 服务与 CLI | `server.py` | 子命令、传输方式、profile、注册顺序 |
| MCP 行为 | `mcp_app.py` | schema 精简、annotations、工具排除、结果字符上限 |
| Profile | `profiles.py` | `full`、`analysis`、`core` 的明确排除列表 |
| 工具标注 | `tool_annotations.py` | 只读、破坏性、开放世界提示 |
| 领域工具 | `tools/` | 数据包、协议、统计、安全、文件与工作流语义 |
| 套件客户端 | `tshark/` | 路径校验、子进程、提取、抓包、统计、缓存 |
| 安装器 | `installer/` | 客户端识别、配置生成、原子写入、诊断 |
| Prompts 与 resources | `prompts.py`、`resources.py` | 内置工作流和字段、过滤器参考 |

## 工具注册与 profile

工具列表会反复进入 MCP prompt 前缀，因此注册顺序必须稳定。`WiresharkMCP.add_tool` 会移除冗余 schema 标题、附加 annotations，并在工具进入管理器前排除当前 profile 不允许的条目。

- `full`：全部工具
- `analysis`：移除实时抓包与写文件操作
- `core`：再移除解密、解析覆写和底层视图

运行时 prompts 和协议推荐会按当前 profile 过滤；文档测试另行保证所有被提及的工具都存在于 full 目录中。

## 命令执行与响应

所有 Wireshark 工具都以参数数组启动，不拼接 shell 命令。客户端只允许已知套件二进制，在诊断信息中隐藏密钥，限制子进程输出，回收超时进程，并返回统一 JSON envelope：

```json
{"success": true, "data": "...", "stderr": "...", "truncated": true}
```

可选字段只在需要时出现。命令失败返回 `success: false` 和带类型的错误对象。诊断 stderr 与 stdout 分开保存，避免破坏 JSON 或字段输出。

只读命令按抓包绝对路径、修改时间、文件大小和命令参数缓存。普通分页在读取缓存后完成。全量聚合使用独立的逐行消费接口：每一行 tshark 字段输出解码后立即进入有界累加器，不保留完整 stdout 或数据包行列表。该接口同时限制行数和字节数，在超限、超时或取消时终止并回收子进程，并发排空 stderr，且不缓存流式输出。

MCP 边界还会按 `WIRESHARK_MCP_MAX_RESULT_CHARS` 限制长文本，默认 8000 字符。工具仍应主动约束自己的结果结构，传输层截断只负责兜底。

## 安全边界

- 抓包路径与输出路径由套件客户端统一校验。
- `WIRESHARK_MCP_ALLOWED_DIRS` 把读写范围限制在指定根目录内；未配置时写入默认失败关闭。
- 创建文件的工具明确标为 destructive，客户端可以要求确认。
- 实时抓包标为 open-world，并依赖主机抓包权限。
- Streamable HTTP 与 SSE 本身不提供认证。监听非回环地址时必须显式使用 `--allow-insecure-http`，并置于可信的 TLS 认证反向代理后。
- 抓包内容属于不可信输入。工具结果可以成为调查证据，不能被当成执行无关命令或越界写文件的指令。

单次实时抓包最多五分钟、一百万个包、100 MiB 输出。环形缓冲必须同时设置单文件大小和文件数，两者乘积也不能超过同一存储上限。

## 修改或增加工具

1. 同一证据模型能够表达的能力，优先扩展已有参数化工具。
2. tshark 命令构造放在套件客户端，分析语义放在 `tools/`。
3. 可预期的用户错误返回标准 envelope，不直接抛异常。
4. tshark 解析或协议语义变化时，除单元测试外还要增加真实 pcap 测试。
5. 检查 profile 可达性、annotations、工具列表体积、结果上限、两份 README 和 `changelog/unreleased.md`。

开发命令见[贡献指南](../CONTRIBUTING.md)，发版前按[发布清单](release-checklist.md)验收。
