# DeepSeek Harness 集成

[English](deepseek-harness.md)

DeepSeek Harness（DSH）不在客户端自动检测名单里，因此 `wireshark-mcp install` 不会自动把它接上。
本页记录在一套 DSH 安装上实测到的结果，省得后来人重新摸索。

> **仅在 DeepSeek Harness `0.2.2-rc.5` 上测试过，未测试任何其他 DSH 版本。**
> 以下内容是那个构建的记录，不是兼容性声明。DSH 处于预发布阶段，其插件加载器、MCP 桥接和权限
> 管线都可能在不同构建间变化，其中任何一处都可能改变这里描述的行为。

## 实测环境

| 项 | 值 |
|---|---|
| DSH 版本 | `0.2.2-rc.5`，`web` profile |
| 主机 | Windows 11 23H2，x64 |
| 服务器 | `wireshark-mcp` 4.0.0，含 `[index]` 扩展 |
| 引擎 | Wireshark / TShark 4.6.10 |
| Python | 3.13.17，独立 venv |
| 客户端 MCP SDK | `@modelcontextprotocol/client` 2.2.0（DSH 自带） |
| 协商协议版本 | `2025-11-25`（服务器声明支持到 `2026-07-28`） |
| 工具面 | `--profile full` 下 54 个工具 |

## 接入方式

DSH 通过插件加载器挂载 MCP 服务器，而不是通过某个 JSON 客户端配置文件。一个纯配置型 bundle
插入一行 `@deepseek-ai/dsh-mcp-client` 即可：

```yaml
- insert:
    - id: wireshark-mcp
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: wireshark
        transport: stdio
        command: 'C:\path\to\venv\Scripts\python.exe'
        args: ['-u', '-m', 'wireshark_mcp.server', 'serve', '--profile', 'full']
        toolCallTimeoutMs: 300000
        failOnStartupError: false
        env:
          WIRESHARK_MCP_TSHARK_PATH: 'C:\path\to\Wireshark\tshark.exe'
          WIRESHARK_MCP_CAPINFOS_PATH: 'C:\path\to\Wireshark\capinfos.exe'
          WIRESHARK_MCP_MERGECAP_PATH: 'C:\path\to\Wireshark\mergecap.exe'
          WIRESHARK_MCP_EDITCAP_PATH: 'C:\path\to\Wireshark\editcap.exe'
          WIRESHARK_MCP_DUMPCAP_PATH: 'C:\path\to\Wireshark\dumpcap.exe'
          WIRESHARK_MCP_TEXT2PCAP_PATH: 'C:\path\to\Wireshark\text2pcap.exe'
          WIRESHARK_MCP_ALLOWED_DIRS: 'D:\pcaps,D:\wireshark-results'
          WIRESHARK_MCP_INDEX_DIR: 'D:\wireshark-results\index'
          PYTHONIOENCODING: 'utf-8'
```

模型看到的工具名会变成 `mcp__<serverName>__<tool>`，例如
`mcp__wireshark__wireshark_aggregate`，而不是服务器侧的短名。重复的词是 DSH 的命名契约，
不是服务器的问题。

有两个设置比看上去更重要：

- **显式钉住程序路径。** Windows 上的 Wireshark 安装包不会把安装目录写进 `PATH`。配齐六个
  `WIRESHARK_MCP_*_PATH` 覆盖变量可以确保所有套件程序都指向预期安装目录，避免找不到引擎或命中旧版本。
- **必须抬高 `toolCallTimeoutMs`。** DSH 每次 `tools/call` 默认 60 秒。多 GB 抓包的 DuckDB
  索引构建、或在 tshark 路径上做全抓包统计，都放不进这个预算。实测最慢的一次调用是 56 秒的索引
  构建，300 秒足够。

## 与其它客户端不同的行为

以下若未特别说明，均指 `0.2.2-rc.5` 这个构建的 DSH 桥接行为，与本服务器无关。

**MCP prompts 不会被桥接。** 客户端处理 `tools/list` 与 `resources/*`，但不处理
`prompts/list`，所以内置的六个 prompt（`security_audit`、`performance_analysis`、
`incident_response`、`traffic_overview`、`analyze_with_hypothesis`、`investigate_alert`）
在 DSH 中不可达。可以从 [`src/wireshark_mcp/prompts.py`](../src/wireshark_mcp/prompts.py)
读取正文后粘贴，或把它们各自重新发布成 DSH 命令。

**工具注解会被丢弃。** MCP 的 `readOnlyHint` / `destructiveHint` 到不了权限层，54 个工具在
它看来完全一样。本机上 41 个标注为只读、13 个会写文件。请按工具名配置审批规则，不要依赖注解。

**MCP resources 可用。** `list_mcp_resources` / `read_mcp_resource` 能读到全部四个资源与案卷
模板；`wireshark://capabilities` 是最省事的健康检查。

**结果上限被强制两次。** 服务器按 `WIRESHARK_MCP_MAX_RESULT_CHARS` 裁剪一次，DSH 转发时还会
再裁剪一次。只调高服务器侧的值不一定能让调用方拿到更多文本。

## tshark 4.6.10 + DSH 0.2.2-rc.5 组合下的已知限制

- `wireshark_geoip_enrich` 需要 `geoip` 扩展**和**一份 GeoLite2 数据库；`wireshark_yara_scan`
  需要 `yara` 扩展。两者都以 `DependencyMissing` 失败，而不是返回空结果——这是诚实的行为，
  但仍然是一次失败的调用。
- 在没有流量的网卡上实时抓包会返回 `success: true` 和一个 0 包文件。下任何关于网络的结论之前，
  先用 `wireshark_get_file_info` 核对包数。

## 验收清单

接好 DSH 之后，或任意一侧升级之后：

1. `wireshark_get_capabilities` —— 六个程序都 `available`，版本符合预期。这里出现 `false`
   就能直接说明哪个专用工具会失败。
2. 对一个已知抓包跑 `wireshark_open_file` —— 返回真实的 capinfos 元数据，而不是
   "Detailed file metadata unavailable"（后者意味着引擎低于 3.6）。
3. 在小的抓包上跑 `wireshark_aggregate` —— 计数合理且带 `coverage`。
4. `wireshark_index` 之后重跑同一个 aggregate —— `coverage.source` 变成 `"index"`，数字一致。
5. 向允许根内写文件成功，向允许根外写返回 `PermissionDenied`。这证明围栏还在。
6. 工具数量符合请求的 profile（54 / 42 / 34）。

## 报告 DSH 相关问题

如果 DSH 升级后出问题，有用的信息是：DSH 构建版本、协商到的协议版本，以及同一个调用用
Python MCP SDK 直接发起是否也失败。这样能把服务器回归和桥接变化区分开。
