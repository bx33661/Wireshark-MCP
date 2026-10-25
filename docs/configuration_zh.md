# 配置参考

[English](configuration.md)

服务器的每项设置要么是 `wireshark-mcp serve` 的命令行参数，要么是环境变量。环境变量在服务器启动时读取，所以请写在 MCP 客户端配置的 `env` 块里（或启动服务器的 shell 中），修改后重启客户端。无法解析的数字会被忽略并给出警告，改用默认值；超出允许范围的数字会被截到边界。

## 可选扩展

基础包只依赖 `tshark`。扩展只增加功能，不改变其他行为：

| 扩展 | 安装 | 增加 |
|------|------|------|
| `index` | `pip install 'wireshark-mcp[index]'` | DuckDB 抓包索引：`wireshark_index`，以及走索引的 `wireshark_aggregate` / `wireshark_extract_fields`。见 [抓包索引](capture-index_zh.md)。 |
| `geoip` | `pip install 'wireshark-mcp[geoip]'` | `wireshark_geoip_enrich`（还需要 GeoLite2 数据库，见下文）。 |
| `yara` | `pip install 'wireshark-mcp[yara]'` | `wireshark_yara_scan`。 |
| `all` | `pip install 'wireshark-mcp[all]'` | 以上三项。 |

无论是否安装扩展，这些工具都会出现在工具列表里，因此工具列表保持不变。未安装对应扩展时，调用会返回错误并提示需要安装的扩展。

各安装路线是否包含扩展：

| 路线 | 扩展 |
|------|------|
| `pip` / `uv tool install` | 方括号里写了哪些就装哪些。 |
| 容器镜像 `ghcr.io/bx33661/wireshark-mcp` | 不含。需要时构建派生镜像，见 [部署场景](deployment-scenarios_zh.md#容器)。 |
| Codex / Claude Code 插件 | 不含。启动器以 `--no-dev` 运行锁定的项目，不带扩展。 |

## 服务器参数

| 参数 | 默认值 | 含义 |
|------|--------|------|
| `--transport` | `stdio` | `stdio`、`streamable-http` 或 `sse`。 |
| `--host` / `--port` | `127.0.0.1` / `8080` | HTTP 传输的监听地址。 |
| `--allow-insecure-http` | 关闭 | 允许 HTTP 监听非回环地址。传输本身没有认证，只能放在可信、带认证的 TLS 反向代理之后使用。 |
| `--mount-path` | `/` | 旧版 SSE 挂载路径。 |
| `--profile` | `full` | 工具表面：`full`（54 个工具）、`analysis`（去掉实时抓包和由调用方指定路径的写文件工具）、`core`（再去掉解密、解析覆写和底层视图）。 |
| `--log-level` | `WARNING` | 输出到 stderr 的日志级别。 |

## 路径与权限

| 变量 | 默认值 | 含义 |
|------|--------|------|
| `WIRESHARK_MCP_ALLOWED_DIRS` | 未设置 | 逗号分隔的已存在目录。设置后，所有抓包读取和文件写入都必须位于这些目录内。未设置时读取不受限（以当前系统用户权限为准），所有会创建文件的工具一律失败关闭。 |
| `WIRESHARK_MCP_CASE_DIR` | 第一个允许目录下的 `.wireshark-mcp-cases` | `wireshark_case` 存放案卷的位置，必须位于允许目录内。 |
| `WIRESHARK_MCP_INDEX_DIR` | `~/.wireshark-mcp/index` | 抓包索引、Parquet 导出（`exports/`）和查询溢写文件（`.spill/`）所在目录。这是服务器自己的缓存，不受 `WIRESHARK_MCP_ALLOWED_DIRS` 约束；每个索引约占抓包大小的 15–20%，构建时还需要临时导出文件的空间。 |
| `GEOIP_DB_PATH` | 未设置 | GeoLite2 `.mmdb` 文件路径。未设置时使用 `~/.wireshark-mcp/geoip/GeoLite2-City.mmdb`（或 `-Country`、`-ASN`）。 |

## Wireshark 可执行文件

服务器会在 `PATH` 和常见安装位置中查找 Wireshark 套件。装了多个版本，或 GUI 客户端启动时 `PATH` 不完整时，可单独指定：

| 变量 | 程序 | 用途 |
|------|------|------|
| `WIRESHARK_MCP_TSHARK_PATH` | `tshark` | 全部功能（必需）。 |
| `WIRESHARK_MCP_CAPINFOS_PATH` | `capinfos` | 文件元数据（推荐）。 |
| `WIRESHARK_MCP_MERGECAP_PATH` | `mergecap` | `wireshark_merge_pcaps`（推荐）。 |
| `WIRESHARK_MCP_EDITCAP_PATH` | `editcap` | 四个 editcap 工具（裁剪、分割、去重、时移）。 |
| `WIRESHARK_MCP_DUMPCAP_PATH` | `dumpcap` | 实时抓包后端（缺失时退回 `tshark`）。 |
| `WIRESHARK_MCP_TEXT2PCAP_PATH` | `text2pcap` | `wireshark_text2pcap_import`。 |

`wireshark-mcp doctor` 会列出每个程序找到的位置以及是通过哪个变量找到的。

## 上限

| 变量 | 默认值 | 范围 | 含义 |
|------|--------|------|------|
| `WIRESHARK_MCP_MAX_RESULT_CHARS` | 8000 | ≥ 512 | 单个工具结果的文本上限。超出部分保留首尾截断；用工具的 `offset` / `limit` / `display_filter` 翻页。 |
| `WIRESHARK_MCP_AGGREGATE_SCAN_LIMIT` | 1,000,000 | 1,000–10,000,000 | 走 tshark 路径的 `wireshark_aggregate` 的匹配行上限。走索引时改用固定的 50,000,000 行上限。 |
| `WIRESHARK_MCP_AGGREGATE_TIMEOUT` | 30 秒 | 5–600 | 单次 `wireshark_aggregate` 的时间预算，两条路径都适用。 |
| `WIRESHARK_MCP_INDEX_TIMEOUT` | 1800 秒 | 30–7200 | 索引构建中 tshark 解析的时间预算。 |

不可配置的固定上限：聚合每次调用 stdout 最多 50 MiB；索引 SQL 查询最多返回 200 行，内存上限 2 GB，60 秒后中断（timeline、diff、export 为 600 秒）；实时抓包每次最多五分钟、一百万个包或 100 MiB。

## 示例

一个 Claude Desktop 配置：只读分析一个抓包目录，启用索引并调大结果上限：

```json
{
  "mcpServers": {
    "wireshark-mcp": {
      "command": "wireshark-mcp",
      "args": ["serve", "--profile", "analysis"],
      "env": {
        "WIRESHARK_MCP_ALLOWED_DIRS": "/srv/pcaps,/srv/wireshark-results",
        "WIRESHARK_MCP_INDEX_DIR": "/srv/wireshark-index",
        "WIRESHARK_MCP_MAX_RESULT_CHARS": "16000",
        "WIRESHARK_MCP_AGGREGATE_TIMEOUT": "120"
      }
    }
  }
}
```

可以先用 `wireshark-mcp config` 打印本机的启动命令再修改；各客户端的配置文件和字段名见 [手动配置](manual-configuration_zh.md)。
