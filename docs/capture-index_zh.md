# 抓包索引（DuckDB）

[English](capture-index.md)

`wireshark_aggregate` 平时每问一次就要用 tshark 把整个抓包重新解析一遍。1 GB 抓包每次调用接近一分钟，改一个参数又要付一次全价。抓包索引把解析成本只付一次：一次 tshark 解析把每个包的常用字段写进本地 DuckDB 文件，之后的统计直接读这个文件。

索引是可选扩展，不装就一切照旧。

```bash
pip install 'wireshark-mcp[index]'
```

## 不变的部分

- **包级证据仍来自 tshark。** 索引只回答"哪些帧、多少、怎么分组"。`wireshark_get_packet_details`、`wireshark_follow_stream` 等包级工具依旧现场解析。
- **答案完全一致。** 每个索引列保存的是 tshark 对该字段的原始文本（与 `tshark -T fields` 输出一致），走索引的聚合使用与 tshark 路径相同的累加器。测试套件在真实抓包上逐项比对两条路径的结果。
- **默认本地。** 索引文件在 `~/.wireshark-mcp/index/`（或 `WIRESHARK_MCP_INDEX_DIR`），不上传任何内容。

## 用法

```text
wireshark_index(pcap_file="big.pcapng")                    # 构建（一次 tshark 解析）
wireshark_aggregate(pcap_file="big.pcapng", group_by="ip.src", distinct="ip.dst")
wireshark_index(pcap_file="big.pcapng", action="query",
                sql="SELECT src, dport, packets, bytes FROM flows ORDER BY bytes DESC LIMIT 20")
wireshark_index(pcap_file="big.pcapng", action="timeline")  # 每个实体的首次/末次出现
wireshark_index(pcap_file="big.pcapng", action="diff",
                display_filter="frame.time_relative < 600",
                compare_filter="frame.time_relative >= 600")
wireshark_index(pcap_file="big.pcapng", action="export")    # Parquet 文件
wireshark_index(pcap_file="big.pcapng", action="status")   # fresh / stale / missing
wireshark_index(pcap_file="big.pcapng", action="drop")
```

`wireshark_aggregate` 会自动查找新鲜的索引。结果里的 `coverage.source` 标明由哪条路径回答：`"index"` 或 `"tshark"`。索引存在但没能使用时，`coverage.index_unused` 说明原因（字段不在索引中，或过滤器无法在索引上精确复现），并回退到 tshark。

只有抓包的大小和修改时间与构建时记录一致，索引才算 **fresh**。任何改动都会让它变成 stale，聚合会忽略它，`action="build"` 会重建。构建时还会记录抓包的 SHA-256，便于把结果对应到确切的字节。

## 哪些工具使用索引

| 工具 | 如何使用索引 | 何时回退到 tshark |
|------|--------------|-------------------|
| `wireshark_aggregate` | 分组、去重计数、数值指标和时间桶在 DuckDB 里用 SQL 计算（`coverage.pushdown: true`）。如果 SQL 路径无法证明结果一致，就把匹配行送进与 tshark 路径相同的 Python 累加器（`coverage.pushdown: false`）。 | 字段不在索引中，或过滤器无法翻译（`coverage.index_unused` 说明原因）。 |
| `wireshark_extract_fields` | 按帧顺序从索引逐字节重建所请求窗口的 `tshark -T fields` 输出，结果带 `coverage.source: "index"`。 | 字段或过滤器不受支持、`limit=0`、索引由另一个 tshark 版本构建、构建时有无法解析的行，或窗口内有值包含引号、反斜杠、制表符或换行（这些字符的转义在不同 tshark 版本间不同）。 |

下推不是默认成立，而是要过门槛。只有满足以下条件才会走下推：涉及的每个值都是 Python `float` 与 DuckDB `CAST` 读法完全相同的纯文本；数值都是整数且绝对值之和小于 2^53（任何求和顺序都精确）；去重项没有 `str.strip` 会去掉的空白；不会碰到分组或去重上限（超过上限后保留哪些行取决于到达顺序）。因此 `tcp.flags` 这类十六进制文本、`frame.time_relative` 这类小数求和，以及非常大的分组都会走流式路径。tshark 一致性测试让每个聚合用例都经过下推，并与 tshark 结果比对。

## 抓包集合

`more_files` 以逗号分隔传入更多抓包。每个抓包仍然有自己的索引文件（各自构建、刷新和删除），对集合的查询会把它们全部只读挂载并叠在一起：

```text
wireshark_index(pcap_file="day1.pcapng", more_files="day2.pcapng,day3.pcapng")          # 构建缺失的索引
wireshark_index(pcap_file="day1.pcapng", more_files="day2.pcapng,day3.pcapng", action="query",
                sql="SELECT capture_id, src, count(*) FROM pkt GROUP BY ALL ORDER BY 3 DESC LIMIT 20")
```

每个视图最前面多一列 `capture_id`：抓包文件名，重名时加 `~2`、`~3`。`captures` 表把每个 `capture_id` 对应到路径、SHA-256 和包数。帧号、相对时间和流编号仍然按抓包各自计算，所以关联 flows 时要同时按 `capture_id` 和 `stream`。如果有抓包没有新鲜索引，查询以 `IndexMissing` 失败并列出所有这样的抓包。每次调用最多 64 个抓包。

## 时间线

`action="timeline"` 把选中的包归约为实体，报告每个实体首次和末次出现的时间：

| 类型 | 实体 |
|------|------|
| `host` | 所有 IPv4/IPv6 源或目的地址，包括内层头 |
| `conversation` | `传输层 客户端 -> 服务端:端口`，取自该流的第一个包 |
| `protocol` | `frame.protocols` 的每一层 |
| `dns_name`、`tls_sni`、`http_host`、`user_agent`、`ja3`、`ja4` | 对应字段的值 |

结果是列名列表加 `items` 行：类型、值、包数、首帧、首次相对时间、首次绝对时间（UTC）、末帧、末次相对时间；在抓包集合上再加 `first_capture_id` 和 `last_capture_id`。条目按首次出现排序，每种类型最多 20 条，总共最多 60 条；`kinds` 总是给出每种类型的完整数量。用 `display_filter` 缩小范围（例如 `frame.time_relative` 时间窗，或 `ip.addr == 10.0.0.5`）查看其余部分。帧号就是抓包里的帧号，可直接用于 `wireshark_get_packet_details`。

## Diff

`action="diff"` 比较两组选择，只返回差异：

- **两个抓包：** `pcap_file` 是基线，`more_files` 中的唯一文件是比较对象。
- **同一抓包的两个时间窗：** `more_files` 留空，给出不同的 `display_filter`（基线）和 `compare_filter`（比较）。

两个抓包时也可以同时使用这两个过滤器。结果包含两侧的包数、按类型的 `summary`（`baseline`、`compare`、`new`、`gone`、`common`），以及 `items` 行：`change`（`new` 或 `gone`）、类型、值，和时间线相同的首末列；新增条目指向比较侧，消失条目指向基线。每种类型每种变化最多返回 10 行，按首次出现排序；summary 的计数总是完整的。

## Parquet 导出

`action="export"` 把三个 Parquet 文件（zstd 压缩）写到 `<索引目录>/exports/<名称>/`，并返回路径、行数和大小：

| 文件 | 内容 |
|------|------|
| `packets.parquet` | 选中包的 `pkt` 视图（类型化列加全部索引字段），按抓包和帧排序 |
| `flows.parquet` | 至少有一个选中包的流；统计值覆盖整条流 |
| `captures.parquet` | `capture_id`、路径、SHA-256 和包数 |

`display_filter` 限定导出范围，`more_files` 导出带 `capture_id` 列的抓包集合。相同的抓包和过滤器总是对应同一个目录，重新导出时会替换。导出只写在索引目录里，所以 `wireshark_index` 仍然只写服务器自己的缓存；需要给 pandas、Polars、Spark 或 DuckDB 使用时，从那里复制文件即可。

## 表

| 表 | 内容 |
|----|------|
| `packets` | 每帧一行。每个索引字段一列 `VARCHAR`，列名与 tshark 字段名相同（`"ip.src"`、`"dns.qry.name"`），保存 tshark 文本。多次出现的值用逗号连接（同 `-E aggregator=,`），缺失字段为 `NULL`。 |
| `pkt` | 基于 `packets` 的视图，增加类型化列：`frame`、`epoch`、`rel`、`len`、`src`、`dst`、`transport`、`stream`、`sport`、`dport`。 |
| `flows` | 每个 `tcp.stream` / `udp.stream` 一行：首包端点、`first_frame`、`last_frame`、`start_epoch`、`end_epoch`、`duration`、`packets`、`bytes`、`payload_bytes`，以及 TCP `syn`、`syn_ack`、`rst`、`fin` 计数。 |
| `captures` | 本次调用中每个抓包一行：`capture_id`、`capture_path`、`capture_sha256`、`packets`。 |
| `index_meta` | 构建元数据（抓包路径、大小、mtime、SHA-256、tshark 版本、字段列表），保存在每个索引文件里。 |

查询时 `packets`、`pkt` 和 `flows` 的第一列都是 `capture_id`，单个抓包也一样。

索引字段覆盖帧时间与长度、以太网、VLAN、IPv4/IPv6、TCP（端口、流、标志、长度）、UDP、ICMP、ARP、DNS、HTTP、TLS（SNI、JA3、JA4）、QUIC 版本、DHCP 主机名、SMB2 命令、Kerberos 与 NTLMSSP 用户名。完整列表见 `src/wireshark_mcp/index/schema.py` 的 `INDEX_FIELDS`。旧版 tshark 不认识的字段会在构建时跳过，并列在 `fields_unavailable` 中。

## SQL 查询

`action="query"` 只执行一条 `SELECT`（或 `WITH … SELECT`），最多返回 200 行；更大的结果请在 SQL 里聚合。每个索引文件以只读方式挂载到内存连接上，随后关闭 DuckDB 外部访问并锁定配置，扩展加载关闭，内存上限 2 GB，因此查询无法读取其他文件、写入、挂载数据库或访问网络。查询超过 60 秒会被中断；时间线、diff 和导出的上限是 600 秒。

SQL 结果和聚合结果一样，用来排序和定位。结论要用返回的帧号配合包级工具确认。

## 索引上的显示过滤器

只有能精确复现 tshark 语义时，`wireshark_aggregate`、`wireshark_extract_fields`、时间线、diff 和导出才把显示过滤器翻译成 SQL。在抓包集合上，字段必须在每个抓包里都有索引。时间线、diff 和导出没有 tshark 路径，所以无法翻译的过滤器会以 `InvalidParameter` 拒绝，而不是回退。支持：

- 协议名（`dns`、`tcp`）和字段存在性（`http.host`）
- `==`、`!=`、`<`、`<=`、`>`、`>=` 及其单词形式，`contains`，`in {a, b, c}`
- `and`/`&&`、`or`/`||`、`not`/`!`、括号
- `ip.addr`、`ipv6.addr`、`eth.addr`、`tcp.port`、`udp.port`

任一次出现匹配即算匹配；`!=` 表示所有出现都不相等且字段存在，与 Wireshark 4.x 相同。其余情况一律回退到 tshark，包括 CIDR 网段、IPv6 地址比较、`matches`、切片、函数、集合中的范围、值字符串名（`dns.qry.type == A`），以及不加括号混用 `and` 与 `or`。

## 限制与设置

| 设置 | 默认值 | 含义 |
|------|--------|------|
| `WIRESHARK_MCP_INDEX_DIR` | `~/.wireshark-mcp/index` | 索引文件存放位置。 |
| `WIRESHARK_MCP_INDEX_TIMEOUT` | 1800 秒（30–7200） | 构建时 tshark 解析的时间上限。 |
| 索引聚合行数上限 | 50,000,000 | 由索引回答时替代 tshark 路径的 1,000,000 行扫描上限，聚合超时仍然生效。 |

构建时中间导出文件写在索引旁边，构建完成后删除；构建期间预留大约"索引大小 + 一份索引列的未压缩文本导出"的磁盘空间。

## 基准

使用 `scripts/benchmark_capture_index.py`，在分析路径基准的确定性合成抓包上测量（Linux，4 vCPU，tshark 4.2.2，DuckDB 1.5.6）。每个答案都与生成抓包时记录的事实比对，两条路径全部通过。tshark 路径使用了放宽的扫描策略，让 1 GB 能跑完；默认 30 秒超时下它会失败，见 [3.1 基准](analysis-path-benchmark_zh.md)。

| 抓包 | 包数 | tshark 聚合（每次中位数） | 索引构建 | 索引文件 | 索引聚合（每次中位数） | 加速 | 回本点 |
|------|-----:|-------------------------:|---------:|---------:|-----------------------:|-----:|-------:|
| 100 MB | 156,557 | 4.7 秒 | 8.2 秒 | 13 MB | 0.05–0.37 秒 | 21× | 第 2 个问题 |
| 1 GB | 1,561,889 | 52.6 秒 | 79.6 秒（tshark 70.4 秒，DuckDB 8.8 秒） | 147 MB | 0.2–3.6 秒 | 27× | 第 2 个问题 |

每次调用的数字覆盖分析路径基准的五个场景（包数、最大源、DNS 查询数、去重 User-Agent、字节和）。加速为五个中位数之和的比值。

原始结果：[`docs/benchmarks/capture-index-2026-10-19.json`](benchmarks/capture-index-2026-10-19.json)。

构建成本大约等于两次 tshark 聚合调用，因此同一个文件问到第二个全量统计问题时索引就开始回本。目前索引路径把匹配行送进与 tshark 路径相同的 Python 累加器；如果更大的抓包需要，下一步是把分组下推到 DuckDB。

## 尚未支持

- 让 `wireshark_stats_endpoints`、`wireshark_stats_conversations`、`wireshark_stats_protocol_hierarchy` 和检测工具走索引。它们返回 tshark 的 `-z` tap 表格，布局和计数规则（例如隧道包按层计数）随 tshark 版本变化，所以每个工具切换前都需要一套对照解析后 tap 输出的一致性测试。
- 把长时间的构建、时间线和导出作为带进度和取消的 MCP Tasks 运行（3.3）。
