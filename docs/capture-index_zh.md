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
wireshark_index(pcap_file="big.pcapng", action="status")   # fresh / stale / missing
wireshark_index(pcap_file="big.pcapng", action="drop")
```

`wireshark_aggregate` 会自动查找新鲜的索引。结果里的 `coverage.source` 标明由哪条路径回答：`"index"` 或 `"tshark"`。索引存在但没能使用时，`coverage.index_unused` 说明原因（字段不在索引中，或过滤器无法在索引上精确复现），并回退到 tshark。

只有抓包的大小和修改时间与构建时记录一致，索引才算 **fresh**。任何改动都会让它变成 stale，聚合会忽略它，`action="build"` 会重建。构建时还会记录抓包的 SHA-256，便于把结果对应到确切的字节。

## 表

| 表 | 内容 |
|----|------|
| `packets` | 每帧一行。每个索引字段一列 `VARCHAR`，列名与 tshark 字段名相同（`"ip.src"`、`"dns.qry.name"`），保存 tshark 文本。多次出现的值用逗号连接（同 `-E aggregator=,`），缺失字段为 `NULL`。 |
| `pkt` | 基于 `packets` 的视图，增加类型化列：`frame`、`epoch`、`rel`、`len`、`src`、`dst`、`transport`、`stream`、`sport`、`dport`。 |
| `flows` | 每个 `tcp.stream` / `udp.stream` 一行：首包端点、`first_frame`、`last_frame`、`start_epoch`、`end_epoch`、`duration`、`packets`、`bytes`、`payload_bytes`，以及 TCP `syn`、`syn_ack`、`rst`、`fin` 计数。 |
| `index_meta` | 构建元数据（抓包路径、大小、mtime、SHA-256、tshark 版本、字段列表）。 |

索引字段覆盖帧时间与长度、以太网、VLAN、IPv4/IPv6、TCP（端口、流、标志、长度）、UDP、ICMP、ARP、DNS、HTTP、TLS（SNI、JA3、JA4）、QUIC 版本、DHCP 主机名、SMB2 命令、Kerberos 与 NTLMSSP 用户名。完整列表见 `src/wireshark_mcp/index/schema.py` 的 `INDEX_FIELDS`。旧版 tshark 不认识的字段会在构建时跳过，并列在 `fields_unavailable` 中。

## SQL 查询

`action="query"` 只执行一条 `SELECT`（或 `WITH … SELECT`），最多返回 200 行；更大的结果请在 SQL 里聚合。连接以只读方式打开，关闭 DuckDB 外部访问和扩展加载，内存上限 2 GB，配置锁定，因此查询无法读取其他文件、写入、挂载数据库或访问网络。查询超过 60 秒会被中断。

SQL 结果和聚合结果一样，用来排序和定位。结论要用返回的帧号配合包级工具确认。

## 索引上的显示过滤器

只有能精确复现 tshark 语义时，`wireshark_aggregate` 才把显示过滤器翻译成 SQL。支持：

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

- 多抓包集合（一个索引覆盖多个文件，带 `capture_id` 列）。
- 让 `wireshark_extract_fields` 和 `wireshark_stats_*` 也走索引。
- 导出 Parquet 供服务器之外使用。
