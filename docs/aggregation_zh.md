# 全量聚合指南

[English](aggregation.md)

`wireshark_aggregate` 用来回答必须查看整个过滤结果的问题，包括总包数、分组计数、去重基数、Top-K 和时间分桶。要看逐包明细时使用数据包列表或字段提取；要判断全局规模与分布时使用聚合，不能把一页数据当成整个抓包。

实现会逐行消费 tshark 输出，只保留有边界的分组、去重集合和数值累加状态，不再在内存中构造完整 TSV 字符串或数据包行列表。

## 参数

| 参数 | 含义 |
|------|------|
| `pcap_file` | 服务端可读取的本地 `.pcap` 或 `.pcapng` 路径。 |
| `display_filter` | 聚合前应用的 Wireshark 显示过滤器，可留空。 |
| `group_by` | 逗号分隔的 tshark 字段，组成分组键。 |
| `distinct` | 逗号分隔的字段，在每个分组内计算去重数量。 |
| `sum_fields`、`min_fields`、`max_fields`、`avg_fields` | 分别执行数值运算的字段列表。每个字段和分组都会报告有效、缺失和非法值数量。 |
| `time_bucket_seconds` | 时间桶宽度，单位为秒。`0` 表示关闭；正数不得小于 `0.000001`。 |
| `top_k` | 返回的分组数，范围 1–200；它不会减少实际扫描的匹配包数。 |
| `sort_by` | 原有计数/键排序，以及 `numeric_desc`、`numeric_asc`。数值排序必须同时设置 `sort_numeric`。 |
| `sort_numeric` | 用于排序的数值字段，必须出现在至少一项数值运算中。一个字段请求多项运算时，依次优先使用 `sum`、`avg`、`min`、`max`。 |

分组、去重和数值运算合计最多使用 12 个不重复字段。

## 常用调用

统计所有 TCP SYN 包：

```text
wireshark_aggregate(
  pcap_file="capture.pcap",
  display_filter="tcp.flags.syn == 1 and tcp.flags.ack == 0"
)
```

查找 DNS 查询最多的源地址，并统计每个源查询过多少个域名：

```text
wireshark_aggregate(
  pcap_file="capture.pcap",
  display_filter="dns.flags.response == 0",
  group_by="ip.src",
  distinct="dns.qry.name",
  top_k=20
)
```

按源地址生成一分钟粒度的时间线：

```text
wireshark_aggregate(
  pcap_file="capture.pcap",
  display_filter="ip",
  group_by="ip.src",
  time_bucket_seconds=60,
  sort_by="auto"
)
```

设置时间桶后无需再把 `frame.time_relative` 放进 `group_by`。即使传入，该字段也会被移除，因为时间已经是隐含分组维度。

查找贡献抓包字节最多的源地址：

```text
wireshark_aggregate(
  pcap_file="capture.pcap",
  display_filter="ip.src",
  group_by="ip.src",
  sum_fields="frame.len",
  avg_fields="frame.len",
  sort_by="numeric_desc",
  sort_numeric="frame.len"
)
```

`frame.len` 表示捕获帧长度，不是应用有效载荷。单位和语义由请求的 tshark 字段决定，工具不会自动换算。

## 返回结构

成功响应包含：

- `matched_packets`：时间校验前匹配到的数据包行数
- `groups_total`：对完整扫描结果计算出的分组总数
- `groups_returned`：经过 `top_k` 限制后实际返回的分组数
- `truncated`：是否还有未返回的分组
- `groups`：每项包含 `key`、包计数 `count`，以及可选的 `distinct` 和 `numeric` 结果
- `skipped_invalid_time`：存在无法分配到有效时间桶的数据包时才出现

`count` 始终表示组内包数，不是字段 occurrence 数，也不是字节数。`distinct` 字段在单个包内可能出现多次，计算基数前会展开 tshark 输出中的重复值。

每个数值字段都会报告 `valid_values`、`missing_values`、`invalid_values` 和请求的运算。没有有效值时运算结果为 `null`。非十进制、非有限、累加溢出和多 occurrence 单元格不会被猜测，会计为非法值并将覆盖状态标记为部分完成。

## 边界与解释

- 匹配包超过 1,000,000 行时，工具提前停止并返回 `LimitExceeded`。此时应收紧 `display_filter`，或按有业务含义的时间窗口拆分抓包。
- 流式 stdout 另有 50 MiB 上限。即使包数没有达到行数上限，异常宽的字段值也不能绕过内存边界。
- `top_k` 只控制返回的分组，不截断统计输入，因此排名仍然基于完整结果。
- 分组键来自 tshark 字段文本。除时间桶前缀按数值排序外，键排序均为字典序。
- 某些文本字段本身可能带逗号，会与 tshark 的重复值分隔符产生歧义。优先使用 `ip.src`、`ip.dst`、`tcp.srcport`、`tcp.dstport` 这类单值方向字段，并用 `wireshark_extract_fields` 核验异常分组。
- 服务端还有独立的结果字符上限。结果过大时应降低 `top_k` 或减少分组维度。
- 空字段会进入空字符串分组。不需要缺失值时，可在显示过滤器中加入字段存在性判断，例如 `http.host`。

聚合适合确认规模和确定排查优先级。重要结论仍需回到准确帧号、包详情、上下文或完整流中核验。
