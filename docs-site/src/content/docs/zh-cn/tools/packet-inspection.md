---
title: 包检查
description: 检查包、流、字段、上下文和原始字节。
---

在全局初筛已经找出值得调查的主机、流或协议之后，再使用包检查工具。

## 核心工具

| 工具 | 用途 |
| --- | --- |
| `wireshark_get_packet_list` | 包摘要表，类似 Wireshark 顶部列表。 |
| `wireshark_get_packet_details` | 单帧完整 JSON 详情。 |
| `wireshark_get_packet_context` | 指定帧前后的上下文包。 |
| `wireshark_get_packet_bytes` | 单帧原始十六进制和 ASCII 字节。 |
| `wireshark_follow_stream` | 分页重组 TCP、UDP、TLS 或 HTTP 流。 |
| `wireshark_search_packets` | 按字符串、十六进制、正则或显示过滤器搜索。 |
| `wireshark_extract_fields` | 在显示过滤器范围内提取表格字段。 |

## 证据标准

非平凡发现至少包含其中两项：

- 精确帧号
- 流索引
- 显示过滤器
- 提取的字段名
- 源和目的主机或端口
- 产生证据的工具调用

## 分页

大抓包需要分页。不要根据一小页包列表直接下结论。
