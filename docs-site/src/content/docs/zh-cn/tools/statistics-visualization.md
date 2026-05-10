---
title: 统计和可视化
description: 用抓包级统计确定包级调查优先级。
---

统计工具用于决定从哪里深入。在未知抓包中，应该先用统计工具，再打开单个流。

## 核心统计

| 工具 | 回答的问题 |
| --- | --- |
| `wireshark_stats_protocol_hierarchy` | 出现了哪些协议，各层协议流量占比如何？ |
| `wireshark_stats_endpoints` | 哪些主机出现了，发送或接收多少流量？ |
| `wireshark_stats_conversations` | 哪些主机对存在有意义的通信？ |
| `wireshark_stats_expert_info` | 哪些错误、警告、重传、reset 或畸形包值得审查？ |
| `wireshark_stats_io_graph` | 流量何时随时间发生变化？ |
| `wireshark_stats_service_response_time` | 哪些协议操作显得缓慢或不稳定？ |

## 可视化工具

| 工具 | 输出 |
| --- | --- |
| `wireshark_plot_traffic` | ASCII I/O 柱状图 |
| `wireshark_plot_protocols` | ASCII 协议层级树 |

## 解读规则

- 协议层级百分比不是互斥桶。一个包可以在不同协议层贡献到多行。
- 端点回答“谁存在”。会话回答“谁在交换流量”。
- 专家信息是线索生成器。分配严重性前要用包上下文和流确认。
- I/O 图展示时间，不直接证明根因。

## 常见 pivot

从端点和会话开始，然后转向：

- 高字节数 TCP 流
- DNS 密集主机
- 大量短连接失败的主机
- 报告故障时间附近的突增
- 环境中不应出现的协议
