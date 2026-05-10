---
title: 快速分析
description: 先建立抓包全局视图，再进入单包检查。
---

当抓包内容未知，需要快速获得态势时，使用这个流程。

## 推荐流程

1. `wireshark_open_file`
2. `wireshark_quick_analysis`
3. `wireshark_stats_protocol_hierarchy`
4. `wireshark_stats_endpoints`
5. `wireshark_stats_conversations`
6. 如果时间分布重要，调用 `wireshark_plot_traffic` 或 `wireshark_stats_io_graph`
7. 对最相关的会话调用 `wireshark_follow_stream`

## 观察重点

- 主要协议和异常协议族。
- 按包数和字节数排序的主要通信方。
- 长连接或高流量会话。
- 会影响解读的广播、多播或非对称流量。
- 与用户报告问题或事件窗口对齐的流量突增。

## 报告结构

包含：

- 抓包时长和文件上下文
- 主要协议
- 主要端点和会话
- 明显异常
- 最值得继续检查的三个过滤器、流或主机

不要把第一页包列表当成整体代表。先看全局，再缩小范围。
