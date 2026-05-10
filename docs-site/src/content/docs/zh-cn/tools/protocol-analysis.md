---
title: 协议分析
description: 深入分析现代协议 — QUIC、WebSocket、MQTT、gRPC 和 TCP 健康检查。
---

Wireshark MCP 包含上下文感知的协议分析工具，当 `wireshark_open_file` 检测到相关协议时自动激活。

## 协议工具

| 工具 | 分析内容 | 适用场景 |
| --- | --- | --- |
| `wireshark_analyze_tcp_health` | 重传、重复 ACK、零窗口、窗口满、RST、乱序、Keep-Alive | 连接质量诊断和故障排查 |
| `wireshark_analyze_quic` | QUIC 版本、连接 ID、SNI、HTTP/3 帧类型 | 现代 Web 传输分析（Chrome、HTTP/3 站点） |
| `wireshark_analyze_websocket` | 帧操作码（文本/二进制/关闭）、载荷长度、掩码 | 实时应用调试（聊天、游戏、实时数据） |
| `wireshark_analyze_mqtt` | 消息类型、主题、QoS 等级、客户端 ID 及主题频率 | IoT 设备流量分析和 Broker 监控 |
| `wireshark_analyze_grpc` | 方法路径、消息长度、content-type 检测 | 微服务调用追踪和 API 调试 |

## 上下文激活

这些工具并非始终可见。当 `wireshark_open_file` 在抓包的协议层级中检测到匹配协议时，它们会出现在推荐工具列表中：

| 检测到的协议 | 激活的工具 |
| --- | --- |
| `quic`、`http3` | `wireshark_analyze_quic` |
| `websocket` | `wireshark_analyze_websocket` |
| `mqtt` | `wireshark_analyze_mqtt` |
| `grpc`、`http2` | `wireshark_analyze_grpc` |
| `tcp` | `wireshark_analyze_tcp_health` |

## 性能

TCP 健康检查和所有协议工具使用 `asyncio.gather` 并发执行 tshark 查询，比顺序执行快得多 — 尤其是 TCP 健康检查，它并行运行 8 个独立检查。

## 使用说明

- **QUIC**：当存在 QUIC 流量时也会检查 HTTP/3 帧。同时报告 QUIC 连接元数据和 HTTP/3 帧类型。
- **gRPC**：如果你的 tshark 版本没有原生 gRPC 解析器，会回退到 HTTP/2 content-type 检测（`application/grpc`）。
- **MQTT**：提供主题频率分析 — 有助于识别频繁通信的 IoT 设备或异常发布模式。
- **WebSocket**：分别统计文本、二进制和关闭帧，帮助识别连接生命周期问题。
- **TCP 健康**：按包数分级：`[OK]`（0）、`[i]`（1-50）、`[W]`（51-200）、`[!]`（200+）。

## 证据提示

当协议工具发现问题时，用以下工具确认：

- `wireshark_follow_stream` 查看完整会话
- `wireshark_get_packet_details` 检查单个帧
- `wireshark_extract_fields` 使用显示过滤器自定义字段提取
