---
title: 更新日志
description: 版本发布历史和重要变更。
---

## 1.2.0 — 2026-05-10

性能优化、Token 优化和新协议分析工具。

### 新增

- **QUIC/HTTP3 分析** — `wireshark_analyze_quic` 提取 QUIC 版本、连接 ID、SNI 和 HTTP/3 帧
- **WebSocket 分析** — `wireshark_analyze_websocket` 报告帧类型、载荷长度和掩码
- **MQTT 分析** — `wireshark_analyze_mqtt` 提取消息类型、主题、QoS 和客户端 ID
- **gRPC 分析** — `wireshark_analyze_grpc` 支持 HTTP/2 content-type 回退检测
- **结果缓存** — tshark 只读命令的 LRU 缓存，文件变更自动失效

### 变更

- **并发安全审计** — 6 个独立阶段通过 `asyncio.gather` 运行（快约 3 倍）
- **并发快速分析** — 7 个数据获取并行运行
- **并发 TCP 健康检查** — 8 个检查并发执行而非顺序执行
- **Docstring 优化** — 全部 51 个工具描述精简至约 4400 字符
- **输出格式** — emoji 替换为文本标签，移除 ASCII 框线

---

## 1.1.5 — 2026-04-18

修复 TUI 方向键输入（SS3 序列 + BufferedReader 竞态）；新增 Void、BoltAI、Kiro 客户端。

---

## 1.1.0 — 2026-04-17

OpenCode 支持、交互式 TUI 安装器、`update` 子命令、双语更新日志。

---

## 1.0.0 — 2026-03-16

稳定版发布：套件工具、能力 API、稳定工具面、威胁情报语义。

---

## 更早版本

完整更新日志见 GitHub 上的 [changelog/ 目录](https://github.com/bx33661/Wireshark-MCP/tree/main/changelog)。
