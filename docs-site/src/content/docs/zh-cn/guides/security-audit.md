---
title: 安全审计
description: 用证据驱动的方式调查可疑行为。
---

当需要分析可疑流量、明文凭据、类恶意软件行为、外传线索或进行整体安全审查时，使用这个流程。

## 推荐流程

1. 先执行快速分析流程。
2. 调用 `wireshark_security_audit` 获得广覆盖初筛。
3. 用定向工具验证具体信号：
   - `wireshark_check_threats`
   - `wireshark_extract_credentials`
   - `wireshark_detect_port_scan`
   - `wireshark_detect_dns_tunnel`
   - `wireshark_analyze_suspicious_traffic`
4. 根据需要提取协议证据：
   - `wireshark_extract_http_requests`
   - `wireshark_extract_dns_queries`
   - `wireshark_extract_tls_handshakes`
5. 用 `wireshark_follow_stream` 跟踪可疑流。
6. 用 `wireshark_get_packet_details` 或 `wireshark_get_packet_context` 固定证据。

## 置信标签

每个非平凡发现都应使用明确标签：

- `confirmed`：包证据直接支持结论。
- `likely`：证据强，但抓包限制导致无法完全证明。
- `possible`：行为可疑，但仍存在常见良性解释。
- `unresolved`：抓包内证据不足。

## 报告结构

包含风险摘要、可疑行为、精确证据、置信度和下一步验证建议。
