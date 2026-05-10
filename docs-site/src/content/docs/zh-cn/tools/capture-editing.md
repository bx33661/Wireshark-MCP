---
title: 抓包和编辑
description: 实时抓包，并为聚焦分析重塑 pcap 文件。
---

抓包和编辑工具在可用时包装 Wireshark suite 工具。它们可以在深入分析前缩小抓包范围。

## 实时抓包

| 工具 | 用途 |
| --- | --- |
| `wireshark_capture` | 使用 BPF 过滤器和 ring buffer 抓取实时流量。 |
| `wireshark_list_interfaces` | 列出可用抓包接口。 |

实时抓包在可用时优先使用 `dumpcap`，否则回退到 `tshark`。

## 文件重塑

| 工具 | 用途 |
| --- | --- |
| `wireshark_filter_save` | 把匹配过滤器的包保存为新抓包。 |
| `wireshark_merge_pcaps` | 合并多个抓包文件。 |
| `wireshark_editcap_split` | 按包数或时间间隔拆分。 |
| `wireshark_editcap_trim` | 按时间戳窗口裁剪。 |
| `wireshark_editcap_deduplicate` | 移除重复包。 |
| `wireshark_editcap_time_shift` | 调整包时间戳。 |
| `wireshark_text2pcap_import` | 把十六进制或 ASCII dump 转换为 pcap。 |
| `wireshark_verify_ssl_decryption` | 使用 `SSLKEYLOGFILE` 验证 TLS 解密。 |

## 什么时候重塑抓包

当抓包过大、包含无关时间窗口，或需要以更窄范围共享时，使用文件重塑。

证据完整性重要时保留原始抓包。基于派生副本工作，并记录过滤器、裁剪窗口、拆分规则或合并输入。
