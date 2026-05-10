---
title: 安全检测
description: 使用专用检测器发现扫描、洪泛、隧道、欺骗、凭据和威胁情报命中。
---

## 检测工具

| 工具 | 检测对象 |
| --- | --- |
| `wireshark_detect_port_scan` | SYN、FIN、NULL 和 Xmas 扫描模式。 |
| `wireshark_detect_dos_attack` | SYN flood、ICMP flood、UDP flood 和 DNS amplification 模式。 |
| `wireshark_detect_dns_tunnel` | 长查询、TXT 滥用和高熵子域。 |
| `wireshark_detect_arp_spoofing` | 重复 IP-MAC 映射和 gratuitous ARP 洪泛。 |
| `wireshark_check_threats` | URLhaus 威胁情报命中。 |
| `wireshark_analyze_suspicious_traffic` | 跨信号异常分析。 |
| `wireshark_extract_credentials` | HTTP Basic、FTP、Telnet 等协议中的明文凭据。 |

## 把检测器当作线索

检测器输出是调查起点。重要发现需要用包上下文、流、字段和时间证据确认。

## 避免过度断言

长 DNS 查询、重传、reset 和非常见端口都可能有良性解释。使用置信标签，并说明还需要什么证据才能证明意图。
