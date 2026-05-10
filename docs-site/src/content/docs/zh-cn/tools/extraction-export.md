---
title: 提取和导出
description: 从抓包中提取结构化协议数据和嵌入对象。
---

提取工具把包级数据转换为更容易推理和引用的表格。

## 协议提取

| 工具 | 提取内容 | 适用场景 |
| --- | --- | --- |
| `wireshark_extract_http_requests` | HTTP 方法、URI、host 和请求元数据 | Web 活动审查、CTF pivot、明文流量 |
| `wireshark_extract_dns_queries` | DNS 查询名和记录类型 | 域名清单、隧道线索、IOC 检查 |
| `wireshark_extract_tls_handshakes` | TLS 版本、密码套件、SNI、issuer 元数据 | 加密流量分类、SNI 审查 |
| `wireshark_extract_smtp_emails` | 发件人、收件人和主题 | 邮件流调查 |
| `wireshark_extract_dhcp_info` | 租约、主机名、DNS 服务器、选项 | 端点识别和网络配置审查 |

## 凭据

`wireshark_extract_credentials` 搜索 HTTP Basic、FTP、Telnet 等协议中的明文凭据。

报告凭据发现时要谨慎：

- 包含协议和帧或流证据
- 说明凭据是完整还是部分
- 除非用户明确需要用于事件处理，否则不要完整打印秘密值

## 对象导出

`wireshark_export_objects` 从 HTTP、SMB、TFTP、IMF、DICOM 等支持协议中导出嵌入文件。

适用场景：

- 恶意软件或载荷恢复
- CTF artifact 提取
- 验证文件传输
- 从 HTTP 或 SMB 会话恢复证据

## IP 清单

`wireshark_list_ips` 按源、目的或两者列出唯一 IP。在端点富化或时间线工作前使用。

## 证据提示

当某一行提取结果支撑结论时，包含字段名和显示过滤器。例如引用 `dns.qry.name`、`http.host`、`tls.handshake.extensions_server_name`，或确认该行的精确流索引。
