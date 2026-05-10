---
title: Wireshark 工具链
description: 理解必需和可选的 Wireshark 命令行工具。
---

Wireshark MCP 必需 `tshark`。其他 Wireshark suite 工具是可选增强，存在时启用额外能力。

## 必需工具

| 工具 | 作用 |
| --- | --- |
| `tshark` | 读取包、过滤、解码、协议字段、统计、流和大多数分析操作。 |

## 可选工具

| 工具 | 启用能力 |
| --- | --- |
| `capinfos` | 快速抓包元数据检查。 |
| `mergecap` | 合并多个抓包文件。 |
| `editcap` | 拆分、裁剪、去重和时间戳编辑。 |
| `dumpcap` | 首选实时抓包后端。 |
| `text2pcap` | 把十六进制或 ASCII dump 导入为 pcap。 |

## 能力探测

运行：

```sh
wireshark-mcp doctor
wireshark-mcp config
```

`doctor` 验证本机工具链。`config` 展示 MCP 客户端可见的命令路径。

## 最小安装行为

只有 `tshark` 时，核心包读取、过滤、提取、统计和安全分析仍然可用。可选文件编辑和抓包功能会在对应后端工具被探测到后启用。
