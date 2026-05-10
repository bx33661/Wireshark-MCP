---
title: 故障排查
description: 处理常见安装、客户端和 tshark 问题。
---

## 先运行 doctor

```sh
wireshark-mcp doctor
```

`doctor` 会检查 Python 包、客户端可见的命令路径，以及 Wireshark CLI 工具。

## 找不到 tshark

确认 Wireshark 已安装，并且 `tshark` 位于 `PATH` 中：

```sh
tshark --version
```

如果 GUI 客户端看不到同一个 shell 环境，生成带绝对路径的配置：

```sh
wireshark-mcp config
```

## 客户端能启动但工具失败

检查 MCP 服务进程是否能读取抓包文件路径。如果启用了目录沙箱，确认 `WIRESHARK_MCP_ALLOWED_DIRS` 包含抓包所在目录。

## 实时抓包失败

实时抓包可能需要操作系统级抓包权限。按常规方式安装 Wireshark，确认可用的 `dumpcap`，然后重新运行：

```sh
wireshark-mcp doctor
```

## Docker SSE 模式

```sh
docker compose up -d
```

然后把 MCP 客户端指向：

```text
http://localhost:8080/sse
```
