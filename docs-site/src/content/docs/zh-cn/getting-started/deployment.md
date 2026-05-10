---
title: 部署
description: 本地、Docker 或 HTTP transport 方式运行 Wireshark MCP。
---

大多数用户通过 `stdio` 在本机运行 Wireshark MCP，因为抓包文件和 Wireshark 工具通常都在 AI 客户端所在工作站。

## 本地 stdio

桌面客户端和 CLI agent 推荐使用本地 stdio：

```json
{
  "mcpServers": {
    "wireshark-mcp": {
      "command": "wireshark-mcp",
      "args": []
    }
  }
}
```

这是最简单的模式，也避免把数据包分析工具暴露到网络上。

## Docker SSE

需要隔离运行时可以使用 Docker：

```sh
docker compose up -d
```

然后把 MCP 客户端指向：

```text
http://localhost:8080/sse
```

## 目录沙箱

设置 `WIRESHARK_MCP_ALLOWED_DIRS` 限制服务可读取路径：

```sh
export WIRESHARK_MCP_ALLOWED_DIRS="/captures:/tmp/pcaps"
```

当服务被共享使用，或抓包都来自固定工作区时，建议启用。

## 运行检查

正式使用前确认：

- 运行 `wireshark-mcp doctor`
- 确认 `tshark --version`
- 打开一个已知的小抓包
- 运行 `wireshark_get_capabilities`
- 测试一次包列表或文件信息调用

## 安全姿态

把抓包当作敏感数据处理。抓包可能包含凭据、session cookie、主机名、内网 IP、邮件内容和专有协议载荷。除非远程服务有明确访问控制和存储策略，否则优先本地运行。
