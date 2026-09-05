# 部署场景

## 本地桌面或 CLI 客户端

默认使用 stdio：

```sh
wireshark-mcp install
```

需要先确认识别到了哪些客户端时，运行 `wireshark-mcp clients`。受管环境可以用
`wireshark-mcp config` 生成配置，审核后再修改客户端文件。

只做离线只读分析，并希望使用最小工具面时：

```sh
wireshark-mcp serve --profile core
```

## SSH 或远程分析主机

在远端仅监听回环地址：

```sh
wireshark-mcp serve --transport streamable-http --host 127.0.0.1 --port 8080
```

客户端机器建立转发：

```sh
ssh -L 8080:127.0.0.1:8080 user@analysis-host
```

随后在客户端中配置远程 MCP 地址 `http://127.0.0.1:8080/mcp`。
`wireshark-mcp config` 只生成本地 stdio 配置，不生成远程 URL。

除非可信反向代理提供 TLS 和认证，否则不要直接监听公网地址。HTTP 与 SSE
传输本身不附带认证机制；3.0 在没有 `--allow-insecure-http` 时会拒绝监听非回环地址。

## 容器

只读挂载抓包并限制允许访问的目录：

```sh
docker run --rm -p 127.0.0.1:8080:8080 \
  -v "$PWD/captures:/captures:ro" \
  -v "$PWD/results:/results" \
  -e WIRESHARK_MCP_ALLOWED_DIRS=/captures,/results \
  IMAGE wireshark-mcp serve --transport streamable-http --host 0.0.0.0 --port 8080 --allow-insecure-http
```

默认优先离线 PCAP 分析。实时抓包需要显式配置网卡和容器 capability。
不需要任何写文件工具时，移除 results 挂载并使用 `core` profile。

写文件工具只有在 `WIRESHARK_MCP_ALLOWED_DIRS` 指向现有目录后才可运行；一旦配置，
读取路径也会受同一组根目录约束。依赖导出、抓包、合并或编辑文件的自动化在升级前，
请阅读 [3.0 安全迁移指南](security-hardening-v3_zh.md)。

## WSL

在同一个 WSL 发行版中安装 Wireshark CLI 和 `wireshark-mcp`，配置使用 Linux
路径。如果 Windows 客户端启动 WSL stdio 不稳定，可在 WSL 内运行
Streamable HTTP，再通过 localhost 连接。

## CI 和自动化

非交互环境必须明确范围：

```sh
wireshark-mcp clients --client cursor --format json
wireshark-mcp config
wireshark-mcp install --client cursor
wireshark-mcp doctor --format json
wireshark-mcp clients --format json
```

`doctor` 和 `clients` 支持 JSON 输出。受管镜像执行 `install` 前，应先审核生成的配置。

## 恢复

安装器采用原子写入，但不会保存可回滚副本。受管客户端在安装前应自行备份配置。
需要移除服务配置时运行：

```sh
wireshark-mcp uninstall --client cursor
```

`update` 只会重写已经存在 `wireshark-mcp` 配置的客户端。
