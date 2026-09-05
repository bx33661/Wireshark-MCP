# Wireshark MCP 3.0 安全迁移

3.0 有意收紧了不安全的默认行为。只读 stdio 分析不需要额外配置；会写文件或
暴露 HTTP 传输的流程，需要按下面的方式迁移。

## 文件访问

未设置 `WIRESHARK_MCP_ALLOWED_DIRS` 时，所有创建文件的工具都会返回
`PermissionDenied`。先创建目录，再用逗号分隔配置多个根目录：

```sh
mkdir -p /srv/pcaps /srv/wireshark-results
export WIRESHARK_MCP_ALLOWED_DIRS=/srv/pcaps,/srv/wireshark-results
wireshark-mcp serve
```

一旦配置，输入读取和输出写入都会受同一组根目录约束。建议把输入抓包以操作系统
只读方式挂载，把结果放到另一个可写挂载点。边界检查前会解析软链接和 `..` 路径。

受影响的工具包括实时抓包、对象/YARA 导出、合并、过滤保存、editcap 操作、帧提取
和 text2pcap 导入。使用 `--profile analysis` 或 `--profile core` 可以从公开工具面
彻底移除全部写文件工具。

## HTTP 与 SSE

默认仍只监听回环地址。内置 HTTP 传输不提供应用认证或 TLS，因此非回环监听会被拒绝：

```sh
wireshark-mcp serve --transport streamable-http --host 127.0.0.1 --port 8080
```

如果容器位于可信、带认证的 TLS 反向代理后，可以显式覆盖：

```sh
wireshark-mcp serve --transport streamable-http --host 0.0.0.0 \
  --port 8080 --allow-insecure-http
```

不要把这个监听端口直接暴露到不可信网络。

## 资源上限

- 子进程 stdout 最多 16 MiB，stderr 最多 1 MiB。
- 单次实时抓包最多 300 秒、1,000,000 个包、100 MiB。
- 环形缓冲必须同时设置 `filesize` 和 `files`，乘积不能超过 100 MiB。
- Wireshark 版本探测五秒超时。
- WPA 口令和 TLS key-log 路径不会出现在命令诊断中。

这些是服务端安全上限，MCP 工具参数不能提高。达到上限时请收窄显示过滤器，或按合理
时间窗口拆分离线抓包。

## 升级检查

1. 盘点所有会调用写文件工具的自动化。
2. 创建专用抓包与结果目录，设置 `WIRESHARK_MCP_ALLOWED_DIRS`。
3. 远程服务保持回环监听，或放到带认证的 TLS 反向代理后。
4. 重启 MCP 客户端，让它刷新 3.0 工具 schema 和服务版本。
5. 运行 `wireshark-mcp doctor`，分别验证一次读取和一次预期写入。

本版本关闭了 [CVE-2026-43901 / GHSA-3r68-x3xc-rxpg](https://github.com/bx33661/Wireshark-MCP/security/advisories/GHSA-3r68-x3xc-rxpg)
所描述的任意写入行为。
