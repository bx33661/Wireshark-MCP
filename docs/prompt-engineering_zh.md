# Prompt Engineering（提示词工程）

Wireshark MCP 在下面这种提示方式下效果最好：

- 先宽后深
- 不猜，直接调用工具验证
- 先用 `wireshark_open_file`
- 明确要求输出结构化结论

## 安全审计

```text
你的任务是对 <file.pcap> 进行全面安全审计。

1. 先用 wireshark_open_file 建立全局上下文并查看推荐工具
2. 运行 wireshark_security_audit 执行自动化 8 阶段分析
3. 对发现的问题深挖：
   - 用 wireshark_follow_stream 检查可疑会话
   - 用 wireshark_extract_credentials 检查明文密码
   - 用 wireshark_check_threats 对照威胁情报验证 IOC
4. 绝对不要猜测过滤器语法 — 使用 wireshark://reference/display-filters 资源
5. 绝对不要编造数据包内容 — 始终用工具验证
6. 将结构化报告写入 report.md，包含风险评分（0-100）
```

## CTF 解题

```text
你的任务是使用 <file.pcap> 解决 CTF 网络挑战。

1. 先用 wireshark_open_file 再用 wireshark_quick_analysis 了解全貌
2. 用 wireshark_search_packets 搜索 "flag{"、"CTF{" 等模式
3. 逐个检查 wireshark_follow_stream — flag 经常藏在 HTTP body 或 TCP 数据中
4. 用 wireshark_decode_payload 解码 Base64、Hex、URL 编码、Gzip 数据
5. 用 wireshark_export_objects 导出嵌入文件（HTTP、SMB、TFTP）
6. 绝对不要自己做 Base64/Hex 解码 — 始终使用 wireshark_decode_payload
7. 记录所有步骤和找到的 flag 到 report.md
```

## 性能排查

```text
你的任务是诊断 <file.pcap> 中的网络性能问题。

1. 先用 wireshark_open_file 建立全局上下文并查看推荐工具
2. 用 wireshark_analyze_tcp_health 检查重传、零窗口、RST
3. 用 wireshark_stats_io_graph 找到流量尖峰或骤降
4. 用 wireshark_stats_service_response_time 检查 HTTP/DNS 延迟
5. 用 wireshark_stats_expert_info 查看异常
6. 用 wireshark_stats_endpoints 识别流量大户
7. 将发现写入 report.md，附上具体时间戳和修复建议
```

## 使用技巧

- 优先先调用 `wireshark_open_file`，先拿到抓包全局上下文和推荐工具
- 用 agentic 工具（`security_audit`、`quick_analysis`）做宏观分析，再继续深挖
- 不要猜测过滤器语法，直接使用 `wireshark://reference/display-filters`
- 不要手动解码，直接使用 `wireshark_decode_payload`
