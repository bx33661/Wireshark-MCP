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
2. 运行 wireshark_quick_analysis 做一次自动化初筛
3. 用 wireshark_aggregate 计算全量计数与分布。例如按 ip.src 分组 DNS 查询，
   再统计 dns.qry.name 的去重数量
4. 对发现的问题深挖：
   - 用 wireshark_follow_stream 检查可疑会话
   - 用 wireshark_extract_credentials 检查明文密码
   - 将提取的 DNS、TLS 和 HTTP 指标与给定 IOC 进行关联
5. 不要猜测过滤器语法，使用 wireshark://reference/display-filters 资源
6. 不要编造数据包内容，所有结论都要用工具验证
7. 将结构化报告写入 report.md，包含风险评分（0-100）
```

## CTF 解题

```text
你的任务是使用 <file.pcap> 解决 CTF 网络挑战。

1. 先用 wireshark_open_file 再用 wireshark_quick_analysis 了解全貌
2. 用 wireshark_search_packets 搜索 "flag{"、"CTF{" 等模式
3. 用 wireshark_aggregate 给协议、端点、流或承载内容的字段排序，再选择深挖对象
4. 用 wireshark_follow_stream 查看相关流，并按协议选择 ascii、hex 或 raw 输出
5. 用 wireshark_get_packet_bytes 和 wireshark_get_packet_details 保留准确的帧级证据
6. 用 wireshark_export_objects 导出嵌入文件（HTTP、SMB、TFTP）
7. 确需外部解码时，记录来源帧或流索引，以及完整转换步骤
8. 将调查路径和恢复出的 flag 写入 report.md
```

## 性能排查

```text
你的任务是诊断 <file.pcap> 中的网络性能问题。

1. 先用 wireshark_open_file 建立全局上下文并查看推荐工具
2. 用 wireshark_analyze_tcp_health 检查重传、零窗口、RST
3. 用 wireshark_stats_io_graph 找到流量尖峰或骤降
4. 用 wireshark_aggregate 配合 time_bucket_seconds，量化受影响主机或错误出现的峰值时段
5. 用 wireshark_stats_service_response_time 检查 HTTP/DNS 延迟
6. 用 wireshark_stats_expert_info 查看异常
7. 用 wireshark_stats_endpoints 识别流量大户
8. 将发现写入 report.md，附上具体时间戳和修复建议
```

## 使用技巧

- 优先先调用 `wireshark_open_file`，先拿到抓包全局上下文和推荐工具
- 客户端支持 MCP prompts 时，可用内置 `security_audit` prompt 起步；自动化初筛使用 `wireshark_quick_analysis`
- 总量、分布、去重基数、Top-K 和时间桶使用 `wireshark_aggregate`
- 分页提取用来查看逐行数据，不用于估算全量抓包
- 不要猜测过滤器语法，直接使用 `wireshark://reference/display-filters`
- 结论要落到准确过滤器、帧号、流索引和工具输出
