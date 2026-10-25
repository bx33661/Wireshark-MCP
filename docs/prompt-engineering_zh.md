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

## 大抓包与抓包集合

需要可选的 `[index]` 扩展（见[抓包索引指南](capture-index_zh.md)）。

```text
你的任务是找出 <day1.pcapng> 和 <day2.pcapng> 之间的变化。

1. 用 wireshark_index(pcap_file=<day1>, more_files=<day2>) 为两个文件建索引
2. 以 day1 为基线、day2 为对比，运行 wireshark_index action="diff"；
   列出新增的主机、会话、DNS 名称、TLS SNI 和 JA3/JA4
3. 对每个新增条目，用带 display_filter 的 wireshark_index action="timeline"
   找到它的首个帧号和时间
4. 计数使用 wireshark_aggregate，并确认 coverage.source 为 "index"
5. 对报告中的每个条目，用索引返回的帧号调用 wireshark_get_packet_details 确认。
   索引用来定位证据，包级工具用来证明
6. 把新增条目、首个帧号、时间和验证结果整理成表格写入 report.md
```

## 用案卷进行长时间调查

案卷需要配置 `WIRESHARK_MCP_ALLOWED_DIRS`（见[发现模型与调查案卷](findings-and-cases_zh.md)）。

```text
调查 <file.pcap> 中疑似的信标行为，并把过程记录在案卷里。

1. 用 wireshark_case action="create" 建立案卷，并写明抓包
2. 运行 wireshark_detect_beaconing 和 wireshark_detect_dns_tunnel；用
   wireshark_case action="record" 记录每个 JSON 结果
3. 用 wireshark_follow_stream 或 wireshark_get_packet_details 验证每条发现，
   再按其 id 设置结论：confirmed、dismissed 或 open，并写明理由
4. 会话中断时，从 wireshark_case action="show" 继续
5. 最后用 wireshark_case action="report" 生成报告并保存为 report.md
```

## 使用技巧

- 优先先调用 `wireshark_open_file`，先拿到抓包全局上下文和推荐工具
- 客户端支持 MCP prompts 时，可用内置 `security_audit` prompt 起步；自动化初筛使用 `wireshark_quick_analysis`
- 总量、分布、去重基数、Top-K 和时间桶使用 `wireshark_aggregate`
- 对同一抓包要问不止一个全量问题时先建索引；第二个问题就能收回构建成本
- 引用发现时使用其 `id`，并用它附带的 `reproduce` 命令复核
- 分页提取用来查看逐行数据，不用于估算全量抓包
- 不要猜测过滤器语法，直接使用 `wireshark://reference/display-filters`
- 结论要落到准确过滤器、帧号、流索引和工具输出
