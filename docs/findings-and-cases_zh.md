# 发现模型与调查案卷

[English](findings-and-cases.md)

## 统一的发现结构

所有检测类工具都返回 `data.findings` 和简短的 `data.summary`：
`wireshark_detect_port_scan`、`wireshark_detect_dns_tunnel`、`wireshark_detect_dos_attack`、
`wireshark_extract_credentials`、`wireshark_detect_beaconing`、`wireshark_detect_exfiltration`、
`wireshark_detect_protocol_anomalies`、`wireshark_detect_arp_spoofing`、`wireshark_yara_scan`，
`wireshark_analyze_protocol` 的 BLE 扫描者与配对分析值，以及 `wireshark_quick_analysis` 的异常部分
（其 Markdown 由同一份发现数据渲染）。

| 字段 | 含义 |
|------|------|
| `id` | `wf-` 加 16 位十六进制，对工具、类别、观察和证据锚点做内容哈希；同一检测器看到同样证据得到同一 id。 |
| `tool`、`category` | 产生该发现的工具和检测类别（`port_scan`、`beaconing`、`arp_spoofing` 等）。 |
| `observation` | 经过校准的结论，按"看到了什么"表述。 |
| `severity` | `info`、`low`、`medium`、`high`、`critical`。 |
| `confidence` | `candidate`、`likely`、`confirmed`，与严重性相互独立。 |
| `evidence[]` | 证据锚点：`frame`、`stream`、`protocol`、`filter`、`field`、`value`、`description`。 |
| `constraints` | 扫描边界：`scanned`、`limit`、`truncated`、阈值、时间窗。 |
| `reproduce[]` | 由证据过滤器或帧号生成的原生 `tshark` 命令，脱离本服务也能复核。 |
| `mitre_attack[]` | 非 info 级发现的候选 ATT&CK 技术编号，仅供分诊参考，不代表归因。 |
| `next_steps[]`、`details` | 建议的核验步骤，以及检测器自己的数值（间隔、字节数等）。 |

流量排名这类背景信息是 `info` 级发现，不附 ATT&CK 候选。

## 调查案卷

`wireshark_case` 把调查状态保存在模型上下文之外，上下文压缩或换会话后可以续查。

```text
wireshark_case(action="create", text="疑似来自 10.0.0.5 的扫描", target="/captures/a.pcap,/captures/b.pcap")
wireshark_case(action="record", case_id="case-…", text=<某个 wireshark_* 工具返回的 JSON>)
wireshark_case(action="verdict", case_id="case-…", target="wf-…", text="dismissed: 已授权的扫描器")
wireshark_case(action="note", case_id="case-…", text="变更单 CHG-1234 覆盖该时间窗")
wireshark_case(action="show", case_id="case-…")      # 续查用的精简状态
wireshark_case(action="report", case_id="case-…")    # 由案卷渲染的 Markdown 报告
wireshark_case(action="list")
```

案卷记录每个抓包的 SHA-256 与大小、每次记录的工具结果的 SHA-256、范围和覆盖情况、其中的发现（按 `id` 合并，并记下看到它的查询）、分析者结论与备注。服务端不会替案卷重跑 tshark；记录来自案卷以外抓包的结果时会给出警告。完整 JSON 可通过资源 `wireshark://cases/{case_id}` 读取。

存储遵守写文件边界：案卷写入 `WIRESHARK_MCP_ALLOWED_DIRS` 第一项下的 `.wireshark-mcp-cases/`，或写入位于允许目录内的 `WIRESHARK_MCP_CASE_DIR`。未配置允许目录时工具失败关闭。案卷包含抓包路径和发现内容，请按抓包本身的敏感级别保管该目录。
