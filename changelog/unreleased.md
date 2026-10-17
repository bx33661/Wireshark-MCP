# Unreleased

## English

### Added

- Unified findings: every detector returns `data.findings` with a stable
  content-hash `id`, producing `tool`, `category`, native `tshark` `reproduce`
  commands and candidate `mitre_attack` techniques for non-informational
  findings. Beaconing, exfiltration, protocol-anomaly, ARP-spoofing and YARA
  results moved from Markdown or ad hoc JSON to this shape, and
  `wireshark_quick_analysis` renders its anomaly section from the findings it
  returns (`data.report` plus `data.findings`).
- `wireshark_case` keeps investigations as JSON case files under the allowed
  write root: capture SHA-256s, recorded tool results with digest, scope and
  coverage, findings merged by id, analyst verdicts and notes, and a Markdown
  report rendered only from that record. `wireshark://cases/{case_id}` exposes
  the full JSON. See [Findings and cases](../docs/findings-and-cases.md).

### Changed

- `wireshark_detect_beaconing`, `wireshark_detect_exfiltration`,
  `wireshark_detect_protocol_anomalies`, `wireshark_detect_arp_spoofing` and
  `wireshark_yara_scan` return the result envelope with `findings`, `summary`,
  `scope` and `coverage` instead of plain text. `wireshark_quick_analysis`
  returns `data.report` instead of a bare string.
- The tool surface grows to 53 (analysis 41, core 33) for `wireshark_case`,
  the only tool that keeps state.

### Fixed

- Protocol-anomaly detection and the Modbus write check used space-separated
  display-filter sets, which tshark 4.x rejects, so both failed on every capture.

## 中文

### 新增

- 统一发现模型：所有检测工具返回 `data.findings`，每条带稳定的内容哈希 `id`、
  产生它的 `tool`、`category`、可直接复核的原生 `tshark` 命令 `reproduce`，非 info
  级发现附候选 `mitre_attack` 技术。信标、外泄、协议异常、ARP 欺骗和 YARA 的结果从
  Markdown 或临时 JSON 改为该结构；`wireshark_quick_analysis` 的异常部分由其返回的
  发现渲染（`data.report` 加 `data.findings`）。
- `wireshark_case` 把调查保存为允许目录下的 JSON 案卷：抓包 SHA-256、记录的工具结果
  及其摘要/范围/覆盖、按 id 合并的发现、分析者结论与备注，以及只依据案卷生成的
  Markdown 报告；`wireshark://cases/{case_id}` 提供完整 JSON。见
  [发现模型与调查案卷](../docs/findings-and-cases_zh.md)。

### 变更

- `wireshark_detect_beaconing`、`wireshark_detect_exfiltration`、
  `wireshark_detect_protocol_anomalies`、`wireshark_detect_arp_spoofing`、
  `wireshark_yara_scan` 改为返回带 `findings`、`summary`、`scope`、`coverage` 的结果信封，
  不再是纯文本；`wireshark_quick_analysis` 返回 `data.report`，不再是裸字符串。
- 为 `wireshark_case` 工具面增至 53 个（analysis 41、core 33），它是唯一保存状态的工具。

### 修复

- 协议异常检测与 Modbus 写操作检查使用了以空格分隔的过滤器集合，tshark 4.x 会直接拒绝，
  导致两者在任何抓包上都失败。
