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
- `scripts/agent_eval_harness.py` collects the 180-cell Agent matrix: it builds
  the nine `synthetic://` inputs, writes blind cells, executes every Agent query
  itself so traces are collector-written, drives any command-line Agent once per
  cell and emits runs files for `check_agent_matrix.py`. See
  [Agent evaluation](../docs/agent-evaluation.md#running-the-matrix-with-the-collector).

### Changed

- `wireshark_detect_beaconing`, `wireshark_detect_exfiltration`,
  `wireshark_detect_protocol_anomalies`, `wireshark_detect_arp_spoofing` and
  `wireshark_yara_scan` return the result envelope with `findings`, `summary`,
  `scope` and `coverage` instead of plain text. `wireshark_quick_analysis`
  returns `data.report` instead of a bare string.
- `wireshark_case` joins the tool surface as the only tool that keeps state.

### Fixed

- Protocol-anomaly detection and the Modbus write check used space-separated
  display-filter sets, which tshark 4.x rejects, so both failed on every capture.
- **Optional DuckDB capture index (`[index]` extra).** New `wireshark_index` tool builds a local DuckDB index of a capture in one tshark pass (`action="build"`), reports freshness (`status`), drops it (`drop`), and runs one read-only, sandboxed `SELECT` over the `packets`, `pkt` and `flows` tables (`query`). Install with `pip install 'wireshark-mcp[index]'`. See [docs/capture-index.md](../docs/capture-index.md).
- `wireshark_aggregate` uses a fresh index automatically and reports `coverage.source` (`"index"` or `"tshark"`). Index columns hold tshark's own field text, so indexed answers match the tshark path; filters the index cannot reproduce exactly, and fields it does not store, fall back to tshark with the reason in `coverage.index_unused`.
- `scripts/benchmark_capture_index.py` and published results for 100 MB and 1 GB synthetic captures.

### Changed

- `wireshark_index` is the second new tool in 3.2: the surface is 54 tools (analysis 42, core 34) and the tools/list prefix budget is 23,500 bytes.
- CI installs the `index` extra for lint/type checks and the Linux and Windows tshark integration jobs.

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
- `scripts/agent_eval_harness.py` 采集 180 格 Agent 矩阵：生成 9 个 `synthetic://`
  输入、写出盲测格、由自身执行 Agent 的每条查询（轨迹由采集器写入）、对每格调用任意
  命令行 Agent，并输出供 `check_agent_matrix.py` 使用的运行文件。见
  [Agent 评测](../docs/agent-evaluation_zh.md#用采集器运行矩阵)。

### 变更

- `wireshark_detect_beaconing`、`wireshark_detect_exfiltration`、
  `wireshark_detect_protocol_anomalies`、`wireshark_detect_arp_spoofing`、
  `wireshark_yara_scan` 改为返回带 `findings`、`summary`、`scope`、`coverage` 的结果信封，
  不再是纯文本；`wireshark_quick_analysis` 返回 `data.report`，不再是裸字符串。
- 新增 `wireshark_case`，它是唯一保存状态的工具。

### 修复

- 协议异常检测与 Modbus 写操作检查使用了以空格分隔的过滤器集合，tshark 4.x 会直接拒绝，
  导致两者在任何抓包上都失败。
- **可选的 DuckDB 抓包索引（`[index]` 扩展）。** 新工具 `wireshark_index`：一次 tshark 解析为抓包建立本地 DuckDB 索引（`action="build"`），查看是否新鲜（`status`），删除（`drop`），以及在 `packets`、`pkt`、`flows` 表上执行一条只读、沙箱化的 `SELECT`（`query`）。安装：`pip install 'wireshark-mcp[index]'`。见 [docs/capture-index_zh.md](../docs/capture-index_zh.md)。
- `wireshark_aggregate` 自动使用新鲜索引，并在 `coverage.source` 中标明来源（`"index"` 或 `"tshark"`）。索引列保存 tshark 原始字段文本，因此索引答案与 tshark 路径一致；索引无法精确复现的过滤器、以及未索引的字段，会回退到 tshark，原因写在 `coverage.index_unused`。
- `scripts/benchmark_capture_index.py`，以及 100 MB 和 1 GB 合成抓包上的公开结果。

### 变更

- `wireshark_index` 是 3.2 的第二个新工具：工具面共 54 个（analysis 42、core 34），tools/list 前缀预算为 23,500 字节。
- CI 在 lint/类型检查以及 Linux、Windows tshark 集成任务中安装 `index` 扩展。
