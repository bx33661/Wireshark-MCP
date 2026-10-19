# Unreleased

## English

### Added

- **Optional DuckDB capture index (`[index]` extra).** New `wireshark_index` tool builds a local DuckDB index of a capture in one tshark pass (`action="build"`), reports freshness (`status`), drops it (`drop`), and runs one read-only, sandboxed `SELECT` over the `packets`, `pkt` and `flows` tables (`query`). Install with `pip install 'wireshark-mcp[index]'`. See [docs/capture-index.md](../docs/capture-index.md).
- `wireshark_aggregate` uses a fresh index automatically and reports `coverage.source` (`"index"` or `"tshark"`). Index columns hold tshark's own field text, so indexed answers match the tshark path; filters the index cannot reproduce exactly, and fields it does not store, fall back to tshark with the reason in `coverage.index_unused`.
- `scripts/benchmark_capture_index.py` and published results for 100 MB and 1 GB synthetic captures.

### Changed

- Tool count 52 → 53; tools/list prefix budget raised to 23,000 bytes for the new tool.
- CI installs the `index` extra for lint/type checks and the Linux and Windows tshark integration jobs.

## 中文

### 新增

- **可选的 DuckDB 抓包索引（`[index]` 扩展）。** 新工具 `wireshark_index`：一次 tshark 解析为抓包建立本地 DuckDB 索引（`action="build"`），查看是否新鲜（`status`），删除（`drop`），以及在 `packets`、`pkt`、`flows` 表上执行一条只读、沙箱化的 `SELECT`（`query`）。安装：`pip install 'wireshark-mcp[index]'`。见 [docs/capture-index_zh.md](../docs/capture-index_zh.md)。
- `wireshark_aggregate` 自动使用新鲜索引，并在 `coverage.source` 中标明来源（`"index"` 或 `"tshark"`）。索引列保存 tshark 原始字段文本，因此索引答案与 tshark 路径一致；索引无法精确复现的过滤器、以及未索引的字段，会回退到 tshark，原因写在 `coverage.index_unused`。
- `scripts/benchmark_capture_index.py`，以及 100 MB 和 1 GB 合成抓包上的公开结果。

### 变更

- 工具数 52 → 53；tools/list 前缀预算为新工具提高到 23,000 字节。
- CI 在 lint/类型检查以及 Linux、Windows tshark 集成任务中安装 `index` 扩展。
