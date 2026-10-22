# Unreleased

## English

Capture index engine (the 4.0 roadmap items, built ahead of 3.3). All of it lives in the optional `[index]` extra; the tool count stays at 54 and the `tools/list` payload stays inside the 23,500-byte budget.

- **Capture sets.** `wireshark_index(more_files=...)` builds, queries, exports and reports status for several captures at once. Each capture keeps its own index file; at query time they are attached read-only and stacked with a leading `capture_id` column, and a `captures` table maps ids to paths and SHA-256.
- **Timeline.** `action="timeline"` lists the first and last sighting of hosts, conversations, protocols, DNS names, TLS SNI, HTTP hosts, user agents and JA3/JA4, with exact frame numbers, relative times and UTC time, optionally inside a display-filter window.
- **Diff.** `action="diff"` compares two captures, or two display-filter windows of one capture (`display_filter` vs `compare_filter`), and returns only new and gone items plus per-kind counts.
- **Parquet export.** `action="export"` writes `packets.parquet`, `flows.parquet` and `captures.parquet` under the index directory, optionally filtered.
- **SQL pushdown for `wireshark_aggregate`.** Grouping, distinct counts, numeric metrics and time buckets run inside DuckDB when exactness gates prove the result equals the streaming accumulator; otherwise rows stream as before. `coverage.pushdown` reports which happened.
- **`wireshark_extract_fields` on the index.** A fresh index built by the same tshark answers with byte-identical output; anything that could print differently goes to tshark.
- **10 GB benchmark tier** in `scripts/benchmark_capture_index.py`, which now also times timeline, diff, export and extract_fields. On a 10 GB capture the index answers all five aggregate questions in 0.08–1.1 s; the tshark path fails four of them on the stdout ceiling and needs 581 s for the fifth. At 1 GB the index is 408× faster ([results](../docs/benchmarks/capture-index-2026-10-22.json)).
- Query connections are now in-memory DuckDB sessions with each index attached read-only before external access is disabled and the configuration locked. Index files keep schema version 1, so 3.2 indexes stay valid.

## 中文

抓包索引引擎（路线图 4.0 的条目，在 3.3 之前完成）。全部位于可选的 `[index]` 扩展中；工具数仍为 54，`tools/list` 仍在 23,500 字节预算内。

- **抓包集合。** `wireshark_index(more_files=...)` 可以一次对多个抓包构建、查询、导出和查看状态。每个抓包保留自己的索引文件；查询时只读挂载并叠加，第一列为 `capture_id`，`captures` 表给出 id 对应的路径和 SHA-256。
- **时间线。** `action="timeline"` 列出主机、会话、协议、DNS 名称、TLS SNI、HTTP 主机、User-Agent 和 JA3/JA4 的首次与末次出现，带准确帧号、相对时间和 UTC 时间，可用显示过滤器限定时间窗。
- **Diff。** `action="diff"` 比较两个抓包，或同一抓包的两个过滤时间窗（`display_filter` 对比 `compare_filter`），只返回新增和消失的条目以及按类型的计数。
- **Parquet 导出。** `action="export"` 在索引目录下写出 `packets.parquet`、`flows.parquet` 和 `captures.parquet`，可加过滤器。
- **`wireshark_aggregate` 的 SQL 下推。** 当精确性门槛证明结果与流式累加器一致时，分组、去重计数、数值指标和时间桶在 DuckDB 中计算；否则照旧流式处理。`coverage.pushdown` 标明走了哪条路。
- **`wireshark_extract_fields` 走索引。** 由同一 tshark 构建的新鲜索引给出逐字节相同的输出；任何可能输出不同的情况都交给 tshark。
- **10 GB 基准档**加入 `scripts/benchmark_capture_index.py`，该脚本现在也测量时间线、diff、导出和 extract_fields。10 GB 抓包上索引在 0.08–1.1 秒内答出全部五个聚合问题；tshark 路径有四个因 stdout 上限失败，第五个用了 581 秒。1 GB 上索引快 408 倍（[结果](../docs/benchmarks/capture-index-2026-10-22.json)）。
- 查询连接改为内存中的 DuckDB 会话：先只读挂载各索引文件，再关闭外部访问并锁定配置。索引文件仍为 schema 版本 1，3.2 建好的索引继续有效。
