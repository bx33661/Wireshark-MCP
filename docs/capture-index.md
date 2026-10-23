# Capture index (DuckDB)

[中文版](capture-index_zh.md)

`wireshark_aggregate` normally re-dissects the whole capture with tshark for every question. On a 1 GB capture that is close to a minute per call, and changing one parameter pays the full cost again. The capture index pays the dissection once: a single tshark pass writes the common fields of every packet into a local DuckDB file, and later statistics read that file instead.

The index is an optional extra. Without it nothing changes.

```bash
pip install 'wireshark-mcp[index]'
```

## What stays the same

- **Packet evidence still comes from tshark.** The index only answers "which frames, how many, grouped how". `wireshark_get_packet_details`, `wireshark_follow_stream` and the other packet tools still dissect live.
- **Answers are identical.** Each index column stores tshark's own text for the field, exactly as `tshark -T fields` prints it, and indexed aggregation runs the same accumulator as the tshark path. The test suite compares both paths result-for-result on real captures.
- **Local by default.** The index file lives under `~/.wireshark-mcp/index/` (or `WIRESHARK_MCP_INDEX_DIR`). Nothing is uploaded.

## Using it

```text
wireshark_index(pcap_file="big.pcapng")                    # build (one tshark pass)
wireshark_aggregate(pcap_file="big.pcapng", group_by="ip.src", distinct="ip.dst")
wireshark_index(pcap_file="big.pcapng", action="query",
                sql="SELECT src, dport, packets, bytes FROM flows ORDER BY bytes DESC LIMIT 20")
wireshark_index(pcap_file="big.pcapng", action="timeline")  # first/last sighting of each entity
wireshark_index(pcap_file="big.pcapng", action="diff",
                display_filter="frame.time_relative < 600",
                compare_filter="frame.time_relative >= 600")
wireshark_index(pcap_file="big.pcapng", action="export")    # Parquet files
wireshark_index(pcap_file="big.pcapng", action="status")   # fresh / stale / missing
wireshark_index(pcap_file="big.pcapng", action="drop")
```

`wireshark_aggregate` checks for a fresh index automatically. Its `coverage.source` says which path answered: `"index"` or `"tshark"`. When an index exists but could not be used, `coverage.index_unused` says why (a field that is not indexed, or a filter the index cannot reproduce exactly), and the call falls back to tshark.

An index is **fresh** only while the capture's size and modification time match what was recorded at build time. Any change makes it stale; aggregate then ignores it, and `action="build"` rebuilds it. The build also records the capture's SHA-256 so results can be tied to exact bytes.

## Which tools use it

| Tool | How the index is used | When it falls back to tshark |
|------|-----------------------|------------------------------|
| `wireshark_aggregate` | Grouping, distinct counts, numeric metrics and time buckets run as SQL inside DuckDB (`coverage.pushdown: true`). If the SQL path cannot prove it would match, matching rows stream into the same Python accumulator the tshark path uses (`coverage.pushdown: false`). | A field is not indexed or the filter cannot be translated (`coverage.index_unused` says which). |
| `wireshark_extract_fields` | The requested window of `tshark -T fields` output is rebuilt from the index, byte for byte, in frame order. The result carries `coverage.source: "index"`. | Unindexed fields or filters, `limit=0`, an index built by a different tshark version, unparsed rows at build time, or any value in the window holding a quote, backslash, tab or line break (their escaping differs between tshark versions). |

Pushdown is gated rather than assumed. It runs only when every value involved is plain text that Python's `float` and DuckDB's `CAST` read identically, numeric values are whole numbers whose absolute sum stays below 2^53 (so the sum is exact in any order), no distinct item carries whitespace that `str.strip` would remove, and no group or distinct ceiling would be reached (which rows survive a ceiling depends on arrival order). Hex text such as `tcp.flags`, fractional sums such as `frame.time_relative`, and very large groupings therefore take the streaming path. The tshark equivalence tests run every aggregate case through pushdown and compare the result with tshark.

## Capture sets

`more_files` takes extra captures as a comma-separated list. Each capture keeps its own index file (built, refreshed and dropped on its own), and a query over the set attaches all of them read-only and stacks them:

```text
wireshark_index(pcap_file="day1.pcapng", more_files="day2.pcapng,day3.pcapng")          # builds what is missing
wireshark_index(pcap_file="day1.pcapng", more_files="day2.pcapng,day3.pcapng", action="query",
                sql="SELECT capture_id, src, count(*) FROM pkt GROUP BY ALL ORDER BY 3 DESC LIMIT 20")
```

Every view gains a leading `capture_id` column: the capture's file name, with `~2`, `~3` added when two files share a name. The `captures` table maps each `capture_id` to its path, SHA-256 and packet count. Frame numbers, relative times and stream numbers stay per capture, so join flows on `capture_id` as well as `stream`. A query fails with `IndexMissing` naming every capture that has no fresh index. Up to 64 captures per call.

## Timeline

`action="timeline"` reduces the selected packets to entities and reports when each was first and last seen:

| Kind | Entity |
|------|--------|
| `host` | every IPv4/IPv6 source or destination address, including inner headers |
| `conversation` | `transport client -> server:port`, taken from the flow's first packet |
| `protocol` | each `frame.protocols` layer |
| `dns_name`, `tls_sni`, `http_host`, `user_agent`, `ja3`, `ja4` | the field values |

The result is a column list plus `items` rows: kind, value, packets, first frame, first relative time, first absolute time (UTC), last frame and last relative time, plus `first_capture_id` and `last_capture_id` over a capture set. Items are ordered by first sighting (captures in the order given, `pcap_file` first, then frame number), up to 20 per kind and 60 in total; `kinds` always gives the complete count per kind. Narrow with `display_filter` (for example a `frame.time_relative` window, or `ip.addr == 10.0.0.5`) to see the rest. Frame numbers are the capture's own, ready for `wireshark_get_packet_details`.

## Diff

`action="diff"` compares two selections and returns only what differs:

- **Two captures:** `pcap_file` is the baseline and the single file in `more_files` is the comparison.
- **Two windows of one capture:** leave `more_files` empty and give different `display_filter` (baseline) and `compare_filter` (comparison).

Both filters may also be used with two captures. The result has the packet count on each side, a per-kind `summary` (`baseline`, `compare`, `new`, `gone`, `common`), and `items` rows of `change` (`new` or `gone`), kind, value and the same first/last columns as the timeline: new items point into the comparison, gone items into the baseline. Up to 10 rows per kind and change are returned, earliest first; the summary counts are always complete.

## Parquet export

`action="export"` writes three Parquet files (zstd) into `<index dir>/exports/<name>/` and returns their paths, row counts and sizes:

| File | Contents |
|------|----------|
| `packets.parquet` | the `pkt` view (typed columns plus every indexed tshark field) for the selected packets, ordered by capture and frame |
| `flows.parquet` | flows with at least one selected packet; totals cover the whole flow |
| `captures.parquet` | `capture_id`, path, SHA-256 and packet count |

`display_filter` restricts the export, and `more_files` exports a capture set with its `capture_id` column. The same captures and filter always map to the same directory, which is replaced on re-export. Exports stay inside the index directory, so `wireshark_index` still writes only the server's own cache; copy the files from there for pandas, Polars, Spark or DuckDB.

## Tables

| Table | Contents |
|-------|----------|
| `packets` | One row per frame. One `VARCHAR` column per indexed field, named exactly like the tshark field (`"ip.src"`, `"dns.qry.name"`), holding tshark's text. Repeated occurrences are comma-joined, as in `-E aggregator=,`. Absent fields are `NULL`. |
| `pkt` | View over `packets` adding typed columns: `frame`, `epoch`, `rel`, `len`, `src`, `dst`, `transport`, `stream`, `sport`, `dport`. |
| `flows` | One row per `tcp.stream` / `udp.stream`: first-packet endpoints, `first_frame`, `last_frame`, `start_epoch`, `end_epoch`, `duration`, `packets`, `bytes`, `payload_bytes`, and TCP `syn`, `syn_ack`, `rst`, `fin` counts. |
| `captures` | One row per capture in the call: `capture_id`, `capture_path`, `capture_sha256`, `packets`. |
| `index_meta` | Build metadata (capture path, size, mtime, SHA-256, tshark version, field list), inside each index file. |

At query time `packets`, `pkt` and `flows` start with a `capture_id` column, also for a single capture.

Indexed fields cover frame timing and length, Ethernet, VLAN, IPv4/IPv6, TCP (ports, stream, flags, lengths), UDP, ICMP, ARP, DNS, HTTP, TLS (SNI, JA3, JA4), QUIC version, DHCP hostname, SMB2 command, Kerberos and NTLMSSP user names. The full list is `INDEX_FIELDS` in `src/wireshark_mcp/index/schema.py`. Fields an older tshark does not know are skipped at build time and listed in `fields_unavailable`.

## SQL queries

`action="query"` runs exactly one `SELECT` (or `WITH … SELECT`) and returns at most 200 rows; aggregate in SQL for anything larger. Each index file is attached read-only to an in-memory connection; then DuckDB's external access is disabled and its configuration locked, with extension loading off and a 2 GB memory limit, so a query cannot read other files, write, attach databases or reach the network. Queries are interrupted after 60 seconds; timeline, diff and export after 600. Work that outgrows the memory limit spills into a private directory under `<index dir>/.spill/`, removed when the query ends.

Treat SQL results like aggregate results: they rank and locate. Confirm a conclusion with the frame numbers they return and the packet tools.

## Display filters on the index

`wireshark_aggregate`, `wireshark_extract_fields`, timeline, diff and export translate a display filter to SQL only when it can reproduce tshark's meaning exactly. Over a capture set, a field must be indexed in every capture. Timeline, diff and export have no tshark path, so an untranslatable filter is refused with `InvalidParameter` instead of falling back. Supported:

- protocol names (`dns`, `tcp`) and field presence (`http.host`)
- `==`, `!=`, `<`, `<=`, `>`, `>=` and their word forms, `contains`, `in {a, b, c}`
- `and`/`&&`, `or`/`||`, `not`/`!`, parentheses
- `ip.addr`, `ipv6.addr`, `eth.addr`, `tcp.port`, `udp.port`

A comparison matches if any occurrence matches; `!=` means every occurrence differs and the field is present, as in Wireshark 4.x. Everything else falls back to tshark, including CIDR ranges, IPv6 address comparison, `matches`, slices, functions, ranges in sets, value-string names (`dns.qry.type == A`), and `and` mixed with `or` without parentheses.

## Limits and settings

| Setting | Default | Meaning |
|---------|---------|---------|
| `WIRESHARK_MCP_INDEX_DIR` | `~/.wireshark-mcp/index` | Where index files are kept. |
| `WIRESHARK_MCP_INDEX_TIMEOUT` | 1800 s (30–7200) | Ceiling for the build's tshark pass. |
| Indexed aggregate row ceiling | 50,000,000 | Replaces the 1,000,000-row tshark scan limit when the index answers. The aggregate timeout still applies. |

The intermediate export is written next to the index and removed after the build; allow roughly the index size plus one uncompressed text export of the indexed columns while building.

## Benchmark

Measured with `scripts/benchmark_capture_index.py` on the deterministic synthetic captures from the analysis-path benchmark (Linux, 4 vCPU, tshark 4.2.2, DuckDB 1.5.6, 2026-10-22). Each answer was checked against facts recorded while the capture was written. The tshark path used the widest scan policy the server allows (10,000,000 rows, 600 s).

| Capture | Packets | tshark aggregate (per call) | Index build | Index file | Indexed aggregate (per call, median) | Speed-up | Break-even |
|---------|--------:|----------------------------:|------------:|-----------:|-------------------------------------:|---------:|-----------:|
| 100 MB | 156,557 | 4.3–5.7 s | 7.5 s | 13 MB | 0.05–0.09 s | 67× | 2nd question |
| 1 GB | 1,561,889 | 41–52 s | 68 s (58 s tshark, 9 s DuckDB) | 147 MB | 0.07–0.21 s | 408× | 2nd question |
| 10 GB | 15,627,345 | 4 of 5 fail; DNS count 581 s | 684 s (622 s tshark, 58 s DuckDB) | 1.7 GB | 0.08–1.1 s | — | 1st question |

At 10 GB the tshark path cannot answer four of the five questions at all: each stops with `LimitExceeded` when tshark's field stream passes the server's 50 MB stdout ceiling, after 75–246 s. The one it answers (DNS query count, a filtered scan) takes 581 s of its 600 s budget. The index answers all five correctly, with grouping pushed down to DuckDB in every case.

Per-call figures cover the five scenarios of the analysis-path benchmark (packet count, top source, DNS query count, distinct user agents, byte sum). Speed-up is the ratio of the five medians summed.

The other index features on the same captures, one timed call each:

| Capture | timeline | diff of the two halves | Parquet export (all packets) | extract_fields (100 rows, filtered) |
|---------|---------:|-----------------------:|-----------------------------:|------------------------------------:|
| 100 MB | 0.9 s | 0.9 s | 0.9 s | 0.2 s |
| 1 GB | 2.4 s | 4.0 s | 8.8 s | 0.3 s |
| 10 GB | 21.5 s | 33.3 s | 95.8 s (645 MB packets file) | 0.9 s |

The synthetic captures are a worst case for timeline and diff: nearly every packet starts a new flow, so the 10 GB capture has five million distinct conversations to profile.

Raw results: [`docs/benchmarks/capture-index-2026-10-22.json`](benchmarks/capture-index-2026-10-22.json) (this run) and [`docs/benchmarks/capture-index-2026-10-19.json`](benchmarks/capture-index-2026-10-19.json) (index core, before pushdown).

## Not yet

- Routing `wireshark_stats_endpoints`, `wireshark_stats_conversations`, `wireshark_stats_protocol_hierarchy` and the detection tools through the index. They return tshark's `-z` tap tables, whose layout and counting rules (for example per-layer counting of tunnelled packets) change between tshark versions, so each needs its own equivalence harness against parsed tap output before it can switch.
- Running long builds, timelines and exports as MCP Tasks with progress and cancellation (3.3).
