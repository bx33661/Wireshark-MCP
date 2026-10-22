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
wireshark_index(pcap_file="big.pcapng", action="status")   # fresh / stale / missing
wireshark_index(pcap_file="big.pcapng", action="drop")
```

`wireshark_aggregate` checks for a fresh index automatically. Its `coverage.source` says which path answered: `"index"` or `"tshark"`. When an index exists but could not be used, `coverage.index_unused` says why (a field that is not indexed, or a filter the index cannot reproduce exactly), and the call falls back to tshark.

An index is **fresh** only while the capture's size and modification time match what was recorded at build time. Any change makes it stale; aggregate then ignores it, and `action="build"` rebuilds it. The build also records the capture's SHA-256 so results can be tied to exact bytes.

## Tables

| Table | Contents |
|-------|----------|
| `packets` | One row per frame. One `VARCHAR` column per indexed field, named exactly like the tshark field (`"ip.src"`, `"dns.qry.name"`), holding tshark's text. Repeated occurrences are comma-joined, as in `-E aggregator=,`. Absent fields are `NULL`. |
| `pkt` | View over `packets` adding typed columns: `frame`, `epoch`, `rel`, `len`, `src`, `dst`, `transport`, `stream`, `sport`, `dport`. |
| `flows` | One row per `tcp.stream` / `udp.stream`: first-packet endpoints, `first_frame`, `last_frame`, `start_epoch`, `end_epoch`, `duration`, `packets`, `bytes`, `payload_bytes`, and TCP `syn`, `syn_ack`, `rst`, `fin` counts. |
| `index_meta` | Build metadata (capture path, size, mtime, SHA-256, tshark version, field list). |

Indexed fields cover frame timing and length, Ethernet, VLAN, IPv4/IPv6, TCP (ports, stream, flags, lengths), UDP, ICMP, ARP, DNS, HTTP, TLS (SNI, JA3, JA4), QUIC version, DHCP hostname, SMB2 command, Kerberos and NTLMSSP user names. The full list is `INDEX_FIELDS` in `src/wireshark_mcp/index/schema.py`. Fields an older tshark does not know are skipped at build time and listed in `fields_unavailable`.

## SQL queries

`action="query"` runs exactly one `SELECT` (or `WITH … SELECT`) and returns at most 200 rows; aggregate in SQL for anything larger. The connection is opened read-only with DuckDB's external access disabled, extension loading off, a 2 GB memory limit and its configuration locked, so a query cannot read other files, write, attach databases or reach the network. Queries are interrupted after 60 seconds.

Treat SQL results like aggregate results: they rank and locate. Confirm a conclusion with the frame numbers they return and the packet tools.

## Display filters on the index

`wireshark_aggregate` translates a display filter to SQL only when it can reproduce tshark's meaning exactly. Supported:

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

Measured with `scripts/benchmark_capture_index.py` on the deterministic synthetic captures from the analysis-path benchmark (Linux, 4 vCPU, tshark 4.2.2, DuckDB 1.5.6). Each answer was checked against facts recorded while the capture was written; all passed on both paths. The tshark path used a raised scan policy so 1 GB finishes; with the default 30 s timeout it fails, as published in [the 3.1 benchmark](analysis-path-benchmark.md).

| Capture | Packets | tshark aggregate (median per call) | Index build | Index file | Indexed aggregate (median per call) | Speed-up | Break-even |
|---------|--------:|-----------------------------------:|------------:|-----------:|------------------------------------:|---------:|-----------:|
| 100 MB | 156,557 | 4.7 s | 8.2 s | 13 MB | 0.05–0.37 s | 21× | 2nd question |
| 1 GB | 1,561,889 | 52.6 s | 79.6 s (70.4 s tshark, 8.8 s DuckDB) | 147 MB | 0.2–3.6 s | 27× | 2nd question |

Per-call figures cover the five scenarios of the analysis-path benchmark (packet count, top source, DNS query count, distinct user agents, byte sum). Speed-up is the ratio of the five medians summed.

Raw results: [`docs/benchmarks/capture-index-2026-10-19.json`](benchmarks/capture-index-2026-10-19.json).

The build costs about as much as two tshark aggregate calls, so the index pays off from the second capture-wide question on the same file. The indexed path currently streams matching rows into the same Python accumulator the tshark path uses; pushing grouping into DuckDB is the obvious next step if larger captures need it.

## Not yet

- Multi-capture collections (one index across several files with a `capture_id` column).
- Routing `wireshark_extract_fields` and `wireshark_stats_*` through the index.
- Parquet export for use outside the server.
