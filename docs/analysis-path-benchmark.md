# MCP and native tshark comparison

[中文版](analysis-path-benchmark_zh.md)

The comparison has two layers because engine overhead and Agent behavior answer different questions.

## Reproducible engine baseline

Run five equivalent facts through `wireshark_aggregate` and direct tshark field extraction in isolated workers:

```sh
python scripts/benchmark_analysis_paths.py run --iterations 10 --warmup 2 --output benchmark.json
```

The cases cover packet count, busiest source, filtered DNS count, literal-comma cardinality, and numeric frame-byte reduction. Each result is checked against a deterministic fixture fact. Timed iterations begin after warm-up. On POSIX, the report records worker and tshark peak RSS and a conservative sum of their independently observed peaks; Windows reports memory as unavailable because the standard library does not expose an equivalent per-worker measure.

This baseline measures execution primitives. It does not exercise an LLM, evidence selection, conclusion calibration, or token usage. Small synthetic captures mainly expose fixed process/runtime overhead; they do not establish large-capture throughput or memory scaling.

On the local macOS arm64 validation host with Python 3.13.14 and tshark 4.6.6, five scenarios with two warm-ups and ten measured iterations each produced:

| Path | Correct scenarios | Error rate | Mean | p50 | p95 | Maximum combined peak RSS estimate |
|------|-------------------|------------|------|-----|-----|-----------------------------------|
| MCP aggregate | 5/5 | 0% | 69.71 ms | 68.28 ms | 73.88 ms | 169.0 MB |
| Native tshark CLI | 5/5 | 0% | 68.06 ms | 67.87 ms | 69.98 ms | 124.5 MB |

These numbers are a host-specific smoke baseline, not a performance guarantee. The similar latency shows tshark process cost dominates these tiny inputs. Preparing a fresh MCP server took 236.44 ms on average per isolated scenario worker; a persistent server amortizes that startup. The memory difference largely reflects the resident MCP/Python dependency stack. The scaling tiers below measure behavior under load.

## Large-capture scaling

`--scale` adds deterministic synthetic captures of 10 MB, 100 MB or 1 GB. The generator writes a seeded mix of DNS, HTTP and UDP traffic and records every expected fact while writing, so large tiers stay accuracy-gated without a slow reference parse. An MCP result with partial coverage counts as a failure. Captures are cached in `--work-dir` and reused when their size matches the manifest.

```sh
python scripts/benchmark_analysis_paths.py run --scale 10 --scale 100 --scale-iterations 3 --scale-warmup 1 --work-dir /tmp/wm-bench --output scaling.json
WIRESHARK_MCP_AGGREGATE_SCAN_LIMIT=2000000 WIRESHARK_MCP_AGGREGATE_TIMEOUT=600 \
  python scripts/benchmark_analysis_paths.py run --iterations 1 --warmup 0 --scale 1000 --scale-iterations 1 --scale-warmup 0 --work-dir /tmp/wm-bench --output scaling-1g.json
```

Results from 2026-10-17 on a Linux x86_64 cloud container with Python 3.13.16 and tshark 4.2.2 (raw reports in [docs/benchmarks/](benchmarks/)). The fixture tier ran 2 warm-ups and 10 iterations, 10 MB and 100 MB ran 1 warm-up and 3 iterations, and 1 GB ran once per scenario.

| Tier | Packets | Path | Correct | Mean | p50 | p95 | Max combined peak RSS |
|------|--------:|------|:-------:|-----:|----:|----:|----------------------:|
| Fixture | 3–27 | MCP aggregate | 5/5 | 155 ms | 152 ms | 174 ms | 226 MB |
| Fixture | 3–27 | Native tshark CLI | 5/5 | 145 ms | 144 ms | 161 ms | 177 MB |
| 10 MB | 15,637 | MCP aggregate | 5/5 | 0.66 s | 0.65 s | 0.80 s | 241 MB |
| 10 MB | 15,637 | Native tshark CLI | 5/5 | 0.63 s | 0.63 s | 0.69 s | 196 MB |
| 100 MB | 156,557 | MCP aggregate | 5/5 | 5.43 s | 5.39 s | 6.04 s | 362 MB |
| 100 MB | 156,557 | Native tshark CLI | 5/5 | 5.05 s | 4.99 s | 5.54 s | 364 MB |
| 1 GB, default policy | 1,561,889 | MCP aggregate | 0/5 | timed out at 30 s | | | |
| 1 GB, default policy | 1,561,889 | Native tshark CLI | 5/5 | 50.9 s | 51.2 s | 54.2 s | 2,016 MB |
| 1 GB, tuned policy | 1,561,889 | MCP aggregate | 5/5 | 50.1 s | 50.9 s | 53.1 s | 1,559 MB |
| 1 GB, tuned policy | 1,561,889 | Native tshark CLI | 5/5 | 48.8 s | 49.9 s | 52.6 s | 2,017 MB |

What the numbers show:

- Latency is tshark's single dissection pass on both paths. MCP adds roughly 5–8% at 10–100 MB and about 3% at 1 GB, mostly JSON envelope and Python row reduction; fresh MCP server setup was about 0.7–0.8 s per isolated worker.
- MCP's worker stayed at about 74 MB at every size because `wireshark_aggregate` streams rows into reducers. The CLI worker in this benchmark buffers tshark's whole stdout (`subprocess.run`), reaching 533 MB at 1 GB; a shell pipeline that streams would not pay that. tshark itself grew to about 1.48 GB at 1 GB on both paths, which dominates peak memory.
- With the default policy (30 s timeout, 1,000,000 rows), a 1 GB capture does not finish through MCP: the call times out and returns an error rather than a partial answer presented as complete. Even with a longer timeout, 1.56 million packets exceed the default row ceiling and would report partial coverage. Raising `WIRESHARK_MCP_AGGREGATE_TIMEOUT` and `WIRESHARK_MCP_AGGREGATE_SCAN_LIMIT` (3.1) makes the same queries complete and correct.
- Every query re-parses the whole capture, so five questions on 1 GB cost about four minutes on either path. The optional [capture index](capture-index.md) removes this cost: after one build, the same five questions take well under a second each at 1 GB.

These are host-specific measurements on synthetic traffic, not performance guarantees. Real captures with heavier dissectors (TLS, HTTP/2, SMB) will be slower per byte.

## Independent Agent comparison

Collect at least three fresh-context runs per scenario and path using the format in `evals/agent-traffic-analysis/result.example.json`. Record `execution.status`, tool calls, elapsed time, peak RSS, input tokens, and output tokens. Keep model, reasoning setting, time budget, operating system, tshark version, and repository revision fixed.

Score each set first:

```sh
python scripts/evaluate_agent_traffic.py mcp-results.json
python scripts/evaluate_agent_traffic.py cli-results.json
```

Then compare them:

```sh
python scripts/compare_agent_traffic.py \
  --variant mcp=mcp-results.json \
  --variant tshark-cli=cli-results.json \
  --output comparison.json
```

Efficiency statistics include only runs that pass fact, evidence, coverage, and conclusion-calibration checks. Execution errors remain a separate rate. This prevents a fast unsupported answer from appearing better than a slower correct one.

Do not publish a winner until every variant covers all manifest scenarios. Review causal explanations and realistic alternatives manually; the deterministic scorer cannot establish whether an Agent's reasoning was supported merely from matching final fields.
