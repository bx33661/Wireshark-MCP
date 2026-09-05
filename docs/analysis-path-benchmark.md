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

These numbers are a host-specific smoke baseline, not a performance guarantee. The similar latency shows tshark process cost dominates these tiny inputs. Preparing a fresh MCP server took 236.44 ms on average per isolated scenario worker; a persistent server amortizes that startup. The memory difference largely reflects the resident MCP/Python dependency stack. Larger fixture classes are still needed to measure streaming behavior under load.

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

Do not publish a winner until every variant covers all 12 scenarios. Review causal explanations and realistic alternatives manually; the deterministic scorer cannot establish whether an Agent's reasoning was supported merely from matching final fields.
