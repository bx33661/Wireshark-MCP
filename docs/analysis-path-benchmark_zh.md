# MCP 与原生 tshark 对照基准

[English](analysis-path-benchmark.md)

这项对比分为两层，因为执行开销与 Agent 行为回答的是不同问题。

## 可复现执行基线

在隔离工作进程中，分别通过 `wireshark_aggregate` 和直接 tshark 字段提取执行五项等价事实查询：

```sh
python scripts/benchmark_analysis_paths.py run --iterations 10 --warmup 2 --output benchmark.json
```

场景包括包数、主要源地址、过滤后的 DNS 查询数、带字面逗号字段的去重数量，以及帧字节数值聚合。每项结果都与确定性 PCAP 事实核对，预热完成后才开始计时。在 POSIX 系统上，报告分别记录工作进程和 tshark 的峰值 RSS，并给出两个独立峰值相加的保守估算；Python 标准库在 Windows 上没有等价的逐进程指标，因此该平台的内存值明确为空。

这项基线只测执行原语，不涉及 LLM、证据选择、结论校准或 Token。微型合成抓包主要反映固定的进程与运行时开销，不能证明大抓包吞吐量或内存伸缩表现。

本机 macOS arm64、Python 3.13.14、tshark 4.6.6 环境中，5 个场景各预热 2 次、计时 10 次，结果如下：

| 路径 | 正确场景 | 错误率 | 平均耗时 | p50 | p95 | 最大组合峰值 RSS 估算 |
|------|----------|--------|----------|-----|-----|-----------------------|
| MCP 聚合 | 5/5 | 0% | 69.71 ms | 68.28 ms | 73.88 ms | 169.0 MB |
| 原生 tshark CLI | 5/5 | 0% | 68.06 ms | 67.87 ms | 69.98 ms | 124.5 MB |

这些数值只是当前主机的冒烟基线，不是性能承诺。两者耗时接近，说明在这些极小输入上，tshark 进程成本占主导。每个隔离场景工作进程初始化全新 MCP 服务平均需要 236.44 ms；常驻服务会摊薄这部分启动成本。内存差值主要来自 MCP/Python 依赖的常驻开销。下方的伸缩档位测量了负载下的表现。

## 大抓包伸缩档位

`--scale` 增加 10 MB、100 MB、1 GB 三档确定性合成抓包。生成器按固定种子写入 DNS、HTTP、UDP 混合流量，并在写入时同步记录每项预期事实，因此大档位无需慢速的参考解析也能做准确率门控。MCP 结果覆盖不完整即判失败。抓包缓存在 `--work-dir` 中，大小与清单一致时直接复用。

```sh
python scripts/benchmark_analysis_paths.py run --scale 10 --scale 100 --scale-iterations 3 --scale-warmup 1 --work-dir /tmp/wm-bench --output scaling.json
WIRESHARK_MCP_AGGREGATE_SCAN_LIMIT=2000000 WIRESHARK_MCP_AGGREGATE_TIMEOUT=600 \
  python scripts/benchmark_analysis_paths.py run --iterations 1 --warmup 0 --scale 1000 --scale-iterations 1 --scale-warmup 0 --work-dir /tmp/wm-bench --output scaling-1g.json
```

2026-10-17 在 Linux x86_64 云端容器、Python 3.13.16、tshark 4.2.2 上的结果（原始报告见 [docs/benchmarks/](benchmarks/)）。fixture 档预热 2 次、计时 10 次；10 MB 与 100 MB 预热 1 次、计时 3 次；1 GB 每个场景跑 1 次。

| 档位 | 包数 | 路径 | 正确 | 平均 | p50 | p95 | 最大组合峰值 RSS |
|------|-----:|------|:----:|-----:|----:|----:|-----------------:|
| fixture | 3–27 | MCP 聚合 | 5/5 | 155 ms | 152 ms | 174 ms | 226 MB |
| fixture | 3–27 | 原生 tshark CLI | 5/5 | 145 ms | 144 ms | 161 ms | 177 MB |
| 10 MB | 15,637 | MCP 聚合 | 5/5 | 0.66 s | 0.65 s | 0.80 s | 241 MB |
| 10 MB | 15,637 | 原生 tshark CLI | 5/5 | 0.63 s | 0.63 s | 0.69 s | 196 MB |
| 100 MB | 156,557 | MCP 聚合 | 5/5 | 5.43 s | 5.39 s | 6.04 s | 362 MB |
| 100 MB | 156,557 | 原生 tshark CLI | 5/5 | 5.05 s | 4.99 s | 5.54 s | 364 MB |
| 1 GB，默认策略 | 1,561,889 | MCP 聚合 | 0/5 | 30 秒超时 | | | |
| 1 GB，默认策略 | 1,561,889 | 原生 tshark CLI | 5/5 | 50.9 s | 51.2 s | 54.2 s | 2,016 MB |
| 1 GB，调大策略 | 1,561,889 | MCP 聚合 | 5/5 | 50.1 s | 50.9 s | 53.1 s | 1,559 MB |
| 1 GB，调大策略 | 1,561,889 | 原生 tshark CLI | 5/5 | 48.8 s | 49.9 s | 52.6 s | 2,017 MB |

数据说明：

- 两条路径的耗时都由 tshark 的单次解析决定。10–100 MB 时 MCP 多出约 5–8%，1 GB 时约 3%，主要是 JSON 信封与 Python 逐行归约；每个隔离工作进程新建 MCP 服务约需 0.7–0.8 秒。
- `wireshark_aggregate` 逐行流式归约，MCP 工作进程在各档位都稳定在约 74 MB。本基准的 CLI 工作进程用 `subprocess.run` 缓冲 tshark 全部输出，1 GB 时达到 533 MB；流式 shell 管道不会有这部分开销。tshark 自身在 1 GB 时两条路径都涨到约 1.48 GB，是峰值内存的主体。
- 默认策略（30 秒超时、1,000,000 行）下，1 GB 抓包无法通过 MCP 完成：调用超时并返回错误，而不是把部分结果当成完整答案。即使延长超时，156 万个包也超过默认行数上限，会报告覆盖不完整。调大 3.1 新增的 `WIRESHARK_MCP_AGGREGATE_TIMEOUT` 和 `WIRESHARK_MCP_AGGREGATE_SCAN_LIMIT` 后，同样的查询全部完成且正确。
- 每个查询都要重新解析整个抓包，因此在 1 GB 上问五个问题，两条路径都要约四分钟。可选的[抓包索引](capture-index_zh.md)消除了这部分成本：构建一次之后，1 GB 上同样五个问题每个都远低于一秒。

以上是特定主机上合成流量的测量结果，不是性能承诺。真实抓包若包含 TLS、HTTP/2、SMB 等较重的解析器，单位字节耗时会更高。

## 独立 Agent 对比

按照 `evals/agent-traffic-analysis/result.example.json`，每个场景、每条路径至少采集三次全新上下文运行。记录 `execution.status`、工具调用数、耗时、峰值 RSS、输入 Token 和输出 Token，并固定模型、推理设置、时间预算、操作系统、tshark 版本和代码修订。

先分别评分：

```sh
python scripts/evaluate_agent_traffic.py mcp-results.json
python scripts/evaluate_agent_traffic.py cli-results.json
```

再生成对比：

```sh
python scripts/compare_agent_traffic.py \
  --variant mcp=mcp-results.json \
  --variant tshark-cli=cli-results.json \
  --output comparison.json
```

只有通过事实、证据、覆盖范围和结论校准检查的运行才进入效率统计；执行错误率单独报告。这样可以避免“快速但没有证据的答案”在汇总中显得更好。

两个变体都覆盖全部 12 个场景前，不应宣布哪条路径胜出。因果解释是否真的得到查询支持、是否考虑现实反例，仍需人工复核，不能只根据最终字段匹配交给评分器判断。
