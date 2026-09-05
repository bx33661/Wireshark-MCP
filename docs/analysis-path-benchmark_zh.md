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

这些数值只是当前主机的冒烟基线，不是性能承诺。两者耗时接近，说明在这些极小输入上，tshark 进程成本占主导。每个隔离场景工作进程初始化全新 MCP 服务平均需要 236.44 ms；常驻服务会摊薄这部分启动成本。内存差值主要来自 MCP/Python 依赖的常驻开销。要验证流式聚合在压力下的收益，还需要补充更大的分级抓包样本。

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
