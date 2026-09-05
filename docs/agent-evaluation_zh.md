# Agent 流量分析评测

这套评测用于判断 Agent 能否正确回答流量问题并守住证据边界。它可以在相同任务上比较 Wireshark MCP Skill、无 Skill 和直接 tshark 三种方式，不使用一个混合总分掩盖准确性问题。

## 数据集

`evals/agent-traffic-analysis/scenarios.json` 包含 12 个事实查询、安全分析、失败处理、覆盖范围和故障排查任务。确定性抓包由 `tests/fixtures/generate_pcaps.py` 生成；合成失败场景需要按场景描述注入失败，不能替换成普通抓包。

每个变体都应在全新 Agent 上下文中运行全部场景，并固定模型、推理设置、工具 Profile、时间预算和输入抓包。比较稳定性时至少重复三轮。建议使用 `without-skill`、`with-skill` 和按需加入的 `tshark-cli` 变体。

不要把预期事实、禁止结论或评分规则交给被测 Agent。结构化记录最终答案和真实工具调用；只提出一条命令不算已经取得证据。

## 结果格式

参考 `evals/agent-traffic-analysis/result.example.json`。`facts` 保存可机器核验的观察值；`conclusion` 使用 `confirmed`、`likely`、`candidate`、`unresolved` 或 `no_match`。证据应包含类型和实际执行的查询；帧与流证据还应保存观察到的编号。覆盖范围描述实际完成的扫描。

调用数、耗时、峰值 RSS 和 Token 单独统计。只有准确性、证据和覆盖范围通过后，效率改善才有意义。执行层与 Agent 层的采集、对比方法见 [MCP 与原生 tshark 对照基准](analysis-path-benchmark_zh.md)。

## 评分

```sh
python scripts/evaluate_agent_traffic.py path/to/results.json
```

提交结果失败或套件不完整时，命令返回非零状态。开发期间可使用 `--allow-missing` 评估部分场景，使用 `--output report.json` 保存报告。

评分器检查预期事实、结论校准、扫描覆盖、证据锚点、禁止性断言，以及“部分扫描不能支持抓包级否定结论”这条规则。因果解释是否被查询真正支持、是否检查了现实的替代解释，仍需人工复核。

发布对比结果时，应报告每个场景的通过率和多轮波动。效率只在通过的运行之间比较，同时记录模型、Skill 修订、MCP 修订、tshark 版本、操作系统和代码提交。
