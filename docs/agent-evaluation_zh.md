# Agent 流量分析评测

评测分三层：**Skill 结构正确、分析引擎执行正确、Agent 行为正确**。格式校验和单元测试通过，不等于加载 Skill 后模型更准确。没有独立实测数据时，不发布效果提升结论。

## 独立运行

对 `evals/agent-traffic-analysis/scenarios.json` 中的每个场景，分别运行 `without-skill`、`with-skill`、`tshark-cli`，每种至少三次全新上下文。固定模型、推理设置、工具 profile、时间/输出预算、tshark 与插件版本、操作系统、代码与 Skill 修订。真实抓包由 `tests/fixtures/generate_pcaps.py` 生成；`synthetic://` 场景必须注入所述失败或观察条件。

只给 Agent 用户问题、允许的输入和选定的 Skill/工具，不暴露预期答案、评分规则或标准结论。由独立执行器保存真实工具记录；记录目录与 Agent 可写答案分离。保留执行参数、输入 SHA-256、错误、原始结果、扫描与输出覆盖范围。分享时脱敏；原始敏感证据单独保管。

可复用评测提示：

```text
使用指定的抓包分析工作流回答给定问题，只调查提供的输入和范围。
引用执行器收集的真实查询记录、观察到的帧/流、扫描与输出覆盖情况。
明确结论的证据和限制；不要虚构成功执行，也不要为了凑模板追加调查。
```

## 答案与独立记录

`result.example.json` 是合法 JSON 的格式示例，不是实测成绩。用真实的 `trace_id` 与 `trace_sha256` 替换占位值。`execution.status=completed` 表示调查完成；工具调用失败后，调查仍可正确得出 unresolved。调查本身超时或出错的样本不计入通过样本的效率比较。

执行记录包含 `input_id`、真实文件的 `input_sha256` 和 `calls`。每次调用包含唯一 `id`、实际 `query`、执行 `status`、`coverage`、结果文件 `result_file`/`result_sha256`、以及执行器从结果提取的 `observations.facts`、`frames`、`streams`。不要把标准答案字典复制到实测观察里。

答案证据必须通过 `call_id` 关联真实调用，查询须一致，帧/流编号须出现在该调用的观察中。事实还需匹配观察值；完整性不能与调用记录矛盾；错误证据须对应失败调用。当不止一个标签正确时，场景可以列出 `acceptable_conclusions`：T15、T17、T18 同时接受 `confirmed` 和 `unresolved`，因为直接证实了限制本身（top-10 不是全部分组、抓包已变、输出被截断）的回答，其证据足以支持 confirmed。只有场景接受的证据类型计入 `min_anchors`；其他类型可作为辅助证据，但同样按轨迹核对，错误的辅助证据仍会判失败。Agent 自填一段 trace 不构成执行证明。

```sh
python scripts/evaluate_agent_traffic.py runs.json --trace-dir harness-traces --output evaluation.json
python scripts/compare_agent_traffic.py \
  --variant without-skill=baseline.json --variant with-skill=skill.json \
  --trace-dir variant-traces --output comparison.json
```

对比时，`variant-traces/<variant>/` 保存该路径的记录与结果。不指定目录时，读取答案文件旁的 `traces/`。记录中的路径须位于记录目录内，摘要须匹配。评测器拒绝缺失/篡改记录、输入不符、虚构锚点、未执行查询、缺少观察依据、非法指标和调查失败。`--allow-missing` 只用于开发子集。

**摘要验证的是完整性，不是来源真实性或因果正确性。** 仍需可信采集器、实际输出解析和人工复核。禁用短语检查只是粗粒度回归辅助，无法替代对否定句、多语言语义、因果解释和正常反例的判断。

## 指标与发布门禁

按场景报告正确率、过度断言/虚构证据率、错误缺失判断率、重复调用、耗时、Token、峰值 RSS；缺少指标不等于零。效率只比较通过证据与正确性检查的样本，同时展示多次运行的波动，不用一个混合分数掩盖错误。

发布前分别验证：两个 Skill 格式与引用、MCP 调用 schema、TShark 能力目录、客户端发现、wheel 文件、真实引擎命令、超时/输出限额恢复，以及独立 Agent 轨迹。执行原语基准与模型行为评测分开，见[路径对比](analysis-path-benchmark_zh.md)。

## 完整矩阵与重复运行门禁

单个场景出现一次不等于多次独立对照。生成 20 场景 × 3 路径 × 3 次的盲测任务：

```sh
python scripts/check_agent_matrix.py --prepare /absolute/path/to/new-blind-tasks
```

该命令只生成 180 个输入任务，不调用模型，不产生成绩。任务不包含预期事实、结论、评分规则或故障注入配方。`synthetic://` 输入被明确标记为 `requires_fixture_adapter`；采集器须先按场景建立真实输入/失败条件，不能把尚未注入的占位符当作完成。每个任务需在全新上下文中独立执行；不要把整批任务交给同一对话，也不要在同一上下文串行切换是否加载 Skill。

可复用执行提示（配合实际输入、后端和选定 Skill；不给预期答案）：

```text
回答 task.json 中的用户问题，只分析指定的离线输入。
使用任务指定的后端；仅在指定 Skill 时加载它及本问题需要的参考。
返回结论、事实、已执行查询及其观察依据、覆盖范围和实际限制。
执行器独立保存工具原始输出、状态和测量值；答案不要伪造采集记录。
```

执行器为每次调用保存现有 trace 合同，并为每次独立调查记录以下 trace 顶层字段：

- `context_id`：采集器实际观察到的独立会话标识；跨场景/路径/重复不得复用。
- `experiment`：相同的 `model`、`reasoning_effort`、`engine_version`、`plugin_fingerprint`、`platform`、`source_revision`、`budget`；`source_revision` 应包含未提交源码与 Skill 内容的摘要，不能仅记 Git HEAD。`tool_profile` 可按路径不同，但同一路径须固定。无插件时显式写 `none`，不要省略。
- 答案记录含 `variant` 和整数 `trial`（1–3），仍以 `trace_id`/`trace_sha256` 绑定采集器记录。

```sh
python scripts/check_agent_matrix.py \
  --variant without-skill=baseline.json --variant with-skill=skill.json \
  --variant tshark-cli=cli.json --trace-dir variant-traces --output matrix.json
```

缺少任一格、重复编号、复用上下文/trace、实验设置混杂、记录摘要不符或调查未完成时，门禁退出 1。`collection_complete` 只说明比较数据收集完整且一致，不表示所有答案正确，也不证明 Skill 有提升；错误的 baseline 答案必须保留计分。仍需核对真实输入范围、因果结论和采集器可信性。

比较器在通过样本上补充各指标的样本数、缺失数、最小值、中位数、最大值和样本标准差。一个样本的标准差是缺失，不是零；缺失 Token/RSS 不补零。

## 用采集器运行矩阵

`scripts/agent_eval_harness.py` 是矩阵的可信采集器。它生成 9 个 `synthetic://` 输入（DoS 子查询失败、64 字节 snaplen、两台时钟未同步的传感器、15 个源的 top-k、不存在的字段、被替换的抓包、4 KB 输出限额、载荷中的指令、已知帧），为每个场景 × 路径 × 轮次写一个盲测格，并代为执行 Agent 发出的每条查询，因此轨迹由采集器而不是 Agent 写入。它不调用模型，Agent 由你提供。

```sh
EVAL=/absolute/path/to/new-eval-dir
uv run python scripts/agent_eval_harness.py prepare "$EVAL" \
  --model <model-id> --reasoning-effort <setting> --budget "30 min, 60 tool calls per cell"
```

每个 `cells/<scenario>--<variant>--t<n>/` 含 `task.json` 和 `prompt.md`。提示要求 Agent 通过 `agent_eval_harness.py call --cell <cell> {mcp TOOL JSON | mcp-list | cmd tshark|capinfos ... | hash FILE}` 执行全部查询，并写出 `answer.json`。两条 MCP 路径在进程内使用 `full` 档位；CLI 路径只能运行 `tshark` 与 `capinfos`。输入参数必须是本格自己的输入。期望事实存放在 `.collector/cells.json`，不能让 Agent 读到。

`drive` 对每个尚未作答的格各启动一次 Agent 命令，每次都是新进程，工作目录为该格。模板中替换 `{prompt_file}`、`{cell}`、`{harness}`。以 Claude Code 为例，把隔离参数放进一个小包装脚本，确保用户设置、hooks、MCP 服务器和技能都不会带进来；只允许读取复制出的 skills，只允许写本格的答案（权限路径用绝对路径，因此绝对路径前再加一个 `/`；写文件受 `Edit` 规则约束）：

```sh
cat > agent.sh <<'SH'
#!/bin/sh
# agent.sh PROMPT_FILE CELL EVAL_ROOT
exec claude -p "$(cat "$1")" --model <model-id> --output-format json \
  --setting-sources "" --strict-mcp-config --disable-slash-commands --no-session-persistence \
  --tools Bash Read Write \
  --allowedTools "Bash(*agent_eval_harness.py call*)" "Read(/$3/skills/**)" "Edit(/$2/answer.json)"
SH
chmod +x agent.sh
uv run python scripts/agent_eval_harness.py drive "$EVAL" --agent "$PWD/agent.sh {prompt_file} {cell} $EVAL"
```

采集器规则修改后，`reobserve "$EVAL"` 会用保留的原始结果重新推导每次调用的观测，并逐个核对结果摘要；之后需重新运行 `finalize`。`--only T05_` 只跑名称匹配的格；中断后重跑会跳过已作答的格。Agent 的 JSON 输出含 `usage` 时记录 Token。之后：

```sh
uv run python scripts/agent_eval_harness.py finalize "$EVAL" --output "$EVAL/runs"
uv run python scripts/check_agent_matrix.py --variant without-skill="$EVAL/runs/without-skill.json" \
  --variant with-skill="$EVAL/runs/with-skill.json" --variant tshark-cli="$EVAL/runs/tshark-cli.json" \
  --trace-dir "$EVAL/.collector/traces" --output "$EVAL/matrix.json"
uv run python scripts/compare_agent_traffic.py --variant without-skill="$EVAL/runs/without-skill.json" \
  --variant with-skill="$EVAL/runs/with-skill.json" --variant tshark-cli="$EVAL/runs/tshark-cli.json" \
  --trace-dir "$EVAL/.collector/traces" --output "$EVAL/comparison.json"
```

发布结果时需要一并说明的局限：

- MCP 路径经采集器的命令包装调用服务端，不是原生 MCP 客户端连接，因此不衡量真实客户端的工具发现行为。
- 提示列出了答案需填写的事实名（不含值），比真实用户给的结构更多。
- 观测由规则推导：完成的调用输出中出现该值即视为观测到数值事实；每个判断类事实各有一条场景规则。先屏蔽输入路径，文件名不能当作证据。分歧需人工复核。
- 隔离依赖 Agent 客户端的权限设置；若 Agent 被允许读取 `.collector/`，采集器无法阻止。

本轮工程记录：采集器及其端到端测试已就绪，180 格完整模型实验尚未执行。
