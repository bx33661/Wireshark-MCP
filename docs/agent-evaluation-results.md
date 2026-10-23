# Agent evaluation results — Haiku, October 2026

This page publishes the first complete runs of the [Agent evaluation matrix](agent-evaluation.md): 20 scenarios × 3 analysis paths × 3 trials, collected twice with `claude-haiku-5-5`. It measures how often an Agent answers a packet-analysis question correctly, with evidence the collector actually saw, and how much it spends doing so.

**Short version:** MCP with the `wireshark-mcp` skill passed 87 of 120 cells (73%), MCP without the skill 78 (65%), and native tshark with the CLI skill 68 (57%). The order was the same in both runs. The skill's gain is almost entirely in security scenarios. The CLI path used the fewest tokens.

These are results for one small model. They are not a general claim about every model or client.

## Setup

| Setting | Value |
|---|---|
| Model | `claude-haiku-5-5`, Claude Code `-p`, default reasoning effort |
| Isolation | one fresh process per cell; no user settings, hooks, other MCP servers or skills (`--setting-sources "" --strict-mcp-config --disable-slash-commands --no-session-persistence`) |
| Paths | `without-skill`: MCP `full` profile. `with-skill`: MCP `full` profile plus read access to the copied `wireshark-mcp` skill. `tshark-cli`: only `tshark` and `capinfos`, plus the `tshark-cli-analysis` skill |
| Engine | TShark 4.2.2 on Linux x86_64 |
| Budget | 900 s per cell, Claude Code default turn limit |
| Collector | [`scripts/agent_eval_harness.py`](../scripts/agent_eval_harness.py); every query runs through the collector, so traces are not written by the Agent |
| Completeness | `check_agent_matrix.py`: 180/180 cells, `collection_complete: true` in both runs |
| Cost | about USD 1.30 per 180-cell run |

Run 2 used the collector after the first pilot's fixes. Run 3 added definitions of the five conclusion levels to the cell prompt and fixed overlapping sequence numbers in the T19 capture. Both runs were then rescored with the final rules: T15, T17 and T18 accept `confirmed` as well as `unresolved` (an answer that correctly confirms "the file changed" or "the output was truncated" is right), and the observation rules were widened so the CLI path can produce the same observations as MCP. Rescoring re-derives observations from the saved raw outputs; no model was re-run. The recorded `source_revision` values (`fa55bec…`, `1498087…`) are the collector commits before they were rebased into 3.2; the same changes are in this release.

Raw gate output: [run 2](benchmarks/agent-matrix-2026-10-18-haiku-run2.json), [run 3](benchmarks/agent-matrix-2026-10-18-haiku-run3.json).

## Results

| Path | Run 2 | Run 3 | Total |
|---|---|---|---|
| with-skill (MCP + skill) | 45/60 | 42/60 | **87/120 (73%)** |
| without-skill (MCP) | 38/60 | 40/60 | 78/120 (65%) |
| tshark-cli (native CLI + CLI skill) | 36/60 | 32/60 | 68/120 (57%) |

With 60 cells per path per run, run-to-run noise is about ±4 cells, so the gap between with-skill and without-skill (9 cells over both runs) is suggestive rather than conclusive. The gap to the CLI path is larger and consistent.

### Cost of passing cells (medians)

Only passing cells are counted, so a path is not rewarded for failing fast.

| Path | Run | Tool calls | Elapsed | Input tokens | Output tokens |
|---|---|---|---|---|---|
| with-skill | 2 / 3 | 5 / 4 | 30.6 s / 32.0 s | 114.7k / 112.5k | 4.7k / 4.7k |
| without-skill | 2 / 3 | 4.5 / 4 | 27.3 s / 26.5 s | 90.9k / 94.1k | 3.9k / 3.9k |
| tshark-cli | 2 / 3 | 4 / 4 | 22.5 s / 23.8 s | 66.6k / 65.3k | 4.2k / 4.2k |

The CLI path uses about 58% of the with-skill input tokens; the skill costs about 20% more input than plain MCP.

### By category (both runs)

| Category | Cells per path | with-skill | without-skill | tshark-cli |
|---|---|---|---|---|
| fact | 30 | 28 | 27 | 26 |
| security | 30 | **16** | 9 | 3 |
| coverage | 30 | 25 | 28 | 24 |
| failure handling | 18 | 6 | 3 | 6 |
| troubleshooting | 12 | 12 | 11 | 9 |

Facts and troubleshooting are roughly equal across paths. Security is where the paths separate.

### By scenario (passes out of 6, both runs)

| Scenario | Category | with-skill | without-skill | tshark-cli |
|---|---|---|---|---|
| T01 capture packet count | fact | 6/6 | 6/6 | 6/6 |
| T02 capture primary source | fact | 6/6 | 6/6 | 6/6 |
| T03 DNS query count | fact | 6/6 | 6/6 | 6/6 |
| T04 DNS tunnel candidate | security | 0/6 | 1/6 | 0/6 |
| T05 plaintext credentials | security | 6/6 | 2/6 | 0/6 |
| T06 credential scope | security | 5/6 | 2/6 | 3/6 |
| T07 SYN scan candidate | security | 0/6 | 1/6 | 0/6 |
| T08 threshold-scoped absence | coverage | 6/6 | 6/6 | 4/6 |
| T09 literal comma cardinality | fact | 6/6 | 6/6 | 6/6 |
| T10 empty DNS scope | coverage | 5/6 | 6/6 | 6/6 |
| T11 partial check failure | failure | 3/6 | 2/6 | 1/6 |
| T12 single-sided capture | troubleshooting | 6/6 | 5/6 | 4/6 |
| T13 snaplen answerability | coverage | 4/6 | 6/6 | 3/6 |
| T14 clock uncertainty | troubleshooting | 6/6 | 6/6 | 5/6 |
| T15 output top-k | coverage | 4/6 | 4/6 | 5/6 |
| T16 unknown field | failure | 1/6 | 0/6 | 5/6 |
| T17 changed capture | coverage | 6/6 | 6/6 | 6/6 |
| T18 output budget | failure | 2/6 | 1/6 | 0/6 |
| T19 instructions inside packets | security | 5/6 | 3/6 | 0/6 |
| T20 narrow frame | fact | 4/6 | 3/6 | 2/6 |

## Why cells fail

1. **Calibration on candidate questions.** T04 and T07 ask whether something is a candidate; the model usually answers `likely`. This was the single most common failure (29 cells across paths) and did not change when the prompt defined the levels.
2. **Truncated output cited as evidence.** In T18 the MCP paths often cite a call that hit the output budget as ordinary evidence; the CLI path more often reports `coverage: complete` where only `partial` is supported.
3. **Fact format.** Lists returned where a count is expected (T04 subdomains), or three credentials counted where there are two (T05 on the CLI path).
4. **Coverage after an unknown field.** T16 asks about a field tshark does not know. The CLI path passes 5/6; the MCP paths reach the right conclusion but report `coverage: partial` where the scenario requires `unknown` (11 of 12 cells).

## Known limits

- One model, two runs. A stronger model may narrow or widen the skill's gain.
- The engine was TShark 4.2.2, not the 4.6.9 catalog the CLI skill documents.
- Some judgment facts are derived by one collector rule per scenario. On T19 the CLI path often has no trace observation for "instructions are data", because the injected text appears as hex in raw tshark output; this undercounts the CLI path there.
- Passing requires the right conclusion, the right facts, accepted evidence anchors, allowed coverage and no forbidden claims at once. A partially right answer counts as a fail.

## Reproduce

Follow [Running the matrix with the collector](agent-evaluation.md#running-the-matrix-with-the-collector) with `--model claude-haiku-5-5`, then score with `check_agent_matrix.py` and compare with `compare_agent_traffic.py`.
