# Answer and handoff shapes

Use only the detail needed for the user's question. Answer in the user's language.

## Direct question

State the answer and scope, give the exact query and supporting count/frame/stream, then mention any material limitation. No full report is required for a single count or field lookup.

## Investigation

1. Assessment: what the capture establishes and the confidence of causal/security claims.
2. Scope: capture identity, observed time range, relevant filter, capture vantage point if known, and scan completeness.
3. Findings: observation → packet/stream or aggregate evidence → interpretation → counter-explanation → remaining gap.
4. Next action: only a query or external observation that could change the conclusion. Omit when the task is complete.

Example evidence record (fill from actual output; never copy sample numbers):

```text
Claim:
Confidence / impact:
Capture and time basis:
Executed tool call or command:
Fields and observed values (secrets masked):
Frame / stream, or aggregate denominator:
Coverage and output limits:
Alternative explanation checked:
Remaining gap:
```

## Resuming or handing off

Keep a compact ledger: task; capture identity and decoding settings; scoped queries already completed; findings and anchors; rejected explanations; failed queries and why; unresolved question; next query and expected decision. This avoids repeating broad scans after context loss.

Distinguish an observed result from a command proposed for later execution. Never fabricate packet anchors or label an unexecuted validation as passed.
