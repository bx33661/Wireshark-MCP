---
title: Evidence Standard
description: Write packet-analysis findings that can be reproduced.
---

Wireshark MCP reports should separate facts from interpretation. Facts come from tool output. Interpretation explains what the facts mean and how confident the analyst is.

## Confidence labels

| Label | Meaning |
| --- | --- |
| `confirmed` | Packet evidence directly supports the claim. |
| `likely` | Evidence strongly supports the claim, but capture limits prevent full proof. |
| `possible` | The behavior is suspicious or relevant, but common benign explanations remain. |
| `unresolved` | The capture does not contain enough evidence to decide. |

## Required evidence

For non-trivial findings, include at least two of:

- the tool call that surfaced the lead
- exact host, port, protocol, or field names
- stream index or frame number
- display filter or extraction query
- short explanation of why the signal matters

## Good finding shape

```text
Finding: Cleartext FTP credentials were observed.
Confidence: confirmed
Evidence: wireshark_extract_credentials reported FTP USER/PASS in stream 4.
Frames: 182, 185
Impact: Credentials may be recoverable by anyone with access to the capture path.
Next step: Rotate the exposed account and check whether the same account appears in later sessions.
```

## Avoid these mistakes

- calling uncommon traffic malicious without packet evidence
- calling encrypted traffic benign because payloads are hidden
- over-trusting a single heuristic
- reporting expert info as a verdict
- omitting capture vantage-point limitations
- failing to state what evidence is missing
