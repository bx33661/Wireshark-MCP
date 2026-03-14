# Report Template

Adapt this template to the user's goal. Keep it short unless the user asks for depth.

```markdown
# Packet Analysis Report

## Scope
- Capture: `<path>`
- Goal: `<triage | security | incident-response | troubleshoot | ctf>`
- Assumptions: `<none>` or `<brief list>`

## Executive Summary
- Assessment: `<one-paragraph summary>`
- Confidence: `<confirmed | likely | possible | unresolved>`
- Severity or Impact: `<critical | high | medium | low | informational>`

## Environment Snapshot
- Capture duration:
- Main protocols:
- Top talkers:
- Most relevant conversations:

## Key Findings
| ID | Severity or Impact | Confidence | Finding | Evidence |
|---|---|---|---|---|
| F1 | High | Likely | Suspicious DNS beaconing | `wireshark_detect_dns_tunnel`, stream/filter details |

## Detailed Findings
### F1. `<finding title>`
- What we observed:
- Evidence:
- Interpretation:
- Severity or impact:
- Counterpoints:
- Next filter, stream, or frame:

## Gaps
- What could not be verified from this capture
- What additional packets, logs, or context would change confidence

## Recommended Next Steps
- `<exact filter or stream to inspect>`
- `<additional capture or validation to run>`

## Analyst Notes
- Reproducibility: `<how another analyst can reproduce the finding>`
- Caveats: `<capture vantage point, decryption limits, missing packets, or none>`
```
