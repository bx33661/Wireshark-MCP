---
title: Architecture
description: Internal design — concurrency, caching, token optimization, and contextual tool registry.
---

This page documents the performance and architectural decisions in Wireshark MCP that affect how tools execute and how results are delivered to the LLM.

## Concurrent execution

Wireshark MCP uses `asyncio.gather` to run independent tshark queries in parallel wherever possible.

| Tool | Concurrent phases | Speedup |
| --- | --- | --- |
| `wireshark_security_audit` | 6 independent analysis phases (threat intel, credentials, port scan, DNS, cleartext, expert info) | ~3x |
| `wireshark_quick_analysis` | 7 data fetches (file info, protocols, endpoints, conversations, HTTP hosts, DNS, expert info) | ~3x |
| `wireshark_analyze_tcp_health` | 8 health checks (retransmissions, dup ACKs, zero window, etc.) | ~4x |

The security audit runs in two rounds: first a `gather` for file info + protocol hierarchy (needed to inform later phases), then a second `gather` for the 6 independent analysis phases.

## Result cache

A built-in LRU cache avoids re-running identical tshark commands on the same file.

| Property | Value |
| --- | --- |
| Max entries | 128 |
| Max total size | 50 MB |
| TTL | 5 minutes |
| Invalidation | File mtime + size (automatic) |
| Scope | Read-only commands only (detected by `-r` flag) |

Cache behavior:
- Results larger than 25% of max size are not cached (avoids single-entry domination)
- Truncated results are not cached (avoids serving partial data)
- File modification automatically invalidates all cached results for that file
- Write operations (capture, filter_save, editcap) are never cached

## Token optimization

Tool descriptions and output are optimized to minimize token consumption in LLM conversations.

### Docstring budget

All 51 tool docstrings total ~4400 characters (~1100 tokens). A CI test (`test_token_budget.py`) enforces a ceiling of 8000 characters.

### Output format

- Severity indicators use text tags: `[!]` (critical), `[W]` (warning), `[i]` (info), `[OK]` (normal)
- No ASCII box art or decorative borders
- Markdown headers (`###`) for section structure
- Tabular data auto-truncates at 50 rows with a pagination hint

### Smart truncation

The `smart_truncate` utility preserves the head and tail of long outputs, inserting an omission notice in the middle. Stats tools (`endpoints`, `conversations`, `io_graph`, `expert_info`, `service_response_time`) apply this automatically.

## Contextual tool registry

Not all tools are registered at startup. The contextual tool registry activates protocol-specific tools based on what `wireshark_open_file` detects.

Flow:
1. `wireshark_open_file` runs `tshark -z io,phs` to get the protocol hierarchy
2. Detected protocols are matched against `PROTOCOL_TOOL_MAP`
3. Matching tools are recommended to the LLM in the response

This keeps the active tool surface focused and relevant to the current capture.
