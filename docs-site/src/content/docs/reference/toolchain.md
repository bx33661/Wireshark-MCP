---
title: Wireshark Toolchain
description: Understand required and optional Wireshark command-line tools.
---

Wireshark MCP requires `tshark`. Other Wireshark suite tools are optional and unlock additional capabilities when present.

## Required

| Tool | Role |
| --- | --- |
| `tshark` | Packet reading, filtering, dissection, protocol fields, statistics, streams, and most analysis operations. |

## Optional suite tools

| Tool | Enables |
| --- | --- |
| `capinfos` | Fast capture metadata inspection. |
| `mergecap` | Merging multiple capture files. |
| `editcap` | Splitting, trimming, deduplication, and timestamp editing. |
| `dumpcap` | Preferred live capture backend. |
| `text2pcap` | Importing hex or ASCII dumps as pcap files. |

## Capability detection

Run:

```sh
wireshark-mcp doctor
wireshark-mcp config
```

`doctor` verifies the local toolchain. `config` shows the command paths that will be visible to MCP clients.

## Minimal install behavior

With only `tshark`, core packet reading, filtering, extraction, statistics, and security analysis remain available. Optional file-editing and capture features become available as their backing tools are detected.
