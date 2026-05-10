---
title: Statistics and Visualization
description: Use capture-wide statistics to prioritize packet investigation.
---

Statistics tools help decide where to drill down. They should be used before opening individual streams in an unknown capture.

## Core statistics

| Tool | Answers |
| --- | --- |
| `wireshark_stats_protocol_hierarchy` | What protocols are present, and how much traffic belongs to each layer? |
| `wireshark_stats_endpoints` | Which hosts appear, and how much traffic do they send or receive? |
| `wireshark_stats_conversations` | Which host pairs exchange meaningful traffic? |
| `wireshark_stats_expert_info` | What errors, warnings, retransmissions, resets, or malformed packets deserve review? |
| `wireshark_stats_io_graph` | When does traffic volume change over time? |
| `wireshark_stats_service_response_time` | Which protocol operations appear slow or unstable? |

## Visual tools

| Tool | Output |
| --- | --- |
| `wireshark_plot_traffic` | ASCII I/O bar chart |
| `wireshark_plot_protocols` | ASCII protocol hierarchy tree |

## Interpretation rules

- Protocol hierarchy percentages are not exclusive buckets. A packet can contribute to multiple protocol rows across layers.
- Endpoints answer who is present. Conversations answer who is exchanging traffic.
- Expert info is a lead generator. Confirm with packet context and streams before assigning severity.
- I/O graphs show timing, not root cause.

## Common pivots

Start with endpoints and conversations, then pivot to:

- high-byte TCP streams
- DNS-heavy hosts
- hosts with many short failed connections
- bursts around a reported failure time
- unexpected protocols for the environment
