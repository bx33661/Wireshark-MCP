---
title: Quick Analysis
description: Build a capture-wide picture before inspecting individual packets.
---

Use this workflow when the capture is unknown and you need fast situational awareness.

## Recommended flow

1. `wireshark_open_file`
2. `wireshark_quick_analysis`
3. `wireshark_stats_protocol_hierarchy`
4. `wireshark_stats_endpoints`
5. `wireshark_stats_conversations`
6. `wireshark_plot_traffic` or `wireshark_stats_io_graph` if timing matters
7. `wireshark_follow_stream` for the most relevant conversations

## What to look for

- Dominant protocols and unexpected protocol families.
- Top talkers by packets and bytes.
- Long-lived or high-volume conversations.
- Broadcast, multicast, or asymmetric traffic that changes interpretation.
- Timing bursts that align with a user-reported issue or incident window.

## Report shape

Include:

- capture duration and file context
- top protocols
- top endpoints and conversations
- obvious anomalies
- three best next filters, streams, or hosts to inspect

Do not treat the first page of packets as representative. Start broad, then narrow.
