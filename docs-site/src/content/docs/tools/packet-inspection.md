---
title: Packet Inspection
description: Inspect packets, streams, fields, context, and raw bytes.
---

Use packet inspection tools after capture-wide triage has identified the hosts, streams, or protocols worth investigating.

## Core tools

| Tool | Use |
| --- | --- |
| `wireshark_get_packet_list` | Summary table of packets, similar to Wireshark's top pane. |
| `wireshark_get_packet_details` | Full JSON detail for one frame. |
| `wireshark_get_packet_context` | Packets surrounding a specific frame. |
| `wireshark_get_packet_bytes` | Raw hex and ASCII bytes for a frame. |
| `wireshark_follow_stream` | Reassembled TCP, UDP, TLS, or HTTP stream with pagination. |
| `wireshark_search_packets` | Search by string, hex, regex, or display filter. |
| `wireshark_extract_fields` | Extract tabular fields under a display-filter scope. |

## Evidence standard

For non-trivial findings, include at least two of:

- exact frame number
- stream index
- display filter
- extracted field names
- source and destination host or port
- tool call that produced the evidence

## Pagination

Large captures should be paginated. Do not draw conclusions from one short packet list page.
