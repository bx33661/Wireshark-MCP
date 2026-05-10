---
title: Incident Response
description: Reconstruct what happened, when it happened, and which systems were involved.
---

Use this workflow when the capture is part of an investigation and the answer needs a timeline, scope, and evidence chain.

## Recommended flow

1. Start with the quick analysis workflow.
2. Use `wireshark_get_file_info` to identify duration and capture boundaries.
3. Map actors with `wireshark_list_ips`, `wireshark_stats_endpoints`, and `wireshark_stats_conversations`.
4. Run security-focused tools to identify IOCs and suspicious traffic.
5. Follow streams that matter for initial contact, credential use, lateral movement, downloads, uploads, or command traffic.
6. Anchor important events with frame numbers and timestamps.

## Interpretation notes

Capture start and end times are not the same as incident start and end times. Say when the capture window is too narrow to prove initial access or final impact.

## Report shape

Include:

- incident timeline
- affected hosts and services
- IOC list
- likely attack narrative
- containment or follow-up recommendations
