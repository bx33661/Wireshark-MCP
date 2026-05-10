---
title: Capture and Editing
description: Capture live traffic and reshape pcap files for focused analysis.
---

Capture and editing tools wrap Wireshark suite utilities when they are available. They make it easier to reduce a capture before deeper analysis.

## Live capture

| Tool | Use |
| --- | --- |
| `wireshark_capture` | Capture live traffic with BPF filters and ring buffer support. |
| `wireshark_list_interfaces` | List available capture interfaces. |

Live capture prefers `dumpcap` when available and falls back to `tshark`.

## File shaping

| Tool | Use |
| --- | --- |
| `wireshark_filter_save` | Save packets matching a filter into a new capture. |
| `wireshark_merge_pcaps` | Merge multiple capture files. |
| `wireshark_editcap_split` | Split by packet count or time interval. |
| `wireshark_editcap_trim` | Trim by timestamp window. |
| `wireshark_editcap_deduplicate` | Remove duplicate packets. |
| `wireshark_editcap_time_shift` | Adjust packet timestamps. |
| `wireshark_text2pcap_import` | Convert hex or ASCII dumps into pcap. |
| `wireshark_verify_ssl_decryption` | Verify TLS decryption with `SSLKEYLOGFILE`. |

## When to reshape captures

Use file shaping when a capture is too large, contains unrelated time windows, or needs to be shared with a narrower scope.

Preserve the original capture when evidence integrity matters. Work from derived copies and document the filter, trim window, split rule, or merge inputs.
