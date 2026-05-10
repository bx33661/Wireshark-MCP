---
title: Security Detection
description: Use dedicated detectors for scans, floods, tunnels, spoofing, credentials, and threat intel.
---

## Detection tools

| Tool | Looks for |
| --- | --- |
| `wireshark_detect_port_scan` | SYN, FIN, NULL, and Xmas scan patterns. |
| `wireshark_detect_dos_attack` | SYN flood, ICMP flood, UDP flood, and DNS amplification patterns. |
| `wireshark_detect_dns_tunnel` | Long queries, TXT abuse, and high-entropy subdomains. |
| `wireshark_detect_arp_spoofing` | Duplicate IP-to-MAC mapping and gratuitous ARP floods. |
| `wireshark_check_threats` | URLhaus threat intelligence matches. |
| `wireshark_analyze_suspicious_traffic` | Cross-signal anomaly analysis. |
| `wireshark_extract_credentials` | Cleartext credentials in protocols such as HTTP Basic, FTP, and Telnet. |

## Treat detectors as leads

Detector output is a starting point. Confirm important findings with packet context, streams, fields, and timing evidence.

## Avoid overclaiming

Long DNS queries, retransmissions, resets, and unusual ports can be benign. Use confidence labels and document what would be needed to prove intent.
