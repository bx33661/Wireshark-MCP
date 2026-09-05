# Prompt Engineering

Wireshark MCP works best when the model is told to:

- start broad, then drill down
- verify with tools instead of guessing
- use `wireshark_open_file` first
- produce a structured report

## Security Audit

```text
Your task is to perform a comprehensive security audit on <file.pcap>.

1. Start with wireshark_open_file for capture-wide context and recommended tools
2. Run wireshark_quick_analysis for a broad automated first pass
3. Use wireshark_aggregate for capture-wide counts and distributions. For example,
   group DNS queries by ip.src and count distinct dns.qry.name values.
4. For any findings, drill deeper:
   - Use wireshark_follow_stream to inspect suspicious sessions
   - Use wireshark_extract_credentials to check for cleartext passwords
   - Correlate extracted DNS, TLS, and HTTP indicators with the supplied IOC
5. NEVER guess display filter syntax — use the wireshark://reference/display-filters resource
6. NEVER fabricate packet data — always verify with tools
7. Write a structured report to report.md with risk scores (0-100)
```

## CTF Challenge

```text
Your task is to solve a CTF network challenge using <file.pcap>.

1. Start with wireshark_open_file then wireshark_quick_analysis for overview
2. Look for flags using wireshark_search_packets with patterns like "flag{", "CTF{"
3. Use wireshark_aggregate to rank protocols, endpoints, streams, or content-bearing fields before opening them
4. Follow relevant streams with wireshark_follow_stream; use ascii, hex, or raw output as the protocol requires
5. Use wireshark_get_packet_bytes and wireshark_get_packet_details to preserve exact frame-level evidence
6. Export embedded files with wireshark_export_objects (HTTP, SMB, TFTP)
7. If external decoding is needed, record the source frame or stream and the exact transformation
8. Document the investigation path and recovered flag in report.md
```

## Performance Troubleshooting

```text
Your task is to diagnose network performance issues in <file.pcap>.

1. Start with wireshark_open_file for capture-wide context and recommended tools
2. Use wireshark_analyze_tcp_health to check retransmissions, zero windows, RSTs
3. Use wireshark_stats_io_graph to find traffic spikes or drops
4. Use wireshark_aggregate with time_bucket_seconds to quantify when affected hosts or errors peak
5. Use wireshark_stats_service_response_time for HTTP/DNS latency
6. Use wireshark_stats_expert_info for anomalies
7. Identify top talkers with wireshark_stats_endpoints
8. Write findings to report.md with specific timestamps and recommendations
```

## Usage Tips

- Start with `wireshark_open_file` for capture-wide context and tool recommendations
- Use the built-in `security_audit` prompt when the client exposes MCP prompts; use `wireshark_quick_analysis` for a broad tool-driven first pass
- Use `wireshark_aggregate` for totals, distributions, distinct cardinality, top-k, and time buckets
- Use paginated extraction for individual rows, not for capture-wide estimates
- Never guess filter syntax; use `wireshark://reference/display-filters`
- Anchor conclusions in exact filters, frame numbers, stream indexes, and tool output
