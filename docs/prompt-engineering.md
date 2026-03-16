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
2. Run wireshark_security_audit for automated 8-phase analysis
3. For any findings, drill deeper:
   - Use wireshark_follow_stream to inspect suspicious sessions
   - Use wireshark_extract_credentials to check for cleartext passwords
   - Use wireshark_check_threats to validate IOCs against threat intel
4. NEVER guess display filter syntax — use the wireshark://reference/display-filters resource
5. NEVER fabricate packet data — always verify with tools
6. Write a structured report to report.md with risk scores (0-100)
```

## CTF Challenge

```text
Your task is to solve a CTF network challenge using <file.pcap>.

1. Start with wireshark_open_file then wireshark_quick_analysis for overview
2. Look for flags using wireshark_search_packets with patterns like "flag{", "CTF{"
3. Check every stream with wireshark_follow_stream — flags often hide in HTTP bodies or TCP data
4. Use wireshark_decode_payload to decode Base64, hex, URL-encoded, or gzipped data
5. Export embedded files with wireshark_export_objects (HTTP, SMB, TFTP)
6. NEVER base64-decode or hex-decode yourself — always use wireshark_decode_payload
7. Document all steps taken and flag found in report.md
```

## Performance Troubleshooting

```text
Your task is to diagnose network performance issues in <file.pcap>.

1. Start with wireshark_open_file for capture-wide context and recommended tools
2. Use wireshark_analyze_tcp_health to check retransmissions, zero windows, RSTs
3. Use wireshark_stats_io_graph to find traffic spikes or drops
4. Use wireshark_stats_service_response_time for HTTP/DNS latency
5. Use wireshark_stats_expert_info for anomalies
6. Identify top talkers with wireshark_stats_endpoints
7. Write findings to report.md with specific timestamps and recommendations
```

## Usage Tips

- Start with `wireshark_open_file` for capture-wide context and tool recommendations
- Use the agentic tools (`security_audit`, `quick_analysis`) for broad analysis, then drill down
- Never guess filter syntax; use `wireshark://reference/display-filters`
- Never decode payloads manually; use `wireshark_decode_payload`
