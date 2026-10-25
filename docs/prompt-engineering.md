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

## Large Captures and Capture Sets

Needs the optional `[index]` extra (see the [capture index guide](capture-index.md)).

```text
Your task is to find what changed between <day1.pcapng> and <day2.pcapng>.

1. Build an index for both with wireshark_index(pcap_file=<day1>, more_files=<day2>)
2. Run wireshark_index action="diff" with day1 as baseline and day2 as comparison;
   list new hosts, conversations, DNS names, TLS SNI and JA3/JA4 values
3. For each new item, run wireshark_index action="timeline" with a display_filter on it
   to get its first frame and time
4. Use wireshark_aggregate for counts; check that coverage.source is "index"
5. Confirm every item you report with wireshark_get_packet_details on the frame
   numbers the index returned. The index locates evidence; packet tools prove it
6. Write a table of new items with first frame, time and verification to report.md
```

## Long Investigations with a Case File

Case files need `WIRESHARK_MCP_ALLOWED_DIRS` (see [Findings and cases](findings-and-cases.md)).

```text
Investigate suspected beaconing in <file.pcap> and keep the work in a case file.

1. Create a case with wireshark_case action="create" naming the capture
2. Run wireshark_detect_beaconing and wireshark_detect_dns_tunnel; record each JSON
   result with wireshark_case action="record"
3. Verify each finding with wireshark_follow_stream or wireshark_get_packet_details,
   then set a verdict on its id: confirmed, dismissed or open, with the reason
4. If the session is interrupted, resume from wireshark_case action="show"
5. Finish with wireshark_case action="report" and save it as report.md
```

## Usage Tips

- Start with `wireshark_open_file` for capture-wide context and tool recommendations
- Use the built-in `security_audit` prompt when the client exposes MCP prompts; use `wireshark_quick_analysis` for a broad tool-driven first pass
- Use `wireshark_aggregate` for totals, distributions, distinct cardinality, top-k, and time buckets
- Index a capture you will ask more than one capture-wide question about; the second question already pays back the build
- Cite findings by their `id` and re-check them with the `reproduce` commands they carry
- Use paginated extraction for individual rows, not for capture-wide estimates
- Never guess filter syntax; use `wireshark://reference/display-filters`
- Anchor conclusions in exact filters, frame numbers, stream indexes, and tool output
