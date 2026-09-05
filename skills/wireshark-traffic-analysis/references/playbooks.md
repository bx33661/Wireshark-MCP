# Investigation branches

Choose one branch. These are decision paths, not mandatory call sequences.

## Triage: explain an unknown capture

Use `wireshark_open_file` for unfamiliar input, then `wireshark_quick_analysis` if a broad overview is useful. It already includes several statistics. Fill only missing context using `wireshark_stats_protocol_hierarchy`, `wireshark_stats_endpoints`, or `wireshark_stats_conversations`; select IPv4/IPv6 according to observed traffic.

Rank activity relevant to the question with `wireshark_aggregate`. Inspect the strongest unexplained group. Stop once you can describe the capture and identify evidence-backed leads, or explain that no lead is established. Do not force a quota of suspicious hosts.

## Security: discriminate a signal from benign activity

Start with the supplied indicator or a lead from triage. A detector is a candidate generator; corroborate its output with a separate extraction or packet query.

| Signal | Discriminating evidence | Counter-explanation |
|---|---|---|
| DNS tunnel | Per-client and per-domain query distribution, query/response distinction, timing, sampled labels | CDN, telemetry, security tooling; unrelated domains sharing a public suffix |
| Port scan | Source/target fanout, ports, time window, SYN versus completed connections | Approved scanner, inventory, health checks |
| Beaconing or exfiltration | Repeated timing plus direction, volume and application context for the same conversations | Backup, sync, polling; periodicity alone is insufficient |
| Credentials | Actual credential-bearing field and exact frame; mask the value | A login page or prompt alone is not credential transmission |
| TLS anomaly | Handshake outcome and endpoint context; `wireshark_analyze_protocol(protocol="tls_handshakes")` when available | Internal PKI, interception, test services |

Use `wireshark_extract_dns_queries`, `wireshark_extract_http_requests`, or `wireshark_extract_fields` for targeted evidence. Use `wireshark_follow_stream` and packet details when the claim depends on content or sequence. If an optional export or decryption tool is absent, state the missing evidence instead of assuming its result.

Stop at a supported observation or candidate when intent cannot be established. Do not promote rarity, a fingerprint, or a heuristic threshold to confirmed malware.

## Troubleshoot: locate the failure boundary

Start with the affected endpoint, service, and time. Separate name resolution, connection establishment, TLS negotiation, application response, and transfer behavior. Inspect the earliest failing stage rather than dumping all protocol statistics.

Use `wireshark_analyze_tcp_health`, `wireshark_stats_expert_info`, or `wireshark_stats_service_response_time` only for the relevant symptom. Time buckets from `wireshark_aggregate` or `wireshark_stats_io_graph` help distinguish bursts from whole-capture averages. Validate the time window and units before comparing rates.

Inspect the affected stream and adjacent frames with `wireshark_get_packet_context`. Check capture loss, offload artifacts, and one-sided visibility before attributing retransmissions or missing responses to the network. A delayed response alone does not distinguish application processing from an unseen network segment. Stop at the deepest boundary the capture supports and identify the specific additional observation needed.

## Incident response: reconstruct bounded events

Reuse established evidence. Associate each event with capture identity, timestamp/time basis, actor, action, frame or stream, and confidence. Capture boundaries are not incident boundaries. Before ordering events across files, check clock offsets and capture locations; stream IDs and frame numbers are local to a capture.

Use conversations to establish observed participants, filtered time buckets to locate activity, and packet evidence to verify key transitions. Keep the observed timeline separate from the proposed attack narrative. Do not claim initial access, affected-system scope, or exfiltration solely from missing earlier packets or asymmetric byte totals.

Stop when the requested timeline and visible scope are reconstructed, with unresolved intervals and the next useful log or capture identified.
