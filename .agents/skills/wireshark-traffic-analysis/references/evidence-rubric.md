# Evidence Rubric

Use this rubric when a pattern looks suspicious but the capture alone may not be enough to prove intent or root cause.

## Contents

- [Confidence labels](#confidence-labels)
- [Vantage point checks](#vantage-point-checks)
- [Common signals](#common-signals)

## Confidence labels

Use these labels consistently:

- `confirmed`: directly supported by packet evidence with little ambiguity
- `likely`: multiple signals support the conclusion, but another explanation is still plausible
- `possible`: one or two weak indicators exist, but the conclusion is not stable
- `unresolved`: the capture suggests a question, not an answer

## Vantage point checks

Before concluding, ask:

- Is this capture from the client, server, gateway, mirror port, or only one side of the path?
- Could packet loss in the capture itself create fake retransmissions or gaps?
- Are missing packets making application behavior look incomplete?
- Is TLS decryption unavailable, limiting what can be claimed about payloads?

If vantage point uncertainty affects the conclusion, mention it explicitly.

## Common signals

### DNS tunneling

Treat DNS as suspicious only when several indicators align:

- unusually long query names
- many unique subdomains under one base domain
- repetitive TXT or NULL queries
- regular beacon-like cadence
- high-entropy labels
- weak or failed response patterns

Counterexamples:

- CDN hostnames
- telemetry platforms
- service discovery
- anti-malware lookups

Good confirmation tools:

- `wireshark_detect_dns_tunnel`
- `wireshark_extract_dns_queries`
- `wireshark_extract_fields` with `dns.qry.name`, `dns.qry.type`, `ip.src`, `ip.dst`

### Port scanning

Treat scanning as stronger when you see:

- one source probing many ports or many hosts
- many SYN-only attempts with little follow-through
- short-lived connections with consistent fan-out

Counterexamples:

- vulnerability scanners you already own
- health checks
- inventory tooling
- load balancer probes

Good confirmation tools:

- `wireshark_detect_port_scan`
- `wireshark_extract_fields` with `ip.src`, `ip.dst`, `tcp.dstport`, `tcp.flags.syn`
- `wireshark_stats_conversations`

### Credential exposure

Only call credentials exposed when the capture actually contains the secret or credential-bearing field.

Examples:

- `http.authbasic`
- FTP `PASS`
- Telnet plaintext login flows

Good confirmation tools:

- `wireshark_extract_credentials`
- `wireshark_follow_stream`
- `wireshark_get_packet_details`

### Exfiltration or suspicious data transfer

Treat exfiltration as stronger when you see:

- sustained asymmetric upload volume
- repetitive uploads to a narrow destination set
- encoded or staged payloads
- suspicious destinations plus meaningful payload movement

Counterexamples:

- backups
- software updates
- sync clients
- log shipping

Good confirmation tools:

- `wireshark_stats_conversations`
- `wireshark_follow_stream`
- `wireshark_extract_http_requests`
- `wireshark_export_objects`

### TLS suspicion

TLS alone is not suspicious. Treat it as more interesting when it overlaps with:

- failed or unusual handshakes
- uncommon SNI targets
- self-signed or mismatched certificates
- suspicious destinations found elsewhere in the capture

Counterexamples:

- internal PKI
- TLS interception
- test environments

Good confirmation tools:

- `wireshark_extract_tls_handshakes`
- `wireshark_check_threats`
- `wireshark_follow_stream`

### TCP health problems

One retransmission rarely proves a network issue. Stronger cases include:

- repeated retransmissions in the same conversation
- duplicate ACK bursts
- zero-window events
- resets aligned with user-visible failures

Counterexamples:

- capture loss
- transient congestion
- intentionally closed connections

Good confirmation tools:

- `wireshark_analyze_tcp_health`
- `wireshark_stats_expert_info`
- `wireshark_follow_stream`

## Reporting rule

Whenever a claim could be disputed, include:

- the signal
- the counter-interpretation
- why your conclusion still holds, or why it remains unresolved
