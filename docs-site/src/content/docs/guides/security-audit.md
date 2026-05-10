---
title: Security Audit
description: Investigate suspicious behavior with evidence-backed findings.
---

Use this workflow for suspicious traffic, exposed credentials, malware-like behavior, exfiltration leads, or broad security review.

## Recommended flow

1. Start with the quick analysis workflow.
2. Run `wireshark_security_audit` for a broad first pass.
3. Verify specific signals with targeted tools:
   - `wireshark_check_threats`
   - `wireshark_extract_credentials`
   - `wireshark_detect_port_scan`
   - `wireshark_detect_dns_tunnel`
   - `wireshark_analyze_suspicious_traffic`
4. Extract protocol evidence when relevant:
   - `wireshark_extract_http_requests`
   - `wireshark_extract_dns_queries`
   - `wireshark_extract_tls_handshakes`
5. Follow suspicious streams with `wireshark_follow_stream`.
6. Anchor claims with `wireshark_get_packet_details` or `wireshark_get_packet_context`.

## Confidence labels

Use explicit labels for every non-trivial finding:

- `confirmed`: packet evidence directly supports the claim.
- `likely`: evidence strongly supports the claim, but capture limits prevent full proof.
- `possible`: the behavior is suspicious, but common benign explanations remain.
- `unresolved`: the capture does not contain enough evidence.

## Report shape

Include risk summary, suspicious behaviors, exact evidence, confidence, and next validation steps.
