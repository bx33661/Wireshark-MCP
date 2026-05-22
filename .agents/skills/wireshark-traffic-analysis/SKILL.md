---
name: "wireshark-traffic-analysis"
description: "Use when analyzing packet captures or live network traffic with Wireshark MCP; choose the right workflow for triage, security hunting, incident response, troubleshooting, or CTF work, then produce evidence-backed findings with exact filters, streams, frames, and next steps."
---

# Wireshark Traffic Analysis

Use this skill to turn raw packet captures into a disciplined investigation. The goal is not to list packets. The goal is to build a defensible answer from capture-wide context, protocol-level evidence, and clearly labeled inferences.

## When to use

- `pcap` or `pcapng` analysis
- live traffic review after capture
- security triage, threat hunting, or incident response
- network and protocol troubleshooting
- CTF and forensics-style packet challenges
- any task where packet evidence matters more than intuition

## Required inputs

- capture path
- primary goal: `triage`, `security`, `incident-response`, `troubleshoot`, or `ctf`
- any known scope: suspicious host, port, domain, time window, protocol, or symptom

If the user does not name a goal, default to `triage`.

## Core workflow

1. Open the capture first.
   - Use `wireshark_open_file` before protocol-specific tools. It activates contextual tools and gives an initial protocol summary.
2. Build a global picture before drilling down.
   - Prefer `wireshark_quick_analysis`, `wireshark_stats_protocol_hierarchy`, `wireshark_stats_endpoints`, and `wireshark_stats_conversations`.
3. Choose one mode and follow its playbook.
   - Read [references/playbooks.md](references/playbooks.md) and use the matching section.
4. Confirm interesting leads with packet-level evidence.
   - Use `wireshark_follow_stream`, `wireshark_get_packet_details`, `wireshark_get_packet_context`, `wireshark_extract_fields`, and `wireshark_search_packets`.
5. Separate observation from interpretation.
   - Facts come from tool output.
   - Inferences must be labeled `confirmed`, `likely`, `possible`, or `unresolved`.
6. End with next actions.
   - Suggest exact display filters, stream indexes, frame numbers, fields, or follow-up questions.

## Analysis rules

- Start broad, then narrow.
- Prefer Wireshark MCP tools over freehand `tshark` syntax.
- Never guess display filter syntax. Use `wireshark://reference/display-filters`.
- Use `wireshark://reference/protocol-fields` when you need field names for extraction or filters.
- Never decode payloads manually when `wireshark_decode_payload` can verify the result.
- Treat `wireshark_stats_expert_info` as a lead generator, not a final verdict.
- When a finding depends on context, follow the full stream before concluding.
- For large captures, paginate instead of treating the first page as representative.
- If the capture vantage point could distort interpretation, say so explicitly.
- If evidence is incomplete, say exactly what is missing.

## Statistics notes

- `wireshark_stats_protocol_hierarchy` is for structure, not naive percentage math. A single packet can contribute to multiple protocol rows across layers.
- `wireshark_stats_endpoints` is the fastest host inventory view. Use it to identify broadcast, multicast, and heavy talkers before drilling into conversations.
- `wireshark_stats_conversations` is usually the best place to prioritize long-lived, high-volume, or asymmetric exchanges.
- Stream indexes are tool evidence too. When `wireshark_follow_stream` explains the finding, include the exact stream index in the report.

For official Wireshark behavior notes and source links, see [references/official-wireshark-notes.md](references/official-wireshark-notes.md).

## Evidence standard

For any non-trivial finding, include at least two of the following:

- the tool call that surfaced it
- exact host, port, protocol, or field names
- a stream index or frame number
- a display filter or field extraction query
- a short explanation of why the signal matters

When a pattern looks suspicious but could still be normal, read [references/evidence-rubric.md](references/evidence-rubric.md) before concluding.

## Professional reporting style

- Write like an analyst, not like a chatty observer.
- Do not say "weird", "sketchy", or "probably malware" without evidence.
- Keep severity or impact separate from confidence.
- State scope, assumptions, and gaps when they materially affect the conclusion.
- Prefer "observed", "evidence shows", "likely indicates", and "could not verify" over vague language.
- If the capture alone cannot prove intent, say so directly.

## Output shape

Use the structure in [references/report-template.md](references/report-template.md). Keep reports concise, evidence-backed, and action-oriented.

## Mode selection

Use the matching playbook in [references/playbooks.md](references/playbooks.md):

- `triage`: unknown capture, fast situational awareness
- `security`: suspicious traffic, exfiltration, credential exposure, malware behavior
- `incident-response`: reconstruct the timeline, scope, and affected systems
- `troubleshoot`: retransmissions, latency, resets, failed handshakes, unstable services
- `ctf`: flags, hidden payloads, staged transfers, encoded streams

## Built-in prompts and references

If the user mainly needs a starting workflow rather than a full investigation, the MCP prompts in this repo can help:

- `traffic_overview`
- `security_audit`
- `performance_analysis`
- `incident_response`
- `ctf_solve`

Use `wireshark://guide/usage` when you need the repo's built-in MCP workflow reference.

## Common mistakes to avoid

- calling something malicious because it is uncommon
- calling something benign because it is encrypted
- over-trusting a single heuristic such as long DNS queries or one retransmission
- skipping endpoints and conversations, then missing the real top talker
- reporting a hypothesis as a confirmed root cause
