# Findings and investigation cases

[中文版](findings-and-cases_zh.md)

## One finding shape

Every detector returns `data.findings` and a short `data.summary`:
`wireshark_detect_port_scan`, `wireshark_detect_dns_tunnel`, `wireshark_detect_dos_attack`,
`wireshark_extract_credentials`, `wireshark_detect_beaconing`, `wireshark_detect_exfiltration`,
`wireshark_detect_protocol_anomalies`, `wireshark_detect_arp_spoofing`, `wireshark_yara_scan`,
the BLE scanner and pairing values of `wireshark_analyze_protocol`, and the anomaly section of
`wireshark_quick_analysis` (whose Markdown is rendered from the same findings).

| Field | Meaning |
|-------|---------|
| `id` | `wf-` plus 16 hex digits of a content hash over tool, category, observation and evidence anchors. The same detector seeing the same evidence yields the same id. |
| `tool`, `category` | Producing tool and detector category (`port_scan`, `beaconing`, `arp_spoofing`, …). |
| `observation` | The calibrated claim, worded as what was seen. |
| `severity` | `info`, `low`, `medium`, `high`, `critical`. |
| `confidence` | `candidate`, `likely`, `confirmed`. Separate from severity. |
| `evidence[]` | Anchors: `frame`, `stream`, `protocol`, `filter`, `field`, `value`, `description`. |
| `constraints` | Scan bounds: `scanned`, `limit`, `truncated`, thresholds, time window. |
| `reproduce[]` | Native `tshark` commands derived from the evidence filters or frames, so the finding can be re-checked without this server. |
| `mitre_attack[]` | Candidate ATT&CK technique IDs for non-informational findings. A hint for triage, not attribution. |
| `next_steps[]`, `details` | Suggested verification and detector-specific values such as intervals or byte counts. |

Volume rankings and similar context are `info` findings and never carry ATT&CK candidates.

## Case files

`wireshark_case` keeps an investigation outside the model context, so it survives compaction or a new session.

```text
wireshark_case(action="create", text="Suspected scan from 10.0.0.5", target="/captures/a.pcap,/captures/b.pcap")
wireshark_case(action="record", case_id="case-…", text=<JSON result of a wireshark_* tool>)
wireshark_case(action="verdict", case_id="case-…", target="wf-…", text="dismissed: authorised scanner")
wireshark_case(action="note", case_id="case-…", text="Change ticket CHG-1234 covers the window")
wireshark_case(action="show", case_id="case-…")      # compact state to resume from
wireshark_case(action="report", case_id="case-…")    # Markdown rendered from the case
wireshark_case(action="list")
```

A case records each capture's SHA-256 and size, every recorded tool result's SHA-256, scope and coverage, the findings it carried (merged by `id`, with the queries that saw them), analyst verdicts and notes. The server never re-runs tshark for a case; `record` warns when a result came from a capture that is not part of the case. The full JSON is readable as the resource `wireshark://cases/{case_id}`.

Storage follows the file-write boundary: cases are written to `.wireshark-mcp-cases/` under the first writable entry of `WIRESHARK_MCP_ALLOWED_DIRS` (a read-only evidence mount listed first is skipped), or to `WIRESHARK_MCP_CASE_DIR` when that directory is inside an allowed root. Without an allowed root the tool fails closed. Case files contain capture paths and finding values, so treat the directory like the captures themselves.
