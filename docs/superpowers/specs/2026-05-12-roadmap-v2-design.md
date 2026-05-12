# Wireshark-MCP v2.0 Roadmap: Security Research Enhancement

## Overview

A three-phase roadmap to evolve Wireshark-MCP from a passive tool-calling interface into an active security research partner. Target audience: security researchers and penetration testers.

**Approach**: Capability-layered progression — each phase builds on the previous, each is independently releasable.

- Phase 1 (v1.3): Protocol expansion + forensics foundation — widen the data surface
- Phase 2 (v1.4): AI anomaly detection + natural language query — make AI understand the data
- Phase 3 (v2.0): Intelligent investigation assistant — AI drives the analysis process

---

## Phase 1: Protocol Expansion + Forensics Foundation (v1.3)

### Goal

Expand what Wireshark-MCP can "see" — more protocols, deeper extraction, richer evidence artifacts. This provides the data surface that Phase 2's AI layer will reason over.

### 1.1 New Protocol Modules

| Protocol Family | Protocols | Security Research Value |
|----------------|-----------|----------------------|
| ICS/SCADA | Modbus TCP, S7comm, DNP3 | Industrial control system auditing, critical infrastructure pentesting |
| IoT | CoAP, MQTT 5.0 (deep), Zigbee | IoT device security research |
| Wireless/BLE | Bluetooth LE (HCI), 802.11 management frames | Wireless attack surface analysis |
| Tunneling/Evasion | WireGuard, DNS-over-HTTPS, ICMP tunneling | Covert channel detection |

Each protocol module provides:
- `extract_<protocol>_sessions()` — session extraction with protocol-specific metadata
- `detect_<protocol>_anomalies()` — protocol-level anomaly detection (RFC violations, unusual patterns)
- Integration with `wireshark_open_file` auto-recommendation logic

Architecture: follows existing `tools/` registration pattern (`register_*_tools` functions). New file `tools/ics.py` for industrial protocols, `tools/iot.py` for IoT, extend existing `tools/protocol.py` for wireless/tunneling.

### 1.2 Forensics Enhancement

| Capability | Description |
|-----------|-------------|
| Advanced file carving | Beyond HTTP/SMB export: carve PE, ELF, PDF, Office docs, archives from raw streams using magic bytes validation. New tool: `wireshark_carve_files()` |
| Encrypted traffic fingerprinting | JA3/JA3S/JA4 fingerprint extraction + comparison against known-malware fingerprint database (bundled, updatable). New tool: `wireshark_extract_fingerprints()` |
| Evidence chain generation | Auto-generate timeline + correlation graph: IP → domain → certificate → file hash. Output as structured JSON (`EvidenceChain.v1` schema). New tool: `wireshark_build_evidence_chain()` |
| Metadata enrichment | Optional WHOIS, GeoIP, ASN lookup for extracted IPs/domains (requires network access, disabled by default). New tool: `wireshark_enrich_metadata()` |

### 1.3 Data Schemas

**EvidenceChain.v1** — consumed by Phase 3's investigation assistant:

```json
{
  "version": "1",
  "pcap_file": "capture.pcap",
  "timespan": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-01T01:00:00Z"},
  "nodes": [
    {"type": "ip", "value": "192.168.1.100", "role": "victim", "first_seen": "..."},
    {"type": "domain", "value": "evil.example.com", "resolved_to": ["1.2.3.4"]},
    {"type": "file_hash", "value": "sha256:abc...", "file_type": "PE", "carved_from_frame": 1234}
  ],
  "edges": [
    {"from": 0, "to": 1, "relation": "resolved", "frame": 456},
    {"from": 0, "to": 2, "relation": "downloaded", "frames": [1200, 1234]}
  ],
  "timeline": [
    {"time": "...", "event": "DNS resolution", "frames": [456], "nodes": [0, 1]}
  ]
}
```

### 1.4 Fingerprint Database

- Bundled as `data/fingerprints/ja3_malware.json` (open-source, e.g., from abuse.ch JA3 feed)
- User-extensible: `~/.wireshark-mcp/fingerprints/` for custom entries
- Update mechanism: `wireshark-mcp update-fingerprints` CLI subcommand

---

## Phase 2: AI Anomaly Detection + Natural Language Query (v1.4)

### Goal

Let AI actively understand traffic data — detect anomalies without being asked, and translate natural language intent into precise analysis operations.

### 2.1 Anomaly Detection Engine

Statistical and heuristic methods, fully offline (no external ML model dependency):

| Detection Type | Method | Output |
|---------------|--------|--------|
| Traffic baseline deviation | Statistical modeling of session frequency, packet size distribution, protocol ratios. Flag periods deviating 2σ+ | Anomalous time windows + deviation metrics |
| Beacon detection | Detect periodic communication patterns (C2 heartbeats), compute inter-arrival jitter coefficient | Suspect beacon list + confidence score |
| Data exfiltration indicators | Detect abnormally large outbound transfers, high-volume traffic on non-standard ports, DNS query length anomalies | Suspect exfil events + data volume estimate |
| Protocol anomalies | Field values outside RFC spec, known protocols on non-standard ports | Anomalous packet list + reason |

Architecture:
- New module `tools/anomaly.py`
- Aggregate tool: `wireshark_detect_anomalies(pcap_file, detectors=["all"])`
- Each detector is an independent function, callable individually or in batch
- Unified output schema `AnomalyFinding`:

```json
{
  "type": "beacon",
  "severity": "high",
  "confidence": 0.87,
  "evidence_frames": [100, 200, 300, 400],
  "description": "Host 192.168.1.50 communicates with 1.2.3.4:443 every 60±2s",
  "metadata": {"interval_mean": 60.1, "jitter": 0.03, "session_count": 48}
}
```

- Anomaly findings auto-attach to `EvidenceChain` from Phase 1

### 2.2 Natural Language Query

Tool: `wireshark_nl_query(pcap_file, query: str)`

**Design**: Intent-to-filter template mapping + keyword extraction. Fully offline.

Intent mapping table (bundled, extensible):

| Natural Language | Mapped Operation |
|-----------------|-----------------|
| "Find all hosts connecting to external C2" | Beacon detection + non-standard port outbound + known threat IP comparison |
| "Is there lateral movement in this pcap" | SMB/WMI/RDP/PSExec session extraction + internal scan detection |
| "Extract all suspicious DNS requests" | DNS tunnel detection + high-entropy domains + DGA pattern matching |
| "Which hosts are exfiltrating large files" | Outbound traffic ranking + non-standard port large transfers + time distribution |

Key decisions:
- No external LLM dependency — intent recognition via template matching + keyword extraction
- Extensible — users add custom intent mappings via config file (`~/.wireshark-mcp/nl_templates.yaml`)
- Graceful fallback — unrecognized queries return "cannot parse" + suggest standard filter syntax
- Dry-run validation — generated filters are syntax-checked before execution

Output format:
```json
{
  "interpreted_as": "C2 beacon detection",
  "filters_applied": ["tcp.flags.syn==1 && ...", "..."],
  "tools_invoked": ["detect_beaconing", "check_threats"],
  "results_summary": "Found 3 potential C2 channels",
  "suggested_next": ["Follow stream 12 for payload inspection", "Extract JA3 for 1.2.3.4"]
}
```

### 2.3 Enhanced MCP Prompts

New prompt registrations for AI clients:

- `analyze_with_hypothesis` — guides AI to form and test hypotheses rather than scanning aimlessly
- `investigate_alert` — starts from a single alert/IOC and expands into full correlation analysis
- Structured output format that AI can directly reason over

---

## Phase 3: Intelligent Investigation Assistant (v2.0)

### Goal

AI becomes an active investigation partner — maintains context, drives analysis direction, generates actionable reports.

### 3.1 Investigation Engine

Core concept: **Investigation Session** — a stateful investigation process where AI maintains context and drives analysis.

```
Investigation Session
├── hypothesis_stack[]     # Current hypotheses (priority-ordered)
├── evidence_chain         # Confirmed evidence (EvidenceChain.v1 from Phase 1)
├── findings[]             # Confirmed findings (AnomalyFinding from Phase 2)
├── next_steps[]           # AI-suggested next operations
└── report                 # Real-time generated investigation report
```

Workflow:
1. User provides pcap + optional initial lead (alert, suspect IP, time window)
2. AI runs initial analysis (quick_analysis + anomaly detection)
3. Generates hypotheses based on findings (e.g., "Host X may have C2 implant")
4. Proposes verification steps for each hypothesis, requests user confirmation or auto-executes
5. Updates hypothesis status based on verification (confirmed / refuted / needs more data)
6. Loops until all hypotheses are resolved or user terminates

Tool: `wireshark_investigate(pcap_file, initial_lead=None, playbook=None)`

### 3.2 Playbook Engine

Pre-defined investigation playbooks, one-click launch:

| Playbook | Trigger Scenario | Auto-executed Analysis Chain |
|----------|-----------------|----------------------------|
| `malware_c2` | Suspected C2 communication | Beacon detection → JA3 fingerprint → DNS resolution chain → file carving → evidence chain |
| `lateral_movement` | Internal lateral movement | Internal scan detection → SMB/RDP sessions → credential extraction → timeline |
| `data_exfil` | Data exfiltration | Outbound anomaly → DNS tunnel → encrypted traffic fingerprint → volume estimation |
| `initial_access` | Initial compromise | Phishing email extraction → malicious file carving → first outbound connection time → attacker infrastructure |

Playbook format (YAML, user-customizable):
```yaml
name: malware_c2
description: "Investigate suspected C2 communication"
triggers:
  - anomaly_type: beacon
    min_confidence: 0.7
steps:
  - tool: detect_beaconing
    on_finding: continue
  - tool: extract_fingerprints
    match_against: known_malware_db
    on_match: escalate
  - tool: build_evidence_chain
    output: report
report:
  include: [timeline, iocs, mitre_mapping, detection_rules]
```

Storage: bundled in `data/playbooks/`, user custom in `~/.wireshark-mcp/playbooks/`

### 3.3 Report Generation

Auto-generated at investigation end:

- **Formats**: Markdown + structured JSON dual output
- **Content**: Executive summary, timeline, evidence list (with frame references), IOC extraction, MITRE ATT&CK mapping, confidence rating
- **Actionable outputs**:
  - Snort/Suricata rule suggestions
  - YARA rule drafts
  - IOC list (STIX 2.1 format)
  - Sigma detection rules

Tool: `wireshark_generate_report(session_id, format="markdown")`

### 3.4 Architecture

- `tools/investigator.py` — investigation session management
- `tools/playbooks.py` — playbook loading and execution engine
- `tools/reporter.py` — report generation with multiple output formats
- `data/playbooks/` — bundled playbook definitions
- Investigation state stored as JSON, supports interrupt/resume

---

## Cross-cutting Concerns

### Backward Compatibility

- All new tools are additive; existing 40+ tools remain unchanged
- New schemas (EvidenceChain.v1, AnomalyFinding) are output-only; no breaking changes to existing tool interfaces
- Phase 2/3 features are opt-in; basic tool-calling workflow continues to work

### Performance

- Phase 1 protocol modules leverage existing result cache (LRU, 128 entries, 50MB, 5min TTL)
- Phase 2 anomaly detection runs detectors concurrently (same pattern as existing `security_audit`)
- Phase 3 investigation sessions are stateful but lightweight (JSON state, no persistent process)

### Testing Strategy

- Each phase adds corresponding test modules following existing patterns
- Protocol modules: unit tests with fixture pcaps + integration tests with real tshark
- Anomaly detection: tests with crafted pcaps containing known anomalies
- NL query: intent mapping coverage tests
- Investigation engine: end-to-end scenario tests with pre-recorded sessions

### Distribution

- All phases distributed via existing channels (PyPI, Homebrew, Docker)
- Fingerprint/playbook data files included in wheel via `pyproject.toml` force-include
- CLI subcommands for data updates (`update-fingerprints`, `update-playbooks`)

---

## Release Timeline (Suggested)

| Phase | Version | Scope |
|-------|---------|-------|
| 1 | v1.3.0 | Protocol expansion + forensics foundation |
| 2 | v1.4.0 | AI anomaly detection + NL query |
| 3 | v2.0.0 | Investigation assistant + playbooks + reporting |

Each phase is independently valuable and shippable. Phase ordering reflects technical dependency: Phase 1's data richness feeds Phase 2's AI, which feeds Phase 3's autonomous investigation.
