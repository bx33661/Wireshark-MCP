Use the `wireshark-traffic-analysis` project skill in this repository to investigate a packet capture with a professional, evidence-backed workflow.

Inputs:

- Capture path: `${input:capture_path:Path to the pcap or pcapng file}`
- Goal: `${input:goal:triage | security | incident-response | troubleshoot | ctf}`
- Optional scope: `${input:scope:Suspicious host, protocol, time window, domain, stream, or symptom}`

Requirements:

- Start broad, then narrow.
- Use the project skill playbook that matches the goal.
- Include exact filters, streams, frames, or extracted fields for every important finding.
- Label confidence as `confirmed`, `likely`, `possible`, or `unresolved`.
- End with concrete next steps.

Relevant files:

- [Canonical skill](../../skills/wireshark-traffic-analysis/SKILL.md)
- [Playbooks](../../skills/wireshark-traffic-analysis/references/playbooks.md)
- [Evidence rubric](../../skills/wireshark-traffic-analysis/references/evidence-rubric.md)
- [Report template](../../skills/wireshark-traffic-analysis/references/report-template.md)
