Use the `wireshark-traffic-analysis` project skill in this repository to investigate a packet capture with a professional, evidence-backed workflow.

Inputs:

- Capture path: `${input:capture_path:Path to the pcap or pcapng file}`
- Goal: `${input:goal:triage | security | incident-response | troubleshoot}`
- Optional scope: `${input:scope:Suspicious host, protocol, time window, domain, stream, or symptom}`

Requirements:

- Start with the supplied question; use broad triage only for unfamiliar captures.
- Use the project skill playbook that matches the goal.
- Use `wireshark_aggregate` for full-capture totals, grouped distributions, distinct counts, top-k, or time buckets.
- Include exact filters, streams, frames, or extracted fields for every important finding.
- Label confidence as `confirmed`, `likely`, `candidate`, or `unresolved`.
- Check result coverage and errors before interpreting counts or absence.
- Stop when the question is answered; propose a next step only for an unresolved gap.

Relevant files:

- [Canonical skill](../../skills/wireshark-traffic-analysis/SKILL.md)
- [Playbooks](../../skills/wireshark-traffic-analysis/references/playbooks.md)
- [Evidence rubric](../../skills/wireshark-traffic-analysis/references/evidence-rubric.md)
- [Report template](../../skills/wireshark-traffic-analysis/references/report-template.md)
