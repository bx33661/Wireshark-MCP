# Repository Agent Guide

Use the project skill catalog in `skills/manifest.json` when the task involves packet captures, network forensics, traffic triage, security hunting, incident response, troubleshooting, or CTF-style stream analysis.

## Primary skill

- `wireshark-traffic-analysis`

Canonical source:

- `skills/wireshark-traffic-analysis/SKILL.md`

Project discovery mirrors:

- `.github/skills/wireshark-traffic-analysis/SKILL.md`
- `.claude/skills/wireshark-traffic-analysis/SKILL.md`

## Expected behavior

- Start with capture-wide context before diving into individual packets.
- Prefer evidence-backed findings with exact filters, streams, frames, and confidence labels.
- Use the skill playbooks and evidence rubric rather than improvising analysis methodology.
- Treat `Expert Info` and anomaly tools as leads that still need confirmation.
- Keep conclusions reproducible for another analyst.
