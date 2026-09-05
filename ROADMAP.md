# Roadmap

[中文版](ROADMAP_zh.md)

This roadmap describes intended release outcomes, not delivery dates. An item is complete only when its code, tests, user documentation, and release note are all present.

## Status

- **In progress** — implemented or being validated on the current branch.
- **Next** — the next bounded release target.
- **Later** — accepted direction, scheduled after the next release.
- **Candidate** — useful idea that still needs an interface proposal or evidence of demand.

## 3.0 release — trustworthy analysis and stable interfaces

- [x] Stable result contract: type invariance under character budgets, structured pagination, and `CallToolResult.isError` synchronization.
- [x] Calibrated detection semantics: minimal Finding model, rate-based DoS, query-only DNS analysis, and short credential fix.
- [x] Deterministic PCAP fixtures and end-to-end real TShark regression suite (`test_real_pcap.py`).
- [x] Resource boundaries: byte limit ceilings in stream loops, group cardinality and distinct limits in aggregation.
- [x] Protocol and transport matrix: real stdio subprocess verification, 2026-07-28 protocol validation, and compatibility matrix document.
- [x] Disciplined investigation skills: hypothesis-driven playbooks, concrete evidence anchors, and standalone `tshark-cli-analysis` skill prototype.
- [x] Full-capture count, group, distinct, top-k, and time-bucket statistics.
- [x] Stop oversized aggregate scans at a one-million matched-packet safety ceiling.
- [x] Require an explicit writable root before file-creating tools can run.
- [x] Refuse unauthenticated non-loopback HTTP binds by default.

Exit criterion: results are reproducible, scan boundaries and limitations are explicitly reported, and every finding is anchored in verifiable packet evidence.

## Next — 3.1 deep analysis, memory bounds, and CLI skill release

- [x] **Agent traffic-analysis evaluation baseline**: evaluate Skill behavior with fixed questions, deterministic captures, expected facts, evidence requirements, and forbidden overclaims before optimizing tool count or tokens.
- [x] **True streaming accumulator:** stream row-by-row into reduction aggregators to eliminate large intermediate string and list allocations.
- [x] **Numeric reducers:** add `sum`, `min`, `max`, and `avg` over numeric tshark fields (bytes, payload lengths, response times).
- [ ] **Standalone tshark CLI Skill:** formal release of `tshark-cli-analysis` with automation recipes and shell pipelines.
- [ ] **MCP vs Native CLI Benchmarks:** the reproducible engine runner and accuracy-gated Agent comparison are implemented; independent multi-run Agent results and large-capture scaling remain to be published.
- [ ] **Configurable scan policies:** server-side configurable packet ceilings and timeout budgets.

Exit criterion: numeric aggregation and pagination have real-tshark tests, deterministic output, bounded memory, and examples in both aggregation guides.

## Later — 3.2 evidence-first findings

- Define one finding schema shared by security and anomaly tools: severity, confidence, evidence frames, filters, streams, and caveats.
- Produce Markdown and JSON reports from the same finding data rather than maintaining two independent renderers.
- Add timeline helpers that preserve exact frame numbers and relative times for incident-response workflows.
- Add comparison views for two captures or two display-filter windows without loading packet bodies into model context.

Exit criterion: every automated finding can be traced back to an exact tool result and packet-level verification path.

## Later — 3.3 operational hardening

- Add authenticated deployment recipes and automated checks for Streamable HTTP behind a reverse proxy.
- Add compatibility tests against the supported Wireshark/tshark version matrix.
- Publish a machine-readable capability and compatibility document for clients and packaging systems.

Exit criterion: authenticated remote deployment is reproducible and the supported platform/toolchain matrix is exercised in CI or recorded manual evidence.

## Candidates

- Pluggable local fingerprint and IOC providers with provenance and refresh metadata.
- Optional columnar export for large offline analysis jobs.
- Saved investigation manifests containing filters, frames, streams, and report metadata.
- More protocol packs when a protocol has stable tshark fields and a maintainer for its test fixture.

## Not planned

- Replacing Wireshark's GUI or packet dissection engine.
- Uploading captures to a hosted service by default.
- Declaring traffic malicious without packet evidence.
- Expanding the tool count when an existing parameterized tool can express the same capability.

Feature requests should describe the operator question, expected evidence, relevant tshark command or fields, and a representative capture when it can be shared safely.
