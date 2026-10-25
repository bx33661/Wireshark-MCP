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

## Installation and distribution mainline

- [x] Project/global registration, explicit automation targets, previews, idempotent parsed config edits and recovery backups (implemented locally, publication separate).
- [x] Local Codex/Claude Code plugin bundles and repository marketplace wiring, sharing canonical skills and locked uv launchers.
- [ ] Publish the repository/plugin release, remote transport-specific installers and clean multi-platform client sign-off.
- [ ] Bring the Homebrew tap formula up to the current release. The release dispatch works and opens a bump PR in the tap, but those PRs (2.0.0, 3.1.0, 4.0.0) were never merged, so the tap still installs 1.1.5.
- [x] Offer the capture index in the container image and plugin launcher (both now ship the `[index]` extra).

## 3.1 release — deep analysis, memory bounds, and CLI skill release

- [x] **Agent traffic-analysis evaluation baseline**: evaluate Skill behavior with fixed questions, deterministic captures, expected facts, evidence requirements, and forbidden overclaims before optimizing tool count or tokens.
- [x] **True streaming accumulator:** stream row-by-row into reduction aggregators to eliminate large intermediate string and list allocations.
- [x] **Numeric reducers:** add `sum`, `min`, `max`, and `avg` over numeric tshark fields (bytes, payload lengths, response times).
- [x] **CLI Skill implementation and release gates:** full 4.6.9 capability catalog, on-demand guides, bounded execution, Codex discovery and trace-bound evaluation. Public release and comparative Agent effectiveness claims remain separate.
- [x] **Standalone tshark CLI Skill:** formal release of `tshark-cli-analysis` with automation recipes and shell pipelines.
- [x] **MCP vs Native CLI Benchmarks:** reproducible engine runner with accuracy-gated 10 MB / 100 MB / 1 GB scaling tiers and published results; the accuracy-gated Agent comparator is ready, and independent multi-run Agent results move to 3.2.
- [x] **Configurable scan policies:** server-side configurable packet ceilings and timeout budgets.

Exit criterion: numeric aggregation and pagination have real-tshark tests, deterministic output, bounded memory, and examples in both aggregation guides.

## 3.2 evidence-first findings (ships in 4.0.0)

- [x] Publish the full 20-scenario × 3-path × 3-run Agent evaluation matrix with harness-bound traces: [Haiku results](docs/agent-evaluation-results.md), two runs; a stronger-model run remains open.
- [x] Persist investigation case files (inputs, executed queries, findings, analyst verdicts) so long investigations survive context resets.
- [x] Define one finding schema shared by security and anomaly tools: severity, confidence, evidence frames, filters, streams, and caveats.
- [x] Produce Markdown and JSON reports from the same finding data rather than maintaining two independent renderers.
- [x] Ship the optional DuckDB capture index core (see 4.0) alongside the finding model.
- Timeline helpers and two-capture / two-window comparison views move to 4.0, where they are built on the index and return only the differences.

Exit criterion: every automated finding can be traced back to an exact tool result and packet-level verification path.

## 4.0 release — capture index engine (released 2026-10-25)

The index core was built first, alongside the 3.2 finding model; the remaining engine items below followed, ahead of the long-running jobs work. Everything shipped together in 4.0.0 as the optional `[index]` extra; see the [capture index guide](docs/capture-index.md).

- [x] **DuckDB capture index (core):** one tshark pass per capture, `wireshark_index` (build/status/query/drop), `wireshark_aggregate` reuses a fresh index with tshark-identical answers and reports `coverage.source`; 100 MB / 1 GB benchmark published.
- [x] Capture sets: `more_files` stacks several per-capture indexes with a `capture_id` column and a `captures` table, so files are indexed once and combined at query time.
- [x] Index-backed `timeline` (first and last sighting of hosts, conversations, protocols, DNS/TLS/HTTP names and fingerprints) and `diff` of two captures or two display-filter windows, returning only new and gone items with exact frame numbers and relative times.
- [x] Parquet export of packets, flows and captures into the index directory.
- [x] `wireshark_extract_fields` answers from the index with byte-identical tshark output.
- [x] Grouping pushed down into DuckDB SQL behind exactness gates, with the tshark equivalence tests as the gate.
- [x] 10 GB benchmark tier.
- Routing the endpoint, conversation and protocol-hierarchy statistics and the detection tools through the index moves to the next release.

Exit criterion: capture-wide questions on multi-gigabyte captures and capture sets are answered from the index with results proven equal to the tshark path.

## Next — long-running jobs and operational hardening

- Run index builds, full-capture aggregation, large YARA scans and multi-capture batches as MCP Tasks with progress and cancellation, instead of one bounded call.
- Route the endpoint, conversation and protocol-hierarchy statistics and suitable detection tools through the index, each behind its own equivalence harness against parsed tshark tap output.
- Add authenticated deployment recipes and automated checks for Streamable HTTP behind a reverse proxy.
- Add compatibility tests against the supported Wireshark/tshark version matrix.
- Publish a machine-readable capability and compatibility document for clients and packaging systems.

Exit criterion: authenticated remote deployment is reproducible and the supported platform/toolchain matrix is exercised in CI or recorded manual evidence.

## Candidates

- Pluggable local fingerprint and IOC providers with provenance and refresh metadata.
- Saved investigation manifests containing filters, frames, streams, and report metadata.
- More protocol packs when a protocol has stable tshark fields and a maintainer for its test fixture.

## Not planned

- Replacing Wireshark's GUI or packet dissection engine.
- Uploading captures to a hosted service by default.
- Declaring traffic malicious without packet evidence.
- Expanding the tool count when an existing parameterized tool can express the same capability.

Feature requests should describe the operator question, expected evidence, relevant tshark command or fields, and a representative capture when it can be shared safely.
