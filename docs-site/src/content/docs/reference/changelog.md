---
title: Changelog
description: Release history and notable changes.
---

## 1.2.0 — 2026-05-10

Performance, token optimization, and new protocol analysis tools.

### Added

- **QUIC/HTTP3 analysis** — `wireshark_analyze_quic` extracts QUIC version, connection IDs, SNI, and HTTP/3 frames
- **WebSocket analysis** — `wireshark_analyze_websocket` reports frame types, payload lengths, and masking
- **MQTT analysis** — `wireshark_analyze_mqtt` extracts message types, topics, QoS, and client IDs
- **gRPC analysis** — `wireshark_analyze_grpc` with HTTP/2 content-type fallback
- **Result cache** — LRU cache for tshark read-only commands with automatic file-change invalidation

### Changed

- **Concurrent security audit** — 6 independent phases run via `asyncio.gather` (~3x faster)
- **Concurrent quick analysis** — 7 data fetches run in parallel
- **Concurrent TCP health** — 8 checks run concurrently instead of sequentially
- **Docstring optimization** — all 51 tool descriptions slimmed to ~4400 chars total
- **Output format** — emoji replaced with text tags, ASCII box art removed

---

## 1.1.5 — 2026-04-18

Fix TUI arrow-key input (SS3 sequences + BufferedReader race); add Void, BoltAI, Kiro clients.

---

## 1.1.0 — 2026-04-17

OpenCode support, interactive TUI installer, `update` subcommand, bilingual changelog.

---

## 1.0.0 — 2026-03-16

Stable release: suite tools, capabilities API, stable tool surface, threat-intel semantics.

---

## Previous releases

See the full changelog in the [changelog/ directory](https://github.com/bx33661/Wireshark-MCP/tree/main/changelog) on GitHub.
