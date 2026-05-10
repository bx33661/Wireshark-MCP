---
title: Protocol Analysis
description: Deep-dive into modern protocols — QUIC, WebSocket, MQTT, gRPC, and TCP health.
---

Wireshark MCP includes contextual protocol analysis tools that activate automatically when `wireshark_open_file` detects the relevant protocol in a capture.

## Protocol tools

| Tool | Analyzes | Best used for |
| --- | --- | --- |
| `wireshark_analyze_tcp_health` | Retransmissions, dup ACKs, zero window, window full, resets, out-of-order, keep-alive | Connection quality diagnosis and troubleshooting |
| `wireshark_analyze_quic` | QUIC version, connection IDs, SNI, HTTP/3 frame types | Modern web transport analysis (Chrome, HTTP/3 sites) |
| `wireshark_analyze_websocket` | Frame opcodes (text/binary/close), payload lengths, masking | Real-time application debugging (chat, gaming, live data) |
| `wireshark_analyze_mqtt` | Message types, topics, QoS levels, client IDs with topic frequency | IoT device traffic analysis and broker monitoring |
| `wireshark_analyze_grpc` | Method paths, message lengths, content-type detection | Microservice call tracing and API debugging |

## Contextual activation

These tools are not always visible. They appear in the recommended tool list when `wireshark_open_file` detects matching protocols in the capture's protocol hierarchy:

| Detected protocol | Tools activated |
| --- | --- |
| `quic`, `http3` | `wireshark_analyze_quic` |
| `websocket` | `wireshark_analyze_websocket` |
| `mqtt` | `wireshark_analyze_mqtt` |
| `grpc`, `http2` | `wireshark_analyze_grpc` |
| `tcp` | `wireshark_analyze_tcp_health` |

## Performance

TCP health and all protocol tools run their tshark queries concurrently using `asyncio.gather`, making them significantly faster than sequential execution — especially TCP health which runs 8 independent checks in parallel.

## Usage notes

- **QUIC**: Also checks for HTTP/3 frames when QUIC traffic is present. Reports both QUIC connection metadata and HTTP/3 frame types.
- **gRPC**: Falls back to HTTP/2 content-type detection (`application/grpc`) if the native gRPC dissector is unavailable in your tshark version.
- **MQTT**: Provides topic frequency analysis — useful for identifying chatty IoT devices or unexpected publish patterns.
- **WebSocket**: Counts text, binary, and close frames separately to help identify connection lifecycle issues.
- **TCP health**: Classifies severity by packet count: `[OK]` (0), `[i]` (1-50), `[W]` (51-200), `[!]` (200+).

## Evidence tips

When a protocol tool surfaces an issue, confirm it with:

- `wireshark_follow_stream` to see the full conversation
- `wireshark_get_packet_details` for individual frame inspection
- `wireshark_extract_fields` for custom field extraction with display filters
