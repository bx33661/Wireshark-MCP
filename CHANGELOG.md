# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2025-06-27

### Added

#### 🚀 Agentic Workflows — Server-side Orchestrated Analysis
- `wireshark_security_audit`: One-call comprehensive security audit (8 analysis phases, risk scoring 0-100, structured report with findings and recommendations)
- `wireshark_quick_analysis`: One-call traffic overview (file info, protocol distribution, top talkers, conversations, hostnames, anomaly summary)

#### 🔍 Progressive Discovery — Dynamic Tool Registration
- `wireshark_open_file`: New entry-point tool that analyzes pcap content and dynamically activates protocol-specific tools
- `ToolRegistry` system: Server starts with ~17 core tools; protocol-specific tools activate on demand when matching protocols are detected
- `PROTOCOL_TOOL_MAP`: Configurable mapping from protocols (HTTP, DNS, TLS, etc.) to relevant tool sets

### Changed
- Security tools (`wireshark_check_threats`, `wireshark_extract_credentials`) are now contextual — activated via `wireshark_open_file`
- Protocol tools (`wireshark_extract_tls_handshakes`, `wireshark_analyze_tcp_health`, `wireshark_detect_arp_spoofing`, `wireshark_extract_smtp_emails`, `wireshark_extract_dhcp_info`) are now contextual
- Threat detection tools (`wireshark_detect_port_scan`, `wireshark_detect_dns_tunnel`, `wireshark_detect_dos_attack`, `wireshark_analyze_suspicious_traffic`) are now contextual
- Extract tools (`wireshark_extract_http_requests`, `wireshark_extract_dns_queries`, `wireshark_export_objects`, `wireshark_verify_ssl_decryption`) are now contextual

## [0.4.0] - 2025-06-01

### Added
- `wireshark_get_packet_bytes`: Get raw Hex/ASCII dump (Packet Bytes view)
- `wireshark_get_packet_context`: View packets surrounding a specific frame (before and after) to understand context
- `wireshark_search_packets` enhanced with `scope` parameter:
  - `scope="bytes"`: Search in raw payload (Hex/String)
  - `scope="details"`: Search in decoded text/fields with Regex support
- `wireshark_follow_stream` now supports pagination (`offset_lines`) and content search (`search_content`)

### Changed
- `wireshark_get_packet_list` now supports custom columns (e.g., `"ip.src,http.host"`)
- `wireshark_get_packet_details` now supports layer filtering (e.g., `"ip,tcp,http"`) to reduce token usage

### Deprecated
- `wireshark_read_packets`: Use `wireshark_get_packet_details` instead

## [0.2.1] - 2025-05-01

### Added
- Initial public release
- Core packet analysis tools: `wireshark_get_packet_list`, `wireshark_get_packet_details`, `wireshark_follow_stream`
- Data extraction: `wireshark_extract_fields`, `wireshark_extract_http_requests`, `wireshark_extract_dns_queries`, `wireshark_list_ips`, `wireshark_export_objects`
- Statistics: protocol hierarchy, endpoints, conversations, I/O graph, expert info, service response time
- File operations: `wireshark_get_file_info`, `wireshark_merge_pcaps`, `wireshark_filter_save`
- Live capture: `wireshark_list_interfaces`, `wireshark_capture`
- Security: `wireshark_check_threats` (URLhaus), `wireshark_extract_credentials`
- Decoding: `wireshark_decode_payload` with auto-detection (Base64, Hex, URL, Gzip, Deflate, Rot13)
- Visualization: ASCII traffic plot, ASCII protocol hierarchy tree

[Unreleased]: https://github.com/bx33661/Wireshark-MCP/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/bx33661/Wireshark-MCP/compare/v0.4.0...v0.6.0
[0.4.0]: https://github.com/bx33661/Wireshark-MCP/compare/v0.2.1...v0.4.0
[0.2.1]: https://github.com/bx33661/Wireshark-MCP/releases/tag/v0.2.1
