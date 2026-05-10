---
title: Extraction and Export
description: Pull structured protocol data and embedded objects from captures.
---

Extraction tools turn packet-level data into tables that are easier to reason about and cite.

## Protocol extraction

| Tool | Extracts | Best used for |
| --- | --- | --- |
| `wireshark_extract_http_requests` | HTTP method, URI, host, and request metadata | Web activity review, CTF pivots, cleartext traffic |
| `wireshark_extract_dns_queries` | DNS query names and record types | Domain inventory, tunneling leads, IOC checks |
| `wireshark_extract_tls_handshakes` | TLS version, cipher, SNI, issuer metadata | Encrypted traffic classification, SNI review |
| `wireshark_extract_smtp_emails` | Sender, recipient, and subject | Mail-flow investigations |
| `wireshark_extract_dhcp_info` | Leases, hostnames, DNS servers, options | Endpoint identification and network setup review |

## Credentials

`wireshark_extract_credentials` searches for cleartext credential exposure in protocols such as HTTP Basic, FTP, and Telnet.

Report credential findings carefully:

- include protocol and frame or stream evidence
- state whether the credential is complete or partial
- avoid printing secrets in full unless the user explicitly needs them for incident handling

## Object export

`wireshark_export_objects` extracts embedded files from supported protocols such as HTTP, SMB, TFTP, IMF, and DICOM.

Use exported objects for:

- malware or payload retrieval
- CTF artifact extraction
- validating file transfers
- recovering evidence from HTTP or SMB sessions

## IP inventory

`wireshark_list_ips` lists unique IP addresses by source, destination, or both. Use it before endpoint enrichment or timeline work.

## Evidence tips

When an extracted row drives a finding, include the field names and display filter used to produce it. For example, cite `dns.qry.name`, `http.host`, `tls.handshake.extensions_server_name`, or the exact stream index that confirms the row.
