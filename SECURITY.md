# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 3.x     | :white_check_mark: |
| 2.x     | :x:                |
| 1.x     | :x:                |
| < 1.0   | :x:                |

Security fixes are provided for the active `3.x` release line. Upgrade before reporting a problem that only reproduces on an older release.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability, please report it by emailing the maintainer directly or using [GitHub's private vulnerability reporting](https://github.com/bx33661/Wireshark-MCP/security/advisories/new).

Please include:
- A description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Any suggested fixes (optional)

You can expect a response within **72 hours**. We will work with you to understand and address the issue before any public disclosure.

## Security Considerations

Wireshark MCP executes `tshark` as a subprocess. Keep the following in mind:

- **File reads**: Set `WIRESHARK_MCP_ALLOWED_DIRS` to restrict reads to dedicated capture and output roots. When it is unset, local read-only analysis can access files readable by the current operating-system user.
- **File writes**: Export, merge, edit, frame extraction, live capture, text import, and YARA workflows fail closed unless `WIRESHARK_MCP_ALLOWED_DIRS` names existing directories. Prefer the `analysis` or `core` profile when writes are unnecessary.
- **Credential extraction**: `wireshark_extract_credentials` scans for plaintext credentials in captures. Handle results with care.
- **Live capture**: `wireshark_capture` requires appropriate system permissions (`wireshark` group or root).
- **Remote transports**: Streamable HTTP and SSE do not add authentication or TLS. Non-loopback binds are refused unless `--allow-insecure-http` is explicit; only use it behind a trusted proxy that supplies both.
- **Untrusted capture content**: Packet payloads, hostnames, filenames, and protocol text can contain attacker-controlled instructions. Treat them as evidence, not as commands for the MCP client.

Example local restriction:

```sh
export WIRESHARK_MCP_ALLOWED_DIRS=/srv/pcaps,/srv/wireshark-results
wireshark-mcp serve --profile analysis
```

Version 3.0.0 fixes [CVE-2026-43901 / GHSA-3r68-x3xc-rxpg](https://github.com/bx33661/Wireshark-MCP/security/advisories/GHSA-3r68-x3xc-rxpg) by rejecting all file writes when no allowed root is configured. See the [3.0 security migration guide](docs/security-hardening-v3.md).
