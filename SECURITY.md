# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

Security fixes are provided for the active `1.x` release line. Older pre-1.0 releases are no longer supported.

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

- **File paths**: The server accepts pcap file paths from the MCP client. Ensure your MCP client is trusted.
- **Credential extraction**: `wireshark_extract_credentials` scans for plaintext credentials in captures. Handle results with care.
- **Live capture**: `wireshark_capture` requires appropriate system permissions (`wireshark` group or root).
- **Threat intelligence**: `wireshark_check_threats` may refresh cached URLhaus data via outbound requests.
