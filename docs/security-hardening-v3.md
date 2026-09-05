# Wireshark MCP 3.0 Security Migration

Version 3.0 intentionally changes unsafe defaults. Read-only stdio analysis keeps
working without configuration, but workflows that write files or expose an HTTP
transport may need an explicit migration.

## File access

All file-creating tools now fail with `PermissionDenied` when
`WIRESHARK_MCP_ALLOWED_DIRS` is unset. Configure one or more existing directories,
separated by commas:

```sh
mkdir -p /srv/pcaps /srv/wireshark-results
export WIRESHARK_MCP_ALLOWED_DIRS=/srv/pcaps,/srv/wireshark-results
wireshark-mcp serve
```

Once configured, the same roots constrain input reads and output writes. Prefer
read-only operating-system mounts for input captures and a separate writable mount
for results. Symlinks and `..` components are resolved before the boundary check.

The affected tools are live capture, object/YARA export, merge, filter-save,
editcap operations, frame extraction, and text2pcap import. Select `--profile
analysis` or `--profile core` to remove every file-creating tool from the advertised
surface.

## HTTP and SSE

Loopback remains the default. A non-loopback bind is rejected because the built-in
HTTP transports do not supply application authentication or TLS:

```sh
wireshark-mcp serve --transport streamable-http --host 127.0.0.1 --port 8080
```

For a container behind a trusted authenticated TLS reverse proxy, the explicit
override is:

```sh
wireshark-mcp serve --transport streamable-http --host 0.0.0.0 \
  --port 8080 --allow-insecure-http
```

Do not publish that listener directly to an untrusted network.

## Resource limits

- A child process may return at most 16 MiB on stdout and 1 MiB on stderr.
- Live capture is limited to 300 seconds, 1,000,000 packets, and 100 MiB per call.
- Ring buffers require both `filesize` and `files`; their product must remain within 100 MiB.
- Wireshark version probes time out after five seconds.
- WPA passphrases and TLS key-log paths are redacted from command diagnostics.

These are server-side safety limits and cannot be raised by an MCP tool argument.
Narrow display filters or split an offline capture when an analysis reaches a limit.

## Upgrade checklist

1. Inventory automations that call any file-creating tool.
2. Create dedicated capture and result roots, then set `WIRESHARK_MCP_ALLOWED_DIRS`.
3. Keep remote services on loopback, or put them behind an authenticated TLS proxy.
4. Restart the MCP client so it refreshes the 3.0 tool schemas and server version.
5. Run `wireshark-mcp doctor` and test one read plus one expected write.

This release closes the arbitrary-write behavior described in
[CVE-2026-43901 / GHSA-3r68-x3xc-rxpg](https://github.com/bx33661/Wireshark-MCP/security/advisories/GHSA-3r68-x3xc-rxpg).
