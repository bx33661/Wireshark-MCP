---
title: Troubleshooting
description: Fix common installation, client, and tshark issues.
---

## Run doctor first

```sh
wireshark-mcp doctor
```

The doctor command checks the Python package, client-facing command path, and Wireshark CLI tools.

## tshark is not found

Confirm that Wireshark is installed and that `tshark` is on your `PATH`:

```sh
tshark --version
```

If your GUI client cannot see the same shell environment, generate a config with absolute paths:

```sh
wireshark-mcp config
```

## Client starts but tools fail

Check that the capture file path is readable by the MCP server process. If you use the directory sandbox, confirm `WIRESHARK_MCP_ALLOWED_DIRS` includes the directory that contains the capture.

## Live capture fails

Live capture may require OS-specific capture permissions. Install Wireshark normally, verify `dumpcap` if available, and rerun:

```sh
wireshark-mcp doctor
```

## Docker SSE mode

```sh
docker compose up -d
```

Then point your MCP client to:

```text
http://localhost:8080/sse
```
