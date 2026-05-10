---
title: Deployment
description: Run Wireshark MCP locally, in Docker, or through an HTTP transport.
---

Most users run Wireshark MCP locally through `stdio`, because packet captures and Wireshark tools usually live on the same workstation as the AI client.

## Local stdio

Use local stdio for desktop clients and CLI agents:

```json
{
  "mcpServers": {
    "wireshark-mcp": {
      "command": "wireshark-mcp",
      "args": []
    }
  }
}
```

This is the simplest mode and avoids exposing packet-analysis tools over the network.

## Docker SSE

Use Docker when you want an isolated runtime:

```sh
docker compose up -d
```

Then point your MCP client to:

```text
http://localhost:8080/sse
```

## Directory sandbox

Set `WIRESHARK_MCP_ALLOWED_DIRS` to restrict which paths the server can read:

```sh
export WIRESHARK_MCP_ALLOWED_DIRS="/captures:/tmp/pcaps"
```

Use this when running a shared service or when captures come from a known workspace.

## Operational checks

Before relying on a deployment:

- run `wireshark-mcp doctor`
- confirm `tshark --version`
- open a known small capture
- run `wireshark_get_capabilities`
- test one packet-list or file-info call

## Security posture

Treat packet captures as sensitive data. Captures can include credentials, session cookies, hostnames, internal IPs, email content, and proprietary protocol payloads. Prefer local execution unless a remote service has an explicit access-control and storage policy.
