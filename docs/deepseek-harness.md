# DeepSeek Harness integration

[中文版](deepseek-harness_zh.md)

DeepSeek Harness (DSH) is not in the client-detection list, so `wireshark-mcp install` will
not wire it up. This page records what was measured on one DSH installation, so the next
person does not have to rediscover it.

> **Tested on DeepSeek Harness `0.2.2-rc.5` only. No other DSH version was tested.**
> Everything below is a record of that build, not a compatibility statement. DSH is
> pre-release software; its plugin loader, MCP bridge and permission pipeline can change
> between builds, and any of them can change the behaviour described here.

## What was measured

| Item | Value |
|---|---|
| DSH version | `0.2.2-rc.5`, `web` profile |
| Host | Windows 11 23H2, x64 |
| Server | `wireshark-mcp` 4.0.0 with the `[index]` extra |
| Engine | Wireshark / TShark 4.6.10 |
| Python | 3.13.17, dedicated venv |
| MCP SDK on the client side | `@modelcontextprotocol/client` 2.2.0 (shipped with DSH) |
| Negotiated protocol | `2025-11-25` (server advertises up to `2026-07-28`) |
| Tool surface | 54 tools on `--profile full` |

## Wiring it up

DSH mounts MCP servers through its plugin loader, not through a JSON client file. A
configuration-only bundle inserts one `@deepseek-ai/dsh-mcp-client` row:

```yaml
- insert:
    - id: wireshark-mcp
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: wireshark
        transport: stdio
        command: 'C:\path\to\venv\Scripts\python.exe'
        args: ['-u', '-m', 'wireshark_mcp.server', 'serve', '--profile', 'full']
        toolCallTimeoutMs: 300000
        failOnStartupError: false
        env:
          WIRESHARK_MCP_TSHARK_PATH: 'C:\path\to\Wireshark\tshark.exe'
          WIRESHARK_MCP_CAPINFOS_PATH: 'C:\path\to\Wireshark\capinfos.exe'
          WIRESHARK_MCP_MERGECAP_PATH: 'C:\path\to\Wireshark\mergecap.exe'
          WIRESHARK_MCP_EDITCAP_PATH: 'C:\path\to\Wireshark\editcap.exe'
          WIRESHARK_MCP_DUMPCAP_PATH: 'C:\path\to\Wireshark\dumpcap.exe'
          WIRESHARK_MCP_TEXT2PCAP_PATH: 'C:\path\to\Wireshark\text2pcap.exe'
          WIRESHARK_MCP_ALLOWED_DIRS: 'D:\pcaps,D:\wireshark-results'
          WIRESHARK_MCP_INDEX_DIR: 'D:\wireshark-results\index'
          PYTHONIOENCODING: 'utf-8'
```

Tools then reach the model as `mcp__<serverName>__<tool>` — `mcp__wireshark__wireshark_aggregate`,
not the server-side short name. The doubled word is DSH's naming contract, not a server bug.

Two settings matter more than they look:

- **Pin the binary paths.** The Windows Wireshark installer does not add its directory to
  `PATH`. Pinning the six `WIRESHARK_MCP_*_PATH` overrides ensures every suite tool resolves
  to the intended installation rather than failing or picking up a stale binary.
- **Raise `toolCallTimeoutMs`.** DSH defaults to 60 s per `tools/call`. A DuckDB index build
  on a multi-GB capture, or a whole-capture statistic on the tshark path, does not fit.
  300 s was comfortable here; the slowest measured call was a 56 s index build.

## Behaviour differences worth knowing

These are properties of the DSH bridge as of `0.2.2-rc.5`, not of this server.

**MCP prompts are not bridged.** The client handles `tools/list` and `resources/*` but not
`prompts/list`, so the six built-in prompts (`security_audit`, `performance_analysis`,
`incident_response`, `traffic_overview`, `analyze_with_hypothesis`, `investigate_alert`) are
unreachable from DSH. Read the prompt text from
[`src/wireshark_mcp/prompts.py`](../src/wireshark_mcp/prompts.py) and paste it, or re-publish
each one as a DSH command.

**Tool annotations are dropped.** MCP `readOnlyHint` / `destructiveHint` do not reach the
permission layer, so all 54 tools look alike to it. On this build, 41 are annotated read-only
and 13 write files. Configure approval rules by tool name, not by annotation.

**MCP resources work.** `list_mcp_resources` / `read_mcp_resource` reach all four resources
and the case-file template; `wireshark://capabilities` is the cheapest health check.

**Result ceilings are enforced twice.** The server caps a result at
`WIRESHARK_MCP_MAX_RESULT_CHARS`; DSH also caps what it forwards. Raising the server value
without checking the client side does not necessarily give the caller more text.

## Known limits on the tshark 4.6.10 + DSH 0.2.2-rc.5 pairing

- `wireshark_geoip_enrich` needs the `geoip` extra *and* a GeoLite2 database;
  `wireshark_yara_scan` needs the `yara` extra. Both fail as `DependencyMissing` rather than
  returning an empty result, which is the honest behaviour but is still a failed call.
- Live capture on an adapter with no traffic returns `success: true` and a 0-packet file.
  Check `wireshark_get_file_info` before concluding anything about the network.

## Verification checklist

After wiring DSH up, or after upgrading either side:

1. `wireshark_get_capabilities` — six binaries `available`, versions match the engine you
   expect. A `false` here explains exactly which specialized tool will fail.
2. `wireshark_open_file` on a known capture — real capinfos metadata, not "Detailed file
   metadata unavailable" (that string means an engine older than 3.6).
3. `wireshark_aggregate` on a small capture — a plausible count with `coverage` present.
4. `wireshark_index` then the same aggregate — `coverage.source` becomes `"index"` with the
   same numbers.
5. A write into an allowed root succeeds, and the same write outside it returns
   `PermissionDenied`. This proves the fence is armed.
6. Tool count matches the profile you asked for (54 / 42 / 34).

## Reporting a DSH problem

If something breaks after a DSH upgrade, it is more useful to report the DSH build, the
negotiated protocol version, and whether the same call works from the Python MCP SDK
directly. That separates a server regression from a bridge change.
