# Configuration reference

[中文版](configuration_zh.md)

Every server setting is either a `wireshark-mcp serve` flag or an environment variable. Environment variables are read when the server starts, so set them in the MCP client's `env` block (or the shell that launches the server) and restart the client after a change. Invalid numbers are ignored with a warning and the default applies; numbers outside the allowed range are clamped.

## Optional extras

The base package needs only `tshark`. Extras add features without changing anything else:

| Extra | Install | Adds |
|-------|---------|------|
| `index` | `pip install 'wireshark-mcp[index]'` | DuckDB capture index: `wireshark_index`, and index-backed `wireshark_aggregate` / `wireshark_extract_fields`. See [Capture index](capture-index.md). |
| `geoip` | `pip install 'wireshark-mcp[geoip]'` | `wireshark_geoip_enrich` (also needs a GeoLite2 database, see below). |
| `yara` | `pip install 'wireshark-mcp[yara]'` | `wireshark_yara_scan`. |
| `all` | `pip install 'wireshark-mcp[all]'` | All three. |

The tools are always listed, so the tool list stays the same with or without extras. Without the extra, a call returns an error that names the extra to install.

Which install routes include extras:

| Route | Extras |
|-------|--------|
| `pip` / `uv tool install` | Whatever you name in brackets. |
| Container image `ghcr.io/bx33661/wireshark-mcp` | None. Build a derived image to add them, see [Deployment scenarios](deployment-scenarios.md#containers). |
| Codex / Claude Code plugin | None. The launcher runs the locked project with `--no-dev` and no extras. |

## Server flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--transport` | `stdio` | `stdio`, `streamable-http` or `sse`. |
| `--host` / `--port` | `127.0.0.1` / `8080` | Bind address for HTTP transports. |
| `--allow-insecure-http` | off | Allow an HTTP bind beyond loopback. The transport has no authentication; use only behind a trusted authenticating TLS proxy. |
| `--mount-path` | `/` | Legacy SSE mount path. |
| `--profile` | `full` | Tool surface: `full` (54 tools), `analysis` (no live capture or caller-directed file writes), `core` (also no decryption, dissection overrides or low-level views). |
| `--log-level` | `WARNING` | Server log level on stderr. |

## Paths and permissions

| Variable | Default | Meaning |
|----------|---------|---------|
| `WIRESHARK_MCP_ALLOWED_DIRS` | unset | Comma-separated existing directories. When set, every capture read and file write must stay inside them. When unset, reads are unrestricted (for the OS user) and every file-creating tool fails closed. |
| `WIRESHARK_MCP_CASE_DIR` | first allowed dir + `/.wireshark-mcp-cases` | Where `wireshark_case` keeps case files. Must be inside an allowed root. |
| `WIRESHARK_MCP_INDEX_DIR` | `~/.wireshark-mcp/index` | Where capture indexes, Parquet exports (`exports/`) and query spill files (`.spill/`) live. This is the server's own cache and is not restricted by `WIRESHARK_MCP_ALLOWED_DIRS`; allow roughly 15–20% of the capture size per index, plus room for the build's temporary export. |
| `GEOIP_DB_PATH` | unset | Path to a GeoLite2 `.mmdb` file. Otherwise `~/.wireshark-mcp/geoip/GeoLite2-City.mmdb` (or `-Country`, `-ASN`) is used. |

## Wireshark binaries

The server finds the suite on `PATH` and in the usual install locations. Override a binary when several versions are installed or a GUI client starts with a reduced `PATH`:

| Variable | Binary | Needed for |
|----------|--------|------------|
| `WIRESHARK_MCP_TSHARK_PATH` | `tshark` | Everything (required). |
| `WIRESHARK_MCP_CAPINFOS_PATH` | `capinfos` | File metadata (recommended). |
| `WIRESHARK_MCP_MERGECAP_PATH` | `mergecap` | `wireshark_merge_pcaps` (recommended). |
| `WIRESHARK_MCP_EDITCAP_PATH` | `editcap` | The four editcap tools (trim, split, deduplicate, time shift). |
| `WIRESHARK_MCP_DUMPCAP_PATH` | `dumpcap` | Live capture backend (falls back to `tshark`). |
| `WIRESHARK_MCP_TEXT2PCAP_PATH` | `text2pcap` | `wireshark_text2pcap_import`. |

`wireshark-mcp doctor` shows which binary was found for each and through which variable.

## Limits

| Variable | Default | Range | Meaning |
|----------|---------|-------|---------|
| `WIRESHARK_MCP_MAX_RESULT_CHARS` | 8000 | ≥ 512 | Ceiling on one tool result's text. Larger output is trimmed head-and-tail; use the tool's `offset` / `limit` / `display_filter` to page. |
| `WIRESHARK_MCP_AGGREGATE_SCAN_LIMIT` | 1,000,000 | 1,000–10,000,000 | Matching-row ceiling for a tshark-path `wireshark_aggregate`. An index-backed call uses a fixed 50,000,000-row ceiling instead. |
| `WIRESHARK_MCP_AGGREGATE_TIMEOUT` | 30 s | 5–600 | Time budget for one `wireshark_aggregate` call, on either path. |
| `WIRESHARK_MCP_INDEX_TIMEOUT` | 1800 s | 30–7200 | Time budget for the tshark pass of an index build. |

Fixed limits that are not configurable: aggregate stdout 50 MiB per call; index SQL queries return at most 200 rows, run with a 2 GB memory limit and stop after 60 s (timeline, diff and export after 600 s); live capture stops at five minutes, one million packets or 100 MiB per call.

## Example

A Claude Desktop entry for read-only analysis of one capture directory, with the index enabled and a larger result ceiling:

```json
{
  "mcpServers": {
    "wireshark-mcp": {
      "command": "wireshark-mcp",
      "args": ["serve", "--profile", "analysis"],
      "env": {
        "WIRESHARK_MCP_ALLOWED_DIRS": "/srv/pcaps,/srv/wireshark-results",
        "WIRESHARK_MCP_INDEX_DIR": "/srv/wireshark-index",
        "WIRESHARK_MCP_MAX_RESULT_CHARS": "16000",
        "WIRESHARK_MCP_AGGREGATE_TIMEOUT": "120"
      }
    }
  }
}
```

`wireshark-mcp config` prints the launch command for this machine to start from; see [Manual configuration](manual-configuration.md) for each client's file and field names.
