# Architecture

[中文版](architecture_zh.md)

Wireshark MCP is a local orchestration layer around the Wireshark command-line suite. Packet facts come from `tshark` and related binaries; the MCP server selects commands, validates paths and arguments, normalizes results, and keeps model context bounded.

## Request path

```text
MCP client
  → WiresharkMCP (tool schema, profiles, annotations, result ceiling)
    → tool function (workflow and domain semantics)
      → WiresharkSuiteClient (validation, command construction, cache)
        → tshark / capinfos / editcap / mergecap / dumpcap / text2pcap
      → CaptureIndex (optional DuckDB index: build once, then read-only SQL)
```

`src/wireshark_mcp/server.py` creates one server and one suite client, then registers tools, prompts, and resources. The public tool list is static during a session. `wireshark_open_file` inspects the protocol hierarchy and recommends already-registered tools; it does not mutate the catalog.

## MCP SDK compatibility

The server targets the stable Python SDK 2.x line (`mcp>=2.1.1,<3`) and subclasses `MCPServer`. HTTP bind settings are passed when the transport starts, as required by v2; the legacy `--mount-path` CLI option is translated into explicit SSE and message endpoint paths. Protocol models use snake_case Python attributes and camelCase aliases on the wire. An in-memory client test performs a complete v2 negotiation, checks the advertised server version, and lists the public tools through the protocol rather than through private managers.

## Main modules

| Area | Location | Responsibility |
|------|----------|----------------|
| Server and CLI | `server.py` | Commands, transports, profiles, registration order |
| MCP behavior | `mcp_app.py` | Schema trimming, annotations, exclusions, result character ceiling |
| Profiles | `profiles.py` | Literal tool exclusions for `full`, `analysis`, and `core` |
| Tool annotations | `tool_annotations.py` | Read-only, destructive, and open-world hints |
| Domain tools | `tools/` | Packet, protocol, Bluetooth LE, statistics, security, file, and workflow semantics |
| Findings | `tools/findings.py` | The shared finding shape, stable ids, `reproduce` commands and ATT&CK candidates |
| Case files | `cases.py`, `tools/case.py` | JSON case store under the allowed write root and the Markdown report rendered from it |
| Capture index | `index/` | DuckDB build, freshness, display-filter-to-SQL translation, aggregate pushdown gates, timeline/diff/export (optional `[index]` extra) |
| Toolchain | `toolchain.py` | Wireshark binary names, override variables and requirement levels shared by the client and `doctor` |
| Suite client | `tshark/` | Path validation, subprocess execution, extraction, capture, statistics, cache |
| Installer | `installer/` | Client detection, config generation, atomic config writes, diagnostics |
| Prompts/resources | `prompts.py`, `resources.py` | Built-in workflows and field/filter references |

## Tool registration and profiles

Registration order is deterministic because tool-list bytes are part of the repeated MCP prompt prefix. `WiresharkMCP.add_tool` removes redundant schema titles, attaches annotations, and rejects tools excluded by the active profile before they enter the manager.

- `full`: every tool
- `analysis`: excludes live capture and file-writing operations
- `core`: also excludes decryption, dissection overrides, and low-level views

Runtime prompts and protocol recommendations are filtered against the selected profile. Documentation tests separately ensure that every named tool exists in the full catalog.

## Command execution and results

All Wireshark binaries are launched with argument arrays, not shell command strings. The client permits only known suite binaries, redacts key material in diagnostics, caps subprocess output, reaps timed-out processes, and returns a JSON envelope:

```json
{"success": true, "data": "...", "stderr": "...", "truncated": true}
```

Optional fields appear only when relevant. Command failures use `success: false` with a typed error object. Diagnostic stderr stays separate from stdout so JSON and field output remain parseable.

Read-only command results are cached by resolved capture path, modification time, size, and command arguments. Pagination is normally applied after cache lookup. Full-capture aggregation uses a separate row-consumer seam: each tshark field row is decoded and folded directly into a bounded accumulator, without retaining the complete stdout or a packet-row list. The seam enforces both row and byte ceilings, terminates and reaps the child on overflow, timeout, or cancellation, drains stderr concurrently, and never caches streamed output.

## Capture index

`wireshark_index` runs one `tshark -T fields` pass over the capture, loads the text into a DuckDB file under `WIRESHARK_MCP_INDEX_DIR`, and records the capture's size, mtime, SHA-256 and tshark version. An index is used only while size and mtime still match. `wireshark_aggregate` and `wireshark_extract_fields` check for a fresh index first; they use it only when the field set and the display filter translate to SQL with tshark's exact meaning, and otherwise fall back to the tshark path and say why in `coverage.index_unused`. Grouping runs inside DuckDB only behind exactness gates; the tshark-equivalence tests run every aggregate case through both paths.

Queries open an in-memory DuckDB connection, attach each index read-only, then disable external access, lock the configuration and cap memory, so user SQL cannot read other files, write or reach the network. Packet-level evidence never comes from the index: detail, bytes and stream tools always dissect live. See [Capture index](capture-index.md).

## Findings and case files

Detectors pass their findings through `finalize_findings`, so every tool emits the same fields and the same content-hash id for the same evidence. `wireshark_quick_analysis` renders its Markdown from those findings rather than through a second renderer. `wireshark_case` is the only stateful tool: it stores captures (with SHA-256), recorded results, findings merged by id, verdicts and notes as JSON, never re-runs tshark, and renders its report only from the stored record. See [Findings and cases](findings-and-cases.md).

## Result ceiling

At the MCP boundary, long text is capped by `WIRESHARK_MCP_MAX_RESULT_CHARS` (default 8000). Tools should still bound their own result shape because transport-level truncation is a last resort.

## Security boundaries

- Capture and output paths are validated by the suite client.
- `WIRESHARK_MCP_ALLOWED_DIRS` restricts readable and writable paths to configured roots; writes fail closed when it is unset.
- File-creating tools are explicitly marked destructive; clients may require approval.
- `wireshark_index` writes only the server's own cache under `WIRESHARK_MCP_INDEX_DIR` (indexes, Parquet exports, spill files) and is annotated non-destructive. Index files hold packet field values, so protect that directory like the captures.
- Case files are written only under an allowed root and fail closed without one.
- Live capture is marked open-world and depends on host capture permissions.
- Streamable HTTP and SSE do not add authentication. Non-loopback binds require `--allow-insecure-http` and a trusted authenticated TLS proxy.
- Packet content is untrusted input. Tool output may inform an investigation but must not be treated as instructions to run unrelated commands or write outside the task scope.

Live capture is bounded to five minutes, one million packets, and 100 MiB of output per call. Ring buffers require both a file-size and file-count bound whose product stays within the same storage ceiling.

## Adding or changing a tool

1. Prefer extending an existing parameterized tool when the capability shares its evidence model.
2. Put tshark command construction in the suite client and analysis semantics in `tools/`.
3. Return normalized success or error envelopes instead of raising expected user errors.
4. Add unit tests plus a real-pcap test when tshark parsing or protocol semantics change.
5. Check profile reachability, annotations, tool-list size, result bounds, both READMEs, and `changelog/unreleased.md`.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for commands and the [release checklist](release-checklist.md) for final validation.
