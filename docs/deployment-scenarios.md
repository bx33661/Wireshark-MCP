# Deployment Scenarios

## Local desktop or CLI client

Use stdio and let the installer write an isolated Python path:

```sh
wireshark-mcp install
```

Run `wireshark-mcp clients` first when you want to inspect detected targets. In managed environments, generate the configuration with `wireshark-mcp config` and review it before changing client files.

For read-only offline analysis with the smallest tool surface:

```sh
wireshark-mcp serve --profile core
```

## SSH or a remote analysis host

Run Streamable HTTP on remote loopback:

```sh
wireshark-mcp serve --transport streamable-http --host 127.0.0.1 --port 8080
```

Forward it from the client machine:

```sh
ssh -L 8080:127.0.0.1:8080 user@analysis-host
```

Configure the client with the remote MCP URL `http://127.0.0.1:8080/mcp`.
The `wireshark-mcp config` command emits local stdio configuration, not remote URLs.

Keep the service on loopback unless TLS and authentication are supplied by a
trusted reverse proxy. The server does not add authentication to HTTP or SSE transports,
and 3.0 refuses a non-loopback bind unless `--allow-insecure-http` is supplied.

## Containers

Mount captures read-only and limit the server's allowed directories:

```sh
docker run --rm -p 127.0.0.1:8080:8080 \
  -v "$PWD/captures:/captures:ro" \
  -v "$PWD/results:/results" \
  -e WIRESHARK_MCP_ALLOWED_DIRS=/captures,/results \
  IMAGE wireshark-mcp serve --transport streamable-http --host 0.0.0.0 --port 8080 --allow-insecure-http
```

Prefer offline PCAP analysis. Live capture needs an explicit interface and
container-capability policy. Omit the writable results mount and use the `core`
profile if no file-creating tool is needed.

File-creating tools are disabled until `WIRESHARK_MCP_ALLOWED_DIRS` names existing
directories. The same roots constrain reads once configured. See the
[3.0 security migration guide](security-hardening-v3.md) before upgrading an
automation that exports, captures, merges, or edits files.

## WSL

Install Wireshark CLI tools and `wireshark-mcp` inside the same distribution.
Use Linux paths. If a Windows client cannot reliably launch a WSL stdio command,
run Streamable HTTP inside WSL and connect through localhost.

## CI and automation

Non-interactive use must declare scope:

```sh
wireshark-mcp clients --client cursor --format json
wireshark-mcp config
wireshark-mcp install --client cursor
wireshark-mcp doctor --format json
wireshark-mcp clients --format json
```

`doctor` and `clients` provide JSON output. Review the generated config before
running `install` in a managed image.

## Recovery

The installer writes configuration atomically but does not keep a rollback
archive. Back up managed client configuration before installation. To remove the
server entry later, run:

```sh
wireshark-mcp uninstall --client cursor
```

`update` only rewrites clients that already contain a `wireshark-mcp` entry.
