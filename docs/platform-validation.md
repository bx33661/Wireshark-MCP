# Platform Validation

This checklist records manual evidence for the active stable release:

- Windows works
- Linux works
- macOS works
- installation stays simple
- the documented verification path matches the real product

## Automated Evidence

The repository already validates the following automatically:

- unit and integration-oriented tests on `ubuntu-latest`, `windows-latest`, and `macos-latest`
- packaged CLI smoke tests on `ubuntu-latest`, `windows-latest`, and `macos-latest`
- real `tshark` integration tests on Linux and Windows

Manual validation is still required before a major release because GUI MCP clients and local Wireshark installs vary across hosts.

## Core Acceptance Criteria

Every platform should pass these checks:

1. `wireshark-mcp --version`
2. `wireshark-mcp doctor`
3. `wireshark-mcp clients`
4. `wireshark-mcp config`
5. `wireshark-mcp install`
6. `wireshark-mcp doctor --format json`
7. `wireshark-mcp clients --format json`
8. Open a small `.pcap` in an MCP client and run:

```text
Use wireshark_open_file on this capture, run wireshark_quick_analysis, then use wireshark_aggregate to count packets by ip.src. Verify the busiest source with wireshark_get_packet_list.
```

Expected result:

- the server starts
- `doctor` reports `tshark` as available
- `clients` reports the expected local config targets
- the JSON forms of `doctor` and `clients` are parseable and complete enough for automation
- `config` renders a valid snippet for the current machine
- the MCP client can call `wireshark_open_file`, `wireshark_quick_analysis`, `wireshark_aggregate`, and a packet-level tool successfully
- the aggregate packet counts agree with a direct tshark check on the same filter

## macOS Checklist

1. Install Python `3.10+`.
2. Install Wireshark and confirm `tshark` is available.
3. Run:

```sh
uv tool install wireshark-mcp
wireshark-mcp --version
wireshark-mcp doctor
wireshark-mcp clients
wireshark-mcp install
wireshark-mcp config
```

4. Restart the target MCP client.
5. Open a sample `.pcap` and run the acceptance prompt above.

Optional:

- if live capture matters for the release, confirm `dumpcap` is detected and a short capture can start

## Linux Checklist

1. Install Python `3.10+`.
2. Install Wireshark or the distro package that provides `tshark`.
3. Run:

```sh
uv tool install wireshark-mcp
wireshark-mcp --version
wireshark-mcp doctor
wireshark-mcp clients
wireshark-mcp install
wireshark-mcp config
```

4. Restart the target MCP client.
5. Open a sample `.pcap` and run the acceptance prompt above.

Optional:

- if live capture matters for the release, confirm the host has the required capture permissions

## Windows Checklist

1. Install Python `3.10+`.
2. Install Wireshark and keep the `TShark` component enabled.
3. In PowerShell or Command Prompt, run:

```powershell
uv tool install wireshark-mcp
wireshark-mcp --version
wireshark-mcp doctor
wireshark-mcp clients
wireshark-mcp install
wireshark-mcp config --format codex-toml
```

4. Restart the target MCP client.
5. Open a sample `.pcap` and run the acceptance prompt above.

Windows-specific note:

- GUI clients often do not inherit the shell `PATH`, so `doctor` and `install` should both be checked before release sign-off
- UTF-8 JSON configs with a BOM are supported; malformed client configs are reported and left untouched
- device namespace paths, reserved device names, and NTFS alternate data streams are rejected by file tools
- Wireshark child processes are launched without opening console windows

## Release Sign-Off

Do not call the major release ready until:

- all automated CI jobs are green
- at least one manual validation run was completed on each OS family
- the documented commands above still match the current CLI output
- `full`, `analysis`, and `core` advertise the documented tool counts
