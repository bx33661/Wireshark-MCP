# Wireshark MCP v1.0.0

Wireshark MCP `v1.0.0` is now live.

This release turns the project from a fast-moving toolkit into a stable `1.x` baseline: Windows, Linux, and macOS are all in scope, installation is simpler, diagnostics are stronger, and the documentation has been tightened up so teams can adopt it with less guesswork.

## Short Version

`Wireshark MCP v1.0.0` is out.

- Stable `1.0` baseline for Windows, Linux, and macOS
- `tshark` remains the only required Wireshark dependency
- Optional suite tools like `capinfos`, `mergecap`, `editcap`, `dumpcap`, and `text2pcap` are auto-detected
- Better install and diagnostics flow with `install`, `doctor`, `clients`, and `config`
- New machine-readable `doctor --format json` and `clients --format json`
- Documentation now matches the real `1.0` workflow end to end

GitHub Release: <https://github.com/bx33661/Wireshark-MCP/releases/tag/v1.0.0>  
PyPI: <https://pypi.org/project/wireshark-mcp/>

## Full Announcement

`v1.0.0` is our "stable for a while" release.

The goal for this version was not to ship the most new features possible. The goal was to make the project feel dependable: clear install paths, predictable CLI behavior, explicit platform support, stronger release metadata, and documentation that actually reflects how the project works today.

What changed in `1.0`:

- The project now commits to a real `1.0` baseline across Windows, Linux, and macOS.
- The server keeps a stable tool surface for the full MCP session, while `wireshark_open_file` recommends the most relevant tools for a given capture.
- Threat-intelligence matching is now aligned with captured HTTP URLs plus DNS and TLS hostnames, which makes the workflow more reproducible.
- The CLI is more product-like, with clearer subcommands and better diagnostics.
- `doctor` and `clients` now support JSON output, which helps with automation, issue templates, and CI-style validation.
- The README was trimmed into more of a landing page, while detailed setup and prompt guidance moved into focused `docs/` pages.

For `v1.0`, "stable" means that if one of the documented baseline promises breaks, we treat it as a `1.0.x` bug to fix, not as a future enhancement.

## Upgrade Notes

- Install or upgrade from PyPI:

```sh
pip install --upgrade wireshark-mcp
```

- Verify your environment:

```sh
wireshark-mcp doctor
wireshark-mcp clients
```

- If you want machine-readable output for validation or support bundles:

```sh
wireshark-mcp doctor --format json
wireshark-mcp clients --format json
```

## Key Links

- GitHub Release: <https://github.com/bx33661/Wireshark-MCP/releases/tag/v1.0.0>
- PyPI: <https://pypi.org/project/wireshark-mcp/>
- Changelog: <https://github.com/bx33661/Wireshark-MCP/blob/main/CHANGELOG.md>
- README: <https://github.com/bx33661/Wireshark-MCP/blob/main/README.md>
