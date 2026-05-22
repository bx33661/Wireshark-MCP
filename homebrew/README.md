# homebrew-wireshark-mcp

Homebrew tap for [Wireshark MCP](https://github.com/bx33661/Wireshark-MCP) — an MCP server that
turns `tshark` into a structured packet-analysis interface for AI assistants.

## Install

```sh
brew tap bx33661/wireshark-mcp
brew install wireshark-mcp
```

Then auto-configure your MCP clients:

```sh
wireshark-mcp install
```

## Requirements

- macOS (Homebrew)
- Wireshark is installed automatically as a dependency (`brew install wireshark`)

## Updating

```sh
brew update && brew upgrade wireshark-mcp
```

## Formula maintenance

The `Formula/wireshark-mcp.rb` file is auto-updated via a GitHub Actions workflow
whenever a new version is published to PyPI. Maintainers can also trigger it manually:

```
Actions → Bump Formula → Run workflow → enter version
```

A `HOMEBREW_TAP_TOKEN` secret (fine-grained PAT with `contents: write` on this repo)
must be set in the main `bx33661/Wireshark-MCP` repository for auto-dispatch to work.
