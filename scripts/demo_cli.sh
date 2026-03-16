#!/usr/bin/env sh

set -eu

run() {
  printf '\n$ %s\n' "$*"
  "$@"
}

run pip install wireshark-mcp
run wireshark-mcp install
run wireshark-mcp doctor
run wireshark-mcp clients
run wireshark-mcp doctor --format json
run wireshark-mcp config
