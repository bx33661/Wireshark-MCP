# Contributing to Wireshark MCP

Thank you for your interest in contributing! This guide will help you get started.

## Development Setup

**Requirements**: Python 3.10+, [uv](https://docs.astral.sh/uv/), Wireshark (for `tshark`)

```sh
# Clone the repo
git clone https://github.com/bx33661/Wireshark-MCP.git
cd Wireshark-MCP

# Install in editable mode with dev dependencies
pip install -e .
pip install pytest pytest-asyncio ruff mypy
```

## Running Tests

```sh
# Run all tests
python -m unittest discover tests

# Or with pytest
pytest tests/
```

## Code Style

This project uses [ruff](https://docs.astral.sh/ruff/) for linting and formatting.

```sh
# Check for issues
ruff check src/

# Auto-fix
ruff check --fix src/

# Format
ruff format src/
```

**Key conventions:**
- All functions must have type hints
- All I/O-bound tool functions must be `async`
- Tools must return JSON error objects `{"success": False, "error": {...}}` instead of raising exceptions
- Use `TSharkClient` for all system calls — never call `subprocess` directly in tools

## Project Architecture

```
src/wireshark_mcp/
├── server.py          # MCP server entry point and tool registration
├── tshark/
│   └── client.py      # Core logic wrapping TShark CLI commands
└── tools/             # Individual tool definitions
    ├── extract.py     # Packet analysis and data extraction
    ├── stats.py       # Statistics tools
    ├── files.py       # File operation tools
    ├── capture.py     # Live capture tools
    ├── security.py    # Security analysis tools
    ├── decode.py      # Payload decoding tools
    └── visualize.py   # ASCII visualization tools
```

## Submitting Changes

1. **Fork** the repository and create a branch from `main`
2. **Write or update tests** for your changes
3. **Ensure all tests pass**: `pytest tests/`
4. **Lint your code**: `ruff check src/`
5. **Add a change record** under `spec/changes/` following the format in `spec/README.md`
6. **Open a Pull Request** — fill in the PR template

## Adding a New Tool

1. Add your tool function to the appropriate file in `src/wireshark_mcp/tools/`
2. Register it in `server.py`
3. Document it in `README.md` and `README_zh.md`
4. Add tests in `tests/`

## Reporting Bugs

Please use the [Bug Report issue template](https://github.com/bx33661/Wireshark-MCP/issues/new?template=bug_report.yml).

## Requesting Features

Please use the [Feature Request issue template](https://github.com/bx33661/Wireshark-MCP/issues/new?template=feature_request.yml).
