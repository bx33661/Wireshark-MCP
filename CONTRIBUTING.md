# Contributing to Wireshark MCP

Thank you for your interest in contributing! This guide will help you get started.

## Development Setup

**Requirements**: Python 3.10+, [uv](https://docs.astral.sh/uv/), Wireshark (for `tshark`)

```sh
# Clone the repo
git clone https://github.com/bx33661/Wireshark-MCP.git
cd Wireshark-MCP

# Install the locked development environment
uv sync --group dev
```

## Running Tests

```sh
uv run python -m pytest tests/
```

## Code Style

This project uses [ruff](https://docs.astral.sh/ruff/) for linting and formatting.

```sh
# Check for issues
uv run python -m ruff check src/ tests/

# Auto-fix
uv run python -m ruff check --fix src/ tests/

# Format
uv run python -m ruff format src/ tests/

# Type check
uv run python -m mypy --package wireshark_mcp --ignore-missing-imports --no-namespace-packages
```

**Key conventions:**
- All functions must have type hints
- All I/O-bound tool functions must be `async`
- Tools must return JSON error objects `{"success": False, "error": {...}}` instead of raising exceptions
- Use `TSharkClient` for all system calls — never call `subprocess` directly in tools

## Project Architecture

```
src/wireshark_mcp/
├── server.py            # CLI, server construction, registration order
├── mcp_app.py           # schemas, profiles, annotations, result ceiling
├── profiles.py          # full / analysis / core exclusions
├── prompts.py           # built-in MCP analysis prompts
├── resources.py         # display-filter, field, and capability resources
├── tools/               # public tool behavior and analysis semantics
├── tshark/              # typed Wireshark suite client mixins and cache
└── installer/           # client detection, config generation, diagnostics
```

The execution path and security boundaries are described in [docs/architecture.md](docs/architecture.md).

## Submitting Changes

1. **Fork** the repository and create a branch from `main`
2. **Write or update tests** for your changes
3. **Ensure all tests pass**: `uv run python -m pytest tests/`
4. **Lint your code**: `uv run python -m ruff check src/ tests/`
5. **Update `changelog/unreleased.md`** for user-visible behavior
6. **Update both language variants** when changing bilingual documentation
7. **Open a Pull Request** — fill in the PR template

For release work, use [docs/release-checklist.md](docs/release-checklist.md) and
[docs/platform-validation.md](docs/platform-validation.md) before tagging a version.

## Adding a New Tool

1. Add your tool function to the appropriate file in `src/wireshark_mcp/tools/`
2. Put new Wireshark command construction in `src/wireshark_mcp/tshark/`
3. Register it through the appropriate module and check all three tool profiles
4. Add read/write annotations and keep the public tool surface within its tested budget
5. Document it in `README.md`, `README_zh.md`, the relevant guide, and `changelog/unreleased.md`
6. Add unit tests; add a real-pcap test when parsing or protocol semantics change

Before proposing another public tool, check whether an existing parameterized tool can express the capability. The project deliberately keeps the advertised tool list small.

## Reporting Bugs

Please use the [Bug Report issue template](https://github.com/bx33661/Wireshark-MCP/issues/new?template=bug_report.yml).

## Requesting Features

Please use the [Feature Request issue template](https://github.com/bx33661/Wireshark-MCP/issues/new?template=feature_request.yml).
