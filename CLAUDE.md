# Wireshark MCP Developer Guide

## Commands
- **Install**: `pip install -e .`
- **Test**: `python -m unittest discover tests`
- **Run (Local)**: `python src/wireshark_mcp/server.py`
- **Syntax Check**: `python -m compileall src`
- **Build**: `python -m build` (or `hatch build`)

## Code Style
- **Type Hints**: All functions should have type hints.
- **Async/Await**: This project uses `asyncio`. Ensure all I/O bound tools are `async`.
- **Error Handling**: Return JSON error objects `{"success": False, "error": {...}}` instead of raising exceptions for tools.
- **TShark Wrapper**: Use `wireshark_mcp.tshark.client.TSharkClient` for all system calls. Do not use `subprocess` directly in tools.

## Architecture
- `src/wireshark_mcp/server.py`: MCP server entry point and tool registration.
- `src/wireshark_mcp/tshark/client.py`: Core logic wrapping TShark CLI commands.
- `src/wireshark_mcp/tools/`: Individual tool definitions (extract, decode, visualize, etc.).
