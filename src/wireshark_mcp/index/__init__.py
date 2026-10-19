"""Optional DuckDB capture index (the ``[index]`` extra).

One tshark pass writes the common columns of every packet into a local DuckDB
file. Capture-wide statistics then run against that file instead of
re-dissecting the capture; packet-level evidence still comes from tshark.
"""

from __future__ import annotations

import importlib.util

INSTALL_HINT = "DuckDB is not installed. Install the index extra with: pip install 'wireshark-mcp[index]'"


def duckdb_available() -> bool:
    """True when the optional duckdb dependency can be imported."""
    return importlib.util.find_spec("duckdb") is not None
