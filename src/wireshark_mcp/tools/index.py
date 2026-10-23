"""Capture index tools (optional ``[index]`` extra, backed by DuckDB)."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Literal

from ..index import INSTALL_HINT, duckdb_available
from ..index.store import CaptureIndexError, CaptureIndexStore
from .envelope import envelope_response, error_response

if TYPE_CHECKING:
    from mcp.server import MCPServer

    from ..tshark.client import TSharkClient

# Rows returned per query; use SQL LIMIT / aggregation for anything larger.
MAX_QUERY_ROWS = 200
QUERY_TIMEOUT_SECONDS = 60

_STATUS_KEYS = (
    "capture_path",
    "capture_sha256",
    "capture_size",
    "packets",
    "flows",
    "rejected_rows",
    "fields_unavailable",
    "tshark",
    "built_at",
    "export_seconds",
    "load_seconds",
    "index_bytes",
)


def _summary(meta: dict[str, object]) -> dict[str, object]:
    return {key: meta[key] for key in _STATUS_KEYS if key in meta}


def _error(exc: CaptureIndexError) -> str:
    return error_response(exc.message, exc.error_type, exc.details)


def register_index_tools(mcp: MCPServer, client: TSharkClient, store: CaptureIndexStore) -> None:
    async def query(pcap_file: str, sql: str) -> str:
        if not sql.strip():
            return error_response("action='query' needs sql.", "InvalidParameter")
        handle = await asyncio.to_thread(store.lookup, pcap_file)
        if handle is None:
            return error_response(
                "No fresh index for this capture. Run wireshark_index(action='build') first.", "IndexMissing"
            )
        try:
            result = await asyncio.to_thread(
                store.run_sql, handle, sql, max_rows=MAX_QUERY_ROWS, timeout=QUERY_TIMEOUT_SECONDS
            )
        except CaptureIndexError as exc:
            return _error(exc)
        return envelope_response(
            result,
            truncated=result["truncated"],
            coverage={
                "status": "complete",
                "source": "index",
                "capture_sha256": handle.meta.get("capture_sha256"),
                "indexed_packets": handle.packets,
            },
        )

    async def build(pcap_file: str) -> str:
        try:
            meta, reused = await store.build(pcap_file)
        except CaptureIndexError as exc:
            return _error(exc)
        warnings = []
        if meta.get("rejected_rows"):
            warnings.append(f"{meta['rejected_rows']} exported row(s) could not be parsed and are not indexed.")
        if meta.get("fields_unavailable"):
            warnings.append("This tshark lacks: " + ", ".join(meta["fields_unavailable"]))
        return envelope_response(
            {"action": "build", "state": "fresh", "reused": reused, "index": _summary(meta)},
            warnings=warnings or None,
            coverage={
                "status": "partial" if meta.get("rejected_rows") else "complete",
                "scanned": meta.get("packets", 0),
                "source": "index",
            },
        )

    @mcp.tool()
    async def wireshark_index(
        pcap_file: str,
        action: Literal["build", "status", "query", "drop"] = "build",
        sql: str = "",
    ) -> str:
        """[Index] One tshark pass builds a DuckDB index that wireshark_aggregate reuses. query: one read-only SELECT over packets ("ip.src" text columns), pkt (typed), flows."""
        if not duckdb_available():
            return error_response(INSTALL_HINT, "DependencyMissing")
        validation = client._validate_file(pcap_file)
        if not validation["success"] and not (action == "drop" and validation["error"].get("type") == "FileNotFound"):
            return error_response(validation["error"]["message"], validation["error"]["type"])

        if action == "query":
            return await query(pcap_file, sql)
        if action == "drop":
            removed = await asyncio.to_thread(store.drop, pcap_file)
            return envelope_response({"action": "drop", "removed": removed})
        if action == "status":
            _, meta, state = await asyncio.to_thread(store.describe, pcap_file)
            data: dict[str, object] = {"action": "status", "state": state}
            if meta is not None:
                data["index"] = _summary(meta)
            if state != "fresh":
                data["hint"] = "Run wireshark_index(action='build'); a stale index is rebuilt."
            return envelope_response(data)
        return await build(pcap_file)
