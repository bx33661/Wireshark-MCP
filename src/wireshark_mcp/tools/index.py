"""Capture index tools (optional ``[index]`` extra, backed by DuckDB)."""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import re
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from ..index import INSTALL_HINT, compare, duckdb_available
from ..index.filter_sql import TranslatedFilter, UnsupportedFilter, translate_filter
from ..index.store import CaptureIndexError, CaptureIndexStore, IndexHandle
from .envelope import envelope_response, error_response

if TYPE_CHECKING:
    from mcp.server import MCPServer

    from ..tshark.client import TSharkClient

# Rows returned per query; use SQL LIMIT / aggregation for anything larger.
MAX_QUERY_ROWS = 200
QUERY_TIMEOUT_SECONDS = 60
# Timeline, diff and export scan every selected packet of every capture.
ANALYSIS_TIMEOUT_SECONDS = 600
MAX_COLLECTION_FILES = 64

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


def _split_files(pcap_file: str, more_files: str) -> list[str]:
    """The primary capture plus the comma-separated extras, each resolved path once."""
    files: dict[Path, str] = {}
    for raw in [pcap_file, *more_files.split(",")]:
        name = raw.strip()
        if name:
            files.setdefault(Path(name).resolve(), name)
    return list(files.values())


def _label(handles: list[IndexHandle]) -> list[IndexHandle]:
    """Give each capture a unique, readable capture_id: its file name, suffixed on clashes."""
    seen: dict[str, int] = {}
    labelled = []
    for handle in handles:
        count = seen.get(handle.label, 0) + 1
        seen[handle.label] = count
        label = handle.label if count == 1 else f"{handle.label}~{count}"
        labelled.append(dataclasses.replace(handle, label=label))
    return labelled


def _coverage(handles: list[IndexHandle], **extra: Any) -> dict[str, Any]:
    coverage: dict[str, Any] = {"status": "complete", "source": "index", **extra}
    if len(handles) == 1:
        coverage["capture_sha256"] = handles[0].meta.get("capture_sha256")
        coverage["indexed_packets"] = handles[0].packets
    else:
        coverage["captures"] = [
            {"capture_id": h.label, "capture_sha256": h.meta.get("capture_sha256"), "indexed_packets": h.packets}
            for h in handles
        ]
    if any(h.meta.get("rejected_rows") for h in handles):
        coverage["status"] = "partial"
    return coverage


def _translate(display_filter: str, handles: list[IndexHandle]) -> TranslatedFilter:
    """Translate against what every capture in the set has indexed."""
    columns = set.intersection(*(set(h.columns) for h in handles))
    protocols = set().union(*(set(h.meta.get("protocols", [])) for h in handles))
    return translate_filter(display_filter, columns, protocols)


def register_index_tools(mcp: MCPServer, client: TSharkClient, store: CaptureIndexStore) -> None:
    async def fresh_handles(files: list[str]) -> list[IndexHandle] | str:
        handles = []
        missing = []
        for name in files:
            handle = await asyncio.to_thread(store.lookup, name)
            if handle is None:
                missing.append(name)
            else:
                handles.append(handle)
        if missing:
            return error_response(
                "No fresh index for: " + ", ".join(missing) + ". Run wireshark_index(action='build') first.",
                "IndexMissing",
            )
        return _label(handles)

    async def query(handles: list[IndexHandle], sql: str) -> str:
        if not sql.strip():
            return error_response("action='query' needs sql.", "InvalidParameter")
        try:
            result = await asyncio.to_thread(
                store.run_sql, handles, sql, max_rows=MAX_QUERY_ROWS, timeout=QUERY_TIMEOUT_SECONDS
            )
        except CaptureIndexError as exc:
            return _error(exc)
        return envelope_response(result, truncated=result["truncated"], coverage=_coverage(handles))

    async def build(files: list[str]) -> str:
        built: list[dict[str, Any]] = []
        warnings: list[str] = []
        scanned = 0
        partial = False
        for name in files:
            try:
                meta, reused = await store.build(name)
            except CaptureIndexError as exc:
                if len(files) == 1:
                    return _error(exc)
                return error_response(f"{name}: {exc.message}", exc.error_type, exc.details)
            prefix = f"{Path(name).name}: " if len(files) > 1 else ""
            if meta.get("rejected_rows"):
                partial = True
                warnings.append(
                    f"{prefix}{meta['rejected_rows']} exported row(s) could not be parsed and are not indexed."
                )
            if meta.get("fields_unavailable"):
                warnings.append(prefix + "This tshark lacks: " + ", ".join(meta["fields_unavailable"]))
            scanned += int(meta.get("packets", 0))
            built.append({"reused": reused, "index": _summary(meta)})
        data: dict[str, Any] = {"action": "build", "state": "fresh"}
        if len(built) == 1:
            data.update(built[0])
        else:
            data["captures"] = built
        return envelope_response(
            data,
            warnings=warnings or None,
            coverage={
                "status": "partial" if partial else "complete",
                "scanned": scanned,
                "source": "index",
            },
        )

    async def status(files: list[str]) -> str:
        reports = []
        for name in files:
            _, meta, state = await asyncio.to_thread(store.describe, name)
            report: dict[str, object] = {"state": state}
            if meta is not None:
                report["index"] = _summary(meta)
            if state != "fresh":
                report["hint"] = "Run wireshark_index(action='build'); a stale index is rebuilt."
            reports.append(report)
        if len(reports) == 1:
            return envelope_response({"action": "status", **reports[0]})
        return envelope_response({"action": "status", "captures": reports})

    def runner(handles: list[IndexHandle]) -> compare.Run:
        """Run server-built SQL over ``handles``, all calls sharing one analysis deadline."""
        deadline = time.monotonic() + ANALYSIS_TIMEOUT_SECONDS

        def run(sql: str, params: list[Any]) -> list[tuple[Any, ...]]:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CaptureIndexError("TimeoutError", f"Index analysis exceeded {ANALYSIS_TIMEOUT_SECONDS} seconds")
            return store.fetch(handles, sql, params, timeout=remaining)

        return run

    async def timeline(handles: list[IndexHandle], display_filter: str) -> str:
        try:
            translated = _translate(display_filter, handles)
        except UnsupportedFilter as exc:
            return error_response(f"display_filter cannot run on the index: {exc}", "InvalidParameter")
        kinds = compare.available_kinds(set.intersection(*(set(h.columns) for h in handles)))
        side = compare.Side([h.label for h in handles], translated.sql, translated.params)
        try:
            result = await asyncio.to_thread(compare.timeline, runner(handles), kinds, side)
        except CaptureIndexError as exc:
            return _error(exc)
        data = {"action": "timeline", "display_filter": display_filter, **result}
        return envelope_response(data, truncated=data["truncated"], coverage=_coverage(handles))

    async def diff(handles: list[IndexHandle], display_filter: str, compare_filter: str) -> str:
        baseline, other = handles[0], handles[-1]
        if len(handles) == 1 and display_filter.strip() == compare_filter.strip():
            return error_response(
                "diff needs a second capture in more_files or a compare_filter that differs from display_filter.",
                "InvalidParameter",
            )
        try:
            base_filter = _translate(display_filter, handles)
            cmp_filter = _translate(compare_filter, handles)
        except UnsupportedFilter as exc:
            return error_response(f"filter cannot run on the index: {exc}", "InvalidParameter")
        kinds = compare.available_kinds(set.intersection(*(set(h.columns) for h in handles)))
        try:
            result = await asyncio.to_thread(
                compare.diff,
                runner(handles),
                kinds,
                compare.Side([baseline.label], base_filter.sql, base_filter.params),
                compare.Side([other.label], cmp_filter.sql, cmp_filter.params),
            )
        except CaptureIndexError as exc:
            return _error(exc)
        data = {
            "action": "diff",
            "baseline": {"capture_id": baseline.label, "display_filter": display_filter},
            "compare": {"capture_id": other.label, "display_filter": compare_filter},
            **result,
        }
        return envelope_response(data, truncated=data["truncated"], coverage=_coverage(handles))

    async def export(handles: list[IndexHandle], display_filter: str) -> str:
        try:
            translated = _translate(display_filter, handles)
        except UnsupportedFilter as exc:
            return error_response(f"display_filter cannot run on the index: {exc}", "InvalidParameter")
        digest = hashlib.sha256(
            "\0".join([*(str(h.capture) for h in handles), display_filter]).encode("utf-8", "surrogateescape")
        ).hexdigest()[:12]
        stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", handles[0].capture.stem)[:40] or "capture"
        name = f"{stem}{f'+{len(handles) - 1}' if len(handles) > 1 else ''}-{digest}"
        try:
            result = await asyncio.to_thread(
                store.export_parquet, handles, translated.sql, translated.params, name, timeout=ANALYSIS_TIMEOUT_SECONDS
            )
        except CaptureIndexError as exc:
            return _error(exc)
        return envelope_response(
            {"action": "export", "format": "parquet", "display_filter": display_filter, **result},
            coverage=_coverage(handles),
        )

    @mcp.tool()
    async def wireshark_index(
        pcap_file: str,
        action: Literal["build", "status", "query", "timeline", "diff", "export", "drop"] = "build",
        sql: str = "",
        more_files: str = "",
        display_filter: str = "",
        compare_filter: str = "",
    ) -> str:
        """[Index] Build once; aggregate/extract_fields reuse it. more_files: extra captures (capture_id). query: SELECT on packets/pkt/flows/captures. timeline: first/last seen. diff: vs more_files/compare_filter. export: Parquet."""
        if not duckdb_available():
            return error_response(INSTALL_HINT, "DependencyMissing")
        files = _split_files(pcap_file, more_files)
        if len(files) > MAX_COLLECTION_FILES:
            return error_response(f"At most {MAX_COLLECTION_FILES} captures per call.", "InvalidParameter")
        if action == "diff" and len(files) > 2:
            return error_response("diff compares pcap_file with at most one file in more_files.", "InvalidParameter")
        for name in files:
            validation = client._validate_file(name)
            if not validation["success"] and not (
                action == "drop" and validation["error"].get("type") == "FileNotFound"
            ):
                return error_response(validation["error"]["message"], validation["error"]["type"])

        if action == "build":
            return await build(files)
        if action == "status":
            return await status(files)
        if action == "drop":
            removed = [await asyncio.to_thread(store.drop, name) for name in files]
            return envelope_response({"action": "drop", "removed": removed[0] if len(removed) == 1 else removed})

        handles = await fresh_handles(files)
        if isinstance(handles, str):
            return handles
        if action == "query":
            return await query(handles, sql)
        if action == "timeline":
            return await timeline(handles, display_filter)
        if action == "diff":
            return await diff(handles, display_filter, compare_filter)
        return await export(handles, display_filter)
