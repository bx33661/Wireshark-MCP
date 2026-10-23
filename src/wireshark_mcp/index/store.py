"""Build, look up, and query per-capture DuckDB index files.

An index is a single DuckDB file under the index directory, named by a hash of
the capture's resolved path. It records the capture's size, mtime and SHA-256;
a capture that changed since the build is treated as unindexed, so a stale
index can never answer for new bytes.

Tables in each file:

``packets``  one row per frame, one VARCHAR column per field in
             :data:`~wireshark_mcp.index.schema.INDEX_FIELDS`, holding tshark's
             own text for that field.
``flows``    one row per tcp.stream / udp.stream with endpoints, timing, packet
             and byte totals and TCP flag counts.
``pkt``      a view over ``packets`` adding typed convenience columns.
``index_meta`` key/value build metadata.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import math
import os
import re
import shutil
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .schema import INDEX_FIELDS, SCHEMA_VERSION

if TYPE_CHECKING:
    from collections.abc import Callable

    from ..tshark.client import TSharkClient

logger = logging.getLogger("wireshark_mcp")

INDEX_DIR_ENV = "WIRESHARK_MCP_INDEX_DIR"
INDEX_TIMEOUT_ENV = "WIRESHARK_MCP_INDEX_TIMEOUT"
DEFAULT_INDEX_TIMEOUT = 1800
MIN_INDEX_TIMEOUT = 30
MAX_INDEX_TIMEOUT = 7200
MAX_EXPORT_BYTES = 16 * 1024**3
QUERY_MEMORY_LIMIT = "2GB"

_INVALID_FIELD_RE = re.compile(r"^\s+([A-Za-z0-9_.\-]+)\s*$", re.MULTILINE)


def resolve_index_dir() -> Path:
    raw = os.environ.get(INDEX_DIR_ENV, "").strip()
    return Path(raw).expanduser() if raw else Path.home() / ".wireshark-mcp" / "index"


def resolve_index_timeout() -> int:
    raw = os.environ.get(INDEX_TIMEOUT_ENV, "").strip()
    try:
        value = int(raw) if raw else DEFAULT_INDEX_TIMEOUT
    except ValueError:
        logger.warning("Ignoring non-integer %s=%r", INDEX_TIMEOUT_ENV, raw)
        value = DEFAULT_INDEX_TIMEOUT
    return min(max(value, MIN_INDEX_TIMEOUT), MAX_INDEX_TIMEOUT)


def _quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _sandbox_config() -> dict[str, Any]:
    """Read-only, no filesystem or network, no extensions, settings frozen."""
    return {
        "enable_external_access": False,
        "autoload_known_extensions": False,
        "autoinstall_known_extensions": False,
        "allow_community_extensions": False,
        "memory_limit": QUERY_MEMORY_LIMIT,
        "lock_configuration": True,
    }


def _json_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    return str(value)


@dataclass(frozen=True)
class IndexHandle:
    """A fresh index for one capture."""

    path: Path
    capture: Path
    columns: frozenset[str]
    packets: int
    meta: dict[str, Any]


class CaptureIndexError(Exception):
    """Build or query failure carrying an envelope error type."""

    def __init__(self, error_type: str, message: str, details: str | None = None) -> None:
        super().__init__(message)
        self.error_type = error_type
        self.message = message
        self.details = details


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _count_lines(path: Path) -> int:
    lines = 0
    last = b"\n"
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            lines += chunk.count(b"\n")
            last = chunk[-1:]
    return lines + (0 if last == b"\n" else 1)


_FLOWS_SQL = """
CREATE TABLE flows AS
WITH base AS (
    SELECT
        TRY_CAST("frame.number" AS BIGINT) AS frame,
        TRY_CAST("frame.time_epoch" AS DOUBLE) AS epoch,
        TRY_CAST("frame.len" AS BIGINT) AS len,
        COALESCE(NULLIF(split_part("ip.src", ',', 1), ''), NULLIF(split_part("ipv6.src", ',', 1), '')) AS src,
        COALESCE(NULLIF(split_part("ip.dst", ',', 1), ''), NULLIF(split_part("ipv6.dst", ',', 1), '')) AS dst,
        CASE WHEN COALESCE("tcp.stream", '') <> '' THEN 'tcp'
             WHEN COALESCE("udp.stream", '') <> '' THEN 'udp' END AS transport,
        TRY_CAST(split_part(COALESCE(NULLIF("tcp.stream", ''), "udp.stream"), ',', 1) AS BIGINT) AS stream,
        TRY_CAST(split_part(COALESCE(NULLIF("tcp.srcport", ''), "udp.srcport"), ',', 1) AS INTEGER) AS sport,
        TRY_CAST(split_part(COALESCE(NULLIF("tcp.dstport", ''), "udp.dstport"), ',', 1) AS INTEGER) AS dport,
        TRY_CAST(split_part("tcp.len", ',', 1) AS BIGINT) AS tcp_len,
        split_part("tcp.flags.syn", ',', 1) IN ('1', 'True') AS syn,
        split_part("tcp.flags.ack", ',', 1) IN ('1', 'True') AS ack,
        split_part("tcp.flags.reset", ',', 1) IN ('1', 'True') AS rst,
        split_part("tcp.flags.fin", ',', 1) IN ('1', 'True') AS fin
    FROM packets
)
SELECT
    transport,
    stream,
    arg_min(src, frame) AS src,
    arg_min(sport, frame) AS sport,
    arg_min(dst, frame) AS dst,
    arg_min(dport, frame) AS dport,
    min(frame) AS first_frame,
    max(frame) AS last_frame,
    min(epoch) AS start_epoch,
    max(epoch) AS end_epoch,
    max(epoch) - min(epoch) AS duration,
    count(*) AS packets,
    sum(len) AS bytes,
    sum(tcp_len) AS payload_bytes,
    count(*) FILTER (WHERE syn AND NOT ack) AS syn,
    count(*) FILTER (WHERE syn AND ack) AS syn_ack,
    count(*) FILTER (WHERE rst) AS rst,
    count(*) FILTER (WHERE fin) AS fin
FROM base
WHERE transport IS NOT NULL AND stream IS NOT NULL
GROUP BY transport, stream
"""

_PKT_VIEW_SQL = """
CREATE VIEW pkt AS
SELECT
    TRY_CAST("frame.number" AS BIGINT) AS frame,
    TRY_CAST("frame.time_epoch" AS DOUBLE) AS epoch,
    TRY_CAST("frame.time_relative" AS DOUBLE) AS rel,
    TRY_CAST("frame.len" AS INTEGER) AS len,
    COALESCE(NULLIF(split_part("ip.src", ',', 1), ''), NULLIF(split_part("ipv6.src", ',', 1), '')) AS src,
    COALESCE(NULLIF(split_part("ip.dst", ',', 1), ''), NULLIF(split_part("ipv6.dst", ',', 1), '')) AS dst,
    CASE WHEN COALESCE("tcp.stream", '') <> '' THEN 'tcp'
         WHEN COALESCE("udp.stream", '') <> '' THEN 'udp' END AS transport,
    TRY_CAST(split_part(COALESCE(NULLIF("tcp.stream", ''), "udp.stream"), ',', 1) AS BIGINT) AS stream,
    TRY_CAST(split_part(COALESCE(NULLIF("tcp.srcport", ''), "udp.srcport"), ',', 1) AS INTEGER) AS sport,
    TRY_CAST(split_part(COALESCE(NULLIF("tcp.dstport", ''), "udp.dstport"), ',', 1) AS INTEGER) AS dport,
    *
FROM packets
"""


def _load_index(tsv: Path, db_path: Path, fields: list[str], meta: dict[str, Any]) -> dict[str, Any]:
    import duckdb

    exported_rows = max(_count_lines(tsv) - 1, 0)
    # Column names come from INDEX_FIELDS and are quoted as SQL string literals.
    columns = "{" + ", ".join("'" + field.replace("'", "''") + "': 'VARCHAR'" for field in fields) + "}"
    read_options = (
        "delim = '\t', header = true, quote = '', escape = '', auto_detect = false, "
        "null_padding = true, ignore_errors = true, max_line_size = 16777216"
    )
    load_sql = f"CREATE TABLE packets AS SELECT * FROM read_csv(?, {read_options}, columns = {columns})"  # nosec B608
    connection = duckdb.connect(str(db_path))
    try:
        connection.execute(load_sql, [str(tsv)])
        row = connection.execute("SELECT count(*) FROM packets").fetchone()
        packets = int(row[0]) if row else 0
        connection.execute(_FLOWS_SQL)
        connection.execute(_PKT_VIEW_SQL)
        row = connection.execute("SELECT count(*) FROM flows").fetchone()
        flows = int(row[0]) if row else 0
        protocols = sorted(
            str(token)
            for (token,) in connection.execute(
                "SELECT DISTINCT unnest(string_split(\"frame.protocols\", ':')) FROM packets"
            ).fetchall()
            if token
        )
        meta = {
            **meta,
            "packets": packets,
            "flows": flows,
            "protocols": protocols,
            "rejected_rows": max(exported_rows - packets, 0),
        }
        connection.execute("CREATE TABLE index_meta (key VARCHAR PRIMARY KEY, value VARCHAR)")
        connection.executemany(
            "INSERT INTO index_meta VALUES (?, ?)", [(key, json.dumps(value)) for key, value in meta.items()]
        )
        connection.execute("CHECKPOINT")
    finally:
        connection.close()
    return meta


class CaptureIndexStore:
    """Owns the index directory and every DuckDB connection the server opens."""

    def __init__(self, client: TSharkClient, index_dir: Path | None = None, build_timeout: int | None = None) -> None:
        self._client = client
        self._index_dir = index_dir or resolve_index_dir()
        self._build_timeout = build_timeout or resolve_index_timeout()
        self._locks: dict[Path, asyncio.Lock] = {}

    @property
    def index_dir(self) -> Path:
        return self._index_dir

    def index_path(self, capture: Path) -> Path:
        digest = hashlib.sha256(str(capture).encode("utf-8", "surrogateescape")).hexdigest()[:24]
        return self._index_dir / f"{digest}.duckdb"

    # ── lookup ───────────────────────────────────────────────────────────
    def _read_meta(self, path: Path) -> dict[str, Any] | None:
        import duckdb

        try:
            connection = duckdb.connect(str(path), read_only=True, config=_sandbox_config())
        except Exception as exc:
            logger.warning("Ignoring unreadable capture index %s: %s", path, exc)
            return None
        try:
            rows = connection.execute("SELECT key, value FROM index_meta").fetchall()
        except Exception as exc:
            logger.warning("Ignoring capture index without metadata %s: %s", path, exc)
            return None
        finally:
            connection.close()
        return {key: json.loads(value) for key, value in rows}

    def describe(self, pcap_file: str) -> tuple[Path, dict[str, Any] | None, str]:
        """Return (capture path, metadata or None, state) without validating access."""
        capture = Path(pcap_file).resolve()
        path = self.index_path(capture)
        if not path.exists():
            return capture, None, "missing"
        meta = self._read_meta(path)
        if meta is None:
            return capture, None, "unreadable"
        if meta.get("schema_version") != SCHEMA_VERSION:
            return capture, meta, "outdated_schema"
        try:
            stat = capture.stat()
        except OSError:
            return capture, meta, "capture_missing"
        if meta.get("capture_size") != stat.st_size or meta.get("capture_mtime_ns") != stat.st_mtime_ns:
            return capture, meta, "stale"
        return capture, meta, "fresh"

    def lookup(self, pcap_file: str) -> IndexHandle | None:
        """Return the fresh index for ``pcap_file``, or None."""
        from . import duckdb_available

        if not duckdb_available():
            return None
        capture, meta, state = self.describe(pcap_file)
        if state != "fresh" or meta is None:
            return None
        return IndexHandle(
            path=self.index_path(capture),
            capture=capture,
            columns=frozenset(meta.get("fields", [])),
            packets=int(meta.get("packets", 0)),
            meta=meta,
        )

    # ── build ────────────────────────────────────────────────────────────
    async def build(self, pcap_file: str, *, force: bool = False) -> tuple[dict[str, Any], bool]:
        """Build the index, or reuse a fresh one unless ``force``. Returns (metadata, reused)."""
        validation = self._client._validate_file(pcap_file)
        if not validation["success"]:
            error = validation.get("error") or {}
            raise CaptureIndexError(error.get("type", "InvalidParameter"), error.get("message", "Invalid capture"))

        capture = Path(pcap_file).resolve()
        lock = self._locks.setdefault(capture, asyncio.Lock())
        async with lock:
            if not force:
                _, meta, state = self.describe(pcap_file)
                if state == "fresh" and meta is not None:
                    return meta, True
            return await self._build_locked(capture), False

    async def _build_locked(self, capture: Path) -> dict[str, Any]:
        self._index_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        work = self._index_dir / f".build-{uuid.uuid4().hex}"
        work.mkdir(mode=0o700)
        started = time.monotonic()
        try:
            stat_before = capture.stat()
            sha_task = asyncio.create_task(asyncio.to_thread(_sha256, capture))
            tsv = work / "packets.tsv"
            fields = list(INDEX_FIELDS)
            dropped: list[str] = []
            for _attempt in range(3):
                exported = await self._client.export_fields_to_file(
                    str(capture), fields, tsv, timeout=self._build_timeout, max_bytes=MAX_EXPORT_BYTES
                )
                if exported.get("success"):
                    break
                error = exported.get("error") or {}
                details = str(error.get("details") or "")
                invalid = set(_INVALID_FIELD_RE.findall(details)) & set(fields) if "aren't valid" in details else set()
                if not invalid:
                    sha_task.cancel()
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await sha_task
                    raise CaptureIndexError(
                        error.get("type", "ExecutionError"), error.get("message", "tshark export failed"), details
                    )
                # Older tshark builds lack some fields (ja4, newer names); index without them.
                dropped.extend(sorted(invalid))
                fields = [field for field in fields if field not in invalid]
            else:
                raise CaptureIndexError("ExecutionError", "tshark rejected the index field list")
            export_seconds = time.monotonic() - started
            sha256 = await sha_task
            stat_after = capture.stat()
            if (stat_before.st_size, stat_before.st_mtime_ns) != (stat_after.st_size, stat_after.st_mtime_ns):
                raise CaptureIndexError(
                    "ExecutionError", "Capture changed while it was being indexed; rebuild the index"
                )

            meta: dict[str, Any] = {
                "schema_version": SCHEMA_VERSION,
                "capture_path": str(capture),
                "capture_size": stat_after.st_size,
                "capture_mtime_ns": stat_after.st_mtime_ns,
                "capture_sha256": sha256,
                "fields": fields,
                "fields_unavailable": dropped,
                "tshark": await self._tshark_version(),
                "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "export_seconds": round(export_seconds, 3),
            }
            temp_db = work / "index.duckdb"
            load_started = time.monotonic()
            meta = await asyncio.to_thread(_load_index, tsv, temp_db, fields, meta)
            load_seconds = round(time.monotonic() - load_started, 3)
            meta["load_seconds"] = load_seconds
            final = self.index_path(capture)
            os.replace(temp_db, final)
            meta["index_bytes"] = final.stat().st_size
            return meta
        finally:
            shutil.rmtree(work, ignore_errors=True)

    async def _tshark_version(self) -> str:
        raw = await self._client._run_command([self._client.tshark_path, "--version"], limit_lines=1)
        ok, output = self._client._unwrap(raw)
        return output.strip().splitlines()[0] if ok and output.strip() else "unknown"

    def drop(self, pcap_file: str) -> bool:
        path = self.index_path(Path(pcap_file).resolve())
        if not path.exists():
            return False
        path.unlink()
        return True

    # ── queries ──────────────────────────────────────────────────────────
    def _connect(self, handle: IndexHandle) -> Any:
        import duckdb

        return duckdb.connect(str(handle.path), read_only=True, config=_sandbox_config())

    @staticmethod
    def _with_deadline(connection: Any, timeout: float) -> threading.Timer:
        timer = threading.Timer(timeout, connection.interrupt)
        timer.daemon = True
        timer.start()
        return timer

    def stream_rows(
        self,
        handle: IndexHandle,
        fields: list[str],
        where_sql: str,
        params: list[Any],
        consumer: Callable[[list[str]], None],
        *,
        max_rows: int,
        timeout: float,
    ) -> dict[str, Any]:
        """Feed matching rows (tshark text, '' for absent) to ``consumer`` in capture order."""
        select = ", ".join(f"COALESCE({_quote_ident(field)}, '')" for field in fields)
        # Identifiers are quoted and where_sql comes from filter_sql with bound params.
        sql = f"SELECT {select} FROM packets WHERE {where_sql}"  # nosec B608
        connection = self._connect(handle)
        timer = self._with_deadline(connection, timeout)
        rows = 0
        try:
            cursor = connection.execute(sql, params)
            while batch := cursor.fetchmany(8192):
                for row in batch:
                    if rows >= max_rows:
                        return {
                            "success": False,
                            "rows": rows,
                            "error": {
                                "type": "LimitExceeded",
                                "message": f"Matching packet rows exceed the {max_rows} row limit",
                            },
                        }
                    consumer(list(row))
                    rows += 1
        except Exception as exc:
            if timer.finished.is_set() or "interrupt" in str(exc).lower():
                return {
                    "success": False,
                    "rows": rows,
                    "error": {"type": "TimeoutError", "message": f"Index query timed out after {timeout} seconds"},
                }
            raise
        finally:
            timer.cancel()
            connection.close()
        return {"success": True, "rows": rows}

    def run_sql(self, handle: IndexHandle, sql: str, *, max_rows: int, timeout: float) -> dict[str, Any]:
        """Run one read-only SELECT inside the sandbox."""
        connection = self._connect(handle)
        timer: threading.Timer | None = None
        try:
            import duckdb

            try:
                statements = connection.extract_statements(sql)
            except duckdb.Error as exc:
                raise CaptureIndexError("InvalidParameter", "SQL could not be parsed", str(exc)) from exc
            if len(statements) != 1:
                raise CaptureIndexError("InvalidParameter", "Provide exactly one SQL statement")
            if statements[0].type != duckdb.StatementType.SELECT:
                raise CaptureIndexError("InvalidParameter", "Only SELECT queries are allowed against the capture index")
            timer = self._with_deadline(connection, timeout)
            started = time.monotonic()
            try:
                cursor = connection.execute(sql)
                columns = [column[0] for column in cursor.description or []]
                fetched = cursor.fetchmany(max_rows + 1)
            except duckdb.Error as exc:
                if timer.finished.is_set():
                    raise CaptureIndexError("TimeoutError", f"Index query timed out after {timeout} seconds") from exc
                raise CaptureIndexError("QueryError", "SQL query failed", str(exc)) from exc
            return {
                "columns": columns,
                "rows": [[_json_value(value) for value in row] for row in fetched[:max_rows]],
                "row_count": min(len(fetched), max_rows),
                "truncated": len(fetched) > max_rows,
                "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
            }
        finally:
            if timer is not None:
                timer.cancel()
            connection.close()
