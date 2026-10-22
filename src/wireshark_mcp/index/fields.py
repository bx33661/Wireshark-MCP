"""Answer wireshark_extract_fields from the index with tshark's exact text.

``tshark -T fields -E header=y -E separator=/t -E aggregator=, -E quote=d``
prints one header line, then one line per matching frame in frame order, each
non-empty value wrapped in double quotes. The index stores the same values
(exported with ``quote=n``), so a window of that output can be rebuilt from
SQL. Anything that could print differently falls back to tshark: an index
built by another tshark version, rows the build could not parse, and values
holding quotes, backslashes or line/field separators, whose escaping is
version dependent.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from .filter_sql import UnsupportedFilter, translate_filter

if TYPE_CHECKING:
    from .store import CaptureIndexStore, IndexHandle

_UNSAFE = ('"', "\\", "\t", "\n", "\r")


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def window_sql(fields: list[str], where_sql: str) -> str:
    select = ", ".join(f"COALESCE({_q(field)}, '')" for field in fields)
    return (
        f"SELECT {select}, count(*) OVER () FROM packets WHERE {where_sql} "
        f'ORDER BY TRY_CAST("frame.number" AS BIGINT) LIMIT ? OFFSET ?'
    )


def count_sql(where_sql: str) -> str:
    return f"SELECT count(*) FROM packets WHERE {where_sql}"


def render(
    handle: IndexHandle,
    store: CaptureIndexStore,
    fields: list[str],
    display_filter: str,
    limit: int,
    offset: int,
    timeout: float,
) -> str | None:
    """The tshark-identical result envelope, or None when tshark must answer."""
    if limit <= 0 or offset < 0 or not fields or any(not field for field in fields):
        return None
    if handle.meta.get("rejected_rows") or any(field not in handle.columns for field in fields):
        return None
    try:
        translated = translate_filter(display_filter, set(handle.columns), set(handle.meta.get("protocols", [])))
    except UnsupportedFilter:
        return None

    # Output lines are the header plus one per frame; offset/limit count lines.
    first_row = max(offset - 1, 0)
    rows_wanted = limit if offset > 0 else limit - 1
    params: list[Any] = [*translated.params, rows_wanted + 1, first_row]
    rows = store.fetch([handle], window_sql(fields, translated.sql), params, timeout=timeout)
    if rows:
        matched = int(rows[0][-1])
    else:
        (count,) = store.fetch([handle], count_sql(translated.sql), translated.params, timeout=timeout)
        matched = int(count[0])

    lines: list[str] = ["\t".join(fields)] if offset == 0 else []
    for row in rows[:rows_wanted]:
        values = row[:-1]
        if any(marker in value for value in values for marker in _UNSAFE):
            return None
        lines.append("\t".join(f'"{value}"' if value else "" for value in values))

    total_lines = matched + 1
    truncated = total_lines - offset > limit
    text = "\n".join(lines)
    if truncated:
        text += f"\n\n[Showing {limit}/{total_lines} lines. Next: offset={offset + limit}]"
    envelope: dict[str, Any] = {"success": True, "data": text}
    if truncated:
        envelope["truncated"] = True
    envelope["coverage"] = {
        "status": "complete",
        "source": "index",
        "capture_sha256": handle.meta.get("capture_sha256"),
    }
    return json.dumps(envelope)
