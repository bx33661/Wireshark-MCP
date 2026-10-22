"""Run wireshark_aggregate's grouping inside DuckDB when the answer is provably the same.

The streaming accumulator in ``tools/stats.py`` defines the answer. This module
reproduces it in SQL only for inputs where SQL cannot disagree with it, and
returns ``None`` otherwise so the caller streams rows into the accumulator
instead. The gates are:

* every time value and numeric value is plain decimal text that Python's
  ``float`` and DuckDB's ``CAST`` read identically, numeric values are whole
  numbers, and their absolute sum stays below 2**53, so float summation is exact
  in any order;
* no distinct item carries the whitespace ``str.strip`` would remove;
* no group, distinct-per-group or total-distinct ceiling would be reached, since
  which rows the accumulator keeps past a ceiling depends on arrival order.

The tshark equivalence tests in ``tests/test_capture_index.py`` are the gate
for this module: every aggregate case runs through it and must match tshark.
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING, Any

from ..tools.stats import (
    AMBIGUOUS_COMMAS_WARNING,
    INVALID_NUMERIC_WARNING,
    LITERAL_STRING_FIELDS,
    MAX_AGGREGATE_GROUPS,
    MAX_DISTINCT_PER_GROUP,
    MAX_TOTAL_DISTINCT_ITEMS,
)

if TYPE_CHECKING:
    from .store import CaptureIndexStore, IndexHandle

# Characters Python's str.strip() removes, as an RE2 class.
_PY_WHITESPACE = r"[\t-\r\x{1c}-\x{20}\x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}]"
_TIME_RE = r"^-?[0-9]{1,12}(\.[0-9]{1,12})?$"
_INTEGER_RE = r"^-?[0-9]{1,15}$"
_EXACT_SUM_LIMIT = 2**53
_UNAMBIGUOUS_PREFIXES = ("ip.", "ipv6.", "tcp.", "udp.", "dns.")


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _text(field: str) -> str:
    return f"COALESCE({_q(field)}, '')"


def _items(field: str) -> str:
    """The accumulator's distinct items for one row, before stripping."""
    if field in LITERAL_STRING_FIELDS:
        return f"CASE WHEN {_text(field)} <> '' THEN [{_text(field)}] ELSE [] END"
    return f"list_filter(string_split({_text(field)}, ','), lambda v: v <> '')"


def _sql_double(value: float) -> str:
    # A string cast parses the shortest repr back to the identical double; a bare
    # literal such as 0.1 would be typed DECIMAL and change the arithmetic.
    return f"CAST('{value!r}' AS DOUBLE)"


class _Query:
    def __init__(
        self,
        where_sql: str,
        group_fields: list[str],
        distinct_fields: list[str],
        numeric_fields: list[str],
        time_bucket_seconds: float,
    ) -> None:
        self.where_sql = where_sql
        self.group_fields = group_fields
        self.distinct_fields = distinct_fields
        self.numeric_fields = numeric_fields
        self.bucket = time_bucket_seconds
        self.keys = [f"k{i}" for i in range(len(group_fields) + (1 if self.bucket > 0 else 0))]

    def selected(self) -> str:
        """Matching rows with their group key columns k0..kn (bucket first) and raw values."""
        columns = []
        if self.bucket > 0:
            rel = _text("frame.time_relative")
            columns.append("rel_text")
            columns.append("rel_text <> '' AS g")
            columns.append(
                f"CASE WHEN rel_text <> '' THEN floor(TRY_CAST(rel_text AS DOUBLE) / {_sql_double(self.bucket)}) "
                f"* {_sql_double(self.bucket)} END AS k0"
            )
            inner = f"SELECT *, {rel} AS rel_text FROM packets WHERE {self.where_sql}"
        else:
            inner = f"SELECT * FROM packets WHERE {self.where_sql}"
        offset = 1 if self.bucket > 0 else 0
        for position, field in enumerate(self.group_fields):
            columns.append(f"{_text(field)} AS k{position + offset}")
        for position, field in enumerate(self.distinct_fields):
            columns.append(f"{_items(field)} AS d{position}")
        for position, field in enumerate(self.numeric_fields):
            columns.append(f"{_text(field)} AS n{position}")
        if self.bucket <= 0:
            columns.append("TRUE AS g")
        return f"SELECT {', '.join(columns)} FROM ({inner})"

    def grouped_rows(self) -> str:
        """Rows that join a group: invalid times are skipped, as in the accumulator."""
        return "SELECT * FROM selected WHERE g"

    def gates(self) -> str:
        checks = ["count(*) AS matched"]
        if self.bucket > 0:
            checks.append("count(*) FILTER (WHERE rel_text = '') AS skipped_time")
            checks.append(
                f"count(*) FILTER (WHERE rel_text <> '' AND NOT regexp_matches(rel_text, '{_TIME_RE}')) AS bad"
            )
        else:
            checks.append("0 AS skipped_time")
            checks.append("0 AS bad")
        for position, _field in enumerate(self.numeric_fields):
            n = f"n{position}"
            checks.append(
                f"count(*) FILTER (WHERE g AND {n} <> '' AND NOT contains({n}, ',') "
                f"AND (NOT regexp_matches({n}, '{_INTEGER_RE}') OR regexp_matches({n}, '^-0+$'))) AS nbad{position}"
            )
            checks.append(
                f"sum(abs(TRY_CAST({n} AS HUGEINT))) FILTER (WHERE g AND regexp_matches({n}, '{_INTEGER_RE}'))"
                f" AS nabs{position}"
            )
            checks.append(f"bool_or(contains({n}, ',')) FILTER (WHERE g) AS ninvalid{position}")
        for position, field in enumerate(self.distinct_fields):
            d = f"d{position}"
            checks.append(
                f"bool_or(len(list_filter({d}, lambda v: regexp_matches(v, '^{_PY_WHITESPACE}|{_PY_WHITESPACE}$')))"
                f" > 0) FILTER (WHERE g) AS dws{position}"
            )
            ambiguous = field not in LITERAL_STRING_FIELDS and not field.startswith(_UNAMBIGUOUS_PREFIXES)
            checks.append(
                f"bool_or(len({d}) > 1) FILTER (WHERE g) AS damb{position}" if ambiguous else f"false AS damb{position}"
            )
        return f"WITH selected AS ({self.selected()}) SELECT {', '.join(checks)} FROM selected"

    def groups(self) -> str:
        keys = ", ".join(self.keys)
        metrics = ["count(*) AS count"]
        for position, _field in enumerate(self.numeric_fields):
            n = f"n{position}"
            valid = f"regexp_matches({n}, '{_INTEGER_RE}')"
            metrics.extend(
                [
                    f"count(*) FILTER (WHERE {valid}) AS valid{position}",
                    f"count(*) FILTER (WHERE {n} = '') AS missing{position}",
                    f"count(*) FILTER (WHERE {n} <> '' AND NOT {valid}) AS invalid{position}",
                    f"sum(TRY_CAST({n} AS BIGINT)) FILTER (WHERE {valid}) AS sum{position}",
                    f"min(TRY_CAST({n} AS BIGINT)) FILTER (WHERE {valid}) AS min{position}",
                    f"max(TRY_CAST({n} AS BIGINT)) FILTER (WHERE {valid}) AS max{position}",
                ]
            )
        group_by = f" GROUP BY {keys}" if keys else ""
        select_keys = f"{keys}, " if keys else ""
        return (
            f"WITH selected AS ({self.selected()}), grouped AS ({self.grouped_rows()}) "
            f"SELECT {select_keys}{', '.join(metrics)} FROM grouped{group_by} LIMIT {MAX_AGGREGATE_GROUPS}"
        )

    def distinct(self, position: int) -> str:
        keys = ", ".join(self.keys)
        select_keys = f"{keys}, " if keys else ""
        group_by = f" GROUP BY {keys}" if keys else ""
        return (
            f"WITH selected AS ({self.selected()}), grouped AS ({self.grouped_rows()}) "
            f"SELECT {select_keys}count(DISTINCT item) FROM "
            f"(SELECT {select_keys}unnest(d{position}) AS item FROM grouped){group_by}"
        )


def aggregate(
    store: CaptureIndexStore,
    handle: IndexHandle,
    where_sql: str,
    params: list[Any],
    *,
    group_fields: list[str],
    distinct_fields: list[str],
    numeric_operations: dict[str, set[str]],
    time_bucket_seconds: float,
    max_rows: int,
    timeout: float,
) -> tuple[list[dict[str, Any]], int, int, list[str]] | None:
    """Return (groups, matched packets, skipped invalid time, warnings), or None to stream instead."""
    numeric_fields = list(numeric_operations)
    query = _Query(where_sql, group_fields, distinct_fields, numeric_fields, time_bucket_seconds)

    (gate,) = store.fetch([handle], query.gates(), params, timeout=timeout)
    matched, skipped_time, bad_time, *rest = gate
    if matched > max_rows or bad_time:
        return None
    invalid_numeric: set[str] = set()
    for position, field in enumerate(numeric_fields):
        bad, abs_sum, has_invalid = rest[3 * position : 3 * position + 3]
        if bad or (abs_sum or 0) >= _EXACT_SUM_LIMIT:
            return None
        if has_invalid:
            invalid_numeric.add(field)
    rest = rest[3 * len(numeric_fields) :]
    ambiguous = False
    for position in range(len(distinct_fields)):
        whitespace, multi = rest[2 * position : 2 * position + 2]
        if whitespace:
            return None
        ambiguous = ambiguous or bool(multi)

    rows = store.fetch([handle], query.groups(), params, timeout=timeout)
    if len(rows) >= MAX_AGGREGATE_GROUPS:
        return None
    width = len(query.keys)
    groups: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in rows:
        key = tuple(row[:width])
        groups[key] = {"row": row[width:], "distinct": {}}

    total_distinct = 0
    for position, field in enumerate(distinct_fields):
        for row in store.fetch([handle], query.distinct(position), params, timeout=timeout):
            count = int(row[width])
            if count >= MAX_DISTINCT_PER_GROUP:
                return None
            total_distinct += count
            groups[tuple(row[:width])]["distinct"][field] = count
    if total_distinct >= MAX_TOTAL_DISTINCT_ITEMS:
        return None

    rendered = []
    seen_buckets: set[tuple[Any, ...]] = set()
    for key, state in groups.items():
        rendered_key: dict[str, Any] = {}
        parts = list(key)
        if time_bucket_seconds > 0:
            bucket = round(float(parts.pop(0)), 9)
            if not math.isfinite(bucket):
                return None
            rendered_key["time_bucket_start"] = bucket
            rendered_key["time_bucket_end"] = round(bucket + time_bucket_seconds, 9)
        for field, value in zip(group_fields, parts, strict=True):
            rendered_key[field] = value
        identity = tuple(rendered_key.values())
        if identity in seen_buckets:  # two raw buckets rounded together: let the accumulator merge them
            return None
        seen_buckets.add(identity)

        count = int(state["row"][0])
        entry: dict[str, Any] = {"key": rendered_key, "count": count}
        if distinct_fields:
            entry["distinct"] = {field: state["distinct"].get(field, 0) for field in distinct_fields}
        if numeric_fields:
            numeric: dict[str, dict[str, int | float | None]] = {}
            for position, field in enumerate(numeric_fields):
                valid, missing, invalid, total, low, high = state["row"][1 + 6 * position : 7 + 6 * position]
                operations = numeric_operations[field]
                values: dict[str, int | float | None] = {
                    "valid_values": int(valid),
                    "missing_values": int(missing),
                    "invalid_values": int(invalid),
                }
                as_float = float(total) if valid else 0.0
                if "sum" in operations:
                    values["sum"] = as_float if valid else None
                if "min" in operations:
                    values["min"] = float(low) if low is not None else None
                if "max" in operations:
                    values["max"] = float(high) if high is not None else None
                if "avg" in operations:
                    values["avg"] = as_float / int(valid) if valid else None
                numeric[field] = values
            entry["numeric"] = numeric
        rendered.append(entry)

    warnings = []
    if ambiguous:
        warnings.append(AMBIGUOUS_COMMAS_WARNING)
    if invalid_numeric:
        warnings.append(INVALID_NUMERIC_WARNING + ", ".join(sorted(invalid_numeric)))
    return rendered, int(matched), int(skipped_time), warnings
