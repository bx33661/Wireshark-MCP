"""First-seen timelines and differences between two captures or two filter windows.

Both views reduce the selected packets to *entities* — hosts, conversations,
protocols, DNS names, TLS server names, HTTP hosts and user agents, JA3/JA4
fingerprints — and record for each entity the first and last frame it appeared
in. Frame numbers and relative times are the capture's own, so every row points
at packets the tshark tools can open for evidence.

Each kind is profiled by its own query, and a sighting is carried as one
BIGINT (capture position << 40 | frame), so every step is a plain hash
aggregate, join or top-N that DuckDB can spill to disk: a 10 GB capture with
fifteen million conversations fits the 2 GB memory limit. Relative and absolute
times are looked up afterwards for the few frames that are returned.

SQL here interpolates only quoted identifiers, module constants and
``filter_sql`` output, whose literal values are bound parameters; that is what
the ``nosec B608`` markers assert.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

Run = Callable[[str, list[Any]], list[tuple[Any, ...]]]

# Per kind: (columns that must be indexed, SQL list of the entity values in one packet row).
# Items within a packet are de-duplicated so `packets` counts frames, not occurrences.
_KINDS: dict[str, tuple[tuple[str, ...], str]] = {
    "host": (
        ("ip.src", "ip.dst", "ipv6.src", "ipv6.dst"),
        "list_concat(string_split(COALESCE(\"ip.src\", ''), ','), string_split(COALESCE(\"ip.dst\", ''), ','),"
        " string_split(COALESCE(\"ipv6.src\", ''), ','), string_split(COALESCE(\"ipv6.dst\", ''), ','))",
    ),
    "conversation": (("tcp.stream", "udp.stream"), ""),  # built from flows, see _profile_sql
    "protocol": (("frame.protocols",), "string_split(COALESCE(\"frame.protocols\", ''), ':')"),
    "dns_name": (("dns.qry.name",), "string_split(COALESCE(\"dns.qry.name\", ''), ',')"),
    "tls_sni": (("tls.handshake.extensions_server_name",), '["tls.handshake.extensions_server_name"]'),
    "http_host": (("http.host",), '["http.host"]'),
    "user_agent": (("http.user_agent",), '["http.user_agent"]'),
    "ja3": (("tls.handshake.ja3",), "string_split(COALESCE(\"tls.handshake.ja3\", ''), ',')"),
    "ja4": (("tls.handshake.ja4",), "string_split(COALESCE(\"tls.handshake.ja4\", ''), ',')"),
}

# Rows returned per view, sized to fit the default 8,000-character result cap;
# per-kind totals are always complete. Narrow with display_filter for more.
TIMELINE_ITEMS_PER_KIND = 20
TIMELINE_ITEMS = 60
DIFF_ITEMS_PER_KIND = 10

_FRAME_BITS = 40
_FRAME_MASK = (1 << _FRAME_BITS) - 1

SPAN_COLUMNS = ["packets", "first_frame", "first_rel", "first_time", "last_frame", "last_rel"]


def available_kinds(columns: frozenset[str] | set[str]) -> list[str]:
    return [kind for kind, (needed, _) in _KINDS.items() if all(column in columns for column in needed)]


def _sql_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


@dataclass(frozen=True)
class Side:
    """One selection: capture labels in sighting order plus a translated filter."""

    labels: list[str]
    where_sql: str
    params: list[Any]


def _position_sql(labels: list[str]) -> str:
    if len(labels) == 1:
        return "0"
    cases = " ".join(f"WHEN {_sql_string(label)} THEN {position}" for position, label in enumerate(labels))
    return f"CASE capture_id {cases} END"


def _selected_sql(side: Side) -> str:
    """Selected packets with a sortable sighting key; capture order first, then frame."""
    labels = ", ".join(_sql_string(label) for label in side.labels)
    return (
        f"SELECT (CAST({_position_sql(side.labels)} AS BIGINT) << {_FRAME_BITS}) + frame AS key, *"  # nosec B608
        f" FROM pkt WHERE capture_id IN ({labels}) AND ({side.where_sql})"
    )


def _profile_sql(kind: str, selected: str) -> str:
    """(item, packets, first key, last key) for one kind over the ``selected`` relation."""
    if kind == "conversation":
        return f"""
            SELECT f.transport || ' ' || COALESCE(f.src, '?') || ' -> ' || COALESCE(f.dst, '?') || ':'
                       || COALESCE(CAST(f.dport AS VARCHAR), '?') AS item,
                   sum(s.packets) AS packets, min(s.f) AS f, max(s.l) AS l
            FROM (
                SELECT capture_id, transport, stream, count(*) AS packets, min(key) AS f, max(key) AS l
                FROM {selected} WHERE stream IS NOT NULL GROUP BY capture_id, transport, stream
            ) s
            JOIN flows f ON f.capture_id = s.capture_id AND f.transport = s.transport AND f.stream = s.stream
            GROUP BY 1
        """  # nosec B608
    values = _KINDS[kind][1]
    return f"""
        SELECT item, count(*) AS packets, min(key) AS f, max(key) AS l
        FROM (
            SELECT unnest(list_filter(list_distinct({values}), lambda v: COALESCE(v, '') <> '')) AS item, key
            FROM {selected}
        )
        GROUP BY item
    """  # nosec B608


def _iso(epoch: float | None) -> str | None:
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


class _Points:
    """Look up capture, relative and absolute time for sighting keys, all at once."""

    def __init__(self, labels: list[str]) -> None:
        self.labels = labels
        self.wanted: set[int] = set()
        self.found: dict[int, tuple[str, int, float | None, float | None]] = {}

    def want(self, *keys: int) -> None:
        self.wanted.update(keys)

    def resolve(self, run: Run) -> None:
        by_capture: dict[int, list[int]] = {}
        for key in self.wanted:
            by_capture.setdefault(key >> _FRAME_BITS, []).append(key & _FRAME_MASK)
        for position, frames in by_capture.items():
            label = self.labels[position]
            placeholders = ", ".join("?" for _ in frames)
            sql = f"SELECT frame, rel, epoch FROM pkt WHERE capture_id = ? AND frame IN ({placeholders})"  # nosec B608
            for frame, rel, epoch in run(sql, [label, *frames]):
                self.found[(position << _FRAME_BITS) + int(frame)] = (label, int(frame), rel, epoch)

    def span(self, packets: int, first: int, last: int, with_capture: bool) -> list[Any]:
        first_capture, first_frame, first_rel, first_epoch = self.found[first]
        last_capture, last_frame, last_rel, _ = self.found[last]
        span = [packets, first_frame, first_rel, _iso(first_epoch), last_frame, last_rel]
        if with_capture:
            span.extend([first_capture, last_capture])
        return span


def timeline(run: Run, kinds: list[str], side: Side) -> dict[str, Any]:
    """First and last sighting per entity, earliest first, up to the row budget."""
    selected = f"({_selected_sql(side)})"
    totals: dict[str, int] = {}
    found: list[tuple[int, str, str, int, int]] = []
    for kind in kinds:
        sql = f"""
            WITH profile AS MATERIALIZED ({_profile_sql(kind, selected)})
            SELECT * FROM (SELECT item, packets, f, l FROM profile ORDER BY f, item LIMIT {TIMELINE_ITEMS_PER_KIND})
            UNION ALL SELECT NULL, count(*), NULL, NULL FROM profile
        """  # nosec B608
        for item, packets, first, last in run(sql, list(side.params)):
            if first is None:
                totals[kind] = int(packets)
            else:
                found.append((int(first), kind, item, int(packets), int(last)))
    (count,) = run(f"SELECT count(*) FROM {selected}", list(side.params))  # nosec B608
    found.sort(key=lambda row: (row[0], row[1], row[2]))
    shown = found[:TIMELINE_ITEMS]
    points = _Points(side.labels)
    for first, _kind, _item, _packets, last in shown:
        points.want(first, last)
    points.resolve(run)
    with_capture = len(side.labels) > 1
    columns = ["kind", "value", *SPAN_COLUMNS]
    if with_capture:
        columns.extend(["first_capture_id", "last_capture_id"])
    return {
        "selected_packets": int(count[0]),
        "kinds": {kind: total for kind, total in totals.items() if total},
        "columns": columns,
        "items_returned": len(shown),
        "truncated": len(shown) < sum(totals.values()),
        "items": [
            [kind, item, *points.span(packets, first, last, with_capture)] for first, kind, item, packets, last in shown
        ],
    }


def diff(run: Run, kinds: list[str], baseline: Side, compare: Side) -> dict[str, Any]:
    """Entities only one side has: ``new`` point into the comparison, ``gone`` into the baseline."""
    base_selected = f"({_selected_sql(baseline)})"
    cmp_selected = f"({_selected_sql(compare)})"
    params = [*baseline.params, *compare.params]
    summary: dict[str, dict[str, int]] = {}
    rows: list[tuple[str, str, str, int, int, int]] = []
    for kind in kinds:
        sql = f"""
            WITH base AS ({_profile_sql(kind, base_selected)}),
            cmp AS ({_profile_sql(kind, cmp_selected)}),
            joined AS MATERIALIZED (
                SELECT COALESCE(b.item, c.item) AS item,
                       CASE WHEN c.item IS NULL THEN 'gone' WHEN b.item IS NULL THEN 'new' ELSE 'common' END AS change,
                       COALESCE(c.packets, b.packets) AS packets,
                       COALESCE(c.f, b.f) AS f, COALESCE(c.l, b.l) AS l
                FROM base b FULL OUTER JOIN cmp c ON b.item = c.item
            )
            SELECT * FROM (SELECT change, item, packets, f, l FROM joined WHERE change = 'new'
                           ORDER BY f, item LIMIT {DIFF_ITEMS_PER_KIND})
            UNION ALL
            SELECT * FROM (SELECT change, item, packets, f, l FROM joined WHERE change = 'gone'
                           ORDER BY f, item LIMIT {DIFF_ITEMS_PER_KIND})
            UNION ALL
            SELECT change || '_total', NULL, count(*), NULL, NULL FROM joined GROUP BY change
        """  # nosec B608
        counts = {"baseline": 0, "compare": 0, "new": 0, "gone": 0, "common": 0}
        for change, item, packets, first, last in run(sql, params):
            if change.endswith("_total"):
                counts[change.removesuffix("_total")] = int(packets)
            else:
                rows.append((change, kind, item, int(packets), int(first), int(last)))
        counts["baseline"] = counts["gone"] + counts["common"]
        counts["compare"] = counts["new"] + counts["common"]
        summary[kind] = counts
    (packets,) = run(
        f"SELECT (SELECT count(*) FROM {base_selected}), (SELECT count(*) FROM {cmp_selected})",  # nosec B608
        params,
    )
    order = {kind: position for position, kind in enumerate(kinds)}
    rows.sort(key=lambda row: (row[0] != "new", order[row[1]], row[4], row[2]))
    labels = list(dict.fromkeys([*baseline.labels, *compare.labels]))
    points = _Points(labels)
    remap = {label: position for position, label in enumerate(labels)}
    resolved_rows = []
    for change, kind, item, count, first, last in rows:
        side = compare if change == "new" else baseline
        # Keys were built with the side's own capture positions; translate to the shared list.
        offset = remap[side.labels[first >> _FRAME_BITS]] << _FRAME_BITS
        first_key = offset + (first & _FRAME_MASK)
        last_key = (remap[side.labels[last >> _FRAME_BITS]] << _FRAME_BITS) + (last & _FRAME_MASK)
        points.want(first_key, last_key)
        resolved_rows.append((change, kind, item, count, first_key, last_key))
    points.resolve(run)
    return {
        "selected_packets": {"baseline": int(packets[0]), "compare": int(packets[1])},
        "summary": {kind: counts for kind, counts in summary.items() if counts["baseline"] or counts["compare"]},
        "columns": ["change", "kind", "value", *SPAN_COLUMNS],
        "items_returned": len(resolved_rows),
        "truncated": len(resolved_rows) < sum(counts["new"] + counts["gone"] for counts in summary.values()),
        "items": [
            [change, kind, item, *points.span(count, first, last, False)]
            for change, kind, item, count, first, last in resolved_rows
        ],
    }
