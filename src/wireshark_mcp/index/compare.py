"""First-seen timelines and differences between two captures or two filter windows.

Both views reduce the selected packets to *entities* — hosts, conversations,
protocols, DNS names, TLS server names, HTTP hosts and user agents, JA3/JA4
fingerprints — and record for each entity the first and last frame it appeared
in. Frame numbers and relative times are the capture's own, so every row points
at packets the tshark tools can open for evidence.

SQL here interpolates only quoted identifiers, module constants and
``filter_sql`` output, whose literal values are bound parameters; that is what
the ``nosec B608`` markers assert.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

# Per kind: (columns that must be indexed, SQL list of the entity values in one packet row).
# Items within a packet are de-duplicated so `packets` counts frames, not occurrences.
_KINDS: dict[str, tuple[tuple[str, ...], str]] = {
    "host": (
        ("ip.src", "ip.dst", "ipv6.src", "ipv6.dst"),
        "list_concat(string_split(COALESCE(\"ip.src\", ''), ','), string_split(COALESCE(\"ip.dst\", ''), ','),"
        " string_split(COALESCE(\"ipv6.src\", ''), ','), string_split(COALESCE(\"ipv6.dst\", ''), ','))",
    ),
    "conversation": (
        ("tcp.stream", "udp.stream"),
        "[conversation]",
    ),
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


def available_kinds(columns: frozenset[str] | set[str]) -> list[str]:
    return [kind for kind, (needed, _) in _KINDS.items() if all(column in columns for column in needed)]


def _entities_sql(kinds: list[str], source: str) -> str:
    """UNION ALL of (kind, item, capture_id, frame, rel, epoch) for each packet in ``source``."""
    parts = []
    for kind in kinds:
        values = _KINDS[kind][1]
        parts.append(
            f"SELECT '{kind}' AS kind, unnest(list_filter(list_distinct({values}), lambda v: COALESCE(v, '') <> '')) "  # nosec B608
            f"AS item, capture_id, frame, rel, epoch FROM {source}"
        )
    return "\nUNION ALL\n".join(parts)


def _selected_sql(where_sql: str) -> str:
    """Selected packets, with each one's conversation taken from its flow's first packet."""
    return f"""
        SELECT p.*,
            CASE WHEN f.stream IS NOT NULL
                 THEN f.transport || ' ' || COALESCE(f.src, '?') || ' -> ' || COALESCE(f.dst, '?') || ':'
                      || COALESCE(CAST(f.dport AS VARCHAR), '?') END AS conversation
        FROM pkt p
        LEFT JOIN flows f ON f.capture_id = p.capture_id AND f.transport = p.transport AND f.stream = p.stream
        WHERE {where_sql}
    """  # nosec B608


_PROFILE_SQL = """
    SELECT kind, item,
        count(*) AS packets,
        min({'epoch': epoch, 'capture_id': capture_id, 'frame': frame, 'rel': rel}) AS first,
        max({'epoch': epoch, 'capture_id': capture_id, 'frame': frame, 'rel': rel}) AS last
    FROM entities
    GROUP BY kind, item
"""


def _iso(epoch: float | None) -> str | None:
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


SPAN_COLUMNS = ["packets", "first_frame", "first_rel", "first_time", "last_frame", "last_rel"]


def _span(packets: int, first: dict[str, Any], last: dict[str, Any], with_capture: bool) -> list[Any]:
    """Packet count plus first and last sighting; frame numbers and relative times are per capture."""
    span = [packets, first["frame"], first["rel"], _iso(first["epoch"]), last["frame"], last["rel"]]
    if with_capture:
        span.extend([first["capture_id"], last["capture_id"]])
    return span


@dataclass(frozen=True)
class Side:
    """One side of a comparison: a capture label plus a translated filter."""

    capture_id: str
    where_sql: str
    params: list[Any]


def timeline_sql(kinds: list[str], where_sql: str) -> str:
    return f"""
        WITH selected AS ({_selected_sql(where_sql)}),
        entities AS ({_entities_sql(kinds, "selected")}),
        profile AS ({_PROFILE_SQL}),
        ranked AS (
            SELECT *, row_number() OVER (PARTITION BY kind ORDER BY first) AS position,
                   count(*) OVER (PARTITION BY kind) AS kind_total
            FROM profile
        )
        SELECT kind, item, packets, first, last, position, kind_total,
               (SELECT count(*) FROM selected) AS selected_packets
        FROM ranked
        WHERE position <= {TIMELINE_ITEMS_PER_KIND}
        ORDER BY first, kind, item
    """  # nosec B608


def render_timeline(rows: list[tuple[Any, ...]], kinds: list[str], with_capture: bool) -> dict[str, Any]:
    """Rows as a column list plus ``items`` arrays: compact, and the result cap trims ``items`` cleanly."""
    totals = {kind: 0 for kind in kinds}
    selected = 0
    items = []
    for kind, item, packets, first, last, _position, kind_total, selected_packets in rows:
        totals[kind] = int(kind_total)
        selected = int(selected_packets)
        items.append([kind, item, *_span(int(packets), first, last, with_capture)])
    shown = items[:TIMELINE_ITEMS]
    columns = ["kind", "value", *SPAN_COLUMNS]
    if with_capture:
        columns.extend(["first_capture_id", "last_capture_id"])
    return {
        "selected_packets": selected,
        "kinds": {kind: total for kind, total in totals.items() if total},
        "columns": columns,
        "items_returned": len(shown),
        "truncated": len(shown) < sum(totals.values()),
        "items": shown,
    }


def diff_sql(kinds: list[str], baseline: Side, compare: Side) -> tuple[str, list[Any]]:
    entities = _entities_sql(kinds, "selected")
    sql = f"""
        WITH
        base_selected AS ({_selected_sql("p.capture_id = ? AND (" + baseline.where_sql + ")")}),
        cmp_selected AS ({_selected_sql("p.capture_id = ? AND (" + compare.where_sql + ")")}),
        base_profile AS (WITH selected AS (SELECT * FROM base_selected), entities AS ({entities}) {_PROFILE_SQL}),
        cmp_profile AS (WITH selected AS (SELECT * FROM cmp_selected), entities AS ({entities}) {_PROFILE_SQL}),
        joined AS (
            SELECT COALESCE(b.kind, c.kind) AS kind, COALESCE(b.item, c.item) AS item,
                   CASE WHEN c.item IS NULL THEN 'gone' WHEN b.item IS NULL THEN 'new' ELSE 'common' END AS change,
                   COALESCE(b.packets, 0) AS base_packets, COALESCE(c.packets, 0) AS cmp_packets,
                   COALESCE(c.first, b.first) AS first, COALESCE(c.last, b.last) AS last
            FROM base_profile b FULL OUTER JOIN cmp_profile c ON b.kind = c.kind AND b.item = c.item
        ),
        counted AS (
            SELECT *, row_number() OVER (PARTITION BY kind, change ORDER BY first) AS position FROM joined
        )
        SELECT kind, item, change, base_packets, cmp_packets, first, last
        FROM counted
        WHERE change <> 'common' AND position <= {DIFF_ITEMS_PER_KIND}
        UNION ALL
        SELECT kind, NULL, change || '_total', count(*), NULL, NULL, NULL FROM joined GROUP BY kind, change
        UNION ALL
        SELECT '', NULL, 'packets', (SELECT count(*) FROM base_selected), (SELECT count(*) FROM cmp_selected), NULL, NULL
        ORDER BY 1, 3, 6
    """  # nosec B608
    return sql, [baseline.capture_id, *baseline.params, compare.capture_id, *compare.params]


def render_diff(rows: list[tuple[Any, ...]], kinds: list[str]) -> dict[str, Any]:
    """New items come from the compare side, gone items from the baseline, so no capture column is needed."""
    summary = {kind: {"baseline": 0, "compare": 0, "new": 0, "gone": 0, "common": 0} for kind in kinds}
    items: list[list[Any]] = []
    packets = {"baseline": 0, "compare": 0}
    for kind, item, change, base_packets, cmp_packets, first, last in rows:
        if change == "packets":
            packets = {"baseline": int(base_packets), "compare": int(cmp_packets)}
            continue
        if change.endswith("_total"):
            summary[kind][change.removesuffix("_total")] = int(base_packets)
            continue
        seen = int(cmp_packets if change == "new" else base_packets)
        items.append([change, kind, item, *_span(seen, first, last, False)])
    order = {kind: position for position, kind in enumerate(kinds)}
    items.sort(key=lambda row: (row[0] != "new", order[row[1]]))  # stable: keeps first-seen order per kind
    for counts in summary.values():
        counts["baseline"] = counts["gone"] + counts["common"]
        counts["compare"] = counts["new"] + counts["common"]
    return {
        "selected_packets": packets,
        "summary": {kind: counts for kind, counts in summary.items() if counts["baseline"] or counts["compare"]},
        "columns": ["change", "kind", "value", *SPAN_COLUMNS],
        "items_returned": len(items),
        "truncated": len(items) < sum(summary[kind]["new"] + summary[kind]["gone"] for kind in kinds),
        "items": items,
    }
