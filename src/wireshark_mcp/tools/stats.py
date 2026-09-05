import math
from collections import defaultdict
from typing import Any, Literal, TypedDict

from mcp.server import MCPServer

from ..tshark.client import TSharkClient
from .envelope import (
    envelope_response,
    error_response,
    normalize_tool_result,
    parse_tool_result,
    success_response,
)
from .formatting import summarize_tabular

MAX_AGGREGATE_FIELDS = 12
MAX_AGGREGATE_TOP_K = 200
AGGREGATE_SCAN_LIMIT = 1_000_000
MIN_TIME_BUCKET_SECONDS = 0.000001


def _field_list(value: str) -> list[str]:
    """Parse and de-duplicate a comma-separated field list without reordering it."""
    return list(dict.fromkeys(part.strip() for part in value.split(",") if part.strip()))


MAX_AGGREGATE_GROUPS = 10_000
MAX_DISTINCT_PER_GROUP = 5_000
MAX_TOTAL_DISTINCT_ITEMS = 50_000

LITERAL_STRING_FIELDS = frozenset(
    {
        "http.user_agent",
        "http.authorization",
        "http.cookie",
        "http.set_cookie",
        "http.accept",
        "http.host",
        "tls.handshake.extensions_server_name",
        "x509sat.printableString",
        "x509sat.uTF8String",
    }
)


class _NumericState(TypedDict):
    valid_values: int
    missing_values: int
    invalid_values: int
    sum: float
    min: float | None
    max: float | None


class _AggregateAccumulator:
    """Bounded aggregate state consumed one decoded tshark row at a time."""

    def __init__(
        self,
        extracted_fields: list[str],
        group_fields: list[str],
        distinct_fields: list[str],
        time_bucket_seconds: float,
        numeric_operations: dict[str, set[str]] | None = None,
    ) -> None:
        self.indexes = {field: index for index, field in enumerate(extracted_fields)}
        self.field_count = len(extracted_fields)
        self.group_fields = group_fields
        self.distinct_fields = distinct_fields
        self.time_bucket_seconds = time_bucket_seconds
        self.numeric_operations = numeric_operations or {}
        self.grouped_counts: dict[tuple[Any, ...], int] = defaultdict(int)
        self.grouped_distinct: dict[tuple[Any, ...], dict[str, set[str]]] = defaultdict(
            lambda: {field: set() for field in distinct_fields}
        )
        self.numeric_state: dict[tuple[Any, ...], dict[str, _NumericState]] = defaultdict(dict)
        self.skipped_invalid_time = 0
        self.dropped_groups = 0
        self.distinct_capped = False
        self.total_distinct_items = 0
        self.total_distinct_capped = False
        self.ambiguous_commas = False
        self.invalid_numeric_fields: set[str] = set()

    def add(self, row: list[str]) -> None:
        padded = row + [""] * max(0, self.field_count - len(row))
        key_parts: list[Any] = []
        if self.time_bucket_seconds > 0:
            try:
                relative_time = float(padded[self.indexes["frame.time_relative"]])
                bucket_start = math.floor(relative_time / self.time_bucket_seconds) * self.time_bucket_seconds
                if not math.isfinite(bucket_start):
                    self.skipped_invalid_time += 1
                    return
            except (TypeError, ValueError, OverflowError):
                self.skipped_invalid_time += 1
                return
            key_parts.append(round(bucket_start, 9))

        key_parts.extend(padded[self.indexes[field]] for field in self.group_fields)
        key = tuple(key_parts)
        if len(self.grouped_counts) >= MAX_AGGREGATE_GROUPS and key not in self.grouped_counts:
            self.dropped_groups += 1
            return
        self.grouped_counts[key] += 1
        self._add_distinct(key, padded)
        self._add_numeric(key, padded)

    def _add_distinct(self, key: tuple[Any, ...], row: list[str]) -> None:
        for field in self.distinct_fields:
            value = row[self.indexes[field]]
            if not value:
                continue
            current = self.grouped_distinct[key][field]
            if field in LITERAL_STRING_FIELDS:
                items = [value.strip()]
            else:
                items = [item.strip() for item in value.split(",") if item.strip()]
                if len(items) > 1 and not field.startswith(("ip.", "ipv6.", "tcp.", "udp.", "dns.")):
                    self.ambiguous_commas = True
            for item in items:
                if item in current:
                    continue
                if len(current) >= MAX_DISTINCT_PER_GROUP:
                    self.distinct_capped = True
                    break
                if self.total_distinct_items >= MAX_TOTAL_DISTINCT_ITEMS:
                    self.total_distinct_capped = True
                    break
                current.add(item)
                self.total_distinct_items += 1

    def _add_numeric(self, key: tuple[Any, ...], row: list[str]) -> None:
        for field in self.numeric_operations:
            value = row[self.indexes[field]].strip()
            state = self.numeric_state[key].setdefault(
                field,
                {"valid_values": 0, "missing_values": 0, "invalid_values": 0, "sum": 0.0, "min": None, "max": None},
            )
            if not value:
                state["missing_values"] += 1
                continue
            try:
                number = float(value) if "," not in value else math.nan
            except (TypeError, ValueError):
                number = math.nan
            new_sum = state["sum"] + number
            if not math.isfinite(number) or not math.isfinite(new_sum):
                state["invalid_values"] += 1
                self.invalid_numeric_fields.add(field)
                continue
            state["valid_values"] += 1
            state["sum"] = new_sum
            state["min"] = number if state["min"] is None else min(state["min"], number)
            state["max"] = number if state["max"] is None else max(state["max"], number)

    def finish(self) -> tuple[list[dict[str, Any]], int, list[str]]:
        warnings: list[str] = []
        if self.dropped_groups:
            warnings.append(
                f"Aggregate exceeded maximum unique group limit of {MAX_AGGREGATE_GROUPS}; "
                f"{self.dropped_groups} new group(s) were dropped."
            )
        if self.distinct_capped:
            warnings.append(
                f"One or more groups hit the distinct cardinality ceiling of {MAX_DISTINCT_PER_GROUP} items."
            )
        if self.total_distinct_capped:
            warnings.append(
                f"Aggregate hit the global distinct cardinality budget of {MAX_TOTAL_DISTINCT_ITEMS} items."
            )
        if self.ambiguous_commas:
            warnings.append(
                "Distinct field(s) contained comma delimiters; distinct count may combine multiple occurrences "
                "with literal comma characters."
            )
        if self.invalid_numeric_fields:
            warnings.append(
                "Numeric aggregation skipped invalid, non-finite, or multi-occurrence values for: "
                + ", ".join(sorted(self.invalid_numeric_fields))
            )
        return self._render_groups(), self.skipped_invalid_time, warnings

    def _render_groups(self) -> list[dict[str, Any]]:
        groups: list[dict[str, Any]] = []
        for key, count in self.grouped_counts.items():
            key_index = 0
            rendered_key: dict[str, Any] = {}
            if self.time_bucket_seconds > 0:
                bucket_start = key[key_index]
                rendered_key["time_bucket_start"] = bucket_start
                rendered_key["time_bucket_end"] = round(bucket_start + self.time_bucket_seconds, 9)
                key_index += 1
            for field in self.group_fields:
                rendered_key[field] = key[key_index]
                key_index += 1

            entry: dict[str, Any] = {"key": rendered_key, "count": count}
            if self.distinct_fields:
                entry["distinct"] = {field: len(self.grouped_distinct[key][field]) for field in self.distinct_fields}
            if self.numeric_operations:
                entry["numeric"] = self._render_numeric(key, count)
            groups.append(entry)
        return groups

    def _render_numeric(self, key: tuple[Any, ...], count: int) -> dict[str, dict[str, int | float | None]]:
        numeric: dict[str, dict[str, int | float | None]] = {}
        for field, operations in self.numeric_operations.items():
            state = self.numeric_state[key].get(
                field,
                {"valid_values": 0, "missing_values": count, "invalid_values": 0, "sum": 0.0, "min": None, "max": None},
            )
            valid = state["valid_values"]
            rendered: dict[str, int | float | None] = {
                "valid_values": valid,
                "missing_values": state["missing_values"],
                "invalid_values": state["invalid_values"],
            }
            if "sum" in operations:
                rendered["sum"] = state["sum"] if valid else None
            if "min" in operations:
                rendered["min"] = state["min"]
            if "max" in operations:
                rendered["max"] = state["max"]
            if "avg" in operations:
                rendered["avg"] = state["sum"] / valid if valid else None
            numeric[field] = rendered
        return numeric


def _aggregate_rows(
    rows: list[list[str]],
    extracted_fields: list[str],
    group_fields: list[str],
    distinct_fields: list[str],
    time_bucket_seconds: float,
    numeric_operations: dict[str, set[str]] | None = None,
) -> tuple[list[dict[str, Any]], int, list[str]]:
    """Compatibility helper exercising the same accumulator as streaming calls."""
    accumulator = _AggregateAccumulator(
        extracted_fields, group_fields, distinct_fields, time_bucket_seconds, numeric_operations
    )
    for row in rows:
        accumulator.add(row)
    return accumulator.finish()


def _maybe_summarize(raw_result: str, max_rows: int = 50) -> str:
    """Apply tabular summarization to successful string results."""
    wrapped = parse_tool_result(raw_result)
    if wrapped["success"] and isinstance(wrapped.get("data"), str):
        return success_response(summarize_tabular(wrapped["data"], max_rows))
    return normalize_tool_result(raw_result)


def register_stats_tools(mcp: MCPServer, client: TSharkClient) -> None:

    @mcp.tool()
    async def wireshark_aggregate(
        pcap_file: str,
        display_filter: str = "",
        group_by: str = "",
        distinct: str = "",
        sum_fields: str = "",
        min_fields: str = "",
        max_fields: str = "",
        avg_fields: str = "",
        time_bucket_seconds: float = 0,
        top_k: int = 50,
        sort_by: Literal[
            "auto", "count_desc", "count_asc", "key_asc", "key_desc", "numeric_desc", "numeric_asc"
        ] = "auto",
        sort_numeric: str = "",
    ) -> str:
        """[Primary statistics] Full-filter counts, groups, distinct values, numeric metrics, top-k, and time buckets. Field lists are comma-separated."""
        group_fields = _field_list(group_by)
        distinct_fields = _field_list(distinct)
        requested_numeric = {
            "sum": _field_list(sum_fields),
            "min": _field_list(min_fields),
            "max": _field_list(max_fields),
            "avg": _field_list(avg_fields),
        }
        numeric_operations: dict[str, set[str]] = {}
        for operation, fields in requested_numeric.items():
            for field in fields:
                numeric_operations.setdefault(field, set()).add(operation)
        # The time bucket is already an implicit grouping dimension. Models often
        # also pass frame.time_relative in group_by; keeping it would split every
        # bucket back into one group per packet and defeat the requested timeline.
        time_field_normalized = time_bucket_seconds > 0 and "frame.time_relative" in group_fields
        if time_field_normalized:
            group_fields.remove("frame.time_relative")
        requested_fields = list(dict.fromkeys(group_fields + distinct_fields + list(numeric_operations)))

        if len(requested_fields) > MAX_AGGREGATE_FIELDS:
            return error_response(
                f"At most {MAX_AGGREGATE_FIELDS} aggregate fields are allowed.",
                "InvalidParameter",
            )
        if not 1 <= top_k <= MAX_AGGREGATE_TOP_K:
            return error_response(
                f"top_k must be between 1 and {MAX_AGGREGATE_TOP_K}.",
                "InvalidParameter",
            )
        if not math.isfinite(time_bucket_seconds) or time_bucket_seconds < 0:
            return error_response(
                "time_bucket_seconds must be a finite non-negative number.",
                "InvalidParameter",
            )
        if 0 < time_bucket_seconds < MIN_TIME_BUCKET_SECONDS:
            return error_response(
                f"time_bucket_seconds must be at least {MIN_TIME_BUCKET_SECONDS} seconds.",
                "InvalidParameter",
            )
        if sort_by.startswith("numeric_"):
            if sort_numeric not in numeric_operations:
                return error_response(
                    "sort_numeric must name a field requested by sum_fields, min_fields, max_fields, or avg_fields.",
                    "InvalidParameter",
                )
            sort_operation = next(
                (
                    operation
                    for operation in ("sum", "avg", "min", "max")
                    if operation in numeric_operations[sort_numeric]
                ),
                None,
            )
        else:
            sort_operation = None

        # frame.number guarantees one non-empty output line per matching packet.
        # frame.time_relative is added only when the grouping requires it.
        extracted_fields = list(dict.fromkeys(["frame.number", *requested_fields]))
        if time_bucket_seconds > 0 and "frame.time_relative" not in extracted_fields:
            extracted_fields.append("frame.time_relative")

        accumulator = _AggregateAccumulator(
            extracted_fields,
            group_fields,
            distinct_fields,
            time_bucket_seconds,
            numeric_operations,
        )
        streamed = await client.stream_fields(
            pcap_file,
            extracted_fields,
            accumulator.add,
            display_filter,
            max_rows=AGGREGATE_SCAN_LIMIT,
        )
        matched_packets = streamed.get("rows", 0)
        if not streamed.get("success", False):
            stream_error = streamed.get("error", {})
            error_type = stream_error.get("type", "ExecutionError")
            message = stream_error.get("message", "tshark field stream failed")
            details = stream_error.get("details")
            return error_response(
                message,
                error_type,
                details,
                coverage={
                    "status": "partial",
                    "scanned": matched_packets,
                    "limit": AGGREGATE_SCAN_LIMIT,
                },
            )
        groups, skipped_invalid_time, agg_warnings = accumulator.finish()

        def key_tuple(entry: dict[str, Any]) -> tuple[Any, ...]:
            return tuple(entry["key"].values())

        resolved_sort = "key_asc" if sort_by == "auto" and time_bucket_seconds > 0 else sort_by
        if resolved_sort == "auto":
            resolved_sort = "count_desc"

        if resolved_sort.startswith("numeric_"):
            if sort_operation is None:
                return error_response(
                    "Numeric sort operation could not be resolved.",
                    "InternalError",
                )

            def numeric_sort_value(entry: dict[str, Any]) -> float | None:
                value = entry["numeric"][sort_numeric].get(sort_operation)
                return float(value) if isinstance(value, (int, float)) else None

            if resolved_sort == "numeric_desc":
                groups.sort(
                    key=lambda entry: (
                        numeric_sort_value(entry) is not None,
                        numeric_sort_value(entry) or 0.0,
                        key_tuple(entry),
                    ),
                    reverse=True,
                )
            else:
                groups.sort(
                    key=lambda entry: (
                        numeric_sort_value(entry) is None,
                        numeric_sort_value(entry) or 0.0,
                        key_tuple(entry),
                    )
                )
        elif resolved_sort == "count_desc":
            groups.sort(key=lambda entry: (-entry["count"], key_tuple(entry)))
        elif resolved_sort == "count_asc":
            groups.sort(key=lambda entry: (entry["count"], key_tuple(entry)))
        elif resolved_sort == "key_desc":
            groups.sort(key=key_tuple, reverse=True)
        else:
            groups.sort(key=key_tuple)

        total_groups = len(groups)
        result: dict[str, Any] = {
            "display_filter": display_filter,
            "group_by": group_fields,
            "distinct": distinct_fields,
            "numeric_operations": {field: sorted(operations) for field, operations in numeric_operations.items()},
            "time_bucket_seconds": time_bucket_seconds,
            "sort_by": resolved_sort,
            "matched_packets": matched_packets,
            "groups_total": total_groups,
            "groups_returned": min(total_groups, top_k),
            "truncated": total_groups > top_k,
            "groups": groups[:top_k],
        }
        if skipped_invalid_time:
            result["skipped_invalid_time"] = skipped_invalid_time
        if time_field_normalized:
            result["normalized_group_by"] = "frame.time_relative is implicit in time buckets"
        return envelope_response(
            result,
            warnings=agg_warnings if agg_warnings else None,
            coverage={
                "status": "complete" if not agg_warnings else "partial",
                "scanned": matched_packets,
                "limit": AGGREGATE_SCAN_LIMIT,
            },
            stderr=streamed.get("stderr"),
        )

    @mcp.tool()
    async def wireshark_stats_protocol_hierarchy(pcap_file: str) -> str:
        """[PHS] Protocol hierarchy statistics showing distribution of protocols in the capture."""
        return normalize_tool_result(await client.get_protocol_stats(pcap_file))

    @mcp.tool()
    async def wireshark_stats_endpoints(pcap_file: str, type: str = "ip") -> str:
        """[Endpoints] List all endpoints and traffic stats. type: 'eth'|'ip'|'ipv6'|'tcp'|'udp'|'sctp'|'wlan'."""
        return _maybe_summarize(await client.get_endpoints(pcap_file, type))

    @mcp.tool()
    async def wireshark_stats_conversations(pcap_file: str, type: str = "ip") -> str:
        """[Conversations] Communication pairs and stats. type: 'eth'|'ip'|'ipv6'|'tcp'|'udp'|'sctp'|'wlan'."""
        return _maybe_summarize(await client.get_conversations(pcap_file, type))

    @mcp.tool()
    async def wireshark_stats_io_graph(pcap_file: str, interval: int = 1, filters: str = "") -> str:
        """[I/O Graph] Traffic volume over time. interval: bucket size in seconds. filters: optional
        semicolon-separated display filters to break the traffic out by type, e.g. 'tcp;udp;dns'."""
        filter_list = [f.strip() for f in filters.split(";") if f.strip()] if filters else None
        if filter_list:
            return _maybe_summarize(await client.get_io_stat_filtered(pcap_file, interval, filter_list))
        return _maybe_summarize(await client.get_io_graph(pcap_file, interval))

    @mcp.tool()
    async def wireshark_stats_expert_info(pcap_file: str) -> str:
        """[Expert Info] Automatic anomaly detection: retransmissions, errors, warnings, protocol issues."""
        return _maybe_summarize(await client.get_expert_info(pcap_file), max_rows=80)

    @mcp.tool()
    async def wireshark_stats_service_response_time(pcap_file: str, protocol: str = "http") -> str:
        """[SRT] Service response time statistics. protocol: 'http'|'dns'|'smb' etc."""
        return _maybe_summarize(await client.get_service_response_time(pcap_file, protocol))
