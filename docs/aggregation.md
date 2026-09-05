# Capture-wide aggregation

[中文版](aggregation_zh.md)

`wireshark_aggregate` answers questions that require the whole filtered capture: totals, grouped packet counts, distinct cardinality, top-k groups, and time buckets. Use packet-list and field-extraction tools when individual rows matter; use aggregation when a page of rows would be a misleading sample.

The implementation consumes tshark output one row at a time. It retains only bounded group, distinct-value, and numeric-reducer state; it does not build a complete TSV string or packet-row list in memory.

## Parameters

| Parameter | Meaning |
|-----------|---------|
| `pcap_file` | Local `.pcap` or `.pcapng` path readable by the server. |
| `display_filter` | Optional Wireshark display filter applied before aggregation. |
| `group_by` | Comma-separated tshark fields that form each group key. |
| `distinct` | Comma-separated fields whose distinct values are counted inside each group. |
| `sum_fields`, `min_fields`, `max_fields`, `avg_fields` | Comma-separated numeric fields for each operation. The result reports valid, missing, and invalid values per field and group. |
| `time_bucket_seconds` | Bucket width in seconds. `0` disables bucketing; positive values must be at least `0.000001`. |
| `top_k` | Number of groups returned, from 1 to 200. It does not reduce the number of matched packets scanned. |
| `sort_by` | Existing count/key orders, plus `numeric_desc` or `numeric_asc`. Numeric sorting requires `sort_numeric`. |
| `sort_numeric` | Numeric field used for ordering. It must appear in at least one numeric operation. When several operations were requested, sorting prefers `sum`, then `avg`, `min`, and `max`. |

At most 12 unique fields may be requested across grouping, distinct, and numeric operations.

## Common calls

Count all TCP SYN packets:

```text
wireshark_aggregate(
  pcap_file="capture.pcap",
  display_filter="tcp.flags.syn == 1 and tcp.flags.ack == 0"
)
```

Find the busiest DNS query sources and count the queried names per source:

```text
wireshark_aggregate(
  pcap_file="capture.pcap",
  display_filter="dns.flags.response == 0",
  group_by="ip.src",
  distinct="dns.qry.name",
  top_k=20
)
```

Build a one-minute timeline split by source:

```text
wireshark_aggregate(
  pcap_file="capture.pcap",
  display_filter="ip",
  group_by="ip.src",
  time_bucket_seconds=60,
  sort_by="auto"
)
```

Find sources contributing the most captured bytes:

```text
wireshark_aggregate(
  pcap_file="capture.pcap",
  display_filter="ip.src",
  group_by="ip.src",
  sum_fields="frame.len",
  avg_fields="frame.len",
  sort_by="numeric_desc",
  sort_numeric="frame.len"
)
```

`frame.len` is the captured frame length, not application payload. Units and semantics come from the requested tshark field; the tool does not convert them.

There is no need to include `frame.time_relative` in `group_by` when a time bucket is set. If supplied, it is removed because time is already an implicit grouping dimension.

## Result shape

The success envelope contains:

- `matched_packets`: packet rows matched before time validation
- `groups_total`: number of groups computed across the complete scan
- `groups_returned`: number of groups included after `top_k`
- `truncated`: whether additional groups exist beyond `top_k`
- `groups`: each entry contains a `key`, packet `count`, optional `distinct` cardinality, and optional `numeric` results
- `skipped_invalid_time`: present when packets could not be assigned to a valid time bucket

`count` always means packets in the group, not field occurrences or bytes. A field in `distinct` may occur more than once in one packet; repeated tshark occurrences are expanded before cardinality is calculated.

Each numeric field reports `valid_values`, `missing_values`, and `invalid_values`, followed by the requested operations. An operation is `null` when no valid values exist. Non-decimal, non-finite, overflowing, and multi-occurrence cells are not guessed; they are counted as invalid and make coverage partial.

## Limits and interpretation

- The tool stops and returns `LimitExceeded` when more than 1,000,000 matching packet rows are found. Narrow `display_filter` or split the capture into justified time windows.
- Streamed stdout is also capped at 50 MiB. This independent limit covers captures with unusually wide field values even when the packet count is below the row ceiling.
- `top_k` limits returned groups only. This keeps the statistical result complete while controlling response size.
- Group keys are tshark field text. Key sorting is lexical except for the numeric time-bucket prefix.
- Text fields that can contain literal commas may be ambiguous with tshark's repeated-value separator. Prefer scalar directional fields such as `ip.src`, `ip.dst`, `tcp.srcport`, or `tcp.dstport`, then verify unusual groups with `wireshark_extract_fields`.
- The server has a separate result character ceiling. Lower `top_k` or reduce grouped dimensions when a result is too large.
- Empty field values can form an empty-string group. Add a presence test such as `http.host` to the display filter when missing values should be excluded.

Aggregation establishes scale and priority. Confirm important conclusions with exact frame numbers, packet details, context, or a followed stream.
