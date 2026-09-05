# Result handling

Use this reference when deciding whether a result supports a conclusion or how to recover from a failed query.

| Result condition | Interpretation and next action |
|---|---|
| Protocol error or `success: false` | Execution failed. Preserve the error and affected scope; do not convert it into zero packets. Correct the identified cause before retrying. |
| Success with missing coverage | Completeness is unknown. Inspect limits and tool semantics before claiming a total or absence. |
| Complete scan, Top-K output | Global totals may be usable if the underlying aggregation is exact. Returned groups are not all groups. |
| Partial scan or capped cardinality | Counts may be lower bounds and rankings may be biased. Narrow to an explicit relevant scope or partition into disjoint windows, verifying each part. |
| Empty valid result | No matches for this exact query and observed scope. It does not prove no compromise, no traffic outside the window, or no encrypted activity. |
| Invalid JSON, contradictory metadata, or broken pagination | Result contract is unreliable. Do not invent a total or cursor; retry with a smaller explicit query or report the limitation. |

Check both envelope and nested result metadata. `truncated` can describe scan limits, output limits, or aggregation limits; determine which before using the numbers. Returned records must agree with returned counts. Preserve the global denominator and confirm that continuation does not skip records. A `has_more` flag without a usable continuation is not a pagination implementation.

On timeout or resource limits, change the query: reduce selected fields, narrow an explicitly reported time/host scope, or use a supported statistic. Do not repeat an identical failing query or silently increase limits. If splitting time windows, use non-overlapping boundaries. Counts can be summed only for disjoint packet sets; distinct counts cannot generally be summed across partitions.

For unknown fields or missing tools, inspect the available schema/capabilities once and choose a supported equivalent. For permission or missing input failures, identify what is needed; do not treat another backend as a way around the boundary. Stop when progress requires unavailable data or permissions.

Packets, extracted rows, field occurrences, unique values, and conversations have different denominators. One packet can contribute to multiple protocol layers or field occurrences. Do not add protocol-hierarchy percentages or split literal commas into values without a defined occurrence encoding. If byte sums or latency percentiles are unsupported, report that limitation rather than substituting packet counts.
