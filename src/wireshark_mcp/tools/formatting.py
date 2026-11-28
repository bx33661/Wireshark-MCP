"""Token-efficient output formatting utilities."""

import re

CRIT = "[!]"
WARN = "[W]"
INFO = "[i]"
OK = "[OK]"

_PAGINATE_FOOTER_RE = re.compile(
    r"\n\n(?:"
    r"\[Showing (?P<s_limit>\d+)/(?P<s_total>\d+) lines\. Next: offset=(?P<s_next>\d+)\]"
    r"|"
    r"\[Displaying (?P<d_limit>\d+) lines\. (?P<d_rem>\d+) more lines available\. Use offset=(?P<d_next>\d+) to see more\.\]"
    r")\s*\Z"
)


def section(title: str) -> str:
    return f"### {title}"


def parse_tsv_rows(data: str, *, skip_header: bool = True, strip_quotes: bool = True) -> list[list[str]]:
    """Split tab-separated tshark field output into rows of cells.

    skip_header: drop the first data line (from tshark's ``-E header=y``).
    strip_quotes: strip surrounding whitespace and double-quotes from each cell.
    Comment lines (starting with ``#``) and blank lines are always dropped.
    """
    lines = [ln for ln in data.splitlines() if ln.strip() and not ln.startswith("#")]
    if skip_header and lines:
        lines = lines[1:]
    rows: list[list[str]] = []
    for line in lines:
        cells = line.split("\t")
        if strip_quotes:
            cells = [c.strip().strip('"') for c in cells]
        rows.append(cells)
    return rows


def smart_truncate(text: str, max_chars: int = 4000) -> str:
    """Truncate long output preserving head and tail."""
    if len(text) <= max_chars:
        return text
    if max_chars <= 0:
        return ""

    # Compute the marker and content budgets together so very small limits never
    # produce a negative slice (which would retain almost the entire input).
    marker = f"\n\n[... {len(text)} chars omitted, use offset for pagination ...]\n\n"
    if len(marker) >= max_chars:
        return text[:max_chars]

    remaining = max_chars - len(marker)
    tail_budget = min(500, remaining // 4)
    head_budget = remaining - tail_budget
    omitted = len(text) - head_budget - tail_budget
    marker = f"\n\n[... {omitted} chars omitted, use offset for pagination ...]\n\n"

    # The number of digits in `omitted` can change the marker length.
    remaining = max_chars - len(marker)
    tail_budget = min(500, max(0, remaining // 4))
    head_budget = max(0, remaining - tail_budget)
    omitted = len(text) - head_budget - tail_budget
    marker = f"\n\n[... {omitted} chars omitted, use offset for pagination ...]\n\n"
    head_budget = max(0, max_chars - len(marker) - tail_budget)

    result = f"{text[:head_budget]}{marker}{text[-tail_budget:] if tail_budget else ''}"
    return result[:max_chars]


def split_paginated_body(text: str) -> tuple[str, int | None, int | None]:
    """Strip a trailing pagination footer and return ``(body, base_offset, total_lines)``."""
    tail_start = max(0, len(text) - 256)
    match = _PAGINATE_FOOTER_RE.search(text, tail_start)
    if not match:
        return text, None, None
    body = text[: match.start()]
    if match.group("s_limit") is not None:
        limit = int(match.group("s_limit"))
        total = int(match.group("s_total"))
        next_off = int(match.group("s_next"))
        return body, max(0, next_off - limit), total
    limit = int(match.group("d_limit"))
    rem = int(match.group("d_rem"))
    next_off = int(match.group("d_next"))
    return body, max(0, next_off - limit), next_off + rem


def format_leading_lines(
    prefix_lines: list[str],
    body_line_count: int,
    max_lines: int,
    *,
    base_offset: int | None = None,
    total_lines: int | None = None,
    full_text: str | None = None,
) -> str:
    """Format the first ``max_lines`` of pre-split ``prefix_lines`` with an honest footer."""
    if max_lines <= 0:
        return ""
    if max_lines >= body_line_count:
        return full_text if full_text is not None else "\n".join(prefix_lines[:body_line_count])
    kept = list(prefix_lines[:max_lines])
    withheld = body_line_count - max_lines
    if base_offset is not None and total_lines is not None:
        next_offset = base_offset + max_lines
        kept.append(
            f"[Showing {max_lines}/{total_lines} lines, {withheld} more withheld by the result ceiling. "
            f"Next: offset={next_offset}]"
        )
    else:
        kept.append(
            f"[Showing {max_lines} lines, {withheld} more withheld by the result ceiling. Use offset for pagination.]"
        )
    return "\n".join(kept)


def keep_leading_lines(text: str, max_lines: int) -> str:
    """Keep at most ``max_lines`` complete lines from the START of ``text``.

    Line-oriented results are paged with an offset/limit pair, so a capped page
    must stay a contiguous prefix: dropping lines from the middle would put the
    page's tail out of reach of every later page. Any pre-existing pagination
    footer is replaced so ``withheld`` and ``Next: offset=...`` stay exact.
    """
    if max_lines <= 0:
        return ""
    body, base_offset, total_lines = split_paginated_body(text)
    body_line_count = body.count("\n") + 1
    if max_lines >= body_line_count:
        return text
    prefix_lines = body.split("\n", max_lines)[:max_lines]
    return format_leading_lines(
        prefix_lines,
        body_line_count,
        max_lines,
        base_offset=base_offset,
        total_lines=total_lines,
        full_text=text,
    )


def summarize_tabular(data: str, max_rows: int = 50) -> str:
    """Truncate tabular data beyond max_rows with a hint."""
    lines = data.splitlines()
    if len(lines) <= max_rows + 1:
        return data
    header = lines[0]
    rows = lines[1 : max_rows + 1]
    remaining = len(lines) - max_rows - 1
    return "\n".join([header] + rows + [f"[{remaining} more rows. Use display_filter or offset to narrow.]"])
