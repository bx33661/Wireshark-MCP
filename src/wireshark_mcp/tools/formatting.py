"""Token-efficient output formatting utilities."""

CRIT = "[!]"
WARN = "[W]"
INFO = "[i]"
OK = "[OK]"


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


def keep_leading_lines(text: str, max_lines: int) -> str:
    """Keep at most ``max_lines`` complete lines from the START of ``text``.

    Line-oriented results are paged with an offset/limit pair, so a capped page
    must stay a contiguous prefix: dropping lines from the middle would put the
    page's tail out of reach of every later page. A marker records how many
    lines were withheld so the caller can resume from ``offset + kept``.
    """
    if max_lines <= 0:
        return ""
    lines = text.split("\n")
    if len(lines) <= max_lines:
        return text
    kept = lines[:max_lines]
    withheld = len(lines) - max_lines
    kept.append(f"[Showing {max_lines} lines, {withheld} more withheld by the result ceiling. Use offset for pagination.]")
    return "\n".join(kept)


def summarize_tabular(data: str, max_rows: int = 50) -> str:
    """Truncate tabular data beyond max_rows with a hint."""
    lines = data.splitlines()
    if len(lines) <= max_rows + 1:
        return data
    header = lines[0]
    rows = lines[1 : max_rows + 1]
    remaining = len(lines) - max_rows - 1
    return "\n".join([header] + rows + [f"[{remaining} more rows. Use display_filter or offset to narrow.]"])
