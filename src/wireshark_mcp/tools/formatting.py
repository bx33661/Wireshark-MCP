"""Token-efficient output formatting utilities."""

CRIT = "[!]"
WARN = "[W]"
INFO = "[i]"
OK = "[OK]"


def section(title: str) -> str:
    return f"### {title}"


def smart_truncate(text: str, max_chars: int = 4000) -> str:
    """Truncate long output preserving head and tail."""
    if len(text) <= max_chars:
        return text
    tail_budget = 500
    head_budget = max_chars - tail_budget - 60
    head = text[:head_budget]
    tail = text[-tail_budget:]
    omitted = len(text) - head_budget - tail_budget
    return f"{head}\n\n[... {omitted} chars omitted, use offset for pagination ...]\n\n{tail}"


def summarize_tabular(data: str, max_rows: int = 50) -> str:
    """Truncate tabular data beyond max_rows with a hint."""
    lines = data.splitlines()
    if len(lines) <= max_rows + 1:
        return data
    header = lines[0]
    rows = lines[1 : max_rows + 1]
    remaining = len(lines) - max_rows - 1
    return "\n".join([header] + rows + [f"[{remaining} more rows. Use display_filter or offset to narrow.]"])
