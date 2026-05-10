"""Guard test: ensure tool docstrings stay within token budget.

Total docstring characters across all tools should stay under 8000 (~2000 tokens).
This prevents docstring bloat from creeping back in over time.
"""

import ast
from pathlib import Path

TOOLS_DIR = Path(__file__).parent.parent / "src" / "wireshark_mcp" / "tools"
MAX_TOTAL_CHARS = 8000
MAX_SINGLE_CHARS = 300


def _collect_tool_docstrings() -> list[tuple[str, str]]:
    """Parse all .py files in tools/ and extract docstrings from wireshark_* functions."""
    results: list[tuple[str, str]] = []
    seen: set[str] = set()

    for py_file in sorted(TOOLS_DIR.glob("*.py")):
        try:
            tree = ast.parse(py_file.read_text())
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not node.name.startswith("wireshark_"):
                    continue
                if node.name in seen:
                    continue
                doc = ast.get_docstring(node)
                if doc:
                    seen.add(node.name)
                    results.append((node.name, doc))

    return results


def test_total_docstring_budget() -> None:
    """All tool docstrings combined must stay under the character budget."""
    docstrings = _collect_tool_docstrings()
    total_chars = sum(len(doc) for _, doc in docstrings)

    assert len(docstrings) >= 30, f"Expected 30+ tools, found {len(docstrings)} — collection broken?"
    assert total_chars < MAX_TOTAL_CHARS, (
        f"Total tool docstring chars: {total_chars} exceeds budget {MAX_TOTAL_CHARS}. "
        f"Found {len(docstrings)} tools. Trim verbose descriptions."
    )


def test_no_single_docstring_too_long() -> None:
    """No individual tool docstring should exceed 300 chars."""
    docstrings = _collect_tool_docstrings()
    violations = [(name, len(doc)) for name, doc in docstrings if len(doc) > MAX_SINGLE_CHARS]

    assert not violations, f"{len(violations)} tool(s) exceed {MAX_SINGLE_CHARS} char limit: " + ", ".join(
        f"{name}({length})" for name, length in violations
    )
