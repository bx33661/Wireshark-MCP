"""TUI: arrow-key + space checkbox selector (pure stdlib, no dependencies)."""

from __future__ import annotations

import os
import sys

_ANSI_HIDE_CURSOR = "\x1b[?25l"
_ANSI_SHOW_CURSOR = "\x1b[?25h"
_ANSI_CLEAR_LINE = "\x1b[2K\r"
_ANSI_UP = "\x1b[{}A"
_ANSI_CYAN = "\x1b[96m"
_ANSI_GREEN = "\x1b[92m"
_ANSI_DIM = "\x1b[2m"
_ANSI_RESET = "\x1b[0m"


def _read_key_unix() -> str:
    """Read a single keypress on Unix, handling escape sequences."""
    import select
    import termios
    import tty

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = os.read(fd, 1)
        if ch == b"\x1b":
            if select.select([fd], [], [], 0.1)[0]:
                ch2 = os.read(fd, 1)
                if ch2 in (b"[", b"O") and select.select([fd], [], [], 0.1)[0]:
                    ch3 = os.read(fd, 1)
                    return {b"A": "UP", b"B": "DOWN"}.get(ch3, "ESC")
            return "ESC"
        return {
            b" ": "SPACE",
            b"\r": "ENTER",
            b"\n": "ENTER",
            b"a": "a",
            b"A": "a",
            b"n": "n",
            b"N": "n",
            b"q": "ESC",
            b"Q": "ESC",
            b"\x03": "ESC",
        }.get(ch, "")
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _read_key_windows() -> str:
    """Read a single keypress on Windows."""
    import importlib

    msvcrt = importlib.import_module("msvcrt")
    ch = msvcrt.getch().decode("mbcs", errors="replace")
    if ch in ("\x00", "\xe0"):
        ch2 = msvcrt.getch().decode("mbcs", errors="replace")
        return {"H": "UP", "P": "DOWN"}.get(ch2, "")
    return {
        " ": "SPACE",
        "\r": "ENTER",
        "\n": "ENTER",
        "a": "a",
        "A": "a",
        "n": "n",
        "N": "n",
        "q": "ESC",
        "Q": "ESC",
        "\x03": "ESC",
    }.get(ch, "")


def _supports_ansi() -> bool:
    """Return True if the terminal likely supports ANSI colour codes."""
    if sys.platform == "win32":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _interactive_select_clients(all_clients: dict[str, tuple[str, str]]) -> list[str] | None:
    """Arrow-key + space TUI checkbox to pick which MCP clients to configure.

    Returns None  -- stdin not a TTY (fall back to install-all).
    Returns []    -- user aborted (ESC / q) or confirmed with nothing selected.
    Returns [str] -- list of client names chosen by the user.
    """
    if not sys.stdin.isatty():
        return None

    read_key = _read_key_windows if sys.platform == "win32" else _read_key_unix
    use_ansi = _supports_ansi()

    names = list(all_clients)
    detected = {name for name, (config_dir, _) in all_clients.items() if os.path.exists(config_dir)}
    selected: set[int] = {i for i, n in enumerate(names) if n in detected}
    cursor = 0
    n = len(names)

    def _c(code: str, text: str) -> str:
        return f"{code}{text}{_ANSI_RESET}" if use_ansi else text

    def _render(first: bool = False) -> int:
        header = [
            "",
            "  Select MCP clients to install wireshark-mcp into:",
            _c(_ANSI_DIM, "  ↑/↓ move   Space toggle   a select-all   n clear   Enter confirm   q quit"),
            "",
        ]
        rows = []
        for i, name in enumerate(names):
            chk = _c(_ANSI_GREEN, "●") if i in selected else _c(_ANSI_DIM, "○")
            tag = _c(_ANSI_DIM, " (detected)") if name in detected else ""
            line = _c(_ANSI_CYAN, f"  ❯ {chk} {name}") + tag if i == cursor else f"    {chk} {name}{tag}"
            rows.append(line)
        footer = [""]
        lines = header + rows + footer
        total = len(lines)

        if not first and use_ansi:
            sys.stdout.write(_ANSI_UP.format(total) + "\r")
        for line in lines:
            if use_ansi:
                sys.stdout.write(_ANSI_CLEAR_LINE + line + "\n")
            else:
                print(line)
        sys.stdout.flush()
        return total

    if use_ansi:
        sys.stdout.write(_ANSI_HIDE_CURSOR)
        sys.stdout.flush()

    try:
        _render(first=True)
        while True:
            key = read_key()
            if key == "UP":
                cursor = (cursor - 1) % n
            elif key == "DOWN":
                cursor = (cursor + 1) % n
            elif key == "SPACE":
                if cursor in selected:
                    selected.discard(cursor)
                else:
                    selected.add(cursor)
            elif key == "a":
                selected = set(range(n))
            elif key == "n":
                selected = set()
            elif key == "ENTER":
                _render()
                break
            elif key == "ESC":
                _render()
                return []
            else:
                continue
            _render()
    finally:
        if use_ansi:
            sys.stdout.write(_ANSI_SHOW_CURSOR)
            sys.stdout.flush()

    return [names[i] for i in sorted(selected)]
