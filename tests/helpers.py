"""Shared test helpers: import the project modules from the repo root, and a
fake curses window so renderers can be exercised without a terminal."""

import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def load_logger_module():
    """syswatch-logger.py has a hyphen in its name, so it can't be imported
    with a plain import statement."""
    spec = importlib.util.spec_from_file_location(
        "syswatch_logger", os.path.join(ROOT, "syswatch-logger.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeWin:
    """Minimal stand-in for a curses window: records what was drawn and
    enforces the same bounds a real window would (addstr past the edge
    raises curses.error)."""

    def __init__(self, h, w):
        import curses
        self._error = curses.error
        self.h, self.w = h, w
        self.erase()

    def getmaxyx(self):
        return self.h, self.w

    def erase(self):
        self.cells = [[" "] * self.w for _ in range(self.h)]

    def addstr(self, y, x, text, attr=0):
        if not (0 <= y < self.h and 0 <= x < self.w):
            raise self._error("addstr out of bounds")
        for i, c in enumerate(text):
            if x + i >= self.w:
                raise self._error("addstr wrapped past right edge")
            self.cells[y][x + i] = c

    def addch(self, y, x, ch, attr=0):
        if not (0 <= y < self.h and 0 <= x < self.w):
            raise self._error("addch out of bounds")
        self.cells[y][x] = ch if isinstance(ch, str) else "|"

    def noutrefresh(self):
        pass

    def timeout(self, _ms):
        pass

    def keypad(self, _flag):
        pass

    def text(self):
        return "\n".join("".join(r) for r in self.cells)
