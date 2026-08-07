from __future__ import annotations

import re
from dataclasses import dataclass


_FILE_RE = re.compile(
    r'^\s+File "(?P<file>.*?)", line (?P<line>\d+), in (?P<func>.*?)\s*$'
)
# A terminal exception line: a dotted type, optionally followed by ": message".
# Anchored on both ends so ordinary log lines ("INFO ready") do not match.
_EXC_RE = re.compile(
    r'^(?P<type>[A-Za-z_][A-Za-z0-9_.]*)(?::[ \t]?(?P<msg>.*))?$'
)

_CHAINING = frozenset(
    {
        "During handling of the above exception, another exception occurred:",
        "The above exception was the direct cause of the following exception:",
    }
)

TRACEBACK_START = "Traceback (most recent call last):"


@dataclass(frozen=True)
class Frame:
    filename: str
    lineno: int
    function: str
    code: str | None


@dataclass(frozen=True)
class ParsedTraceback:
    """The terminal exception of a (possibly chained) traceback, with its frames.

    ``frames`` are ordered outermost -> innermost, matching Python's own "most
    recent call last" convention, so the innermost frames -- the ones nearest the
    crash -- are at the end.
    """

    exception_type: str
    exception_message: str
    frames: tuple[Frame, ...]
    raw: str


def parse(text: str) -> ParsedTraceback | None:
    """Parse a traceback blob, returning the *terminal* exception.

    For chained exceptions ("During handling ...") the last block is the one that
    actually propagated, so it is the one returned. Frames belong to that terminal
    block. Returns ``None`` if no complete traceback is present.
    """
    lines = text.splitlines()
    terminal: ParsedTraceback | None = None
    pending: list[Frame] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        file_match = _FILE_RE.match(line)
        if file_match:
            code = None
            if i + 1 < len(lines):
                nxt = lines[i + 1]
                # A code line is indented and is not itself another File line.
                if nxt[:1] in (" ", "\t") and nxt.strip() and not _FILE_RE.match(nxt):
                    code = nxt.strip()
                    i += 1
            pending.append(
                Frame(
                    filename=file_match.group("file"),
                    lineno=int(file_match.group("line")),
                    function=file_match.group("func").strip(),
                    code=code,
                )
            )
            i += 1
            continue

        stripped = line.strip()
        is_col0 = line[:1] not in (" ", "\t") and stripped != ""
        if is_col0 and stripped != TRACEBACK_START and stripped not in _CHAINING:
            exc_match = _EXC_RE.match(stripped)
            if exc_match and pending:
                terminal = ParsedTraceback(
                    exception_type=exc_match.group("type"),
                    exception_message=(exc_match.group("msg") or "").strip(),
                    frames=tuple(pending),
                    raw=text.strip("\n"),
                )
                pending = []
        i += 1

    return terminal
