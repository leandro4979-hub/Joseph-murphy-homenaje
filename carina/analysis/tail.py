from __future__ import annotations

import asyncio
import os
import re
import time
from pathlib import Path
from typing import Awaitable, Callable

from .parser import _EXC_RE, _CHAINING, TRACEBACK_START


class TracebackAssembler:
    """Reassembles multi-line tracebacks from a line stream.

    Pure and synchronous so its state machine can be tested exhaustively without
    timing. Chained exceptions ("During handling ...") are kept together as one
    blob, because the terminal exception -- the thing we actually diagnose -- is
    only meaningful alongside the chain that produced it.

    A blob is emitted when a new independent traceback begins, when an unrelated
    line follows a completed one, or on an explicit ``flush()`` (the timeout path).
    """

    def __init__(self) -> None:
        self._buf: list[str] = []
        self._in_tb = False
        self._seen_exc = False
        self._expect_chain = False

    def feed_line(self, line: str) -> list[str]:
        line = line.rstrip("\n")
        stripped = line.strip()

        if stripped == TRACEBACK_START:
            completed: list[str] = []
            if self._in_tb and self._expect_chain:
                # Second block of a chained exception: keep accumulating.
                self._buf.append(line)
                self._expect_chain = False
                return completed
            if self._in_tb and self._seen_exc:
                completed.append(self._emit())
            self._start(line)
            return completed

        if not self._in_tb:
            return []

        if line[:1] in (" ", "\t") or stripped == "":
            self._buf.append(line)
            return []

        # A column-0, non-empty line while inside a traceback.
        if stripped in _CHAINING:
            self._buf.append(line)
            self._seen_exc = False
            self._expect_chain = True
            return []

        if not self._seen_exc and _EXC_RE.match(stripped):
            self._buf.append(line)
            self._seen_exc = True
            self._expect_chain = False
            return []

        # Anything else terminates the traceback; this line is ordinary log output
        # and is not part of it.
        completed = [self._emit()] if self._seen_exc else []
        self._reset()
        return completed

    def flush(self) -> list[str]:
        if self._in_tb and self._seen_exc:
            return [self._emit()]
        return []

    @property
    def has_complete_pending(self) -> bool:
        return self._in_tb and self._seen_exc

    def _start(self, line: str) -> None:
        self._buf = [line]
        self._in_tb = True
        self._seen_exc = False
        self._expect_chain = False

    def _emit(self) -> str:
        blob = "\n".join(self._buf)
        self._reset()
        return blob

    def _reset(self) -> None:
        self._buf = []
        self._in_tb = False
        self._seen_exc = False
        self._expect_chain = False


class LogTailer:
    """Follows a log file and emits complete traceback blobs.

    Survives rotation (the inode changes) and truncation (the file shrinks) by
    detecting both and re-reading from the top. A partial final line without a
    trailing newline is held until the newline arrives, so a half-written traceback
    is never parsed as complete. If a completed traceback is followed by silence,
    ``flush_interval`` forces it out rather than waiting for the next unrelated line.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        poll_interval: float = 0.25,
        flush_interval: float = 1.0,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._path = Path(path)
        self._poll_interval = poll_interval
        self._flush_interval = flush_interval
        self._clock = clock or time.monotonic
        self._assembler = TracebackAssembler()
        self._offset = 0
        self._inode: int | None = None
        self._partial = ""
        self._stopped = asyncio.Event()

    def stop(self) -> None:
        self._stopped.set()

    async def run(self, on_traceback: Callable[[str], Awaitable[None] | None]) -> None:
        last_activity = self._clock()
        while not self._stopped.is_set():
            blobs = self._read_new_blobs()
            if blobs:
                last_activity = self._clock()
                for blob in blobs:
                    result = on_traceback(blob)
                    if asyncio.iscoroutine(result):
                        await result
            elif (
                self._assembler.has_complete_pending
                and self._clock() - last_activity >= self._flush_interval
            ):
                for blob in self._assembler.flush():
                    result = on_traceback(blob)
                    if asyncio.iscoroutine(result):
                        await result
                last_activity = self._clock()

            try:
                await asyncio.wait_for(self._stopped.wait(), timeout=self._poll_interval)
            except asyncio.TimeoutError:
                pass

    def _read_new_blobs(self) -> list[str]:
        if not self._path.exists():
            return []
        stat = self._path.stat()
        if self._inode is None:
            self._inode = stat.st_ino
        elif stat.st_ino != self._inode or stat.st_size < self._offset:
            # Rotation (new inode) or truncation (shrunk): start over from the top.
            self._inode = stat.st_ino
            self._offset = 0
            self._partial = ""

        if stat.st_size == self._offset:
            return []

        with self._path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(self._offset)
            chunk = handle.read()
            self._offset = handle.tell()

        data = self._partial + chunk
        lines = data.split("\n")
        # The last element is an incomplete line unless the chunk ended in "\n".
        self._partial = lines.pop()

        completed: list[str] = []
        for line in lines:
            completed.extend(self._assembler.feed_line(line))
        return completed
