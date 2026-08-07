import asyncio

import pytest

from carina.analysis.cluster import Clusterer
from carina.analysis.fingerprint import fingerprint, normalize_message
from carina.analysis.parser import parse
from carina.analysis.tail import LogTailer, TracebackAssembler


SIMPLE_TB = """Traceback (most recent call last):
  File "/workspace/app.py", line 42, in main
    result = divide(1, 0)
  File "/workspace/mathlib.py", line 7, in divide
    return a / b
ZeroDivisionError: division by zero"""

CHAINED_TB = """Traceback (most recent call last):
  File "/workspace/app.py", line 10, in load
    return cache[key]
KeyError: 'config'

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/workspace/app.py", line 12, in load
    raise RuntimeError("could not load config")
RuntimeError: could not load config"""


def test_parse_simple_traceback():
    parsed = parse(SIMPLE_TB)
    assert parsed is not None
    assert parsed.exception_type == "ZeroDivisionError"
    assert parsed.exception_message == "division by zero"
    assert parsed.frames[-1].function == "divide"
    assert parsed.frames[-1].lineno == 7
    assert parsed.frames[-1].code == "return a / b"


def test_parse_returns_terminal_of_chain():
    parsed = parse(CHAINED_TB)
    assert parsed is not None
    # The RuntimeError is what propagated; the KeyError is context.
    assert parsed.exception_type == "RuntimeError"
    assert parsed.exception_message == "could not load config"


def test_parse_ignores_non_traceback_text():
    assert parse("INFO server started\nDEBUG handling request") is None


def test_dotted_exception_type_is_captured():
    tb = (
        "Traceback (most recent call last):\n"
        '  File "/workspace/x.py", line 1, in <module>\n'
        "    guard.validate()\n"
        "carina.policy.guard.AuthorizationError: denied"
    )
    parsed = parse(tb)
    assert parsed.exception_type == "carina.policy.guard.AuthorizationError"


def test_fingerprint_is_stable_across_line_numbers_and_values():
    a = parse(SIMPLE_TB)
    shifted = SIMPLE_TB.replace("line 42", "line 88").replace("line 7", "line 9")
    b = parse(shifted)
    assert fingerprint(a) == fingerprint(b)


def test_fingerprint_differs_by_exception_type():
    a = parse(SIMPLE_TB)
    other = SIMPLE_TB.replace("ZeroDivisionError: division by zero", "ValueError: bad input")
    b = parse(other)
    assert fingerprint(a) != fingerprint(b)


def test_normalize_message_strips_addresses_and_numbers():
    assert normalize_message("object at 0x7f3c id 41") == "object at 0xADDR id N"


def test_clusterer_groups_and_counts():
    clusterer = Clusterer()
    clusterer.ingest_raw(SIMPLE_TB)
    clusterer.ingest_raw(SIMPLE_TB.replace("line 42", "line 43"))  # same site, moved line
    clusterer.ingest_raw(CHAINED_TB)
    clusters = clusterer.clusters()
    assert len(clusters) == 2
    top = clusters[0]
    assert top.exception_type == "ZeroDivisionError"
    assert top.count == 2


def test_assembler_emits_on_unrelated_following_line():
    assembler = TracebackAssembler()
    completed = []
    for line in SIMPLE_TB.split("\n"):
        completed.extend(assembler.feed_line(line))
    # Traceback is complete but not yet emitted until a terminator or flush.
    assert completed == []
    completed.extend(assembler.feed_line("INFO request handled"))
    assert len(completed) == 1
    assert "ZeroDivisionError" in completed[0]


def test_assembler_keeps_chained_exception_together():
    assembler = TracebackAssembler()
    completed = []
    for line in CHAINED_TB.split("\n"):
        completed.extend(assembler.feed_line(line))
    completed.extend(assembler.flush())
    assert len(completed) == 1
    assert "KeyError" in completed[0] and "RuntimeError" in completed[0]


def test_assembler_separates_two_independent_tracebacks():
    assembler = TracebackAssembler()
    stream = SIMPLE_TB + "\n" + SIMPLE_TB
    completed = []
    for line in stream.split("\n"):
        completed.extend(assembler.feed_line(line))
    completed.extend(assembler.flush())
    assert len(completed) == 2


def test_tailer_survives_rotation_and_emits_once(tmp_path):
    log = tmp_path / "app.log"
    log.write_text(SIMPLE_TB + "\nINFO idle\n")

    seen: list[str] = []
    fake_time = {"t": 0.0}
    tailer = LogTailer(
        log,
        poll_interval=0.001,
        flush_interval=0.01,
        clock=lambda: fake_time["t"],
    )

    async def drive():
        async def collect(blob: str) -> None:
            seen.append(blob)

        task = asyncio.create_task(tailer.run(collect))
        await asyncio.sleep(0.02)
        # Simulate log rotation: replace the file with a fresh inode + new content.
        log.unlink()
        log.write_text(SIMPLE_TB.replace("ZeroDivisionError", "ValueError") + "\nINFO idle\n")
        await asyncio.sleep(0.02)
        tailer.stop()
        await task

    asyncio.run(drive())
    # One traceback from before rotation, one after -- each exactly once.
    assert len(seen) == 2
    assert "ZeroDivisionError" in seen[0]
    assert "ValueError" in seen[1]
