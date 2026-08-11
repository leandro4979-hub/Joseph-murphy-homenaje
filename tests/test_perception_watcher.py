from pathlib import Path

from carina.perception.watcher import FileEventType, PollingFileWatcher


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_real_writes_are_debounced_into_one_created_event(tmp_path: Path) -> None:
    checks: list[tuple[str, str]] = []
    clock = Clock()
    watcher = PollingFileWatcher(
        [tmp_path], lambda principal, capability: checks.append((principal, capability)),
        debounce_seconds=1,
        clock=clock,
    )

    target = tmp_path / "signal.TXT"
    target.write_text("one")
    assert watcher.poll() == ()
    clock.now = 0.5
    target.write_text("two")
    assert watcher.poll() == ()
    clock.now = 1.4
    assert watcher.poll() == ()
    clock.now = 1.5
    events = watcher.poll()

    assert len(events) == 1
    assert events[0].event_type is FileEventType.CREATED
    assert events[0].path == target
    assert checks == [("perception_loop", "fs.created:.txt")]


def test_existing_file_burst_is_one_modified_event(tmp_path: Path) -> None:
    target = tmp_path / "state.json"
    target.write_text("initial")
    checks: list[tuple[str, str]] = []
    clock = Clock()
    watcher = PollingFileWatcher(
        [tmp_path], lambda *args: checks.append(args), debounce_seconds=1, clock=clock
    )

    target.write_text("change one")
    watcher.poll()
    clock.now = 0.75
    target.write_text("change two is larger")
    watcher.poll()
    clock.now = 1.75
    events = watcher.poll()

    assert [event.event_type for event in events] == [FileEventType.MODIFIED]
    assert checks == [("perception_loop", "fs.modified:.json")]


def test_delete_is_reported_and_create_then_delete_is_suppressed(tmp_path: Path) -> None:
    existing = tmp_path / "gone"
    existing.write_text("content")
    checks: list[tuple[str, str]] = []
    clock = Clock()
    watcher = PollingFileWatcher(
        [tmp_path], lambda *args: checks.append(args), debounce_seconds=1, clock=clock
    )

    transient = tmp_path / "transient.py"
    transient.write_text("pass")
    watcher.poll()
    clock.now = 0.2
    transient.unlink()
    existing.unlink()
    watcher.poll()
    clock.now = 1.2
    events = watcher.poll()

    assert [(event.event_type, event.path) for event in events] == [
        (FileEventType.DELETED, existing)
    ]
    assert checks == [("perception_loop", "fs.deleted:<none>")]
