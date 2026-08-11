"""A small, dependency-free polling filesystem watcher.

The watcher deliberately reports changes only after they have remained unchanged
for a debounce interval.  This makes the behavior independent of platform-specific
filesystem notification APIs and prevents write bursts from overwhelming callers.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import os
from pathlib import Path
from threading import Event
import time
from typing import Callable, Iterable


class FileEventType(str, Enum):
    """Kinds of stable filesystem changes emitted by the watcher."""

    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"


@dataclass(frozen=True)
class FileEvent:
    """A stable change and the capability derived from it."""

    event_type: FileEventType
    path: Path
    capability: str
    principal: str = "perception_loop"


@dataclass(frozen=True)
class _FileState:
    modified_ns: int
    size: int
    inode: int


@dataclass
class _PendingChange:
    event_type: FileEventType
    changed_at: float


CapabilityCheck = Callable[[str, str], object]
EventHandler = Callable[[FileEvent], None]


class PollingFileWatcher:
    """Poll directories and dispatch debounced changes to a capability check.

    Construction takes an initial snapshot, so files that already exist are not
    reported as newly created.  Call :meth:`poll` explicitly in tests or use
    :meth:`run` for a blocking loop.  ``capability_check`` is called as
    ``check(principal, capability)`` before the optional event handler.
    """

    def __init__(
        self,
        directories: Iterable[str | os.PathLike[str]],
        capability_check: CapabilityCheck,
        *,
        on_event: EventHandler | None = None,
        poll_interval: float = 0.25,
        debounce_seconds: float = 0.5,
        recursive: bool = True,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if poll_interval <= 0:
            raise ValueError("poll_interval must be greater than zero")
        if debounce_seconds < 0:
            raise ValueError("debounce_seconds cannot be negative")

        self.directories = tuple(Path(item).resolve() for item in directories)
        if not self.directories:
            raise ValueError("at least one directory must be watched")
        self.capability_check = capability_check
        self.on_event = on_event
        self.poll_interval = poll_interval
        self.debounce_seconds = debounce_seconds
        self.recursive = recursive
        self._clock = clock
        self._snapshot = self._scan()
        self._pending: dict[Path, _PendingChange] = {}

    def _scan(self) -> dict[Path, _FileState]:
        snapshot: dict[Path, _FileState] = {}
        for directory in self.directories:
            if not directory.is_dir():
                continue
            candidates = directory.rglob("*") if self.recursive else directory.glob("*")
            for path in candidates:
                try:
                    stat = path.stat()
                except (FileNotFoundError, PermissionError, OSError):
                    # A file may disappear between directory traversal and stat.
                    continue
                if not path.is_file():
                    continue
                snapshot[path.resolve()] = _FileState(stat.st_mtime_ns, stat.st_size, stat.st_ino)
        return snapshot

    @staticmethod
    def capability_for(event_type: FileEventType, path: Path) -> str:
        """Translate a filesystem change into its Gatekeeper capability."""

        extension = path.suffix.lower() or "<none>"
        return f"fs.{event_type.value}:{extension}"

    def poll(self) -> tuple[FileEvent, ...]:
        """Scan once and return changes that became stable during this poll."""

        now = self._clock()
        current = self._scan()
        old_paths = set(self._snapshot)
        current_paths = set(current)

        raw_changes: dict[Path, FileEventType] = {
            path: FileEventType.CREATED for path in current_paths - old_paths
        }
        raw_changes.update({path: FileEventType.DELETED for path in old_paths - current_paths})
        raw_changes.update(
            {
                path: FileEventType.MODIFIED
                for path in old_paths & current_paths
                if self._snapshot[path] != current[path]
            }
        )

        for path, event_type in raw_changes.items():
            pending = self._pending.get(path)
            if pending is not None and pending.event_type is FileEventType.CREATED:
                if event_type is FileEventType.DELETED:
                    del self._pending[path]
                else:
                    pending.changed_at = now
                continue
            self._pending[path] = _PendingChange(event_type, now)

        self._snapshot = current
        emitted: list[FileEvent] = []
        for path, pending in tuple(self._pending.items()):
            if path in raw_changes or now - pending.changed_at < self.debounce_seconds:
                continue
            event = FileEvent(
                event_type=pending.event_type,
                path=path,
                capability=self.capability_for(pending.event_type, path),
            )
            self.capability_check(event.principal, event.capability)
            if self.on_event is not None:
                self.on_event(event)
            emitted.append(event)
            del self._pending[path]
        return tuple(emitted)

    def run(self, stop_event: Event | None = None) -> None:
        """Poll until ``stop_event`` is set; block forever when it is omitted."""

        stop = stop_event or Event()
        while not stop.wait(self.poll_interval):
            self.poll()


# A concise alias for integrations that do not need to mention the mechanism.
FileSystemWatcher = PollingFileWatcher
