from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class JournalEntry:
    """A single file's pre-image, captured immediately before it was overwritten.

    ``existed`` distinguishes "the patch modified an existing file" (restore the
    bytes) from "the patch created a new file" (revert by deleting it). Storing the
    hash alongside the bytes lets a revert detect if the file was changed by some
    other process after the patch applied.
    """

    action_id: str
    relative_path: str
    existed: bool
    pre_image_sha256: str | None
    pre_image_b64: str | None
    recorded_at: str

    def pre_image_bytes(self) -> bytes | None:
        if self.pre_image_b64 is None:
            return None
        return base64.b64decode(self.pre_image_b64)


class RollbackJournal:
    """Append-only record of pre-images keyed by ``action_id``.

    The journal is deliberately inert: it captures bytes and hands them back. It
    never touches the workspace itself, because a revert is a fresh authorized
    proposal that flows through the guard like any other write. That keeps rollback
    from becoming an unreviewed write primitive.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)
        self._lock = RLock()

    def record(self, action_id: str, relative_path: str, pre_image: bytes | None) -> JournalEntry:
        entry = JournalEntry(
            action_id=action_id,
            relative_path=relative_path,
            existed=pre_image is not None,
            pre_image_sha256=None if pre_image is None else sha256_bytes(pre_image),
            pre_image_b64=None if pre_image is None else base64.b64encode(pre_image).decode("ascii"),
            recorded_at=datetime.now(timezone.utc).isoformat(),
        )
        record: dict[str, Any] = {
            "action_id": entry.action_id,
            "relative_path": entry.relative_path,
            "existed": entry.existed,
            "pre_image_sha256": entry.pre_image_sha256,
            "pre_image_b64": entry.pre_image_b64,
            "recorded_at": entry.recorded_at,
        }
        line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        return entry

    def entries_for(self, action_id: str) -> list[JournalEntry]:
        with self._lock:
            if not self._path.exists():
                return []
            entries: list[JournalEntry] = []
            with self._path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    record = json.loads(line)
                    if record.get("action_id") != action_id:
                        continue
                    entries.append(
                        JournalEntry(
                            action_id=record["action_id"],
                            relative_path=record["relative_path"],
                            existed=record["existed"],
                            pre_image_sha256=record.get("pre_image_sha256"),
                            pre_image_b64=record.get("pre_image_b64"),
                            recorded_at=record["recorded_at"],
                        )
                    )
            return entries
