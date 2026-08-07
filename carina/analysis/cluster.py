from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Callable

from .fingerprint import fingerprint, normalize_message
from .parser import ParsedTraceback, parse


@dataclass
class Cluster:
    fingerprint: str
    exception_type: str
    representative_message: str
    count: int
    first_seen: str
    last_seen: str
    sample_raw: str
    frames: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "exception_type": self.exception_type,
            "representative_message": self.representative_message,
            "count": self.count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "sample_raw": self.sample_raw,
            "frames": self.frames,
        }


class Clusterer:
    """Groups parsed tracebacks by fingerprint and tracks occurrence metadata.

    Thread-safe because the tailer feeds it from a background task while the API
    reads snapshots from request handlers. Snapshots are deep-ish copies so callers
    cannot mutate internal state.
    """

    def __init__(self, clock: Callable[[], datetime] | None = None) -> None:
        self._clusters: dict[str, Cluster] = {}
        self._lock = RLock()
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def ingest_raw(self, raw: str) -> Cluster | None:
        parsed = parse(raw)
        if parsed is None:
            return None
        return self.ingest(parsed)

    def ingest(self, parsed: ParsedTraceback) -> Cluster:
        key = fingerprint(parsed)
        now = self._clock().isoformat()
        with self._lock:
            existing = self._clusters.get(key)
            if existing is None:
                self._clusters[key] = Cluster(
                    fingerprint=key,
                    exception_type=parsed.exception_type,
                    representative_message=normalize_message(parsed.exception_message),
                    count=1,
                    first_seen=now,
                    last_seen=now,
                    sample_raw=parsed.raw,
                    frames=[
                        {
                            "filename": f.filename,
                            "lineno": f.lineno,
                            "function": f.function,
                            "code": f.code,
                        }
                        for f in parsed.frames
                    ],
                )
                return self._snapshot(self._clusters[key])
            existing.count += 1
            existing.last_seen = now
            return self._snapshot(existing)

    def clusters(self) -> list[Cluster]:
        with self._lock:
            ordered = sorted(
                self._clusters.values(),
                key=lambda c: (c.count, c.last_seen),
                reverse=True,
            )
            return [self._snapshot(c) for c in ordered]

    def get(self, fingerprint_key: str) -> Cluster | None:
        with self._lock:
            found = self._clusters.get(fingerprint_key)
            return self._snapshot(found) if found else None

    @staticmethod
    def _snapshot(cluster: Cluster) -> Cluster:
        return Cluster(
            fingerprint=cluster.fingerprint,
            exception_type=cluster.exception_type,
            representative_message=cluster.representative_message,
            count=cluster.count,
            first_seen=cluster.first_seen,
            last_seen=cluster.last_seen,
            sample_raw=cluster.sample_raw,
            frames=[dict(frame) for frame in cluster.frames],
        )
