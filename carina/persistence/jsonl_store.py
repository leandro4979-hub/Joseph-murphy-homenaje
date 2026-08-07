from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from carina.audit.append_only import AppendOnlyAuditLog
from carina.policy.guard import AuthorizationError, AuthorizationStore
from carina.policy.models import Authorization


def _append_jsonl(path: Path, record: Mapping[str, Any]) -> None:
    """Append one JSON record and fsync so it survives a crash.

    Durability here is a security property, not a convenience: the caller relies
    on the record being on stable storage *before* it mutates in-memory state.
    """
    line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


class DurableAuthorizationStore(AuthorizationStore):
    """An ``AuthorizationStore`` whose consumption survives process restarts.

    Ordering is the whole point. We write the consumption record to durable
    storage *before* the in-memory counter is incremented. If the process dies
    between the two, replay on boot counts the execution as consumed. That biases
    every crash toward *over*-counting, so the worst case is refusing a legitimate
    execution -- never permitting one the allowance had already spent.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        super().__init__()
        self._path = Path(path)
        self._replay()

    def _replay(self) -> None:
        with self._lock:
            for record in _read_jsonl(self._path):
                if record.get("type") != "consume":
                    continue
                authorization_id = record["authorization_id"]
                self._consumed[authorization_id] = self._consumed.get(authorization_id, 0) + 1

    def consume_execution(self, authorization: Authorization) -> None:
        # Reimplemented rather than delegated to super() so the durable write can
        # be ordered *before* the in-memory mutation. The check is identical to the
        # base class and is kept in lockstep with it deliberately.
        with self._lock:
            consumed = self._consumed.get(authorization.authorization_id, 0)
            if consumed >= authorization.conditions.max_executions:
                raise AuthorizationError("execution allowance exhausted")
            _append_jsonl(
                self._path,
                {
                    "type": "consume",
                    "authorization_id": authorization.authorization_id,
                    "recorded_at": datetime.now(timezone.utc).isoformat(),
                },
            )
            self._consumed[authorization.authorization_id] = consumed + 1


class DurableAuditLog(AppendOnlyAuditLog):
    """An ``AppendOnlyAuditLog`` that mirrors every entry to fsync'd JSONL.

    The in-memory list remains the read path (``entries()``); disk is the durable
    mirror, replayed into memory on construction so history is continuous across
    restarts. Redaction is inherited from the base ``append`` and therefore applies
    to the persisted copy too -- secrets never reach disk.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        super().__init__()
        self._path = Path(path)
        self._replay()

    def _replay(self) -> None:
        with self._lock:
            for record in _read_jsonl(self._path):
                self._entries.append(record)

    def append(
        self,
        event: str,
        correlations: Mapping[str, str],
        details: Mapping[str, Any] | None = None,
    ) -> None:
        with self._lock:
            super().append(event, correlations, details)
            # The base class has already built and redacted the entry; persist it
            # verbatim so the disk copy and the in-memory copy cannot diverge.
            _append_jsonl(self._path, self._entries[-1])
