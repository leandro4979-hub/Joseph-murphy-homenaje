from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Mapping


_SENSITIVE_KEYS = frozenset({"password", "secret", "token", "api_key", "authorization"})


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: "[REDACTED]" if str(key).lower() in _SENSITIVE_KEYS else _redact(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    return value


class AppendOnlyAuditLog:
    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []
        self._lock = RLock()

    def append(self, event: str, correlations: Mapping[str, str], details: Mapping[str, Any] | None = None) -> None:
        entry = {
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **dict(correlations),
            "details": _redact(details or {}),
        }
        with self._lock:
            self._entries.append(entry)

    def entries(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(deepcopy(self._entries))

