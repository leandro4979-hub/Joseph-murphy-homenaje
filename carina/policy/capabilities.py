from __future__ import annotations

from dataclasses import dataclass
from threading import RLock


@dataclass(frozen=True)
class Capability:
    name: str
    idempotent: bool


class CapabilityRegistry:
    def __init__(self, capabilities: tuple[Capability, ...] = ()) -> None:
        self._lock = RLock()
        self._capabilities = {item.name: item for item in capabilities}

    def register(self, capability: Capability) -> None:
        with self._lock:
            if capability.name in self._capabilities:
                raise ValueError(f"capability already registered: {capability.name}")
            self._capabilities[capability.name] = capability

    def get(self, name: str) -> Capability | None:
        with self._lock:
            return self._capabilities.get(name)

