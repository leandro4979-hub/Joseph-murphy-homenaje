from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Callable

from .capabilities import Capability, CapabilityRegistry
from .models import ActionProposal, Authorization
from .scope_matcher import scope_is_subset


class AuthorizationError(RuntimeError):
    """A fail-closed authorization validation error."""


def _json_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def protected_digest(proposal: ActionProposal) -> str:
    protected = {
        "capability": proposal.capability,
        "scope": asdict(proposal.scope),
        "parameters": _json_value(proposal.parameters),
        "side_effect": proposal.side_effect,
    }
    canonical = json.dumps(protected, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuthorizationStore:
    """Thread-safe, atomic execution allowance accounting."""

    def __init__(self) -> None:
        self._consumed: dict[str, int] = {}
        self._lock = RLock()

    def available(self, authorization: Authorization) -> bool:
        with self._lock:
            return self._consumed.get(authorization.authorization_id, 0) < authorization.conditions.max_executions

    def consume_execution(self, authorization: Authorization) -> None:
        with self._lock:
            consumed = self._consumed.get(authorization.authorization_id, 0)
            if consumed >= authorization.conditions.max_executions:
                raise AuthorizationError("execution allowance exhausted")
            self._consumed[authorization.authorization_id] = consumed + 1

    def executions_consumed(self, authorization_id: str) -> int:
        with self._lock:
            return self._consumed.get(authorization_id, 0)


class Guard:
    def __init__(
        self,
        registry: CapabilityRegistry,
        authorization_store: AuthorizationStore,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.registry = registry
        self.authorization_store = authorization_store
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def validate(self, proposal: ActionProposal, authorization: Authorization) -> Capability:
        capability = self.registry.get(proposal.capability)
        if capability is None:
            raise AuthorizationError("capability is not registered")
        if authorization.decision != "allow":
            raise AuthorizationError("authorization decision is not allow")
        if (proposal.proposal_id, proposal.intent_id, proposal.session_id) != (
            authorization.proposal_id, authorization.intent_id, authorization.session_id
        ):
            raise AuthorizationError("correlation identifiers do not match")
        if proposal.capability != authorization.capability:
            raise AuthorizationError("capability does not match authorization")
        if proposal.side_effect != authorization.side_effect:
            raise AuthorizationError("side effect does not match authorization")
        if self.clock() >= authorization.expires_at:
            raise AuthorizationError("authorization has expired")
        if protected_digest(proposal) != authorization.protected_digest:
            raise AuthorizationError("protected fields changed after authorization")
        if not scope_is_subset(proposal.scope, authorization.scope):
            raise AuthorizationError("requested scope exceeds authorized scope")
        if authorization.conditions.max_executions < 1 or not self.authorization_store.available(authorization):
            raise AuthorizationError("execution allowance exhausted")
        return capability

