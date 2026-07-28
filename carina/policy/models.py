from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Mapping


JsonObject = Mapping[str, Any]


@dataclass(frozen=True)
class Agent:
    name: str
    version: str


@dataclass(frozen=True)
class Scope:
    kind: str
    paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class ActionProposal:
    schema_version: str
    proposal_id: str
    intent_id: str
    session_id: str
    created_at: datetime
    agent: Agent
    capability: str
    scope: Scope
    side_effect: str
    parameters: JsonObject
    expected: JsonObject
    reason: str
    confidence: float


@dataclass(frozen=True)
class Risk:
    level: str
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuthorizationConditions:
    session_only: bool
    max_executions: int


@dataclass(frozen=True)
class Authorization:
    schema_version: str
    authorization_id: str
    proposal_id: str
    intent_id: str
    session_id: str
    created_at: datetime
    expires_at: datetime
    decision: Literal["allow", "deny"]
    capability: str
    scope: Scope
    side_effect: str
    risk: Risk
    conditions: AuthorizationConditions
    protected_digest: str


@dataclass(frozen=True)
class ActionCompletion:
    schema_version: str
    action_id: str
    proposal_id: str
    status: Literal["completed", "failed", "ambiguous"]
    completed_at: datetime
    raw_result: JsonObject = field(default_factory=dict)

