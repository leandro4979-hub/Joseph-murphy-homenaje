from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Mapping, Protocol
from uuid import uuid4

from carina.audit.append_only import AppendOnlyAuditLog
from carina.policy.guard import AuthorizationStore, Guard
from carina.policy.models import ActionCompletion, ActionProposal, Authorization


class AmbiguousExecution(RuntimeError):
    """The side effect may have occurred, so blind retry is unsafe."""


class DefinitePreExecutionFailure(RuntimeError):
    """A failure known to have happened before the side effect began."""


class SideEffect(Protocol):
    async def perform(self, proposal: ActionProposal) -> Mapping[str, Any]: ...


class GuardedExecutor:
    def __init__(
        self,
        guard: Guard,
        authorization_store: AuthorizationStore,
        audit: AppendOnlyAuditLog,
        side_effect: SideEffect,
        *,
        max_retries: int = 1,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self.guard = guard
        self.authorization_store = authorization_store
        self.audit = audit
        self.side_effect = side_effect
        self.max_retries = max_retries
        self.id_factory = id_factory or (lambda: f"act_{uuid4().hex}")

    async def execute(self, proposal: ActionProposal, authorization: Authorization) -> ActionCompletion:
        capability = self.guard.validate(proposal, authorization)
        attempts = 0
        while True:
            if attempts:
                # A retry is a distinct action attempt and must pass the boundary again.
                capability = self.guard.validate(proposal, authorization)
            action_id = self.id_factory()  # Deliberately created only after validation.
            self.authorization_store.consume_execution(authorization)
            correlations = {
                "intent_id": proposal.intent_id,
                "proposal_id": proposal.proposal_id,
                "authorization_id": authorization.authorization_id,
                "action_id": action_id,
            }
            self.audit.append("action_started", correlations, {"agent": proposal.agent.name, "capability": proposal.capability})
            try:
                raw_result = await self.side_effect.perform(proposal)
                completion = ActionCompletion("1.0", action_id, proposal.proposal_id, "completed", datetime.now(timezone.utc), raw_result)
                self.audit.append("action_completed", correlations, {"status": completion.status, "raw_result": raw_result})
                return completion
            except AmbiguousExecution as error:
                self.audit.append("action_ambiguous", correlations, {"error": str(error), "verification_required": True})
                raise
            except (DefinitePreExecutionFailure, TimeoutError, ConnectionError) as error:
                retryable = capability.idempotent or isinstance(error, DefinitePreExecutionFailure)
                if not retryable or attempts >= self.max_retries:
                    self.audit.append("action_failed", correlations, {"error": str(error)})
                    raise
                self.audit.append("action_failed", correlations, {"error": str(error), "retry_planned": True})
                attempts += 1
                await asyncio.sleep(0)
