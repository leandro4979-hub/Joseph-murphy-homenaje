import asyncio
from dataclasses import replace

import pytest

from carina.audit.append_only import AppendOnlyAuditLog
from carina.executors.base import AmbiguousExecution, GuardedExecutor
from carina.executors.fake import FakeSideEffect
from carina.policy.guard import protected_digest
from carina.policy.models import AuthorizationConditions


def test_idempotent_transient_failure_is_bounded_and_retried(runtime, proposal, authorization):
    guard, store = runtime
    authorization = replace(authorization, conditions=AuthorizationConditions(True, 2))
    effect = FakeSideEffect([TimeoutError("temporary"), {"process_exit_code": 0}])
    audit = AppendOnlyAuditLog()
    ids = iter(("act_first", "act_retry"))
    completion = asyncio.run(GuardedExecutor(guard, store, audit, effect, id_factory=lambda: next(ids)).execute(proposal, authorization))
    assert completion.status == "completed"
    assert effect.calls == 2
    assert store.executions_consumed("auth_01") == 2
    assert [entry["action_id"] for entry in audit.entries() if entry["event"] == "action_started"] == ["act_first", "act_retry"]


def test_non_idempotent_ambiguous_execution_is_never_retried(runtime, proposal, authorization):
    guard, store = runtime
    proposal = replace(proposal, capability="message.send")
    authorization = replace(
        authorization, capability="message.send", protected_digest=protected_digest(proposal)
    )
    audit = AppendOnlyAuditLog()
    effect = FakeSideEffect([AmbiguousExecution("unknown delivery state"), {"delivered": True}])
    with pytest.raises(AmbiguousExecution):
        asyncio.run(GuardedExecutor(guard, store, audit, effect).execute(proposal, authorization))
    assert effect.calls == 1
    assert audit.entries()[-1]["details"]["verification_required"] is True
