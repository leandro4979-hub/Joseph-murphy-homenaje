import asyncio

import pytest

from carina.audit.append_only import AppendOnlyAuditLog
from carina.executors.base import GuardedExecutor
from carina.executors.fake import FakeSideEffect
from carina.policy.guard import AuthorizationError


def test_single_use_authorization_is_consumed(runtime, proposal, authorization):
    guard, store = runtime
    effect = FakeSideEffect([{"process_exit_code": 0}])
    executor = GuardedExecutor(guard, store, AppendOnlyAuditLog(), effect)
    completion = asyncio.run(executor.execute(proposal, authorization))
    assert completion.status == "completed"
    assert store.executions_consumed("auth_01") == 1
    with pytest.raises(AuthorizationError):
        asyncio.run(executor.execute(proposal, authorization))


def test_atomic_consumption_allows_only_one_caller(authorization):
    from concurrent.futures import ThreadPoolExecutor
    from carina.policy.guard import AuthorizationStore

    store = AuthorizationStore()
    def consume():
        try:
            store.consume_execution(authorization)
            return True
        except AuthorizationError:
            return False
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: consume(), range(8)))
    assert outcomes.count(True) == 1
    assert store.executions_consumed("auth_01") == 1

