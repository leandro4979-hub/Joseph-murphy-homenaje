from __future__ import annotations

from collections import deque
from typing import Any, Mapping

from carina.policy.models import ActionProposal


class FakeSideEffect:
    def __init__(self, outcomes: list[Mapping[str, Any] | BaseException]) -> None:
        self.outcomes = deque(outcomes)
        self.calls = 0

    async def perform(self, proposal: ActionProposal) -> Mapping[str, Any]:
        self.calls += 1
        outcome = self.outcomes.popleft()
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome
