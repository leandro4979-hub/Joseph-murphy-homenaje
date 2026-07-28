from datetime import datetime, timedelta, timezone

import pytest

from carina.policy.capabilities import Capability, CapabilityRegistry
from carina.policy.guard import AuthorizationStore, Guard, protected_digest
from carina.policy.models import (
    ActionProposal, Agent, Authorization, AuthorizationConditions, Risk, Scope,
)


@pytest.fixture
def now():
    return datetime(2026, 7, 27, 18, 3, tzinfo=timezone.utc)


@pytest.fixture
def proposal(now):
    return ActionProposal(
        "1.0", "prop_01", "int_01", "sess_01", now - timedelta(minutes=1),
        Agent("desktop_agent", "1.0.0"), "file.open",
        Scope("filesystem", ("~/Documents/CARINA/Architecture.docx",)), "internal",
        {"path": "~/Documents/CARINA/Architecture.docx"},
        {"predicate": "document_opened", "fields": {"filename": "Architecture.docx"}},
        "The requested document must be opened before it can be inspected.", 0.97,
    )


@pytest.fixture
def authorization(now, proposal):
    return Authorization(
        "1.0", "auth_01", proposal.proposal_id, proposal.intent_id, proposal.session_id,
        now, now + timedelta(minutes=5), "allow", proposal.capability, proposal.scope,
        proposal.side_effect, Risk("low"), AuthorizationConditions(True, 1),
        protected_digest(proposal),
    )


@pytest.fixture
def runtime(now):
    store = AuthorizationStore()
    registry = CapabilityRegistry((
        Capability("file.open", True), Capability("message.send", False),
    ))
    return Guard(registry, store, lambda: now), store

