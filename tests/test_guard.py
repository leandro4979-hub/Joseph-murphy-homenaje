from dataclasses import replace
from datetime import timedelta

import pytest

from carina.policy.guard import AuthorizationError


def test_valid_authorization_passes(runtime, proposal, authorization):
    guard, _ = runtime
    assert guard.validate(proposal, authorization).name == "file.open"


@pytest.mark.parametrize("change", [
    lambda p: replace(p, capability="unknown"),
    lambda p: replace(p, side_effect="external"),
    lambda p: replace(p, parameters={"path": "/tmp/other"}),
])
def test_protected_field_changes_fail_closed(runtime, proposal, authorization, change):
    guard, _ = runtime
    with pytest.raises(AuthorizationError):
        guard.validate(change(proposal), authorization)


def test_correlation_decision_and_expiry_are_enforced(runtime, proposal, authorization, now):
    guard, _ = runtime
    invalid = (
        replace(authorization, proposal_id="prop_other"),
        replace(authorization, decision="deny"),
        replace(authorization, expires_at=now - timedelta(seconds=1)),
    )
    for item in invalid:
        with pytest.raises(AuthorizationError):
            guard.validate(proposal, item)

