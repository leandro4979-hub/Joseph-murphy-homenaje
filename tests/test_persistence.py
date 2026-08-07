from dataclasses import replace

import pytest

from carina.persistence.jsonl_store import DurableAuditLog, DurableAuthorizationStore
from carina.persistence.journal import RollbackJournal
from carina.policy.guard import AuthorizationError
from carina.policy.models import AuthorizationConditions


def test_consumption_survives_restart(tmp_path, authorization):
    path = tmp_path / "authz.jsonl"
    authorization = replace(authorization, conditions=AuthorizationConditions(True, 1))

    store = DurableAuthorizationStore(path)
    store.consume_execution(authorization)
    assert store.available(authorization) is False

    # Simulate a process restart: a brand-new store replaying the same journal
    # must remember the allowance was already spent.
    revived = DurableAuthorizationStore(path)
    assert revived.available(authorization) is False
    with pytest.raises(AuthorizationError):
        revived.consume_execution(authorization)


def test_multi_execution_counter_is_exact_across_restart(tmp_path, authorization):
    path = tmp_path / "authz.jsonl"
    authorization = replace(authorization, conditions=AuthorizationConditions(True, 3))

    store = DurableAuthorizationStore(path)
    store.consume_execution(authorization)
    store.consume_execution(authorization)

    revived = DurableAuthorizationStore(path)
    assert revived.executions_consumed(authorization.authorization_id) == 2
    revived.consume_execution(authorization)  # third and final
    with pytest.raises(AuthorizationError):
        revived.consume_execution(authorization)


def test_audit_entries_persist_and_redact(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = DurableAuditLog(path)
    log.append("action_started", {"action_id": "act_1"}, {"token": "sk-secret", "ok": True})

    revived = DurableAuditLog(path)
    entries = revived.entries()
    assert len(entries) == 1
    assert entries[0]["event"] == "action_started"
    assert entries[0]["details"]["token"] == "[REDACTED]"
    assert entries[0]["details"]["ok"] is True


def test_journal_round_trips_pre_image(tmp_path):
    journal = RollbackJournal(tmp_path / "journal.jsonl")
    journal.record("act_1", "broken.py", b"original bytes")
    journal.record("act_1", "new_file.py", None)

    entries = journal.entries_for("act_1")
    assert len(entries) == 2
    modified = next(e for e in entries if e.relative_path == "broken.py")
    created = next(e for e in entries if e.relative_path == "new_file.py")
    assert modified.existed is True
    assert modified.pre_image_bytes() == b"original bytes"
    assert created.existed is False
    assert created.pre_image_bytes() is None
    assert journal.entries_for("act_other") == []
