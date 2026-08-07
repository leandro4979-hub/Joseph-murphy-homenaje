import asyncio
import hashlib
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from carina.audit.append_only import AppendOnlyAuditLog
from carina.executors.base import AmbiguousExecution, GuardedExecutor
from carina.executors.patch import CAPABILITY, PatchRejected, PatchSideEffect
from carina.persistence.jsonl_store import DurableAuthorizationStore
from carina.persistence.journal import RollbackJournal
from carina.policy.capabilities import Capability, CapabilityRegistry
from carina.policy.guard import AuthorizationError, Guard, protected_digest
from carina.policy.models import (
    ActionProposal,
    Agent,
    Authorization,
    AuthorizationConditions,
    Risk,
    Scope,
)


NOW = datetime(2026, 8, 7, 12, 0, tzinfo=timezone.utc)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_proposal(root: Path, edits, *, proposal_id="prop_patch"):
    scope_paths = tuple(str(root / e["path"]) for e in edits if not str(e["path"]).startswith(("/", "..")))
    return ActionProposal(
        "1.0", proposal_id, "int_p", "sess_p", NOW, Agent("analyzer", "1.0"),
        CAPABILITY, Scope("filesystem", scope_paths or (str(root),)), "internal",
        {"edits": edits},
        {"predicate": "files_patched"}, "apply fix", 0.9,
    )


def make_auth(proposal, *, max_executions=1):
    return Authorization(
        "1.0", "auth_patch", proposal.proposal_id, proposal.intent_id, proposal.session_id,
        NOW, NOW + timedelta(minutes=5), "allow", CAPABILITY, proposal.scope, "internal",
        Risk("medium"), AuthorizationConditions(True, max_executions), protected_digest(proposal),
    )


def make_effect(tmp_path, *, write_root=None, repo_root=None):
    root = write_root or (tmp_path / "workspace")
    Path(root).mkdir(parents=True, exist_ok=True)
    journal = RollbackJournal(tmp_path / "journal.jsonl")
    return PatchSideEffect(root, journal, repo_root=repo_root or tmp_path), Path(root), journal


# --- Sandbox containment ---------------------------------------------------

def test_parent_traversal_is_rejected(tmp_path):
    effect, root, _ = make_effect(tmp_path)
    proposal = make_proposal(root, [{"path": "../escape.py", "content": "x", "pre_image_sha256": None}])
    with pytest.raises(PatchRejected):
        asyncio.run(effect.perform(proposal))
    assert not (tmp_path / "escape.py").exists()


def test_absolute_path_is_rejected(tmp_path):
    effect, root, _ = make_effect(tmp_path)
    target = tmp_path / "abs_escape.py"
    proposal = make_proposal(root, [{"path": str(target), "content": "x", "pre_image_sha256": None}])
    with pytest.raises(PatchRejected):
        asyncio.run(effect.perform(proposal))
    assert not target.exists()


def test_symlinked_component_is_rejected(tmp_path):
    effect, root, _ = make_effect(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "link").symlink_to(outside, target_is_directory=True)
    proposal = make_proposal(root, [{"path": "link/evil.py", "content": "x", "pre_image_sha256": None}])
    with pytest.raises(PatchRejected):
        asyncio.run(effect.perform(proposal))
    assert not (outside / "evil.py").exists()


# --- Hard denylist (root widened to the repo to prove protection) ----------

@pytest.mark.parametrize("denied_path", [
    "carina/policy/guard.py",
    "carina/persistence/jsonl_store.py",
    "carina/executors/patch.py",
    ".git/hooks/post-commit",
    "pyproject.toml",
])
def test_denylist_blocks_policy_core_and_git(tmp_path, denied_path):
    # Simulate the dangerous configuration where the write root IS the repo root.
    repo = tmp_path / "repo"
    repo.mkdir()
    effect, root, _ = make_effect(tmp_path, write_root=repo, repo_root=repo)
    proposal = make_proposal(root, [{"path": denied_path, "content": "malicious", "pre_image_sha256": None}])
    with pytest.raises(PatchRejected):
        asyncio.run(effect.perform(proposal))
    # Rejected during planning: no file handle was ever opened.
    assert not (repo / denied_path).exists()


# --- Pre-image verification ------------------------------------------------

def test_pre_image_mismatch_refuses_without_writing(tmp_path):
    effect, root, _ = make_effect(tmp_path)
    target = root / "app.py"
    target.write_text("original contents\n")
    proposal = make_proposal(root, [{
        "path": "app.py",
        "content": "rewritten\n",
        "pre_image_sha256": _sha(b"something else entirely"),
    }])
    with pytest.raises(PatchRejected):
        asyncio.run(effect.perform(proposal))
    assert target.read_text() == "original contents\n"  # untouched


def test_expected_new_file_but_exists_is_rejected(tmp_path):
    effect, root, _ = make_effect(tmp_path)
    (root / "app.py").write_text("already here\n")
    proposal = make_proposal(root, [{"path": "app.py", "content": "x", "pre_image_sha256": None}])
    with pytest.raises(PatchRejected):
        asyncio.run(effect.perform(proposal))


def test_expected_existing_file_but_missing_is_rejected(tmp_path):
    effect, root, _ = make_effect(tmp_path)
    proposal = make_proposal(root, [{"path": "ghost.py", "content": "x", "pre_image_sha256": _sha(b"nope")}])
    with pytest.raises(PatchRejected):
        asyncio.run(effect.perform(proposal))


# --- Happy path + journal --------------------------------------------------

def test_valid_patch_writes_and_journals_pre_image(tmp_path):
    effect, root, journal = make_effect(tmp_path)
    target = root / "broken.py"
    target.write_text("old\n")
    proposal = make_proposal(root, [{
        "path": "broken.py", "content": "new\n", "pre_image_sha256": _sha(b"old\n"),
    }])
    result = asyncio.run(effect.perform(proposal))
    assert result["file_count"] == 1
    assert target.read_text() == "new\n"
    entries = journal.entries_for(proposal.proposal_id)
    assert len(entries) == 1
    assert entries[0].pre_image_bytes() == b"old\n"


# --- Partial application is ambiguous, never retried -----------------------

def test_partial_write_raises_ambiguous_execution(tmp_path):
    effect, root, _ = make_effect(tmp_path)
    (root / "a.py").write_text("a-old\n")
    (root / "b.py").write_text("b-old\n")
    proposal = make_proposal(root, [
        {"path": "a.py", "content": "a-new\n", "pre_image_sha256": _sha(b"a-old\n")},
        {"path": "b.py", "content": "b-new\n", "pre_image_sha256": _sha(b"b-old\n")},
    ])

    calls = {"n": 0}
    real_write = effect._atomic_write

    def flaky(target, content):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("disk full")
        return real_write(target, content)

    effect._atomic_write = flaky
    with pytest.raises(AmbiguousExecution):
        asyncio.run(effect.perform(proposal))
    assert (root / "a.py").read_text() == "a-new\n"  # first write landed
    assert (root / "b.py").read_text() == "b-old\n"  # second did not


# --- Guard-level: the diff is inside the protected digest ------------------

def _patch_runtime():
    registry = CapabilityRegistry((Capability(CAPABILITY, False),))
    store = DurableAuthorizationStore  # constructed per-test with a path
    return registry, store


def test_diff_tampering_after_authorization_fails_closed(tmp_path):
    registry, _ = _patch_runtime()
    store = DurableAuthorizationStore(tmp_path / "authz.jsonl")
    guard = Guard(registry, store, lambda: NOW)
    root = tmp_path / "workspace"
    root.mkdir()

    proposal = make_proposal(root, [{"path": "x.py", "content": "safe\n", "pre_image_sha256": None}])
    authorization = make_auth(proposal)

    # An attacker swaps the diff after the human authorized the safe one.
    tampered = replace(proposal, parameters={"edits": [
        {"path": "x.py", "content": "os.system('rm -rf /')\n", "pre_image_sha256": None},
    ]})
    with pytest.raises(AuthorizationError):
        guard.validate(tampered, authorization)


def test_execution_allowance_survives_restart(tmp_path):
    registry, _ = _patch_runtime()
    authz_path = tmp_path / "authz.jsonl"
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "broken.py").write_text("old\n")
    proposal = make_proposal(root, [{
        "path": "broken.py", "content": "new\n", "pre_image_sha256": _sha(b"old\n"),
    }])
    authorization = make_auth(proposal, max_executions=1)

    store = DurableAuthorizationStore(authz_path)
    guard = Guard(registry, store, lambda: NOW)
    effect, _, journal = make_effect(tmp_path, write_root=root)
    audit = AppendOnlyAuditLog()
    completion = asyncio.run(
        GuardedExecutor(guard, store, audit, effect).execute(proposal, authorization)
    )
    assert completion.status == "completed"

    # Restart: fresh store replays the spent allowance from disk.
    revived_store = DurableAuthorizationStore(authz_path)
    revived_guard = Guard(registry, revived_store, lambda: NOW)
    effect2, _, _ = make_effect(tmp_path, write_root=root)
    with pytest.raises(AuthorizationError):
        asyncio.run(
            GuardedExecutor(revived_guard, revived_store, audit, effect2).execute(proposal, authorization)
        )
