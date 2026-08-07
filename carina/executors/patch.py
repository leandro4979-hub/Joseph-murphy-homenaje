from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import carina
from carina.executors.base import AmbiguousExecution, DefinitePreExecutionFailure
from carina.persistence.journal import RollbackJournal
from carina.policy.models import ActionProposal


CAPABILITY = "code.patch"
"""The capability name this side effect implements.

Register it ``idempotent=False`` (``Capability(CAPABILITY, False)``). That is not
cosmetic: a patch that partially applied must never be blind-retried, and the
executor keys retry behavior off this flag.
"""


class PatchRejected(DefinitePreExecutionFailure):
    """A patch was refused before any byte was written.

    Subclasses ``DefinitePreExecutionFailure`` so the executor knows the side effect
    provably did not begin -- the workspace is untouched and the failure is safe.
    """


@dataclass(frozen=True)
class _PlannedWrite:
    target: Path
    relative: str
    content: bytes
    pre_image: bytes | None


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class PatchSideEffect:
    """Applies an authorized code patch inside a fixed sandbox, and only there.

    Three independent gates guard every write, in order, and any failure aborts the
    *entire* patch before the first byte lands:

    1. **Sandbox containment.** The write root is fixed at construction, never read
       from the (attacker-influenced) proposal parameters. Targets are resolved and
       must stay within it; symlinked components are rejected outright so a link
       cannot tunnel out.
    2. **Hard-coded denylist.** Even inside the sandbox, the policy core, the applier
       itself, ``.git``, the persistence journals, and ``pyproject.toml`` are
       unwritable. This is defense-in-depth for the day someone widens the root to
       the repo: a patch that could edit ``guard.py`` would delete the review gate
       for every future patch, and one that could write ``.git/hooks`` would be
       arbitrary code execution outside the boundary entirely. The list is baked in,
       not configurable, because configuration is itself patchable.
    3. **Pre-image verification.** Each target's current bytes must hash to the
       ``pre_image_sha256`` recorded when the patch was proposed. If the file changed
       since diagnosis, the patch is stale and refused rather than clobbering work.

    The full post-image content lives in ``parameters`` -- inside the protected
    digest -- so what a human approved is exactly what is written.
    """

    def __init__(
        self,
        write_root: str | os.PathLike[str],
        journal: RollbackJournal,
        *,
        repo_root: str | os.PathLike[str] | None = None,
        extra_denied: Sequence[str | os.PathLike[str]] = (),
    ) -> None:
        self._root = Path(write_root).resolve()
        self._root.mkdir(parents=True, exist_ok=True)
        self._journal = journal
        if repo_root is not None:
            resolved_repo = Path(repo_root).resolve()
        else:
            # carina/executors/patch.py -> carina -> repo root
            resolved_repo = Path(carina.__file__).resolve().parent.parent
        self._denied = self._build_denylist(resolved_repo, extra_denied)

    @staticmethod
    def _build_denylist(repo_root: Path, extra: Sequence[str | os.PathLike[str]]) -> tuple[Path, ...]:
        core = [
            repo_root / "carina" / "policy",
            repo_root / "carina" / "persistence",
            repo_root / "carina" / "executors" / "patch.py",
            repo_root / "carina" / "api",
            repo_root / ".git",
            repo_root / "pyproject.toml",
        ]
        core.extend(Path(item) for item in extra)
        return tuple(p.resolve() for p in core)

    def _is_denied(self, resolved: Path) -> bool:
        for denied in self._denied:
            if resolved == denied or denied in resolved.parents:
                return True
        return False

    def _resolve_target(self, relative: str) -> Path:
        if os.path.isabs(relative):
            raise PatchRejected(f"absolute paths are not allowed: {relative!r}")
        candidate = self._root / relative
        if ".." in Path(relative).parts:
            raise PatchRejected(f"path traversal is not allowed: {relative!r}")

        # Reject any existing symlink along the chain: a link could otherwise
        # redirect the write outside the sandbox even with a clean relative path.
        probe = self._root
        for part in Path(relative).parts:
            probe = probe / part
            if probe.is_symlink():
                raise PatchRejected(f"symlinked path component is not allowed: {relative!r}")

        resolved = candidate.resolve(strict=False)
        if resolved != self._root and self._root not in resolved.parents:
            raise PatchRejected(f"path escapes the sandbox: {relative!r}")
        if self._is_denied(resolved):
            raise PatchRejected(f"path is on the protected denylist: {relative!r}")
        return resolved

    def _plan(self, proposal: ActionProposal) -> list[_PlannedWrite]:
        parameters = proposal.parameters
        edits = parameters.get("edits") if isinstance(parameters, Mapping) else None
        if not isinstance(edits, Sequence) or not edits:
            raise PatchRejected("proposal has no edits")

        planned: list[_PlannedWrite] = []
        for edit in edits:
            if not isinstance(edit, Mapping):
                raise PatchRejected("edit is not an object")
            relative = edit.get("path")
            content = edit.get("content")
            expected_pre = edit.get("pre_image_sha256")
            if not isinstance(relative, str) or not isinstance(content, str):
                raise PatchRejected("edit requires string 'path' and 'content'")

            target = self._resolve_target(relative)

            if target.exists():
                if target.is_dir():
                    raise PatchRejected(f"target is a directory: {relative!r}")
                current = target.read_bytes()
                actual = _sha256(current)
                if expected_pre is None:
                    raise PatchRejected(f"expected a new file but it exists: {relative!r}")
                if actual != expected_pre:
                    raise PatchRejected(
                        f"pre-image mismatch for {relative!r}: file changed since diagnosis"
                    )
                pre_image: bytes | None = current
            else:
                if expected_pre is not None:
                    raise PatchRejected(f"expected an existing file but it is missing: {relative!r}")
                pre_image = None

            planned.append(
                _PlannedWrite(
                    target=target,
                    relative=relative,
                    content=content.encode("utf-8"),
                    pre_image=pre_image,
                )
            )
        return planned

    def _atomic_write(self, target: Path, content: bytes) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(f".{target.name}.carina.tmp")
        with tmp.open("wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, target)

    async def perform(self, proposal: ActionProposal) -> Mapping[str, Any]:
        # Phase 1: validate every edit. Any failure here is a DefinitePreExecution
        # failure -- nothing has been written, so the workspace is pristine.
        planned = self._plan(proposal)

        # Phase 2: apply. Once the first write lands, a later failure leaves the
        # workspace partially patched, which is exactly AmbiguousExecution: the
        # non-idempotent capability must not retry, and a human must verify.
        written: list[str] = []
        try:
            for item in planned:
                self._journal.record(proposal.proposal_id, item.relative, item.pre_image)
                self._atomic_write(item.target, item.content)
                written.append(item.relative)
        except Exception as error:  # noqa: BLE001 -- deliberately broad; see below
            if written:
                raise AmbiguousExecution(
                    f"patch partially applied ({len(written)} of {len(planned)} files); "
                    f"verification required: {error}"
                ) from error
            raise PatchRejected(f"patch failed before any write: {error}") from error

        return {
            "files_written": written,
            "file_count": len(written),
            "write_root": str(self._root),
        }
