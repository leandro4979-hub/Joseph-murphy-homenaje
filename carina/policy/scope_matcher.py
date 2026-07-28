from __future__ import annotations

import os
from pathlib import Path

from .models import Scope


def _normalize(path: str) -> Path:
    # resolve(strict=False) removes `..` without requiring the target to exist.
    return Path(os.path.expanduser(path)).resolve(strict=False)


def _path_within(requested: str, authorized: str) -> bool:
    requested_path = _normalize(requested)
    authorized_path = _normalize(authorized)
    return requested_path == authorized_path or authorized_path in requested_path.parents


def scope_is_subset(requested: Scope, authorized: Scope) -> bool:
    """Return whether every requested resource is contained by authorized scope."""
    if requested.kind != authorized.kind or requested.kind != "filesystem":
        return False
    if not requested.paths or not authorized.paths:
        return False
    return all(
        any(_path_within(path, allowed) for allowed in authorized.paths)
        for path in requested.paths
    )

