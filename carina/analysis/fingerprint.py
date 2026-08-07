from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath, PureWindowsPath

from .parser import ParsedTraceback


_HEX_RE = re.compile(r"0x[0-9a-fA-F]+")
_NUM_RE = re.compile(r"\b\d+\b")

# The crash site is characterized by its innermost frames. Deeper than this and
# fingerprints start splitting on incidental call-stack depth.
_DEFAULT_MAX_FRAMES = 5


def normalize_message(message: str) -> str:
    """Collapse run-to-run noise so equivalent failures share a signature.

    Memory addresses and bare integers are the usual culprits: the same bug prints
    a different object id or index each time. We replace them with placeholders so
    ``KeyError: 41`` and ``KeyError: 87`` do not masquerade as distinct problems.
    """
    normalized = _HEX_RE.sub("0xADDR", message)
    normalized = _NUM_RE.sub("N", normalized)
    return normalized.strip()


def _frame_signature(filename: str, function: str) -> str:
    # Handle both POSIX and Windows separators regardless of host, then keep the
    # last two path components so absolute vs relative paths collapse together
    # while still distinguishing, e.g., two different __init__.py files.
    parts = PureWindowsPath(filename).parts if "\\" in filename else PurePosixPath(filename).parts
    tail = "/".join(parts[-2:]) if len(parts) >= 2 else (parts[-1] if parts else filename)
    return f"{tail}:{function}"


def fingerprint(parsed: ParsedTraceback, max_frames: int = _DEFAULT_MAX_FRAMES) -> str:
    """A stable cluster key from exception type + innermost frame signatures.

    Deliberately excludes line numbers and the exception message: the same logical
    bug moves line numbers around as code is edited and prints different values each
    run, but its type and its innermost call path stay put.
    """
    innermost = parsed.frames[-max_frames:]
    payload = {
        "type": parsed.exception_type,
        "frames": [_frame_signature(f.filename, f.function) for f in innermost],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
