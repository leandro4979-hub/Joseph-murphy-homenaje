"""Framework-agnostic assembly of the CARINA runtime.

The HTTP layer (``carina.service.api``) is a thin transport over this module.
Everything security-relevant lives here so it can be driven directly from
tests without going through the network.
"""

from __future__ import annotations

from .runtime import AnalyzerRuntime, ProposalRecord, RuntimePaths

__all__ = ["AnalyzerRuntime", "ProposalRecord", "RuntimePaths"]
