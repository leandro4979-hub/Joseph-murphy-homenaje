"""Durable, append-only persistence for authorization counters, audit, and rollback.

The in-memory ``AuthorizationStore`` and ``AppendOnlyAuditLog`` in ``carina.policy``
and ``carina.audit`` are correct but volatile: a process restart resets execution
counters, which would let a previously-exhausted authorization execute again. The
classes here durably back those structures with fsync'd JSONL and replay them on
boot, preserving the exact interfaces and lock semantics of their in-memory bases.
"""
