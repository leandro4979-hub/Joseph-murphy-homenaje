# Joseph Murphy Homenaje

A tribute project for Joseph Murphy.

## CARINA vertical slice

The repository now contains a fail-closed implementation of CARINA's first
authorization/execution slice:

- immutable proposal, authorization, and action-completion models;
- canonical protected-field digests and filesystem scope containment;
- atomic, single-use or bounded execution allowances;
- guarded execution with distinct action IDs for retries;
- capability-aware retry behavior that never retries ambiguous execution; and
- an append-only in-memory audit log with redaction before persistence.

Run the test suite with:

```bash
python -m pytest -q
```
