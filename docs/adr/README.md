# Architecture decision records

Each record states one decision, why it was taken, what it rules out and how it is verified. Records are never
rewritten after they are accepted: a later record supersedes an earlier one and both stay.

Status values: `PROPOSED` (written, waiting for the maintainer), `ACCEPTED`, `SUPERSEDED by ADR-nnnn`, `REJECTED`.
A record marked `PROPOSED` with an open decision (`D-n`) is not implemented until the maintainer decides it; the
open decisions are listed in [V0.2-PLAN.md](../release/V0.2-PLAN.md#open-decisions-human_gate).

| Id | Title | Status | Phase |
|---|---|---|---|
| [ADR-0001](ADR-0001-evidence-coverage-findings.md) | Evidence, coverage and findings | PROPOSED | P1 |
| [ADR-0002](ADR-0002-dependency-graph.md) | Dependency graph and correlation | PROPOSED | P4 |
| [ADR-0003](ADR-0003-process-identity-resources-elevation.md) | Process identity, resources and elevation state | PROPOSED | P1 |
| [ADR-0004](ADR-0004-working-directory-handle-evidence.md) | Working-directory and open-handle evidence | PROPOSED (D-1, D-2) | P1 |
| [ADR-0005](ADR-0005-services-virtualization.md) | Services and virtualization | PROPOSED | P2 |
| [ADR-0006](ADR-0006-git-read-only-execution.md) | Git read-only execution and worktree states | PROPOSED (D-3, D-4) | P3 |
| [ADR-0007](ADR-0007-worktree-discovery-scale.md) | Worktree discovery scope and scale limits | PROPOSED (D-5) | P3 |
| [ADR-0008](ADR-0008-provider-contract-v2.md) | Provider contract v2 and the Claude Desktop scenario | PROPOSED | P1, P2 |
| [ADR-0009](ADR-0009-diagnose-engine-command-schema.md) | Diagnose engine, command, JSON schema and layering | PROPOSED (D-6) | P1, P5 |

## Template

```
# ADR-nnnn: <title>

Status: PROPOSED | ACCEPTED | SUPERSEDED by ADR-nnnn | REJECTED
Date: YYYY-MM-DD
Phase: <V0.2 phase that implements it>

## Context
## Decision
## Rejected alternatives
## Consequences (including new limits)
## Verification (tests and evidence that prove the decision holds)
```
