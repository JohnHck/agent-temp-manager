# Architecture decision records

Each record states one decision, why it was taken, what it rules out and how it is verified. Records are never
rewritten after they are accepted: a later record supersedes an earlier one and both stay.

Status values: `PROPOSED` (written, waiting for the maintainer), `ACCEPTED`, `SUPERSEDED by ADR-nnnn`, `REJECTED`.
A record marked `PROPOSED` with an open decision (`D-n`) is not implemented until the maintainer decides it; the
open decisions are listed in [V0.2-PLAN.md](../release/V0.2-PLAN.md#open-decisions-human_gate).

| Id | Title | Status | Phase |
|---|---|---|---|
| [ADR-0001](ADR-0001-evidence-coverage-findings.md) | Evidence, coverage and findings | ACCEPTED (amendments: P2-A-S conclusive coverage without reasons; P2-B `VirtualizationPlatform` kind) | P1 |
| [ADR-0002](ADR-0002-dependency-graph.md) | Dependency graph and correlation | ACCEPTED (P4-A amendment: `Provider` target of `ATTRIBUTED_TO` and nodes without a finding PROPOSED for the P4-A gate; `VirtualizationPlatform` host context; VM-worker relation proposal only) | P4 |
| [ADR-0003](ADR-0003-process-identity-resources-elevation.md) | Process identity, resources and elevation state | ACCEPTED | P1 |
| [ADR-0004](ADR-0004-working-directory-handle-evidence.md) | Working-directory and open-handle evidence | ACCEPTED IN PRINCIPLE (D-1, D-2: prototype first, P1-C); amendments: D-1 DEFERRED, D-2 behind the closed open-file diagnostics gate (P1-C-S) | P1 |
| [ADR-0005](ADR-0005-services-virtualization.md) | Services and virtualization | ACCEPTED (rule 6 replaced by ADR-0012; P2-A-S: a name not listed is UNKNOWN; P2-B implementation record) | P2 |
| [ADR-0006](ADR-0006-git-read-only-execution.md) | Git read-only execution and worktree states | ACCEPTED (D-3 conditional, D-4 restricted) | P3 |
| [ADR-0007](ADR-0007-worktree-discovery-scale.md) | Worktree discovery scope and scale limits | PARTIALLY ACCEPTED (D-5 paths: privacy review before P3-B) | P3 |
| [ADR-0008](ADR-0008-provider-contract-v2.md) | Provider contract v2 and the Claude Desktop scenario | ACCEPTED | P1, P2 |
| [ADR-0009](ADR-0009-diagnose-engine-command-schema.md) | Diagnose engine, command, JSON schema and layering | ACCEPTED (D-6 accepted) | P1, P5 |
| [ADR-0010](ADR-0010-pseudonymization-of-exported-identifiers.md) | Pseudonymization of exported identifiers | ACCEPTED (D-7 = K1: no persistent key; D-8: partition findings ordered by pseudonym) | P1 |
| [ADR-0011](ADR-0011-file-based-worktree-diagnostics.md) | File-based worktree diagnostics without Git (file gate and Git gate) | PROPOSED (architecture approved in principle; nothing activated) | P3 |
| [ADR-0012](ADR-0012-service-account-privacy.md) | Service account privacy (replaces ADR-0005 rule 6) | ACCEPTED (maintainer decision, PR #42 gate) | P2 |

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
