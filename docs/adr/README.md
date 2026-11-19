# Architecture decision records

Each record states one decision, why it was taken, what it rules out and how it is verified. Records are never
rewritten after they are accepted: a later record supersedes an earlier one and both stay.

Status values: `PROPOSED` (written, waiting for the maintainer), `ACCEPTED`, `SUPERSEDED by ADR-nnnn`, `REJECTED`.
A record marked `PROPOSED` with an open decision (`D-n`) is not implemented until the maintainer decides it; the
open decisions are listed in [V0.2-PLAN.md](../release/V0.2-PLAN.md#open-decisions-human_gate). From ADR-0013 on, a
record lists its own open decisions, with an id prefix of its own (`ISO-D1`...).

| Id | Title | Status | Phase |
|---|---|---|---|
| [ADR-0001](ADR-0001-evidence-coverage-findings.md) | Evidence, coverage and findings | ACCEPTED (amendments: P2-A-S conclusive coverage without reasons; P2-B `VirtualizationPlatform` kind) | P1 |
| [ADR-0002](ADR-0002-dependency-graph.md) | Dependency graph and correlation | ACCEPTED (P4-A amendment and maintainer decisions D1-D4 of the P4-A gate: `Provider` graph-only node and nodes without a finding ACCEPTED; `VirtualizationPlatform` context; `RUNS_VM` PROPOSED, not implemented) | P4 |
| [ADR-0003](ADR-0003-process-identity-resources-elevation.md) | Process identity, resources and elevation state | ACCEPTED | P1 |
| [ADR-0004](ADR-0004-working-directory-handle-evidence.md) | Working-directory and open-handle evidence | ACCEPTED IN PRINCIPLE (D-1, D-2: prototype first, P1-C); amendments: D-1 DEFERRED, D-2 behind the closed open-file diagnostics gate (P1-C-S) | P1 |
| [ADR-0005](ADR-0005-services-virtualization.md) | Services and virtualization | ACCEPTED (rule 6 replaced by ADR-0012; P2-A-S: a name not listed is UNKNOWN; P2-B implementation record) | P2 |
| [ADR-0006](ADR-0006-git-read-only-execution.md) | Git read-only execution and worktree states | ACCEPTED (D-3 conditional, D-4 restricted) | P3 |
| [ADR-0007](ADR-0007-worktree-discovery-scale.md) | Worktree discovery scope and scale limits | PARTIALLY ACCEPTED (D-5 paths: privacy review before P3-B) | P3 |
| [ADR-0008](ADR-0008-provider-contract-v2.md) | Provider contract v2 and the Claude Desktop scenario | ACCEPTED | P1, P2 |
| [ADR-0009](ADR-0009-diagnose-engine-command-schema.md) | Diagnose engine, command, JSON schema and layering | ACCEPTED (D-6 accepted; implementation records P5-A: TUI diagnostics area, P5-B: CLI, JSON contract and export; P5-B-S security addendum: diagnose export gate closed; FINAL-A addendum: pinned file creation) | P1, P5 |
| [ADR-0010](ADR-0010-pseudonymization-of-exported-identifiers.md) | Pseudonymization of exported identifiers | ACCEPTED (D-7 = K1: no persistent key; D-8: partition findings ordered by pseudonym) | P1 |
| [ADR-0011](ADR-0011-file-based-worktree-diagnostics.md) | File-based worktree diagnostics without Git (file gate and Git gate) | PROPOSED (architecture approved in principle; nothing activated) | P3 |
| [ADR-0012](ADR-0012-service-account-privacy.md) | Service account privacy (replaces ADR-0005 rule 6) | ACCEPTED (maintainer decision, PR #42 gate) | P2 |
| [ADR-0013](ADR-0013-isolation-quarantine-recovery-mode.md) | Isolation, quarantine and Recovery Mode | PARTIALLY ACCEPTED (maintainer decisions ISO-D1, ISO-D4, ISO-D5 on 2026-11-01; ISO-D2, ISO-D3, ISO-D6 PROPOSED; nothing implemented) | 0.3.x (own profile), V0.4 (Recovery Mode) |
| [ADR-0014](ADR-0014-desktop-gui-winforms.md) | Desktop GUI and live monitoring in WinForms | ACCEPTED for the technology and the architecture (maintainer decisions D-B and D-A, 2026-11-16); GUI-D1 to GUI-D11 PROPOSED; nothing implemented | V0.2.1 (P1 to P6) |
| [ADR-0015](ADR-0015-v5-pilot-disposable-vm.md) | V5 pilot of real deletion in a disposable VM | ACCEPTED (the environment class is the maintainer's decision D-C, 2026-11-16; V5-D1 to V5-D8 approved as recommended, 2026-11-17; pilot not executed) | V0.3 (V5) |
| [ADR-0016](ADR-0016-v04-assisted-recovery.md) | Assisted recovery (V0.4) | ACCEPTED (V04-D1 to V04-D8 decided 2026-11-17: D3 (b) elevation on demand through UAC; the others as recommended); R0 to R6 implemented (R2 to R4 only past the recovery gate, closed in every copy; R5 is the read-only view of list and plan in the TUI and the GUI, executing stays CLI-only; R6 is the CI-only e2e of the real start and undo on the harness's own services) | V0.4 (R0 to R6) |
| [ADR-0017](ADR-0017-v05-preventive-monitoring.md) | Persistent preventive monitoring (V0.5) | ACCEPTED (V05-D1 to V05-D10 decided: D1-D7 2026-11-17, D8-D10 2026-11-18, as recommended; M0, M1 and M2 implemented; gate `AtmMonitoringEnabled` closed in every copy; nothing scheduled) | V0.5 (M0 to M5; M6 out of V0.5 by V05-D6 (a)) |

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
