# ADR-0001: Evidence, coverage and findings

Status: ACCEPTED (maintainer gate 2026-10-20, after PR #19)
Date: 2026-10-20
Phase: P1 (model and helpers), used by every later phase

## Context

V0.1 reports evidence as free-text lines (`Partition.Evidence`), flags and a few coverage booleans
(`ProcessCoverageComplete`, `CoverageComplete`, `InaccessibleProfiles`). V0.2 adds several independent collectors
(processes, services, virtualization, Git) whose results are combined into dependencies. Without a common model,
each collector would invent its own way of saying "I could not look", and sooner or later an empty result would be
read as "nothing there". The roadmap's first acceptance criterion forbids exactly that: *every finding states its
source and its coverage; unknown is never reported as "not running"*.

## Decision

1. **Every collector returns a `Coverage` record**, never a bare list:

   | Field | Meaning |
   |---|---|
   | `Collector` | Stable id (`processes`, `process-cwd`, `handles`, `services`, `virtualization`, `git`, `worktrees`, ...). |
   | `Status` | `COMPLETE`, `PARTIAL`, `DENIED`, `TIMEOUT`, `NOT_PRESENT`, `NOT_OBSERVABLE`, `UNAVAILABLE`, `FAILED`. |
   | `Reasons` | Language-neutral codes (for example `ACCESS_DENIED`, `OTHER_ACCOUNT`, `PROTECTED_PROCESS`, `GIT_NOT_FOUND`, `DEADLINE_EXCEEDED`). |
   | `ElevationWouldHelp` | `YES`, `NO` or `UNKNOWN`: whether an elevated administrator token is expected to add coverage (PRIV-10). |
   | `Observed` / `Expected` | Counts when they are known (for example 180 of 212 processes inspectable); `$null` otherwise. |
   | `StartedUtc` / `ElapsedMs` / `Budget` | Time spent and the limit that applied. |

   Meaning of the statuses:
   * `NOT_PRESENT` is used **only** when the source was readable and positively says the thing does not exist (the
     service control manager answered and has no such service; Hyper-V's WMI namespace does not exist). It is the
     only status that may be shown as "not present".
   * `DENIED`, `TIMEOUT`, `NOT_OBSERVABLE`, `UNAVAILABLE` (tool missing, for example Git) and `FAILED` mean *we do
     not know*. They are shown as "unknown", never as absent, clean, stopped or unused.
   * `PARTIAL` means some items were observed and some were not; the unobserved part is counted in `Reasons`.

2. **Every finding is a `Finding` record:**

   | Field | Meaning |
   |---|---|
   | `Kind` | `Process`, `Service`, `VirtualMachine`, `Worktree`, `Repository`, `AgentSession`, `TempPartition`. |
   | `Key` | Stable identity (for a process: `pid@creationTicksUtc`, see ADR-0003; for a path: the normalized long path). |
   | `State` | A language-neutral code from the closed list of that kind (for example the worktree states of ADR-0006). |
   | `Evidence` | List of `{ Code; Source; Collector; ObservedUtc; Detail }`. `Detail` never contains a command line, an environment value, a token or file contents. |
   | `Coverage` | The coverage records of the collectors the state depends on. |
   | `Provider` | Provider id when a provider contributed evidence; `$null` otherwise. |

3. **No state is derived from the absence of evidence.** A state that means "nothing depends on it" (for example
   `NO_DEPENDENCY_OBSERVED`) can only be produced when every collector it depends on is `COMPLETE` or `NOT_PRESENT`.
   With any other coverage, the state is `UNKNOWN` and the incomplete collectors are listed. There is no option to
   change this.

4. **Codes are stable and language-neutral**, like the V0.1 flags and classes. Text comes only from `I18n.ps1`
   (keys added in en-US and pt-BR in the same pull request that uses them).

5. **Time and budgets.** A diagnose run has a global deadline; each collector has its own budget. A collector that
   runs out of time returns what it has with `TIMEOUT` (or `PARTIAL` with `DEADLINE_EXCEEDED`), never `COMPLETE`.

6. **V0.1 compatibility.** The V0.1 inventory, flags, classes and gates are not changed by this model. The diagnose
   engine reads the inventory and adds findings next to it; mapping V0.1 coverage booleans to coverage records is a
   one-way adapter in the diagnose engine.

## Rejected alternatives

* *Boolean `Complete` per collector:* cannot distinguish "not present" from "denied" from "timed out", which is the
  distinction the roadmap requires.
* *Free-text evidence as in V0.1:* not testable across languages and too easy to fill with sensitive detail.
* *A confidence score:* invites thresholds that turn "probably unused" into an authorization; V0.3 needs proof or
  preservation, not probability.

## Consequences

* Collectors are more verbose; presentation must summarize coverage without hiding it.
* `NOT_PRESENT` needs a positive answer from the source, so some environments will show `UNKNOWN` where a user
  "knows" a service is absent. That is intended.

## Verification

* Unit tests per collector with injected sources for: present, absent (`NOT_PRESENT`), access denied, partial,
  timeout and failure; each asserts the coverage status and that no finding has a "clean" or "unused" state.
* A table-driven test over every state code that means "no dependency": with each non-complete coverage status the
  state must become `UNKNOWN`.
* Catalog parity test (existing) covers the new keys; a test asserts that exported codes are identical in both
  languages.

## Amendment (P2-A-S, 2026-10-24)

The decisions above are kept; the maintainer's review of PR #42 added:

* **A conclusive status carries no reason.** `COMPLETE` and `NOT_PRESENT` have an empty `Reasons` list: a reason
  means that something was not observed. `New-AtmCoverage` refuses a conclusive status with a reason (test).
* **The services example of rule 1 is not enough.** "The service control manager answered and has no such service"
  is not a positive answer: the enumeration may silently leave out services the caller may not query. The services
  collector therefore never gives `NOT_PRESENT` (ADR-0005 implementation record, P2-A-S); a source whose semantics
  tell a missing item from an inaccessible one is required for `NOT_PRESENT`.

## Amendment (P2-B, 2026-10-24)

* **New finding kind `VirtualizationPlatform`** (key `host`; states `PRESENT`, `NOT_PRESENT`, `UNKNOWN`). The platform
  needs a state of its own, and a coverage record carries none; a new kind reuses the findings, JSON and report
  machinery, which is a smaller contract change than a new top-level object. `PRESENT` only on a positive sign;
  `NOT_PRESENT` is in the closed list but not produced (no source used proves absence, as for services).
* **`VirtualMachine` states:** `RUNNING`, `OFF`, `SAVED`, `PAUSED`, `PENDING`, `UNKNOWN`, only from
  `Msvm_ComputerSystem.EnabledState` values whose meaning for a VM the Microsoft page states (2, 3, 4 and 10 in its
  table; 32768 and 32769 in its text); any other value is `UNKNOWN`.
