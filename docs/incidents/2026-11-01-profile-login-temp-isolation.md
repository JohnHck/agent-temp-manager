# Incident 2026-11-01: profile sign-in restored after isolating the agent temporary folder

* **Kind:** observed operational evidence. **This is not a root-cause analysis.**
* **Date:** 2026-11-01.
* **Source:** reported by the maintainer. Only aggregate numbers are recorded here.
* **Role of Agent Temp Manager:** none. The product has no operation that moves or isolates anything. Every step
  below was taken by hand, outside the tool.
* **Privacy:** no account names, SIDs, machine name, profile paths or names of other private projects. Paths are
  written in their generic form.
* **Follow-up:** [ADR-0013](../adr/ADR-0013-isolation-quarantine-recovery-mode.md) (PROPOSED) and the V0.4 section of
  the [roadmap](../ROADMAP.md#v04--assisted-recovery).

## What was observed

1. On a Windows 10 Pro machine, a user (the **affected user**) could not sign in to their own Windows profile.
2. The diagnosis was done from a **second local account, which was not an administrator**.
3. The affected profile's Claude Code temporary folder, `%LOCALAPPDATA%\Temp\claude`, was inventoried:

   | Measure | Value |
   |---|---|
   | Size | about 6.72 GiB (6,882.40 MB) |
   | Files | 202,983 |
   | Top-level directories | 37 |
   | Test-report directories | 65 |
   | Read errors during the inventory | 32 |
   | Free space on the volume | about 1.16 TB |

   Largest consumers inside that folder. The other projects are private, so only labels are used:

   | Consumer | Size | Files |
   |---|---|---|
   | This repository (Agent Temp Manager) | 3,059.55 MB | not reported |
   | Other private project A | 1,415.88 MB | not reported |
   | Other private project B | 1,204.15 MB | not reported |
   | Other private project C | 524.75 MB | not reported |
   | Other private project D | 506.48 MB | not reported |
   | **These five together** | **6,710.81 MB** of the 6,882.40 MB inventoried | not reported |

   The remaining 171.59 MB were not broken down by consumer.

4. Windows listed the affected profile as loaded (`Loaded = True`), while only the second account had an interactive
   session.
5. An elevated PowerShell process was running with the affected user's identity.
6. A selective deletion of 63 test-report directories (372.03 MB) was started and then cancelled. It did not restore
   the sign-in. This record does not establish how much of it ran before the cancellation.
7. Evidence folders of another private project, inside the same temporary folder, were preserved.

## What restored access

* The whole `%LOCALAPPDATA%\Temp\claude` folder was moved, on the same volume, to a quarantine location outside the
  active tree. Nothing was deleted by this step.
* An empty `claude` folder was created in its place.
* Windows was restarted.
* The affected user confirmed that they could sign in again.

## What this record does not show

The steps above happened in this order, and access came back after the last one. That is a correlation, not a
cause. It is **not known**:

* which file, directory or state was involved, if any;
* whether the cause was Claude Code, Windows, or an interaction between them;
* whether a selective deletion would have been enough;
* whether moving the folder would have worked without the restart, or the restart without moving the folder;
* whether the size or the number of files of the folder played any part;
* what started the elevated PowerShell process that ran with the affected user's identity, or whether it mattered.

Nothing in this record may be cited as proof that a large agent temporary folder blocks a Windows sign-in.

## Relevance to Agent Temp Manager

* **Today:** `audit` and `preview` only read. `clean` (the 0.3.0 candidate, real deletion disabled in every copy)
  can only ever delete a `SessionRoot` partition that passes every gate. The base itself (`<TEMP>\claude`) is never a
  candidate (clean gate 2). Nothing in the product moves a folder, keeps a quarantine or restores anything.
* **What the manual step had that deletion lacks:** it kept everything, so it could be inspected and undone. That is
  why isolation is proposed as an operation of its own, separate from deletion (ADR-0013).
* **What a tool would have done differently:** under the blocking rules proposed in ADR-0013, the state described
  here (the profile loaded, and an elevated process running with the affected user's identity) would make the
  proposed Recovery Mode **refuse** to isolate anything. The restart was a human step, and no proposed tool flow
  performs or replaces it.
* **Prevention still comes first.** The decided dedicated base for agent temporary files (`CLAUDE_CODE_TMPDIR`; the
  base runbook is a publication blocker in [V0.3-RC.md](../release/V0.3-RC.md#g-publication-blockers)) keeps them
  out of the profile's TEMP. Isolation is containment and recovery after the fact; it does not replace prevention.
