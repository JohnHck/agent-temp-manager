# Roadmap

This is the canonical roadmap of Agent Temp Manager. Versions land on `main` in order, each one **dark**: everything
in it that changes the system sits behind a release gate of its own, `$false` in every copy, and its acceptance
criteria are proven in CI. Each gate is opened later, only by an explicit decision of the maintainer, and publishing
stays the maintainer's decision, release by release. So a version can start before an earlier one has opened its
gates, as 0.3.x did. A version may be split into smaller releases, but its safety limits never move: they hold with
its gates closed or open, and no gate opens without the maintainer's decision.

**Design rule for every version: safety over reclaimed space. When in doubt, preserve.**

| Version | Theme | Changes the system? | Status |
|---|---|---|---|
| [V0.1](#v01--audit-preview-tui-and-internationalization) | Audit, preview, TUI, internationalization | No (real deletion disabled) | Complete (0.1.0) |
| [V0.2](#v02--windows-runtime-diagnostics) | Windows Runtime Diagnostics, including Git worktrees | No (read-only) | Published (0.2.0); three diagnostics gates closed |
| [V0.2.1](#v021--desktop-gui-and-live-monitoring) | Desktop GUI and live monitoring (while the window is open) | No (read-only presentation) | Implemented on `main` (P1–P6); GUI gate closed; not published |
| [V0.3](#v03--selective-real-cleanup) | Selective real cleanup | Yes: deletes approved temporary paths only | Published (0.3.0); deletion gate closed |
| [0.3.x](#03x--isolation-and-quarantine-of-the-own-profile) | Isolation and quarantine of the own profile (ADR-0013; after 0.3.0 is published) | Yes: moves approved temporary paths into a quarantine and back; purge deletes behind the purge gate of its own (J-ISO-1 (C)) | On `main`, isolation and purge gates closed; not published |
| [V0.4](#v04--assisted-recovery) | Assisted recovery of services and environments; Recovery Mode for another user's profile (ADR-0013) | Yes: reversible operations, each authorized individually | Accepted in ADR-0016; R0 (read-only service fault signals in the diagnose) and R1 (`recover list` and `recover plan`, read only, eighth gate closed) implemented; R2 (start engine), R3 (undo engine) and R4 (`recover start` and `recover undo`, elevation on demand through UAC) implemented only past the gate, closed in every copy, so no recovery operation can be executed; R5 (the TUI and the GUI show `list` and `plan`, read only; executing stays CLI-only) implemented; R6 (a CI-only harness runs the real start and undo, through the default seams, on services it creates itself on disposable runners; never shipped) implemented |
| [V0.5](#v05--preventive-monitoring) | Persistent preventive monitoring, alerts, growth trends | No (observes and alerts) | ADR-0017 accepted (V05-D1 to V05-D10 decided); M0 (documentation amendments), M1 (the collector and the history storage), M2 (trends, thresholds and alerts) and M3a (the scheduled task, `monitor enable` and the entry point, behind the gate) done; M3b (a CI-only harness runs the real scheduler under a test task name on disposable runners; never shipped) done; M4a (`monitor disable`, behind the gate, and the empty task folder removed by both unschedule commands) done; M4b (`monitor remove-history`, behind the gate, and the uninstaller's read-only warning) done; M5 (the TUI and the GUI) next; M6 out of V0.5 (V05-D6 (a)); monitoring gate (ninth) closed in every copy; nothing scheduled in any copy |
| [V1.0](#v10--stabilization-and-multi-agent-support) | Stabilization and extensible multi-agent support | Same limits as V0.3 and V0.4 | Not started |

## Principles that apply to every version

* **Generic architecture.** Agents are *providers* behind the contract in [PROVIDERS.md](PROVIDERS.md). Claude Code
  (and, from V0.2, Claude Desktop) are the initial providers and scenarios, not dependencies: the tool must run, and
  report correctly, on a machine where neither is installed.
* **Engines decide, presentation shows.** Every decision lives in the engines; the CLI, TUI and reports cannot
  bypass them ([ARCHITECTURE.md](ARCHITECTURE.md)).
* **Fail-closed.** Missing coverage, unreadable state, ambiguity or an unexpected change blocks the action.
  Incomplete process coverage blocks too, except the narrow B1 exception with a declared residual risk (V0.3, a change
  of the product contract; SECURITY-MODEL, gate 6).
* **Read-only by default.** Only an explicit, confirmed command may change the system, and only within the limits of
  the version that introduced it.
* **Least privilege, UAC only.** Everything that can run without administrative rights does. Elevation is explicit,
  only for operations that need it, and only through the Windows UAC prompt; the tool never handles credentials.
  Anything elevated re-validates itself, and destructive operations need a typed confirmation independent of UAC.
  Requirements PRIV-1 to PRIV-11 and their status in V0.1: [ELEVATION.md](ELEVATION.md). V0.1 uses manual
  elevation (installation only) and never elevates itself.
* **No personal data.** Nothing user- or machine-specific is built in, printed beyond what the user asked for, or
  exported: no command lines, tokens, credentials or file contents.
* **Portable.** Windows PowerShell 5.1 and PowerShell 7, any user profile layout, any drive, no network access.
* **Tested on both shells, in CI and in a clean environment** before a version is released ([TESTING.md](TESTING.md)).

---

## V0.1 — Audit, preview, TUI and internationalization

**Status: complete (0.1.0).**

**Objectives.** Show, safely and across every local profile, which temporary directories AI coding agents leave
behind, how much space they use and why each one is or is not a cleanup candidate, without changing anything.

**Deliverables.**
* `agent-temp audit` and `agent-temp preview` (read-only), `verify`, `version`, JSON export.
* Interactive TUI (dashboard, drill-down by user, project and root, detail, preview, help); ASCII fallback.
* en-US and pt-BR catalogs with safe fallback; language-neutral engine codes.
* Clean engine with every gate and the handle-pinning deleter, **shipped with real deletion disabled**
  (`agent-temp clean` validates and prints the exact plan, then stops).
* Installer with manifest verification, ACL audit, private TEMP, rollback and uninstall; privacy-gated release build.
* Provider: Claude Code.

**Acceptance criteria.**
* Test suite green on Windows PowerShell 5.1 and PowerShell 7, locally and in GitHub Actions.
* No code path can delete while the release gate is `$false`; a test asserts the shipped value.
* Privacy scan of the repository and the release zip has zero findings.

**Dependencies.** None.

**Mandatory tests.** Audit and preview leave the sandbox unchanged; reparse points are never traversed; incomplete
coverage blocks; TUI and reports never call deletion APIs; installer integrity and ACL checks; language fallback.

**Safety limits.** No deletion, no ACL or service changes, no process termination, no network.

---

## V0.2 — Windows Runtime Diagnostics

**Status: published as 0.2.0 (GitHub Release `v0.2.0`).** The `diagnose` command and TUI area D shipped read-only:
agent processes and sessions from evidence, resource totals, provider-declared services, the Hyper-V platform and
VMs, the dependency graph, temporary partitions with runtime evidence and profile discovery, plus the runtime-only
Claude Desktop provider. Three parts shipped behind gates closed in every copy: Git worktree diagnostics, open-file
diagnostics and the `diagnose` JSON export. Process working directories (D-1) were deferred. Details:
[CHANGELOG](../CHANGELOG.md) (0.2.0) and [release/V0.2.0-RELEASE-NOTES.md](release/V0.2.0-RELEASE-NOTES.md). Plan,
phases and acceptance criteria per phase: [release/V0.2-PLAN.md](release/V0.2-PLAN.md); architecture decisions:
[adr/](adr/README.md).

**Objectives.** Explain *why* space and resources are in use and *what is still running*, so that a later cleanup
can be based on evidence instead of assumptions. V0.2 is strictly read-only.

**Deliverables.**
* **Processes:** agent-related processes and their parent chains, working directories and open-handle evidence
  where Windows exposes it; coverage reported explicitly when access is denied.
* **Services:** state, start type and account of agent-related services, for example `CoworkVMService` when it is
  present (Claude Desktop scenario); absence is reported as "not present", never as an error.
* **Resource consumption:** CPU, memory, disk and handle counts per agent process tree.
* **Virtualization:** Hyper-V / virtual machine worker processes such as `vmmem`, and which agent scenario they
  belong to, when that can be established; otherwise reported as unattributed.
* **Git worktree diagnostics (read-only)**, see the section below.
* **Temporary directories:** the V0.1 inventory, extended with the runtime evidence above.
* **Dependencies:** which temporary paths, worktrees, services and processes depend on each other.
* A diagnostics view in the TUI and a `diagnose` command (name to be confirmed) with JSON export.
* Runs without elevation (PRIV-1): each finding states whether elevation would add coverage, and the report shows
  the process identity and elevation state (PRIV-10). Diagnostics never request elevation.
* A Claude Desktop provider/scenario, behind the same provider contract.

### Git worktree diagnostics (V0.2, read-only)

Agents often create Git worktrees (an extra working directory attached to a repository). They can hold the only copy
of someone's work, so they are diagnosed, never treated as ordinary temporary directories.

* **Classification:** distinguish a Git worktree (a `.git` *file* pointing to `<repo>/.git/worktrees/<name>`) and a
  main working tree from any other temporary directory. A directory is never assumed to be disposable because of its
  location or name.
* **Registration:** for each worktree, whether the repository still lists it (`git worktree list --porcelain`), whether
  it is prunable or locked, and **apparent orphans**: worktree directories whose repository or administrative entry is
  missing or unreadable. "Apparent" because a missing repository can be a disconnected drive or a permission problem.
* **Local work:** tracked changes (staged and unstaged), untracked files, ignored files (counted separately; they may
  be build output or secrets), stashes, and operations in progress (merge, rebase, cherry-pick, bisect).
* **Unpublished commits:** commits on the worktree's branch or detached `HEAD` that are not proven to exist anywhere
  else. Remote-tracking references in the local repository (`refs/remotes/...`) are **never** treated as proof that
  the server has the commits: they can be stale, rewritten or pruned. Without a fresh, explicit check against the
  server, preservation is reported as **unknown**.
* **Dependencies:** processes and agent sessions whose working directory, open handles or command line refer to the
  worktree (the same evidence model as temporary directories), and services or virtual machines that map it.
* **No network required:** everything above works offline from local data. An optional, explicitly requested
  check against a remote may be added later; it never runs implicitly and GitHub is never a dependency.
* **Scale (to be implemented progressively):** results grouped by repository; progressive analysis with partial
  results; time, memory and process limits per repository (a timeout marks the result **unknown**, never clean);
  tested with thousands of worktrees.
* Output: per worktree a state of `CLEAN_AND_PUBLISHED_UNKNOWN`, `LOCAL_WORK`, `UNPUBLISHED_COMMITS`, `IN_USE`,
  `APPARENT_ORPHAN` or `UNKNOWN` (names to be confirmed), always with the evidence behind it.

**Acceptance criteria.**
* Every finding states its source and its coverage; unknown is never reported as "not running".
* A worktree whose state cannot be fully determined (Git missing, repository unreadable, timeout, corrupt metadata)
  is reported as **unknown**, never as clean or orphaned.
* Works without Claude Code, Claude Desktop, Hyper-V or any service installed.
* No diagnostic changes system state; a test proves the sandbox and the services are unchanged after a run.
* No command lines, environment blocks or tokens are printed or exported.

**Dependencies.** V0.1.

**Mandatory tests.** Mocked process, service and virtualization sources (present, absent, access denied, partial);
PID reuse and process start-time checks; read-only assertion; both shells and both languages. Worktrees: real
throwaway repositories with registered, locked, prunable and orphaned worktrees; tracked, untracked and ignored
changes; stashes and in-progress operations; unpublished commits with and without (stale) remote-tracking
references; Git not installed; unreadable repository; timeouts; thousands of worktrees; proof that no Git command
writes anything (no fetch, no prune, no index refresh that changes files).

**Safety limits.** Read-only. No service start/stop, no process termination, no VM operations, no ACL changes. Git is only read: no fetch, pull, prune, gc, checkout, stash or index refresh that writes; no network access unless a future option is explicitly requested.

> **V0.2 is a prerequisite for V0.3.** Real deletion is not enabled until the runtime diagnostics can show, for every
> candidate, that no process, service, virtual machine or worktree still depends on it.

---

## V0.2.1 — Desktop GUI and live monitoring

**Status: implemented on `main` (P1–P6); GUI gate closed; not published.** It lands on `main` under the order rule above: dark, with its acceptance proven in CI.

**Design:** [ADR-0014](adr/ADR-0014-desktop-gui-winforms.md). The technology is decided: WinForms on Windows
PowerShell 5.1 / .NET Framework (maintainer decision D-B, 2026-11-16). The GUI ships behind a release gate of its own,
closed in every copy (D-A); that gate covers the presentation, not anything the engines decide. The record lists the
architecture, the phases and its open decisions (GUI-D1...).

**Objectives.** Offer the V0.1 audit and preview and the V0.2 diagnostics in a native Windows desktop window, for
users who do not work in a terminal, and refresh them live while the window is open. V0.2.1 is a new presentation
layer only: it adds no decision, no gate and no system change.

**Deliverables.**
* A desktop GUI (technology to be decided in a documented design, with Windows PowerShell 5.1 / .NET Framework
  compatibility as a constraint) showing the same views as the TUI: dashboard, drill-down by user, project and root,
  detail, preview, coverage and errors, and the V0.2 diagnostics.
* **Live monitoring, session-scoped:** while the window is open, the views refresh periodically (or on request)
  from read-only collections, with the time of the last refresh and its coverage visible. Monitoring stops when the
  window closes; nothing keeps running, nothing is scheduled and no history is stored beyond the open session.
* Refresh is bounded (interval, time and memory limits; a slow or failed refresh marks data as stale or unknown,
  never as clean).
* en-US and pt-BR through the same catalog; accessible keyboard navigation; the CLI and TUI remain fully supported.

**Acceptance criteria.**
* The GUI calls the same engines as the CLI/TUI and cannot bypass them ("engines decide, presentation shows"); a test
  proves it never reaches a deletion, recovery or write API. (Since V0.4 R5 the GUI shows the recovery list and plan,
  read only, and the test also refuses the names of recovery execution.)
* Runs without elevation (PRIV-1), never requests elevation and shows the process identity and elevation state
  (PRIV-10).
* Stale, partial or unknown data is labelled as such; a refresh error never hides a previous finding as resolved.
* Closing the window leaves no process, scheduled task, service or stored history behind.

**Dependencies.** V0.2 (the diagnostics it displays). The safety prerequisites of V0.3 are unchanged: real deletion
is not offered in the GUI before V0.3, and when it is, it goes through the same plan, confirmation and re-validation.

**Mandatory tests.** View models fed by mocked engine results (complete, partial, denied, unknown); refresh limits and
stale marking; read-only assertion over a session with many refreshes; no leftover process after close; both shells
where applicable and both languages.

**Safety limits.** Read-only. No deletion, recovery, service or process control, ACL changes or network access. No
persistent monitoring (that is V0.5).

---

## V0.3 — Selective real cleanup

**Objectives.** Enable real deletion of temporary paths that a human selected and approved, with the protections
already built in V0.1 and the evidence gathered in V0.2.

**Status: version 0.3.0, with the deletion gate closed; real deletion is disabled in every copy.** Its publication is
the GitHub Release `v0.3.0` only, created with the maintainer's explicit approval. The operator ran the dedicated base
runbook and the privilege rows with the gate closed (V4) before it. A release with the gate open comes only after the
operator's pilot (V5) and its own gate. Release record, V4 results and publication blockers:
[release/V0.3-RC.md](release/V0.3-RC.md).

**Validation stages (every distributed copy keeps real deletion disabled).**
* V2, disposable CI integration: **in CI**. The real clean, end to end, on roots planted by a CI-only harness on
  disposable GitHub-hosted VMs, against the installed candidate, as a non-elevated standard user (B1 restricted
  exception) and elevated (ELIGIBLE only when the measured process coverage is complete). The confirmation there is
  automated, never a human acceptance. Details and limits: [TESTING.md](TESTING.md#real-clean-on-disposable-vms-v03-v2).
* V3, adversarial cases: **in CI, complete**. Phases V3a (reparse points and links, files and folders in use), V3b (new
  entries, changes, third-party ACL and processes after the plan) and V3c (deleter outcomes, the log, interrupted runs,
  concurrency, shared bases), attacked in each window of the flow with the real deleter. Not tested by design or
  decision: a write keeping every statistic, a real exception inside the deleter, a real log write failure, an
  interruption in the middle of the tree; the elevated leg's in-deleter cases while its coverage is incomplete. Details
  and limits: [TESTING.md](TESTING.md#v3-as-a-whole).
* V4 (privilege matrix, operator): **done** (2026-11-07, deletion gate closed). Rows not tested, and why, are recorded in
  [release/V0.3-RC.md](release/V0.3-RC.md) (section G).
* V5 (operator pilot on one real root): designed in ADR-0015 (accepted; disposable VM); evidence tools in
  `tools/v5-pilot/` (read only); not executed. It is a prerequisite for any release with the gate open.

**Deliverables.**
* Release gate enabled through a reviewed change; deletion only for paths in an explicit allowlist.
* Typed human confirmation of the exact plan (paths, files, bytes) immediately before deletion.
* Re-validation of every gate immediately before deletion, including the V0.2 runtime evidence.
* Race-condition protection: ancestors and directories pinned by handle, deletion by handle, the plan must match the
  validated measurement exactly, writes after confirmation abort that path.
* Post-cleanup audit and a deletion report (what was deleted, what was preserved and why).
* **Process coverage decision first:** protected Windows processes are never inspectable, so today the coverage
  gate blocks every candidate on a real machine. A reviewed design must say which known protected system
  processes cannot reference an agent's temporary paths, with evidence and tests; until then nothing is deletable.
* **Elevation model decided first** ([ELEVATION.md](ELEVATION.md), manual vs on demand) and implemented to PRIV-2
  to PRIV-9: elevation only through UAC, cancellation and failure change nothing, requester and elevated identity
  shown, full re-validation and the typed confirmation inside the elevated process.
* **Safety before deleting anything near Git work:**
  * any local work that is not proven preserved (changes, untracked or ignored files, stashes, in-progress
    operations, unpublished commits) or any **unknown** state blocks the deletion of that path;
  * Git state and dependencies (processes, sessions, services, virtual machines) are re-validated immediately
    before the operation, not reused from the preview;
  * directories outside the allowed temporary scope (repositories, main working trees, worktrees outside the
    agent's temporary area) are always preserved;
  * the human authorizes the exact paths; no class or state authorizes deletion by itself;
  * failures and timeouts of any check result in blocking, never in automatic authorization.

**Acceptance criteria.**
* Any doubt, change, missing coverage or runtime dependency preserves the path (fail-closed), and the test suite
  proves each case.
* Sessions that are active, recent or of unknown liveness are never deleted.
* Real deletion is validated in a clean environment and in elevated and multi-user scenarios before release.
* Every row of the [privilege matrix](TESTING.md#privilege-matrix) is run for real (standard user, administrator
  not elevated and elevated, credentials-prompt elevation, UAC cancelled, non-interactive session; Windows 10 and
  11; PowerShell 5.1 and 7).

**Dependencies.** V0.2 (runtime diagnostics); the elevation-model decision.

**Mandatory tests.** Junction and symlink swaps during deletion; changes between preview, confirmation and deletion;
open files; other users' profiles with and without elevation; incomplete coverage; partial failures; both shells.
Worktrees: a change, untracked file, stash or commit appearing between preview and deletion blocks it; Git missing
or timing out blocks; a worktree outside the temporary scope is never a candidate.

**Safety limits.** Deletes approved temporary paths only. Never deletes profiles, TEMP roots, bases, projects or
anything outside an agent's temporary area; no ACL changes, no service or process changes.

---

## 0.3.x — Isolation and quarantine of the own profile

**Status: implemented on `main`, not published.** Placement decided by the maintainer (ISO-D1, 2026-11-01); design
in [ADR-0013](adr/ADR-0013-isolation-quarantine-recovery-mode.md) (PARTIALLY ACCEPTED). Phases P1 to P6b, ISO-FIX-VOL
and ISO-PLANCHECK-REASONS are on `main`, behind two release gates closed in every copy: `AtmIsolationEnabled`
(`isolate` only plans) and `AtmQuarantinePurgeEnabled` (`quarantine purge` only plans). The code on `main` reports the
next patch version of the 0.3 line, which is not published ([CHANGELOG](../CHANGELOG.md), section Unreleased). The
operator pilot stopped at a documented step; the limitation was accepted. A release
after 0.3.0 that depends on it. It is not part of 0.3.0. Work for 0.3.x lands on `main`; the `v0.3.0` tag goes on the
audited head of `release/0.3.x`, not on `main` ([release/V0.3-RC.md](release/V0.3-RC.md)). Origin: the
[2026-11-01 incident](incidents/2026-11-01-profile-login-temp-isolation.md), observed operational evidence, not a
root cause. **Isolation is containment and recovery, not prevention:** the dedicated base (`CLAUDE_CODE_TMPDIR`)
still comes first, and the system TEMP stays an exception.

**Objectives.** Take agent temporary data of the user's **own profile** out of the active environment while keeping
it intact, so it can be inspected and restored, and manage the quarantine it goes to.

**Decided by the maintainer (2026-11-01).**
* **ISO-D5:** isolation is the default operation. Deletion happens (a) as a purge after the quarantine, or (b)
  directly, when the user confirms with certainty, through the V0.3 deletion flow, unchanged.
* **ISO-D4:** purge at the end of the quarantine is confirmed by default. An automatic mode exists only as an
  explicit, opt-in administrator configuration, never the default, within the limits of ADR-0013 section 8.
* **ISO-D1:** this release covers the own profile only, with no Recovery Mode and no operation on another user's
  profile (those are V0.4).

**Deliverables.**
* **Group A, controlled isolation.**
  * Three operations kept apart: **audit**, **isolate** and **delete**.
  * Targets in the own profile: a file or directory, a session root, a project, or the whole `<TEMP>\claude` base.
    The whole base needs its own explicit confirmation. Isolation has its own target rule: clean gate 2 refuses the
    base, and isolation does not widen it.
  * It reuses the clean gates, the B2-1 evidence, the AUT-2 confirmation, the T1 log, the B8 lock and the handle
    pinning, behind a new closed release gate.
  * Same-volume move through the target's handle, with documented atomicity limits; another volume is refused.
  * A minimal manifest (no file names, contents or command lines), and a restore that never overwrites or mixes old
    and new sessions.
* **Group B, quarantine management.**
  * List, inspect, verify, restore and purge.
  * Retention marks entries as expired (7, 15 or 30 days are examples), and quotas warn and refuse new isolations.
  * Abandoned and incomplete entries are reported and never purged automatically.
  * Purge is irreversible: confirmed by default, one entry per run, through the V0.3 deleter and its pinning, behind
    the purge gate of its own (J-ISO-1 (C)).
  * Automatic purge only when an administrator opts in: expired entries with an intact manifest only, never the
    active environment, off by default, visible in `version` and the reports, each purge logged, fail closed.

**To be settled in the technical contract before implementation.**
* **The activity rule for the own profile.** Without elevation, process coverage is incomplete on a real machine. The
  rule must be at least as strict as clean, and the B1 exception does not extend to isolation by itself.
* **The quarantine location.** ISO-D2 is still open; its recommendation (an administrator-only folder per volume)
  needs elevation or a folder prepared by the installer.
* **How an opted-in automatic purge is scheduled**, with no stored credentials (PRIV-3).

**Acceptance criteria.**
* Nothing is moved without an exact, individually confirmed plan, and every gate is re-validated immediately before
  the move.
* Any activity evidence or unknown refuses. No process is terminated and no existing ACL or owner is changed.
* Every isolation can be restored, or its manifest states exactly why not. No restore overwrites newer content.
* By default nothing in the quarantine is purged without its own confirmation. An opted-in automatic purge respects
  every limit above, and nothing is purged while the purge gate is closed.
* The own-profile rows of
  [TESTING.md](TESTING.md#future-isolation-quarantine-and-recovery-mode-03x-and-v04) pass on disposable VMs.

**Dependencies.** 0.3.0 published (confirmation and re-validation model, T1, B8, pinning deleter); V0.2 (activity
evidence); the dedicated base runbook; ISO-D2.

**Safety limits.** Own profile only. Moves approved agent temporary paths into the quarantine and back; deletes only
through purge, behind the purge gate (J-ISO-1 (C)). No ACL or owner changes on existing objects, no process, service or session
changes, nothing outside an agent's temporary area.

---

## V0.4 — Assisted recovery

**Status: accepted in [ADR-0016](adr/ADR-0016-v04-assisted-recovery.md) (V04-D1 to V04-D8 decided 2026-11-17: D3 (b) elevation on demand through UAC; the others as recommended). Phase R0 is implemented: read-only service fault signals in the diagnose, which authorize nothing. Phase R1 is implemented: the recovery engine with the eighth release gate, `AtmRecoveryEnabled`, closed in every copy; `recover list` and `recover plan` only list and show the plan of `REC-SVC-START` and change nothing. Phases R2 to R4 are implemented: R2 is the engine of the start, R3 the engine of the undo, and R4 the verbs `recover start` and `recover undo` with elevation on demand through UAC. R2 to R4 act only past the gate `AtmRecoveryEnabled`, which is closed in every copy, so no recovery operation can be executed. Phase R5 is implemented: the TUI and the GUI show `recover list` and `recover plan` in a read-only area (key `S`), from a fresh collection made when the area is opened; no key, button or menu starts, undoes, elevates, locks or logs, and executing stays CLI-only (T-ISO-6). Phase R6 is implemented, in CI only: a CI-only harness (`tests/e2e/Invoke-RecoverE2E.ps1`, never shipped) creates its own inert test services on the disposable runners of the install e2e and runs the real start (R2) and the real undo (R3) through the default seams, behind a guard that accepts only those services; it opens the recovery gate in its own process memory only, and every shipped copy keeps it closed.** It lands on `main` under the order rule above: dark, with its acceptance proven in CI.

**Objectives.** Help recover services and agent environments that are stuck or broken, through reversible steps that
the user authorizes one at a time.

**Deliverables.**
* Recovery procedures derived from V0.2 diagnostics (for example, a stuck agent service or virtual machine).
* Each operation shows what it will change, how to undo it and requires its own authorization.
* Before/after state capture and an undo path for every operation; a recovery log.
* Each operation declares whether it needs elevation; only those request it (PRIV-2), one operation per elevated
  process (PRIV-9), with its own typed confirmation inside that process (PRIV-8).

**Acceptance criteria.**
* No operation runs without individual authorization; there is no "fix everything" mode.
* Every operation is reversible or explicitly marked otherwise and then refused by default.
* Failures leave the system in the captured "before" state or report exactly what differs.

**Dependencies.** V0.2 (diagnostics); V0.3 (confirmation and re-validation model).

**Mandatory tests.** Mocked service and process control (success, denial, timeout, partial failure); undo of every
operation; refusal without authorization; both shells.

**Safety limits.** Only documented, reversible operations on agent-related services and environments. No changes to
unrelated services, other users' sessions, ACLs or system configuration.

### Recovery Mode (Group C of ADR-0013)

**Status: placed in V0.4 by the maintainer (ISO-D1, 2026-11-01); its design stays PROPOSED**
([ADR-0013](adr/ADR-0013-isolation-quarantine-recovery-mode.md)). Nothing is implemented. Isolation and quarantine of
the own profile come earlier, in [0.3.x](#03x--isolation-and-quarantine-of-the-own-profile). Origin: the
[2026-11-01 incident](incidents/2026-11-01-profile-login-temp-isolation.md), observed operational evidence, not a
root cause.

* A guided 13-step flow, run by an administrator from another account, for a profile that cannot be used. It uses the
  0.3.x isolation engine on **another user's profile**.
* A loaded profile neither proves an interactive session nor authorizes moving its files: any process or session of
  that user, or any unknown, refuses.
* It never terminates anything, never recreates the base in that profile (ISO-D6, proposed) and never repairs
  Windows.

**Fit with V0.4.** Recovery Mode is reversible (restore), authorized one operation at a time, with before/after state
and a log. These points need an explicit amendment of V0.4's limits before it is implemented:

* moving files inside **another user's profile**, while never touching that user's sessions;
* creating the quarantine folder with its own DACL, which changes no existing ACL.

**Dependencies.**
* 0.3.x (the isolation engine and quarantine management).
* The elevation-model decision, PRIV-5 and ISO-D3, to act on another user's profile ([ELEVATION.md](ELEVATION.md)).
* ISO-D6.

**Acceptance criteria (proposed).**
* The 0.3.x criteria, plus every cross-profile row of
  [TESTING.md](TESTING.md#future-isolation-quarantine-and-recovery-mode-03x-and-v04): on disposable VMs with the VM's
  second account, and on the operator's controlled machine for the rows that need a real second administrator or a
  real sign-in.

---

## V0.5 — Preventive monitoring

**Status: [ADR-0017](adr/ADR-0017-v05-preventive-monitoring.md) accepted.** V05-D1 to V05-D7 were decided on
2026-11-17 and V05-D8 to V05-D10 on 2026-11-18, all as recommended (until 2026-11-18, V05-D8 to V05-D10 were pending).
* **Phases:** M0, the documentation amendments, is done. M1, the collector and the history storage, is done: a
  collection runs the audit only (V05-D8 (a)), and `agent-temp monitor status` reads the history. M2, the trends, the
  thresholds (`monitor.json`, the user's file, read only; V05-D10 (a)) and the alerts, is done: computed only with the
  gate open, each alert naming a command and running none. M3a, the collector's scheduled task, `monitor enable` and
  the entry point `bin\agent-temp-monitor.ps1`, is done behind the gate: in every copy `monitor enable` refuses before
  asking anything, and the entry point exits without collecting. M3b, the CI-only harness with the real scheduler
  (`tests/e2e/Invoke-MonitorE2E.ps1`, never shipped), is done. On disposable runners, under a test task name and with
  the gate opened only in the harness's memory, it covers:
  * the install e2e's standard user registers the task, reads it back and removes it (with the product's removal since
    M4a). Its run once was NOT_TESTED on every runner: the scheduler did not start an interactive task for a user with
    no interactive session;
  * the elevated runner account is refused by `monitor enable`. Its own test task ran once with last result 3, the
    installed gate closed.

  M4a is done behind the gate: `monitor disable` removes the user's own collection task after an exact match and its
  own phrase, and refuses before asking anything in every copy. Both `monitor disable` and `quarantine
  unschedule-autopurge` remove the shared task folder `\AgentTempManager` when it is empty (V05-D9 (c)). M4b is done
  behind the gate: `monitor remove-history` removes the history files the product created, and the history folder
  when it is empty, after its own plan and phrase; the user's `monitor.json` stays, and with it the folder; in every
  copy it refuses before asking anything. The uninstaller only reads and warns about the monitoring's tasks and history,
  naming the two commands (V05-D9 (a)). M5, the TUI and the GUI, is next. M6, a system notification, is out of V0.5
  (V05-D6 (a)).
* **The gate:** the monitoring gate `AtmMonitoringEnabled` (the ninth) is in the code since M1, `$false` in every copy.
  Nothing is collected, written or scheduled in any copy, and no gate is opened.

It lands on `main` under the order rule above: dark, with its acceptance proven in CI.

**Objectives.** Notice problems before they cost space or stability: growth of temporary data, leftover worktrees,
long-running agent virtual machines. Unlike the live monitoring of V0.2.1, which only runs while the window is open,
V0.5 monitoring is **persistent**: it keeps collecting after the GUI or terminal is closed and across sign-ins and
restarts, once the user has opted in.

**Deliverables.**
* Persistent, periodic, read-only collection of the V0.2 metrics with a small local history (for example through a
  per-user scheduled task; the mechanism is decided in a documented design).
* The V0.2.1 GUI and the TUI show the stored history and trends.
* Configurable thresholds and alerts (console/TUI; system notifications if available without extra dependencies).
* Growth trends per user, project and agent.

**Acceptance criteria.**
* Monitoring is opt-in, uses bounded local storage and can be removed completely.
* Monitoring runs without elevation (PRIV-1); installing a scheduler entry is an explicit, separately confirmed
  step that never stores credentials (PRIV-3).
* Monitoring never deletes, recovers or changes anything; it only recommends the V0.3/V0.4 actions.
  * **How this is read (V05-D4 (a), 2026-11-17):** "never deletes, recovers or changes anything" is about the user's
    system and the agents' data.
  * Keeping its own history bounded is not an exception to it. That means removing the oldest files **of its own
    history**, by exact name, in the product's pinned folder (ADR-0017 section 3).
* Collected history contains no personal data beyond what the audit already shows locally.

**Dependencies.** V0.2; V0.2.1 for the GUI views of history and alerts; V0.3 and V0.4 for the recommended actions.

**Mandatory tests.** Threshold and trend calculations; storage limits and removal; read-only assertion; scheduler
installation and removal in a sandbox.

**Safety limits.** Read-only collection; no automatic cleanup or recovery.

---

## V1.0 — Stabilization and multi-agent support

**Status: not started.** It lands on `main` under the order rule above: dark, with its acceptance proven in CI.

**Objectives.** A stable, documented tool that supports several AI agents through the provider contract.

**Deliverables.**
* Stable provider contract (versioned), documentation for third-party providers and at least one provider beyond the
  Claude scenarios.
* Stable CLI and JSON output formats, with compatibility rules.
* Completed security review of every engine and the installer.

**Acceptance criteria.**
* All previous acceptance criteria still hold; clean-environment, elevated and multi-user tests pass, and the full
  privilege matrix passes on Windows 10 and 11 with PowerShell 5.1 and 7.
* A new provider can be added without changing the engines.

**Dependencies.** V0.1–V0.5 (including V0.2.1).

**Mandatory tests.** Provider contract conformance suite; compatibility of output formats; full regression on both
shells.

**Safety limits.** Those of V0.3 and V0.4; a provider can never weaken a gate.
