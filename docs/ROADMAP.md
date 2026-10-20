# Roadmap

This is the canonical roadmap of Agent Temp Manager. Versions are delivered in order; each one has to meet its
acceptance criteria before the next one starts. A version may be split into smaller releases, but its safety limits
never move.

**Design rule for every version: safety over reclaimed space. When in doubt, preserve.**

| Version | Theme | Changes the system? |
|---|---|---|
| [V0.1](#v01--audit-preview-tui-and-internationalization) | Audit, preview, TUI, internationalization | No (real deletion disabled) |
| [V0.2](#v02--windows-runtime-diagnostics) | Windows Runtime Diagnostics, including Git worktrees | No (read-only) |
| [V0.2.1](#v021--desktop-gui-and-live-monitoring) | Desktop GUI and live monitoring (while the window is open) | No (read-only presentation) |
| [V0.3](#v03--selective-real-cleanup) | Selective real cleanup | Yes: deletes approved temporary paths only |
| [V0.4](#v04--assisted-recovery) | Assisted recovery of services and environments | Yes: reversible operations, each authorized individually |
| [V0.5](#v05--preventive-monitoring) | Persistent preventive monitoring, alerts, growth trends | No (observes and alerts) |
| [V1.0](#v10--stabilization-and-multi-agent-support) | Stabilization and extensible multi-agent support | Same limits as V0.3 and V0.4 |

## Principles that apply to every version

* **Generic architecture.** Agents are *providers* behind the contract in [PROVIDERS.md](PROVIDERS.md). Claude Code
  (and, from V0.2, Claude Desktop) are the initial providers and scenarios, not dependencies: the tool must run, and
  report correctly, on a machine where neither is installed.
* **Engines decide, presentation shows.** Every decision lives in the engines; the CLI, TUI and reports cannot
  bypass them ([ARCHITECTURE.md](ARCHITECTURE.md)).
* **Fail-closed.** Missing coverage, unreadable state, ambiguity or an unexpected change blocks the action. There
  are no overrides for incomplete coverage.
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

**Status: complete; first release pending.**

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
  proves it never reaches a deletion, recovery or write API.
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

## V0.4 — Assisted recovery

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

---

## V0.5 — Preventive monitoring

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
* Collected history contains no personal data beyond what the audit already shows locally.

**Dependencies.** V0.2; V0.2.1 for the GUI views of history and alerts; V0.3 and V0.4 for the recommended actions.

**Mandatory tests.** Threshold and trend calculations; storage limits and removal; read-only assertion; scheduler
installation and removal in a sandbox.

**Safety limits.** Read-only collection; no automatic cleanup or recovery.

---

## V1.0 — Stabilization and multi-agent support

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
