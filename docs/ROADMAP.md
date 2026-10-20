# Roadmap

This is the canonical roadmap of Agent Temp Manager. Versions are delivered in order; each one has to meet its
acceptance criteria before the next one starts. A version may be split into smaller releases, but its safety limits
never move.

**Design rule for every version: safety over reclaimed space. When in doubt, preserve.**

| Version | Theme | Changes the system? |
|---|---|---|
| [V0.1](#v01--audit-preview-tui-and-internationalization) | Audit, preview, TUI, internationalization | No (real deletion disabled) |
| [V0.2](#v02--windows-runtime-diagnostics) | Windows Runtime Diagnostics | No (read-only) |
| [V0.3](#v03--selective-real-cleanup) | Selective real cleanup | Yes: deletes approved temporary paths only |
| [V0.4](#v04--assisted-recovery) | Assisted recovery of services and environments | Yes: reversible operations, each authorized individually |
| [V0.5](#v05--preventive-monitoring) | Preventive monitoring, alerts, growth trends | No (observes and alerts) |
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
* **Worktrees:** git worktrees created by agents, their size, whether they are still registered and whether a
  process uses them.
* **Temporary directories:** the V0.1 inventory, extended with the runtime evidence above.
* **Dependencies:** which temporary paths, worktrees, services and processes depend on each other.
* A diagnostics view in the TUI and a `diagnose` command (name to be confirmed) with JSON export.
* A Claude Desktop provider/scenario, behind the same provider contract.

**Acceptance criteria.**
* Every finding states its source and its coverage; unknown is never reported as "not running".
* Works without Claude Code, Claude Desktop, Hyper-V or any service installed.
* No diagnostic changes system state; a test proves the sandbox and the services are unchanged after a run.
* No command lines, environment blocks or tokens are printed or exported.

**Dependencies.** V0.1.

**Mandatory tests.** Mocked process, service and virtualization sources (present, absent, access denied, partial);
PID reuse and process start-time checks; worktree detection with and without git available; read-only assertion;
both shells and both languages.

**Safety limits.** Read-only. No service start/stop, no process termination, no VM operations, no ACL changes.

> **V0.2 is a prerequisite for V0.3.** Real deletion is not enabled until the runtime diagnostics can show, for every
> candidate, that no process, service, virtual machine or worktree still depends on it.

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

**Acceptance criteria.**
* Any doubt, change, missing coverage or runtime dependency preserves the path (fail-closed), and the test suite
  proves each case.
* Sessions that are active, recent or of unknown liveness are never deleted.
* Real deletion is validated in a clean environment and in elevated and multi-user scenarios before release.

**Dependencies.** V0.2 (runtime diagnostics).

**Mandatory tests.** Junction and symlink swaps during deletion; changes between preview, confirmation and deletion;
open files; other users' profiles with and without elevation; incomplete coverage; partial failures; both shells.

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
long-running agent virtual machines.

**Deliverables.**
* Periodic, read-only collection of the V0.2 metrics with a small local history.
* Configurable thresholds and alerts (console/TUI; system notifications if available without extra dependencies).
* Growth trends per user, project and agent.

**Acceptance criteria.**
* Monitoring is opt-in, uses bounded local storage and can be removed completely.
* Monitoring never deletes, recovers or changes anything; it only recommends the V0.3/V0.4 actions.
* Collected history contains no personal data beyond what the audit already shows locally.

**Dependencies.** V0.2; V0.3 and V0.4 for the recommended actions.

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
* All previous acceptance criteria still hold; clean-environment, elevated and multi-user tests pass.
* A new provider can be added without changing the engines.

**Dependencies.** V0.1–V0.5.

**Mandatory tests.** Provider contract conformance suite; compatibility of output formats; full regression on both
shells.

**Safety limits.** Those of V0.3 and V0.4; a provider can never weaken a gate.
