# ADR-0016: Assisted recovery (V0.4)

Status: ACCEPTED (V04-D1 to V04-D8 decided 2026-11-17: D3 (b) elevation on demand through UAC; the others as recommended); R0, R1 and R2 implemented
Date: 2026-11-17
Phase: V0.4 (phases R0 to R6 below, each a future round with its own contract and tests)

## Context

The ROADMAP's V0.4 ("Assisted recovery") asks for recovery procedures derived from the V0.2 diagnostics, for agent
services and environments that are stuck or broken ([ROADMAP](../ROADMAP.md#v04--assisted-recovery)). It sets these
requirements:

* every operation is authorized on its own, and there is no "fix everything" mode;
* every operation captures the state before and after it, has an undo path and is written to a recovery log;
* an operation that is not reversible is marked so and refused by default;
* a failure leaves the captured "before" state, or reports exactly what differs;
* each operation declares whether it needs elevation; only those request it (PRIV-2), one operation per elevated
  process (PRIV-9), with the typed confirmation inside that process (PRIV-8).

**Ordering.** The maintainer's decision D-A (2026-11-16) applies: V0.4 lands on `main` dark, behind a release gate of
its own, `$false` in every copy, with its acceptance proven in CI. Only a decision of the maintainer opens it.

**Out of this record:**

* **Recovery Mode** (Group C of [ADR-0013](ADR-0013-isolation-quarantine-recovery-mode.md)). Section 7 only says where it
  would fit and which decisions it still waits for.
* Anything outside an agent's own services and environment:
  * services not related to agents;
  * other users' sessions;
  * ACLs;
  * system configuration;
  * repairing Windows.

All file and line references below are to commit `9c174e64439686ca1c5b07fd436abae4d03cd755`.

## Decision (proposed)

### 1. Inventory: what V0.2 detects that could call for recovery

**The main finding.** The diagnose engine reports **states**, not **faults**. It has no finding that says a service,
VM, process, lock or worktree is "stuck" or "broken". Its findings are one snapshot per run, each with a closed list of
states (`src/lib/Engine.Diagnose.ps1:34-43`). The table below lists every finding kind that comes near the round's
examples. A row for an example the code does not produce says so (row 10); no row presents a finding the code does not
emit.

| # | Finding (code) | Provider that produces it | Behind a closed V0.2 gate? | Evidence it carries | What is missing before it can ground an operation |
|---|---|---|---|---|---|
| 1 | `Service` in state `RUNNING`, `STOPPED`, `PAUSED` or `PENDING` (`Engine.Diagnose.ps1:36`, state map `:3176`, findings `:3794-3870`) | `claude-desktop`, the single name `CoworkVMService` (`src/providers/ClaudeDesktop.ps1:50`). `claude-code` declares no service (`src/providers/ClaudeCode.ps1:143-175`). | No: the services collector runs in every copy. | `SERVICE_STATE`, `SERVICE_START_MODE`, `SERVICE_DELAYED_AUTO_START`, `SERVICE_ACCOUNT_KIND`, `SERVICE_EXECUTABLE` or `_NAME`, `SERVICE_PROCESS_VERIFIED` (`:3829-3847`) | **No fault signal:** the query reads no exit code (`:3151` lists the properties read), so a `STOPPED` service that failed looks like one that was never started. **"Stuck" is not measurable:** `PENDING` is a single reading with no duration, checkpoint or wait hint. **Weak attribution:** the name is a publicly reported one, not documented by the vendor (`ClaudeDesktop.ps1:24-26`). **No proof of absence:** a name the account cannot see is `UNKNOWN`, never absent (`:3819-3822`; the collector never produces `NOT_PRESENT`, `:3142-3143`). |
| 2 | `Service` in state `UNKNOWN` (query denied, failed, timed out, or name not listed) | as row 1 | No | `SERVICE_NOT_QUERIED`, `SERVICE_NOT_LISTED` (`:3817-3822`) | Nothing is known, so there is nothing to act on. |
| 3 | `VirtualMachine` in state `RUNNING`, `OFF`, `SAVED`, `PAUSED` or `PENDING` (`:37`, `:3896`, `:4058-4196`) | **None.** No provider declares a virtualization hint (`ClaudeDesktop.ps1:51` returns an empty list; `ClaudeCode.ps1` has none), so every VM is `VM_UNATTRIBUTED` (`:4167`). The Cowork VM is a Host Compute Service system, not a Hyper-V VM, and is not expected in this query (`ClaudeDesktop.ps1:33-36`). | No | `VM_ENABLED_STATE`, `VM_WORKER_VERIFIED`, attribution codes (`:4129-4167`) | **Attribution.** Without an agent attribution, a VM is someone else's VM. The `RUNS_VM` graph relation is proposed and not implemented ([ADR index](README.md), ADR-0002). |
| 4 | `VirtualizationPlatform` `PRESENT` (`:38`, `:4194`) | none (engine) | No | hypervisor flag, namespace, `vmms` state (`:4103-4113`) | Context only. Platform features are system configuration, which V0.4 excludes. |
| 5 | `Process` in state `AGENT_PROCESS`, `AGENT_DESCENDANT` or `IDENTITY_UNVERIFIED` (`:35`, `:1304-1320`) | `claude-code`: the image name `claude.exe` (`ClaudeCode.ps1:148`), the session registry and path references. `claude-desktop`: `claude.exe` with a package marker (`ClaudeDesktop.ps1:49`). | No | `PROCESS_MATCHER_IMAGE`/`_MARKER`, `SESSION_PROCESS_MATCH`, `PATH_REFERENCE`, `PARENT_LINK_VERIFIED`. The key is `pid@creationTicksUtc` (`:339-344`). | **There is no "orphan" or "hung" state.** **Discovery is heuristic:** `agent-processes` coverage is never `COMPLETE` (`:1288-1295`). **Ambiguous attribution:** both providers match the same image name (`ClaudeDesktop.ps1:30-32`). **No responsiveness signal.** |
| 6 | `AgentSession` in state `LIVE`, `PID_REUSED`, `IDENTITY_UNVERIFIED` or `SESSION_PROCESS_NOT_FOUND` (`:41`, `:864-900`, `:1131-1153`) | `claude-code`: `<configDir>\sessions\<pid>.json` (`ClaudeCode.ps1:49-50`) | No | `SESSION_REGISTRY`, `SESSION_PROCESS` with its reason, `SESSION_PROCESS_KEY` | **The registry file is the agent's own**, and providers only read (`docs/ARCHITECTURE.md:30`). **The harm is not shown:** no evidence says a stale entry (`SESSION_PROCESS_NOT_FOUND`, given only with a `COMPLETE` snapshot, `:884`; or `PID_REUSED`) breaks anything. |
| 7 | `Worktree` in state `APPARENT_ORPHAN` (`:2716-2720`), with evidence `WORKTREE_LOCKED` (`:2772`), `WORKTREE_DIRECTORY_MISSING` (`:2773`) or `OPERATION_IN_PROGRESS` (`:2591`) | none (Git discovery from partitions and explicit paths) | **Yes:** `AtmWorktreeDiagnosticsEnabled` (`:1722`). Closed, discovery returns `NOT_OBSERVABLE` and reads nothing (`:2651-2653`). | `ADMINISTRATIVE_ENTRY_NOT_FOUND`, `LOCAL_WORK_UNKNOWN`. An orphan that is registered elsewhere drops to `UNKNOWN` (`:2883`). | **The gate must be open.** **Every repair would write to Git**, and Git use is read-only by design (ADR-0006). **Local work is unknown** by definition of the state. |
| 8 | Open-file holders (`FILE_HELD_OPEN`) | none (Restart Manager over sampled files) | **Yes:** `AtmHandleDiagnosticsEnabled` (`:4621`). Closed, the collector is `NOT_OBSERVABLE` (`:4676`). | a process key per holder | Releasing a holder means ending a process (row 5). |
| 9 | `TempPartition` in state `IN_USE` or `NO_DEPENDENCY_OBSERVED` (`:42`, `:4530-4605`) | `claude-code` temp bases | No | graph evidence (`GRAPH_*`) | Not recovery: clean (V0.3) and isolation (0.3.x) already act on these partitions behind their own gates. |
| 10 | A "stale lock" | **None.** No finding exists. The diagnose skips `*.lock` names when it reads references (`:2422`) and reports no lock. B8 is a kernel mutex (`src/lib/Engine.Clean.ps1:360`), and Windows reports it `ABANDONED` when its owner ends without releasing it (`:396-398`). | n/a | n/a | No lock file is left behind for a tool to recover. |

**Also relevant:** the diagnose JSON export is behind `AtmDiagnoseExportEnabled` (`src/lib/Report.ps1:1180`). The keys
in an export are keyed pseudonyms whose key exists only for that run unless the operator supplies one
(`Engine.Diagnose.ps1:4932-4934`). An export can therefore never be the input of an operation (section 3).

**Outcome.** The only finding that names an agent-related object the tool could change in a reversible way is the
`Service` finding of a provider-declared name. Even there, the code gives a state and no fault. The catalog below is
thin on purpose.

### 2. Catalog of candidate operations

**Rules for the catalog:**

* Each operation acts on **one target**, chosen by the operator from a fresh collection.
* An operation that is not reversible is marked `IRREVERSIBLE` and is **refused by default**.
* "Out" means outside V0.4, by the ROADMAP's limits or by this record's recommendation.

**Windows facts used below**, from Microsoft's documentation (Sources):

* starting a service needs `SERVICE_START`, and stopping it needs `SERVICE_STOP`;
* the default security descriptor of a service gives those two rights to LocalSystem and Administrators, not to local
  authenticated users;
* each service can carry its own descriptor;
* `Win32_Service` exposes `ExitCode`, `ServiceSpecificExitCode`, `CheckPoint`, `WaitHint` and `AcceptStop`.

| Id | What it changes | State captured before | Undo, and is it complete? | Elevation | Residual risk | Proposed status |
|---|---|---|---|---|---|---|
| `REC-SVC-START` | One provider-declared agent service from `STOPPED` to `RUNNING` | state, start mode, delayed start, account kind, executable, `ExitCode`/`ServiceSpecificExitCode`, `CheckPoint`/`WaitHint`, `AcceptStop`, the services it depends on and their states | Stop the service (`REC-SVC-STOP` as undo). **Complete for the service's state only.** What the service did while it ran (files, a VM it created, its logs) is not undone, and the plan says so. | Yes by default (the default descriptor); the right is checked for this token and this service in the acting process (phase R2). | Starting a service can make Windows start the services it depends on. That is to be verified in phase R2. Until then, the plan refuses when a dependency is stopped and is not itself a declared agent service. The service's own start-up behaviour is the vendor's. | **Candidate for the first phase** (V04-D1) |
| `REC-SVC-STOP` | One provider-declared agent service from `RUNNING` to `STOPPED`, only when `AcceptStop` is true | as above, plus the verified process key | Start it again. **Not complete:** what the service held in memory, and any VM or session it ran, are lost. | Yes by default | Ends the service's process through the service control manager. Dependent services are never stopped in cascade: a running dependent refuses the operation. | `IRREVERSIBLE` in effect; **refused by default**. Available only as the undo of `REC-SVC-START` in the same chain, or if V04-D1 (b) is decided. |
| `REC-SVC-STARTMODE` | A declared service's start mode (for example `Disabled` to `Manual`) | the start mode and delayed start | Write the previous values back: complete. | Yes (needs `SERVICE_CHANGE_CONFIG`) | It is service configuration, close to the "system configuration" V0.4 excludes. | **Out** unless the maintainer decides otherwise (V04-D1 (c)) |
| `REC-SVC-RESTART-PENDING` | A service stuck in a pending state | — | — | — | A pending service cannot be stopped normally. Forcing it means ending its process. | **Out** (it is `REC-PROC-END`) |
| `REC-VM-*` | Start, stop or save a VM | — | — | — | No VM is attributed to an agent by the code (inventory row 3). | **Out** until a provider declares an attribution that the diagnose verifies (a later version) |
| `REC-PROC-END` | Ends one agent process | — | **None: irreversible.** Unsaved work and in-memory state are lost. | Not for an own process; yes for another user's | See the analysis below. | **Out** (recommended; V04-D2) |
| `REC-SESSION-ENTRY` | Moves a stale session registry entry aside, as isolation moves a root | the entry's name, size and time | Move it back; complete if nothing new took its name | No (own profile) | Writes in the agent's own configuration folder, a file whose format the agent owns. No evidence shows a stale entry causes harm. | **Out of the first phase.** It would need a provider contract stating that the move is safe. |
| `REC-WT-PRUNE`, `REC-WT-UNLOCK` | Git administrative entries | — | Prune: irreversible. Unlock: only if the lock reason is kept. | — | A Git write, behind the closed worktree gate (row 7) | **Out** |
| Isolate a temp root | — | — | — | — | Already in 0.3.x (own profile). Another user's profile is Recovery Mode (section 7). | Not a new operation |

**Ending a process: the analysis behind V04-D2.** The recommendation is to keep it **out** of V0.4.

* **It is irreversible.** The ROADMAP lets an irreversible operation exist only marked and refused by default.
* **The proof of ownership is weak.** Agent discovery is heuristic and never complete (`Engine.Diagnose.ps1:1288-1295`).
  `claude.exe` is matched by both providers (`ClaudeDesktop.ps1:30-32`). No finding says a process is hung or
  orphaned (inventory row 5).
* **Every earlier design refuses it:** ADR-0013 section 4 ("No process is ever terminated"), the 0.3.x acceptance and
  the V0.3 safety limits.

If the maintainer still wants it (V04-D2 (b)), these are the minimum conditions:

* a process key `pid@ticks` proven by a `LIVE` session of the same provider, never by the image name alone;
* the same user as the token, and never `SELF`;
* the process opened by handle, its creation time checked on that handle, and termination through that same handle, so
  a reused PID can never be hit;
* `IRREVERSIBLE`, refused by default, and behind a gate of its own;
* one process per run, with no tree kill.

Until then, the tool shows the process and tells the person how to close the agent.

### 3. Authorization model: what is reused from V0.3

* **Its own engine.** A new `src/lib/Engine.Recover.ps1`. The diagnose engine never controls services, processes or VMs
  (`docs/ARCHITECTURE.md:31-34`), and stays read-only.
* **The input of an operation.** The operation id and **one** target's identity: a service name, or a process key if
  V04-D2 (b) is ever decided. The engine runs its own fresh collection and finds the target again in it. It never
  acts on a pseudonymous key, an export or a plan computed in another process.
* **Presentation and typed confirmation (AUT-2):**
  * the plan is shown through a mandatory presenter;
  * the typed phrase is bound to a plan id (operation, target identity and captured "before" state), as clean binds it
    (`Engine.Clean.ps1:436-447`);
  * the console is observed by the engine (`Get-AtmEngineConsoleObservation`, `Engine.Clean.ps1:383-388`);
  * **one operation per run, fixed in code**, as isolation fixes one root (`src/lib/Engine.Isolate.ps1:30`);
  * there is no list, batch or "all" mode.
* **Revalidation immediately before acting.** The engine re-reads the target and compares it with the confirmed plan:
  name, executable, state, start mode, dependencies, process key, and the token's identity and elevation. Any
  difference refuses, as clean's `REVALIDATION_REFUSED` does (`Engine.Clean.ps1:459`).
* **The lock: reuse B8** (`Global\AgentTempManager.Clean`, `Engine.Clean.ps1:360`) through `Invoke-AtmUnderSharedLock`
  (`:367-381`), as isolation does. Reasons:
  * one changing operation at a time on the machine, in any copy or version;
  * its refusal codes and their tests already exist;
  * a new fixed lock name would need its own policy and tests.

  How the lock behaves between an elevated holder and a non-elevated one is tested in phase R2. V04-D6 keeps the
  alternative of a lock of its own.
* **The log: a recovery log with T1's contract.** It is written by the same pinned writer (`Open-AtmCleanLog`,
  `Engine.Clean.ps1:316-344`), with its own schema `atm.recoverlog/1`:
  * a new file per run, never appended to;
  * a pinned folder, outside every audited base (`Test-AtmOutputPathOutsideBases`, `Engine.Clean.ps1:1039`);
  * a protected DACL, which the suite checks for the T1 writer (`tests/Run-Tests.ps1:1587`);
  * the records: `run-start`, `plan`, `before`, `confirmation`, `plan-check`, `intent`, `result`, `after`, `run-end`;
  * no command line, path of another user or account name in any record.
* **Elevation.**
  * Only an operation that needs a right the token lacks asks for elevation (PRIV-2).
  * One operation per elevated process (PRIV-9).
  * The typed confirmation is shown and read **inside** that process, after its own revalidation (PRIV-6, PRIV-8).
  * **How the elevated process starts, gets its operation and returns its result is V04-D3**, the maintainer's
    decision. The alternatives are compared in [ELEVATION.md](../ELEVATION.md) (manual elevation vs elevation on demand)
    and in ISO-D3 of ADR-0013:
    * **(a) Manual.** The operator opens an elevated console and runs one `recover` operation. The engine refuses a
      second operation in the same process. The result is the console output and the log. This is the same model as
      the installer, and ISO-D3's recommendation.
    * **(b) On demand.** The non-elevated tool relaunches the installed launcher through UAC with fixed arguments: the
      operation id and the target's name or key, never a file or a plan. The elevated copy collects, plans, shows,
      asks, acts, logs and exits. The non-elevated side reads only the log's `run-end`. This adds PRIV-4 (prompt
      outcomes), PRIV-5 (requester and acting identity) and PRIV-7 (trusted code only) as work items.
    * **(c) A broker service or a scheduled task** is excluded by PRIV-3.

    Recommendation: (a) for V0.4, as ELEVATION.md recommends. (b) only later, as an explicit, opt-in option.

### 4. Capture before and after, and failures

* **Before**, read in the acting process just before the confirmation and again at revalidation (for a service):
  * state, start mode, delayed start;
  * `ExitCode` and `ServiceSpecificExitCode`;
  * `CheckPoint` and `WaitHint`;
  * `AcceptStop`;
  * account kind and executable, reduced as the diagnose reduces them (`Engine.Diagnose.ps1:3674-3675`);
  * the verified process key when running;
  * the services it depends on and the services that depend on it, with their states.

  All of it is recorded in the `before` record.
* **After:** the same set, read once the operation settles or a fixed, bounded wait ends. It is recorded in `after`.
* **Outcomes:**
  * `COMPLETE`: the requested state is reached;
  * `PARTIAL`: still pending at the end of the wait;
  * `FAILED`: the service went back to its earlier state, with its exit code;
  * `REFUSED`: access denied, nothing changed;
  * `EXCEPTION`: the `after` record is still read.
* **Failure handling (V04-D7).** The recommendation is that the engine **never** chains a compensating action of its
  own. It reports, field by field, what differs between `before` and `after`, which meets the ROADMAP's "or reports
  exactly what differs". The undo is a separate operation, presented, confirmed and logged by itself. Most failed
  starts leave the "before" state anyway, since a service that fails to start returns to `STOPPED`; R2 verifies that
  with the seam.
* **Undo.**
  * `recover undo <runId>` builds the inverse plan from that run's `before` and `after` records and a fresh collection.
  * It is refused when the current state is no longer the recorded `after`. Someone else changed it, and the undo
    never overwrites a newer state, as restore never overwrites newer content (ADR-0013 section 7).

### 5. The new gate

* `$script:AtmRecoveryEnabled = $false`, a single assignment in `src/lib/Engine.Recover.ps1`, with no switch,
  environment variable, configuration file or UI option. It is the **eighth** release gate. The suite opens it only
  inside its own process, as it does for the other seven.
* **Closed (every copy):**
  * `agent-temp recover list` shows the possible operations derived from a fresh read-only collection: each target,
    why it is offered, reversible or `IRREVERSIBLE`, and whether elevation is likely, from the token alone;
  * `agent-temp recover plan <operation> <target>` shows the full plan, the "before" capture and the undo path, then
    "nothing was changed";
  * nothing is asked, locked or logged, and no service is opened with a control right.
* **Opening it is the maintainer's decision.** It stays `$false` in every copy. The build, the installer and manifest
  checks, the install e2e and `version` learn the new gate in phase R1, as they did for the seventh (CHANGELOG,
  V021-P1).

### 6. Implementation phases (each a future round with its own contract and tests)

Each phase names the files its round will need in ALLOWED_PATHS. None is written by this record.

| Phase | Content | Files (future ALLOWED_PATHS) | Tests |
|---|---|---|---|
| R0 | Read-only fault signals in the diagnose: `ExitCode`, `ServiceSpecificExitCode`, `CheckPoint`, `WaitHint`, `AcceptStop`, dependents and dependencies. If V04-D5 (b) is decided, a provider contract field for the service's expected executable location. | `src/lib/Engine.Diagnose.ps1`, `src/providers/*`, `src/lib/I18n.ps1`, `docs/PROVIDERS.md`, `tests/Run-Tests.ps1` | Injected service rows: values, unreadable values, a dependency missing. The diagnose stays read-only (existing static tests). |
| R1 | `Engine.Recover.ps1` with the gate closed: catalog, `recover list` and `recover plan` (CLI) | `src/lib/Engine.Recover.ps1`, `src/agent-temp.ps1`, `src/lib/Report.ps1`, `src/lib/I18n.ps1`, `tools/Build-Release.ps1`, `install/*`, `tests/Run-Tests.ps1`, `tests/e2e/Invoke-InstallE2E.ps1` | Closed gate: nothing asked, locked, logged or opened with a control right. Static: one gate assignment; only `Engine.Recover.ps1` reaches the service-control seam; diagnose and presentation never do. Installed gate count is eight. Both shells. |
| R2 | `REC-SVC-START` past the gate, through a **service-control seam** (a scriptblock, like clean's `DeleteTreeImpl`) | `src/lib/Engine.Recover.ps1`, `tests/Run-Tests.ps1` | Seam outcomes: success, access denied, timeout (still pending), failure with an exit code, an exception. Before/after capture. AUT-2 phrase and console. Revalidation refusal after each kind of change. B8 busy, abandoned, and an elevated vs non-elevated holder. Log records and their privacy. Refusal without authorization. Both shells. |
| R3 | Undo of every operation in the catalog | as R2 | Undo after success. Undo refused when the state changed after the run. Undo of a `PARTIAL` run. |
| R4 | Elevation per V04-D3 | (a): `Engine.Recover.ps1`. (b): also the launcher in `install/` and `src/bin/`. | (a): a missing right gives `RECOVERY_NEEDS_ELEVATION` and changes nothing; a second operation in one process is refused. (b): also prompt outcomes (PRIV-4), the requester shown (PRIV-5), arguments refused beyond the fixed set. |
| R5 | Presentation: the TUI and the GUI show `list` and `plan` only. Executing stays CLI-only, as restore is (T-ISO-6). | `src/lib/Tui.ps1`, `src/lib/Gui*.ps1`, `src/lib/I18n.ps1`, `tests/Run-Tests.ps1` | The GUI test that it "never reaches a deletion, recovery or write API" (ROADMAP V0.2.1) learns the recovery function names. Both languages. |
| R6 (optional, V04-D8) | A real service on a disposable CI runner: a CI-only harness creates its **own** test service, runs R2 and R3 against it, and leaves the runner. It never touches a service of the runner itself. | `tests/e2e/Invoke-RecoverE2E.ps1` (on the build's CI-only list, out of the package, like the V2/V3 harnesses), `.github/workflows/*` | Its own contract. Without R6, no CI test controls a real service. |

### 7. Where Recovery Mode would fit

Recovery Mode (ADR-0013 section 9) is the other V0.4 item: an administrator, signed in with another account, isolates
agent temporary data of a profile that cannot be used. In this design it would be one more operation of
`Engine.Recover.ps1`'s catalog, built on the 0.3.x isolation engine, with the same authorization model as section 3:

* one target per run;
* AUT-2, revalidation, B8 and its log;
* restore as the undo.

It is not designed again here. It still waits for:

* **the amendment of V0.4's safety limits:** moving files in another user's profile, and creating the quarantine
  folder with a DACL of its own (ROADMAP, "Fit with V0.4");
* the elevation model (V04-D3 here, ISO-D3 there) and **PRIV-5**;
* **ISO-D2** (the quarantine location) and **ISO-D6** (never recreating the base).

### 8. Decisions for the maintainer

None is decided by this record.

| Id | Question | Evidence | Alternatives | Technical recommendation |
|---|---|---|---|---|
| V04-D1 | Which operations enter the first phase | Inventory: only the `Service` finding of a declared name grounds a reversible change. No fault signal is collected yet. | (a) `REC-SVC-START` only. (b) Also `REC-SVC-STOP`, `IRREVERSIBLE` and refused by default, opened by an explicit per-run acceptance. (c) Also `REC-SVC-STARTMODE`. (d) None until R0 shows a fault signal: list and plan only. | **(a), after R0.** Start is the one change with a complete undo of the service's state. R0's exit code is what tells a failed service from one that was never started. |
| V04-D2 | Ending a process: yes or no | Section 2 analysis: irreversible, heuristic discovery, image name shared by two providers, refused by ADR-0013, 0.3.x and V0.3 | (a) Out of V0.4. (b) In, under the minimum conditions of section 2, `IRREVERSIBLE`, refused by default, behind a gate of its own. | **(a).** The tool shows the process and how to close the agent. |
| V04-D3 | The elevation model of V0.4's operations | ELEVATION.md comparison and recommendation; ISO-D3 (a) recommended; the default service descriptor grants start and stop to administrators | (a) manual, one operation per process; (b) on demand through UAC with fixed arguments; (c) a broker (excluded by PRIV-3) | **(a).** (b) later, as an explicit, opt-in option meeting PRIV-2 to PRIV-9. |
| V04-D4 | Does V0.4 wait for V5, or go ahead behind its gate (D-A)? | V5 proves real deletion. V0.4's first operation deletes nothing and does not depend on the deletion gate. D-A lets a version land dark. | (a) Go ahead behind `AtmRecoveryEnabled`. Its opening waits for a pilot of its own in a disposable VM, as D-C did for V5. (b) Wait for V5. | **(a).** |
| V04-D5 | What proves a service is the agent's before acting on it | The name `CoworkVMService` is publicly reported, not documented by the vendor (`ClaudeDesktop.ps1:24-26`). Another product could register the same name. | (a) the declared name, as the diagnose uses it; (b) the name plus an expected executable location declared by the provider (a contract field, R0), plus a verified process link when the service is running | **(b).** |
| V04-D6 | The lock | Isolation reuses B8 (T-ISO-7) | (a) reuse B8; (b) a lock of V0.4's own | **(a).** One changing operation at a time on the machine. |
| V04-D7 | What happens when an operation fails | ROADMAP: "before" state, or report exactly what differs | (a) report the difference; undo is a separate, confirmed operation; (b) an automatic compensating action, included in the confirmed plan | **(a).** No change is ever made without its own confirmation. |
| V04-D8 | A real service in CI | The round's rule: no CI test controls a runner's real service without a contract of its own | (a) R6: a CI-only harness that creates its own test service on a disposable runner, out of the package; (b) seam only, with a real service never touched | **(a), after R2 and R3.** |

### 9. Risks and limits

* **V0.4 does not:**
  * decide that something is broken;
  * repair Windows, services of other products, sessions, ACLs or system configuration;
  * act on a VM;
  * end a process (if V04-D2 (a) is decided);
  * write to Git;
  * touch another user's profile (Recovery Mode waits).
* **What a start cannot undo:** stopping a service again restores its state, not what it did while running.
* **NOT TESTED, by design, until a phase or decision says otherwise:**
  * a real service of a runner or of this machine (R6 only covers a test service of its own);
  * the real Cowork service;
  * real UAC prompts (R4 (b) only);
  * another user's profile;
  * Host Compute Service VMs.
* **To be verified in R2, not assumed here:**
  * whether starting a service starts its stopped dependencies;
  * how B8 behaves between integrity levels.

## Rejected alternatives

* **Recovery inside the diagnose engine:** the diagnose engine is read-only by its layering rule
  (`docs/ARCHITECTURE.md:31-34`).
* **A "fix everything" or batch mode:** excluded by the ROADMAP.
* **Acting on an export or a pseudonymous key:** keys are per run (`Engine.Diagnose.ps1:4932-4934`), and an export is
  behind its own closed gate. The acting process collects again.
* **Calling the `Win32_Service` control methods from presentation:** presentation never changes anything; only the
  engine reaches the service-control seam.
* **A broker service or scheduled task for elevation:** PRIV-3.

## Consequences (including new limits)

* **An eighth release gate.** The build, installer, manifest checks, install e2e, `version` and the GUI's
  "never reaches a recovery API" test change in R1 and R5. Those rounds need `install/`, `tools/Build-Release.ps1` and
  `tests/e2e/` in their ALLOWED_PATHS.
* **New limits:**
  * one operation per run;
  * executing from the CLI only;
  * no operation on an `UNKNOWN`, unattributed or ambiguous target;
  * no automatic compensating action.

## Verification

* **This record:** the documentation-only CI, with the seven gates unchanged.
* **Each phase R0 to R6:** the tests in section 6, in both shells, with the gate closed in every copy and checked by
  the build, the installer and the install e2e.
* **Opening the gate:** that waits for the maintainer and, under V04-D4 (a), for a pilot of its own.

## Sources

* Microsoft, "Service Security and Access Rights" (the rights to start, stop and query a service; the default security
  descriptor of a service object): https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights
* Microsoft, "Win32_Service class" (`ExitCode`, `ServiceSpecificExitCode`, `CheckPoint`, `WaitHint`, `AcceptStop`):
  https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service
* In this repository: [ROADMAP](../ROADMAP.md) (V0.4), [ELEVATION.md](../ELEVATION.md), [ARCHITECTURE.md](../ARCHITECTURE.md),
  [PROVIDERS.md](../PROVIDERS.md), [ADR-0013](ADR-0013-isolation-quarantine-recovery-mode.md).

## R0 implementation record (2026-11-17)

The maintainer decided V04-D1 to V04-D8 on 2026-11-17. Seven are as recommended in section 8.

**V04-D3 is (b), elevation on demand through UAC, not the recommended (a).** Sections 3 and 8 still show the comparison
and the recommendation as they were proposed; this record is where the choice is written down.

* **What (b) means.** The non-elevated tool relaunches the installed launcher through UAC with fixed arguments (section
  3).
* **Where it lands.** Phase R4 covers (b): the launcher in `install/` and `src/bin/`, with these work items:
  * PRIV-4: prompt outcomes;
  * PRIV-5: requester and acting identity;
  * PRIV-7: trusted code only.
* **R0 does not change.** It elevates nothing.

R0 is the only phase implemented. It adds no gate, opens none, and changes no finding state, eligibility, B1 or RECENT
rule: every signal below is evidence in the diagnose, and none of them authorizes anything.

**What is read, and how.**

* **API and access.** CIM only, local, each query bounded by `-OperationTimeoutSec`. No class method is called, and the
  product opens no handle to the service control manager or to a service: the CIM provider does the reads.
  * `Win32_Service`: the query the diagnose already ran, for the declared names. It now also asks for `ExitCode`,
    `ServiceSpecificExitCode`, `CheckPoint`, `WaitHint` and `AcceptStop`.
  * The association class `Win32_DependentService` (`Antecedent` is the service relied upon, `Dependent` the one that
    relies on it): one enumeration, kept in memory only where one end is a declared name.
  * `Win32_BaseService` (services and drivers): `Name`, `State` and `PathName` of the related services, at most 64.
* **Signals** (evidence of a listed service):
  * `SERVICE_EXIT_CODE`, plus `SERVICE_SPECIFIC_EXIT_CODE` only with exit code 1066;
  * `SERVICE_ACCEPT_STOP`;
  * `SERVICE_CHECKPOINT` and `SERVICE_WAIT_HINT_MS` only for a `PENDING` service.

  A value that cannot be read gets its `_UNREADABLE` code and the reason `SERVICE_SIGNAL_UNREADABLE` in
  `service-properties`; it is never replaced by 0 or false. A row that carries none of these properties (rows injected
  by tests written before R0) gives `SERVICE_SIGNALS_NOT_COLLECTED`.

**Classification** (`SERVICE_CONDITION`). Only a `STOPPED` or `PENDING` service gets one. The finding keeps the state
of the first read.

| Condition | Meaning |
|---|---|
| `STOPPED_CLEAN` | Stopped, exit code 0 (no error reported). |
| `STOPPED_NEVER_STARTED` | Stopped, exit code 1077 (not started since the last boot). |
| `STOPPED_FAILED` | Stopped, any other exit code. With 1066, `SERVICE_SPECIFIC_EXIT_CODE` gives the service's own code. |
| `STOPPED_EXIT_UNREADABLE` | Stopped, exit code unreadable. |
| `PENDING_PROGRESSING` | The same pending state in both reads, and `CheckPoint` changed. |
| `PENDING_STALLED` | The same pending state in both reads, `CheckPoint` unchanged after a wait at least as long as a `WaitHint` greater than 0. |
| `PENDING_UNCHANGED` | The same pending state, `CheckPoint` unchanged, but the wait was shorter than `WaitHint`, or `WaitHint` is 0: nothing can be concluded. |
| `PENDING_STATE_CHANGED` | The second read gave another state (`SERVICE_SECOND_READ_STATE`). |
| `PENDING_SINGLE_READ` | No usable second read; `SERVICE_SECOND_READ_NOT_DONE` says why. |

**The second read of a `PENDING` service.**

* **What happens.** One wait for all pending services, then the same `Win32_Service` query for those names only.
  * The wait is the largest `WaitHint` among them, at least 250 ms and at most 2000 ms.
  * The second read is skipped (`DEADLINE`) when the run's deadline is closer than the wait plus one query budget
    (30 s), so the diagnose never passes its deadline because of it.
  * Without readable `CheckPoint` and `WaitHint` there is no second read (`SIGNALS_UNREADABLE`).
* **Why.** Microsoft documents that a pending service must advance `CheckPoint` or change its state before `WaitHint`
  elapses (`SERVICE_STATUS`). So "stalled" is claimed only when the wait reached `WaitHint`. A longer `WaitHint` gives
  `PENDING_UNCHANGED`, never a guess. The 2 s cap keeps the diagnose interactive: it costs at most about 2 s and one
  query, and only when a declared service is pending.
* **Tests.** The wait is injected (`-ServiceWait`); with injected rows and no injected wait there is no second read, so
  no test sleeps.

**Dependencies** (`SERVICE_DEPENDS_ON`, `SERVICE_DEPENDENT`, detail `name|STATE`).

* A related service is named only when a provider declares it or when it is a system service: its executable or driver
  file is, as text, under the Windows folder. Any other related service is `*`, with its state only. Its command line
  is read in memory and dropped.
* `STATE` is `RUNNING`, `STOPPED`, `PAUSED` or `PENDING`, or one of:
  * `UNREADABLE`;
  * `NOT_LISTED` (not returned);
  * `NOT_QUERIED` (over the cap of 64; `SERVICE_DEPENDENCIES_CAPPED`).
* `SERVICE_DEPENDENCIES_NONE` means neither direction has a dependency.
* A failed read gives `SERVICE_DEPENDENCIES_UNREADABLE` with `QUERY_DENIED`, `QUERY_FAILED`, `QUERY_TIMEOUT` or
  `DEADLINE`. It is skipped when the deadline is closer than two query budgets.

**The provider field `ExpectedImage`** (V04-D5 (b)).

* **What a provider may declare.** A file name (`name.exe`), or a location under `%SystemRoot%`, `%ProgramFiles%`,
  `%ProgramFiles(x86)%` or `%ProgramW6432%` with plain folders. Never a drive letter, a profile folder, another
  variable, `..` or `~`. A malformed value makes the provider's service hints malformed, like any other malformed hint.
* **What is recorded.** The collector compares the reduced executable and records only `IMAGE_MATCH`, `IMAGE_MISMATCH`
  or `IMAGE_UNKNOWN` (`SERVICE_IMAGE`), never a path. Placeholders are resolved in memory. No declaration gives
  `SERVICE_IMAGE_NOT_DECLARED`.
* **`CoworkVMService` declares none.** Neither Anthropic's documentation nor the two public reports the provider cites
  name its executable.
  * Open point for R2, for the maintainer: under V04-D5 (b) there is no image to check for this service. R2 has to say
    how it treats `SERVICE_IMAGE_NOT_DECLARED`, and refusing is the reading consistent with (b).

**Where it shows.**

* **CLI** (`diagnose`): one line per listed service with the condition, exit code, accepts stop, image result and
  dependencies.
* **TUI:** unchanged. Its detail view already lists every evidence code with its text.
* **JSON export** (behind its gate): the evidence like any other.
* **Coverage:** `services` is unchanged. Only `service-properties` gains the reasons `SERVICE_SIGNAL_UNREADABLE`,
  `SERVICE_DEPENDENCIES_UNREADABLE` and `SERVICE_DEPENDENCIES_CAPPED`.

**Tests:** the area `V0.4 R0` of `tests/Run-Tests.ps1`, in both shells.

* Injected rows, dependencies and wait cover every condition, unreadable values, dependencies (system, declared, other,
  missing, failed, capped), the deadline cases and the three image results.
* A static check: the services collector calls no control cmdlet, `sc.exe`, `ServiceController` or control method,
  queries only the three classes above, and keeps exactly two `Win32_Service` queries in the file.
* A privacy check: no path or account in the new lines or details, nor in the JSON.
* A CI-runner case reads `EventLog` and `Winmgmt` (read only, states compared before and after).

**Not tested:**

* a real service in a pending state, so the real second read runs only with the injected wait;
* a real denied or failed dependency read;
* a real stopped service that failed;
* `IMAGE_MATCH` against a provider's real declaration, because no shipped provider declares one.

**Outside this round:** `docs/DIAGNOSE-SCHEMA.md` lists evidence codes in prose and does not list the new ones yet.

## R1 implementation record (2026-11-17)

The line numbers in this record are those of the files as V04-R1 adds or changes them, not those of the commit named
in the Context section.

R1 adds the recovery engine, `src/lib/Engine.Recover.ps1`, with the **eighth release gate** closed, and two commands
that only read: `recover list` and `recover plan`. No service is opened, started, stopped or changed, in this phase,
whether the gate is open or closed: the control seam belongs to R2, in this file only. R1 changes no finding state,
eligibility, B1 or RECENT rule, and changes neither the diagnose nor the providers.

**The gate.** `$script:AtmRecoveryEnabled = $false` (`Engine.Recover.ps1:15`), its only assignment in `src/`. Like the
seventh gate, nothing opens it but a code change in that administrator-owned, manifest-verified file. It is checked:

* by the build, which refuses an archive without the eight gates each assigned once to `$false`
  (`tools/Build-Release.ps1`);
* by the launcher's integrity check and the installer (`lib\Engine.Recover.ps1` is in `$loadedLibs` and in
  `AtmRequiredFiles`);
* by the install and isolation e2e, which read the eight installed gates;
* by `agent-temp version`, which prints `assisted recovery: DISABLED in this release (recover only lists and shows the
  plan)`.

With the gate closed, `list` and `plan` ask nothing, take no lock (the B8 mutex is not opened), write no log and no
file. In R1 the open gate changes only the `GateOpen` field of the result: there is no path that acts on it yet.

**The catalog** (`Engine.Recover.ps1:22-35`), closed in code: `REC-SVC-START` only, reversible, undone by
`REC-SVC-STOP` (`UndoScope` `SERVICE_STATE_ONLY`). What it does not undo: `WHAT_THE_SERVICE_DID_WHILE_RUNNING`.
`recover list` shows ending processes and operating virtual machines as not offered, on a fixed line
(`Engine.Recover.ps1:37`).

**The collection** (`Get-AtmRecoverCollection`, `Engine.Recover.ps1:80-133`) is fresh, in the process of the command,
and read only. It reuses the diagnose's own functions:

* the identity from the process's own token (`Get-AtmIdentityState`);
* the providers' runtime hints, with the provider loop of the diagnose;
* one services query (`Invoke-AtmServiceQuery`, with the R0 signals, the dependencies and the image comparison);
* its findings (`Get-AtmServiceFindings`).

It reads no inventory, no export, no pseudonym key and no plan of another process. It takes no process snapshot: only
a `STOPPED` service is ever offered, so no process key is needed. The engine itself has no `Get-CimInstance`.

**The criteria and the refusal codes** (`Get-AtmRecoverRefusals`, `Engine.Recover.ps1:165-217`; the closed list at
`:40-56`). Each criterion is evaluated on its own, and every failing one is returned in ordinal order. No code means
offered.

| Code | Refused when | Line |
|---|---|---|
| `RECOVERY_NOT_DECLARED` | No provider declares this exact name (case-sensitive). The CLI reports it as a usage error. | `:184` |
| `RECOVERY_ATTRIBUTION_AMBIGUOUS` | More than one provider declares it. | `:188` |
| `RECOVERY_COVERAGE_INCOMPLETE` | The services query was not complete or partial, some provider's hints were not read, or this name was over the cap. | `:189` |
| `RECOVERY_IMAGE_NOT_DECLARED` | No provider declares an `ExpectedImage` for it. | `:190` |
| `RECOVERY_NOT_LISTED` | It is declared but not listed for this account. | `:191` |
| `RECOVERY_DUPLICATE_ROW` | More than one row has this name. | `:194` |
| `RECOVERY_PROPERTY_UNREADABLE` | Its state, start mode, delayed start, account or executable is unreadable. | `:195` |
| `RECOVERY_SIGNALS_UNREADABLE` | A fault signal of the capture was not collected or is unreadable. | `:198` |
| `RECOVERY_NOT_STOPPED` | Its state is not `STOPPED`. | `:200` |
| `RECOVERY_START_MODE_DISABLED` | Its start mode is `DISABLED`; changing it would be `REC-SVC-STARTMODE`, which is not offered. | `:201` |
| `RECOVERY_IMAGE_MISMATCH` | `SERVICE_IMAGE` is `IMAGE_MISMATCH`. | `:203` |
| `RECOVERY_IMAGE_UNKNOWN` | `SERVICE_IMAGE` is `IMAGE_UNKNOWN`. | `:204` |
| `RECOVERY_DEPENDENCIES_UNREADABLE` | The dependencies were not collected or not read, or a related state is `UNREADABLE` or `NOT_LISTED`. | `:205`, `:210` |
| `RECOVERY_DEPENDENCIES_CAPPED` | A related service is over the cap (`NOT_QUERIED`). | `:206`, `:211` |
| `RECOVERY_DEPENDENCY_STOPPED` | A service it depends on is `STOPPED` and is not itself declared. A hidden name (`*`) is never declared. | `:212` |

A stopped dependency that a provider declares is allowed. The plan shows it, because the service control manager
starts it with the service.

**The plan** (`Get-AtmRecoverPlan`, `Engine.Recover.ps1:299-329`): one operation and one target per call; there is no
list or batch form. An offered plan gives:

* the "before" capture (`Get-AtmRecoverCapture`, `:219-253`): state, start mode, delayed start, exit code,
  service-specific exit code, checkpoint, wait hint, accepts stop, condition, account kind, standard account, reduced
  executable, image result, and both dependency directions as `name|STATE`. A value that was not read is `$null`, never
  a default;
* the undo path and what it does not undo;
* the likely elevation, from the token only (`:71-78`): `LIKELY_HAS_RIGHT` for an elevated administrator,
  `NEEDS_ELEVATION` otherwise (under V04-D3 (b), executing would ask through UAC in R4), `UNKNOWN` when the token could
  not be read;
* the plan id (`Get-AtmRecoverPlanId`, `:255-274`): SHA-256 of the schema `atm-recover-plan/1`, the operation, the
  target, each declaring provider's id, role and `ExpectedImage`, and every field of the capture. Each value is
  length-prefixed (`$null` is distinct from empty) and each list carries its count. It has no run id and no time. It
  does not include the token: the same plan has the same id under another identity, and revalidating the token is R2's
  work;
* the line "Nothing was changed."

A refused plan gives its codes and no plan id. Both commands end with "Nothing was changed." (pt-BR "Nada foi
alterado."), in every case, the usage errors included.

**Privacy.** The capture keeps the diagnose's reductions. The account is its kind, plus one of the three standard
service accounts. The executable is a full path only under a well-known program location; otherwise it is the file
name. There is never a command line. A related service that is neither declared nor a system service is `*`. The
identity of the token is never shown.

**The commands** (`src/agent-temp.ps1:472-502`; the version line at `:512-514`).

| Command | Exit |
|---|---|
| `agent-temp recover list` | 0 |
| `agent-temp recover plan -Operation REC-SVC-START -Service <exact declared name>` | 0 offered, 3 refused |
| A missing or other subcommand, `-Operation` or `-Service` on `list`, an operation outside the catalog (exact spelling), a service that is not a plain name (a path, wildcard or file), or a name no provider declares | 2 |
| Any of `-User`, `-Project`, `-Root`, `-Path`, `-AllowListFile`, `-IncludeOtherUsers`, `-AcceptB1ResidualRisk`, `-ExportJson`, `-LogFile`, `-RecordFile`, `-Entry`, `-All`, `-PseudonymKeyFile` | 2 |
| The collection failed (reported by exception type only) | 10 |

`-DeadlineSeconds` bounds the collection (default 120 s). `-Lang` selects the language. The engine is loaded only by
`recover` and `version`. The help gains two lines in both languages.

**`SERVICE_IMAGE_NOT_DECLARED`: R1's behavior, and the decision for R2.** R1 refuses a service whose providers
declare no `ExpectedImage`, with `RECOVERY_IMAGE_NOT_DECLARED`. That is the reading consistent with V04-D5 (b). So the
real `CoworkVMService` of the Claude Desktop provider is never offered in R1, whatever its state. The maintainer decided
on 2026-11-17 that this stays a refusal from R2 on; `CoworkVMService` stays refused until a provider declares its
executable (see the R2 implementation record).

**Tests:** the area `V0.4 R1` of `tests/Run-Tests.ps1`, in both shells. Providers, identities, service rows and
dependencies are injected, as in R0.

* The closed catalog, the closed codes, the not-offered line and the texts in both languages.
* The offered case: a test provider that declares an `ExpectedImage` and a matching `STOPPED` row. It covers the
  complete capture, dependency states, the undo, and the elevation from three tokens.
* One case per refusal code, including the real `CoworkVMService` declaration, which gives only
  `RECOVERY_IMAGE_NOT_DECLARED`. A further case checks that every code has its case.
* The plan id: stable for the same input and for another token; different when any captured field, the provider or
  the declared image changes; `$null` distinct from empty.
* Privacy of the plan and the list: no path outside a known location, no account other than the three standard ones,
  no command line, no hidden name.
* The closed gate, by instrumentation: shadow functions count every prompt, lock, log, file write and CIM query, and
  the count must be 0. The B8 mutex does not exist after `list` and `plan`, with a positive control. The sandbox is
  unchanged. The same checks run with the gate opened in the suite's process, then closed again.
* Static checks:
  * one assignment of the gate;
  * no service control API anywhere in `src/` (`Start-Service`, `Stop-Service`, `Set-Service`, `Restart-Service`,
    `sc.exe`, `ServiceController`, `Invoke-CimMethod`, `OpenService`, `ControlService`);
  * no call to the engine from `Engine.Diagnose.ps1`, `Tui.ps1` or `Gui*.ps1`;
  * still two `Win32_Service` queries in the diagnose;
  * the engine in the launcher's check, `AtmRequiredFiles`, the manifest, the build and both e2e.
* The CLI in a new process: the exits of `list`, `plan` and the usage errors, the `version` line and the help, in both
  languages. The runner's `CoworkVMService` state, if it exists, is compared before and after.

**Not tested:**

* an offered plan against a real service: no shipped provider declares an `ExpectedImage`, so the real `recover plan`
  always refuses;
* `LIKELY_HAS_RIGHT` and `NEEDS_ELEVATION` from a real token in the CLI, only from injected tokens;
* exit 10 (a failed collection) through the CLI.

## R2 implementation record (2026-11-17)

The line numbers in this record are those of the files as V04-R2 adds or changes them. Lines 1 to 329 of
`Engine.Recover.ps1` keep the numbers the R1 record cites; R2 appends from line 331 on.

R2 adds `REC-SVC-START` past the recovery gate, in the engine, through a service control seam: `Invoke-AtmRecover`
(`Engine.Recover.ps1:479-565`) and its locked part `Invoke-AtmRecoverLocked` (`:567-700`). **The gate stays `$false` in
every copy** (`:15`, still its only assignment). No command calls `Invoke-AtmRecover` yet: the CLI verb comes with the
UAC relaunch (R4). Only the suite opens the gate, in its own process, and always with the seam injected. R2 changes no
finding state, eligibility, B1 or RECENT rule, and changes neither the diagnose nor the providers.

**`SERVICE_IMAGE_NOT_DECLARED` (decided 2026-11-17).** The maintainer decided that it stays a refusal from R2 on. A
service whose providers declare no `ExpectedImage` is refused with `RECOVERY_IMAGE_NOT_DECLARED`, with the gate open
too, before anything is presented or asked (`RECOVERY_REFUSED`, `:552`). The real `CoworkVMService` stays refused until a
provider declares its executable. This supersedes the "Open point for R2" of the R0 record.

**With the gate closed** (`:531-538`): the fresh collection, the plan, the presenter, then `RECUPERACAO_REAL_DESABILITADA`.
No console check, inventory, lock, log, phrase, wait or seam (injected or default).

**The steps past the gate, in this order** (one operation and one service per call; there is no list or batch form):

| # | Step | Where | Stops with |
|---|---|---|---|
| 1 | The console, observed by the engine (`Get-AtmEngineConsoleObservation`); then a confirmation reader is required | `:541-543` | `CONSOLE_NOT_OBSERVED`, `SEM_APRESENTACAO_OU_CONFIRMACAO` |
| 2 | A new `-LogFile`, outside every base (`Test-AtmOutputPathOutsideBases` on an inventory without progress) and not existing | `:544-548` | `LOG_REQUIRED`, `LOG_DESTINATION_NOT_ALLOWED`, `LOG_ALREADY_EXISTS` |
| 3 | A fresh collection and the R1 criteria (`Get-AtmRecoverCollection`, `Get-AtmRecoverPlan`) | `:549-552` | `RECOVERY_REFUSED` (the codes in `RefusalCodes`) |
| 4 | The presenter shows the plan | `:553` | |
| 5 | Lock B8 (`Invoke-AtmUnderSharedLock`, the clean's own mutex, without waiting); the log (`Open-AtmCleanLog`: a new file through the pinned folder, protected DACL); `run-start`, `plan`, `before` | `:557-558`, `:598-609` | `CLEAN_LOCK_BUSY`, `CLEAN_LOCK_ABANDONED`, `LOG_OPEN_FAILED`, `LOG_WRITE_FAILED` |
| 6 | The typed phrase (`Test-AtmTypedPhrase`, exact); `confirmation` | `:594`, `:612-624` | `CONFIRMACAO_AUSENTE_OU_DIVERGENTE` (reason `CANCELLED` or `DECLINED`) |
| 7 | The revalidation on a fresh collection (`Get-AtmRecoverPlanCheck`, `:399-424`); `plan-check` with `reasons` and `changedFields` | `:627-635` | `REVALIDATION_REFUSED` |
| 8 | `intent`, written and flushed; then the seam, with the service name and nothing else | `:638-650` | `LOG_INTENT_FAILED` (no call) |
| 9 | The settle wait, bounded and injectable, after `OK` only | `:652-669` | |
| 10 | The outcome, the diff, `result` and `after` | `:670-685` | `LOG_RESULT_FAILED`, `LOG_AFTER_FAILED` |
| 11 | `run-end` (only while the log has not failed), the log closed; the lock released by the caller | `:690-696`, `:559-563` | `LOG_END_FAILED`, `LOG_CLOSE_FAILED`, `LOCK_RELEASE_FAILED` |

Before the seam is called, a stop code goes to `Aborted`; after it, to `StoppedBy`. A failed release never replaces the
main code. An operation outside the catalog gives `RECOVERY_OPERATION_INVALID` before any collection; no presenter gives
`SEM_APRESENTACAO`.

**The phrase:** `INICIAR SERVICO <the first 8 characters of the plan id, upper case>` (`:594`). It binds the
confirmation to the presented plan: another plan's phrase, another spelling, a trailing space, empty or cancelled are all
refused.

**The revalidation** (`changedFields`, names only): `target` (no longer declared or listed), `provider` (the declaring
providers' ids, roles and images), every capture field by its log name (`state`, `startMode`, `delayedAutoStart`,
`exitCode`, `serviceSpecificExitCode`, `checkPoint`, `waitHint`, `acceptStop`, `condition`, `accountKind`, `account`,
`executable`, `executableForm`, `image`, `dependsOn`, `dependents`; `:355-359`), `identity` (the token's SID, compared in
memory and never written) and `elevation` (the code and the elevation type) (`:362`). Any reason or changed field
refuses.

**The seam.** `-ServiceControlImpl` (a scriptblock that receives the service name) replaces the default, which is
`Invoke-AtmRecoverServiceStartDefault` (`:443-477`). The default uses `System.ServiceProcess.ServiceController.Start()`,
because it opens the service control manager with connect access and the service with the start right only
(`SERVICE_START`): no other right is asked, nothing but the start is requested, and no arguments are passed. The type is
loaded lazily, on the first default call only (Windows PowerShell 5.1 does not load the assembly by default; PowerShell 7
ships it as a package). A Win32 error of the start is mapped by number (`:340-344`); anything else is thrown again. The
service control API appears only in this function, in this file. The seam is called once (`:647`), past the gate, after
`intent` only. The suite never reaches the default; it injects the seam in every case past the gate.

**The seam's closed results** (`:345-346`). `OK`, or one of these Win32 errors:

| Win32 | Code | Outcome |
|---|---|---|
| 5 | `ACCESS_DENIED` | `REFUSED` |
| 1053 | `SERVICE_REQUEST_TIMEOUT` | `FAILED` |
| 1054 | `SERVICE_NO_THREAD` | `FAILED` |
| 1055 | `SERVICE_DATABASE_LOCKED` | `FAILED` |
| 1056 | `SERVICE_ALREADY_RUNNING` | `FAILED` (never `COMPLETE`) |
| 1058 | `SERVICE_DISABLED` | `FAILED` |
| 1060 | `SERVICE_DOES_NOT_EXIST` | `FAILED` |
| 1068 | `SERVICE_DEPENDENCY_FAIL` | `FAILED` |
| 1069 | `SERVICE_LOGON_FAILED` | `FAILED` |
| 1072 | `SERVICE_MARKED_FOR_DELETE` | `FAILED` |
| 1075 | `SERVICE_DEPENDENCY_DELETED` | `FAILED` |
| any other | `SERVICE_WIN32_OTHER` | `FAILED` |

A result that is not one of these strings (exact case) is `SEAM_RESULT_INVALID`, recorded as the exception type. An
exception is recorded by its type only (`GetBaseException()`), never its message.

**The wait** (`:348-353`, `:652-669`). After `OK` only: one read right after the seam, then one every 500 ms, until the
service is `RUNNING`, back to `STOPPED`, or past the limit. The limit is the largest `WaitHint` read meanwhile, at least
5 s and at most 30 s. It is counted in waited milliseconds and on the clock, whichever ends first. `-SettleWait`
replaces the real wait (`Wait-AtmRecoverSettle`, `:437-441`, the only `Start-Sleep` of the file). Any other seam code
reads "after" once, with no wait.

**The outcomes** (`:675-676`), in this order: `EXCEPTION` (the seam threw or gave no closed code); `REFUSED`
(`ACCESS_DENIED`); `FAILED` (another seam code, or back to `STOPPED`); `COMPLETE` (`RUNNING`); `PARTIAL` (anything else at
the end of the wait). In every outcome "after" is read and compared field by field with "before" (`Diff`, `:386-397`).
Nothing is compensated or retried; the undo (`REC-SVC-STOP`) is never run by R2.

**The log** `atm.recoverlog/1` (`:337`, `Write-AtmRecoverRecord` `:426-435`): one JSON line per record, written and
flushed through the clean's log writer, with `schema`, `type`, `runId`, `recSeq` and `utc`. The records of a complete run,
in order: `run-start`, `plan`, `before`, `confirmation`, `plan-check`, `intent`, `result` (outcome, seam code, exception
type, waited milliseconds, limit, reads, exit codes, diff), `after`, `run-end`. It never holds the token's name or SID,
a command line, a path outside a known program location, a hidden related name or an exception message.

**Tests:** the area `V0.4 R2` of `tests/Run-Tests.ps1` (`:18573-19041`), in both shells. Providers, identities, service
rows, dependencies, the console, the confirmation, the wait and the seam are injected.

* The closed constants, and an operation outside the catalog.
* The closed gate by instrumentation: no inventory, console, lock, log, wait or seam, with positive controls for the
  injected and the default seam.
* One case per outcome: `COMPLETE` (pending, then `RUNNING`), `PARTIAL` (the `WaitHint` limit and the 30 s cap),
  `FAILED` (back to `STOPPED`, and seam codes with no wait), `REFUSED`, `EXCEPTION` (and invalid results); each checks
  the diff, the records and their order.
* AUT-2: every wrong phrase, no console, no reader, no `-LogFile`, an existing log, a log inside a base, no presenter;
  the seam is never called.
* The revalidation: one case per changed field (all the names above), each `REVALIDATION_REFUSED` with the field in
  `changedFields`.
* B8 busy and abandoned (and a retry that completes after an abandoned lock).
* The log's privacy (`COMPLETE` and `EXCEPTION`).
* `SERVICE_IMAGE_NOT_DECLARED`, synthetic and with the real `CoworkVMService` declaration: refused before anything is
  asked; the mutex is not taken.
* A static check: the service control API only in `Engine.Recover.ps1`, only in the default seam, and one `.Start(`; no
  control cmdlet anywhere in `src/` and no other control verb in the engine; lock, log, inventory, console and JSON only
  past the gate; the real wait only in its function; the steps in order; the R1 read-only functions unchanged in
  effect; one seam, one operation, no caller outside the engine; no real wait in the area. The R1 static check now
  exempts `Engine.Recover.ps1` from its `ServiceController` ban and leaves to the R2 check the functions that only R2
  may call past the gate.

**Not tested:**

* the default seam (`ServiceController.Start()`) and its Win32 mapping: never called, by the suite or the CI; no real
  service is started, stopped or opened with a control right;
* lock B8 between an elevated and a non-elevated holder (two tokens on one machine): for the VM or the operator's e2e,
  as in the clean's B8 matrix;
* the real timing of a pending start, so the wait runs only with injected reads and an injected wait;
* the start of a real service, because no shipped provider declares an `ExpectedImage`;
* any command: no CLI verb calls `Invoke-AtmRecover` until R4.
