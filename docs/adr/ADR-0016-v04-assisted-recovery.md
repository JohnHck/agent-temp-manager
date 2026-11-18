# ADR-0016: Assisted recovery (V0.4)

Status: ACCEPTED (V04-D1 to V04-D8 decided 2026-11-17: D3 (b) elevation on demand through UAC; the others as recommended); R0, R1, R2, R3, R4 and R5 implemented
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

The file and line references in sections 1 to 9 are to commit `9c174e64439686ca1c5b07fd436abae4d03cd755`, the state
of `main` this record was proposed on, before phase R0. The implementation records after them use other states: each
one from R1 on says which, and the R0 record cites no line numbers.

## Decision (proposed)

### 1. Inventory: what V0.2 detects that could call for recovery

**The main finding.** The diagnose engine reports **states**, not **faults**. It has no finding that says a service,
VM, process, lock or worktree is "stuck" or "broken". Its findings are one snapshot per run, each with a closed list of
states (`src/lib/Engine.Diagnose.ps1:34-43`). The table below lists every finding kind that comes near the round's
examples. A row for an example the code does not produce says so (row 10); no row presents a finding the code does not
emit.

| # | Finding (code) | Provider that produces it | Behind a closed V0.2 gate? | Evidence it carries | What is missing before it can ground an operation |
|---|---|---|---|---|---|
| 1 | `Service` in state `RUNNING`, `STOPPED`, `PAUSED` or `PENDING` (`Engine.Diagnose.ps1:36`, state map `:3176`, findings `:3794-3870`) | `claude-desktop`, the single name `CoworkVMService` (`src/providers/ClaudeDesktop.ps1:50`). `claude-code` declares no service (`src/providers/ClaudeCode.ps1:143-175`). | No: the services collector runs in every copy. | `SERVICE_STATE`, `SERVICE_START_MODE`, `SERVICE_DELAYED_AUTO_START`, `SERVICE_ACCOUNT_KIND`, `SERVICE_EXECUTABLE` or `_NAME`, `SERVICE_PROCESS_VERIFIED` (`:3829-3847`) | **No fault signal (at proposal time, before R0):** the query read no exit code (`:3151` lists the properties read), so a `STOPPED` service that failed looked like one that was never started. **"Stuck" was not measurable:** `PENDING` was a single reading with no duration, checkpoint or wait hint. (Since R0 the same query also reads `ExitCode`, `ServiceSpecificExitCode`, `CheckPoint`, `WaitHint` and `AcceptStop`, and a `PENDING` service gets one second read; the result is the read-only classification `SERVICE_CONDITION`, which authorizes nothing. See the R0 implementation record.) **Weak attribution:** the name is a publicly reported one, not documented by the vendor (`ClaudeDesktop.ps1:24-26`). **No proof of absence:** a name the account cannot see is `UNKNOWN`, never absent (`:3819-3822`; the collector never produces `NOT_PRESENT`, `:3142-3143`). |
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

  How the lock behaves between an elevated holder and a non-elevated one is tested in phase R2 (R2 left it NAO_TESTADO,
  because it needs two tokens on one machine; see the R2 implementation record). V04-D6 keeps the
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
      outcomes), PRIV-5 (requester and acting identity) and PRIV-7 (trusted code only) as work items. (R4 deviates on
      one point: the non-elevated side reads no log at all and reports only by the elevated copy's exit code, because
      its token cannot read the logs' fixed folder. See the R4 implementation record.)
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

  (R2 left both NAO_TESTADO: its seam is always injected, and the second needs two tokens on one machine. See the R2
  implementation record.)

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
    how it treats `SERVICE_IMAGE_NOT_DECLARED`, and refusing is the reading consistent with (b). (Decided by the
    maintainer on 2026-11-17: `SERVICE_IMAGE_NOT_DECLARED` is a refusal, and `CoworkVMService` stays refused until a
    provider declares its executable. See the R2 implementation record.)

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

**Outside this round:** at R0 time, `docs/DIAGNOSE-SCHEMA.md` listed evidence codes in prose and did not list the new
ones. DOCS-SYNC-R0 (commit `3f3829f`) added them to `findings[].evidence[]`, with their values.

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
`recover` and `version` (at R1 time; since R5 also by `tui` and `gui`, for their read-only area: see the R5
implementation record). The help gains two lines in both languages.

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
    `sc.exe`, `ServiceController`, `Invoke-CimMethod`, `OpenService`, `ControlService`) (superseded by R2:
    `ServiceController` is now allowed only in `Engine.Recover.ps1`, only in the default seam; every other control verb
    is still banned everywhere. See the R2 implementation record. Superseded again by R3: `OpenService` and
    `ControlService` are allowed only in the stop class of `Native.cs`, reached only by the default stop seam. See the R3
    implementation record);
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
start's service control API (`ServiceController`) appears only in this function, in this file (since R3, the stop of the
undo has its own API, in `Native.cs`; see the R3 implementation record). The seam is called once (`:647`), past the
gate, after `intent` only. The suite never reaches the default; it injects the seam in every case past the gate.

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
* whether a real start also starts the service's stopped declared dependencies (the plan only shows them);
* the start of a real service, because no shipped provider declares an `ExpectedImage`;
* any command: no CLI verb calls `Invoke-AtmRecover` until R4.

## R3 implementation record (2026-11-17)

The line numbers in this record are those of the files as V04-R3 adds or changes them. Lines 9 to 700 of
`Engine.Recover.ps1` keep the numbers the R1 and R2 records cite (R3 rewrites only the header comment, lines 5 to 8, with
the same line count); R3 appends from line 702 on.

R3 adds the undo of one `REC-SVC-START` run, in the engine, through a stop seam of its own: `Invoke-AtmRecoverUndo`
(`Engine.Recover.ps1:1141-1232`) and its locked part `Invoke-AtmRecoverUndoLocked` (`:1234-1369`). Its operation is
`REC-SVC-STOP` (`:711-716`), which exists only as that undo (V04-D1 (a)). It is never added to the catalog. `recover list`
never offers it, and `recover plan` and `Invoke-AtmRecover` never accept it (they still answer
`RECOVERY_OPERATION_INVALID`). **The gate stays `$false` in every copy** (`:15`, still its only assignment). No command
calls `Invoke-AtmRecoverUndo`: the `recover undo` verb comes with the UAC relaunch (R4). Only the suite opens the gate,
in its own process, and always with the stop seam injected. R3 changes no finding state, eligibility, B1 or RECENT rule,
and changes neither the diagnose nor the providers.

**The engine's contract, and what R4's verb will receive.** Section 4 names the verb `recover undo <runId>`, but an R2
log goes to any `-LogFile` the caller chose, and the engine keeps no index of runs. So the engine takes two values:

* `-SourceLog`: the absolute path of the run's log;
* `-RunId`: the run id, as a cross-check. The log must carry exactly this id (`UNDO_SOURCE_RUN_MISMATCH`).

The log is a source of data, never of instructions. The target it names is used only if a provider still declares it
today. The current state comes only from a fresh collection. Nothing else in the log reaches an action. R4 kept this
contract and fixed the verb's spelling differently from what this record first expected: `recover undo -RunId <id>`
takes no path from the operator. The engine's `-SourceLog` is always `<fixed folder>\<run id>.log`, built by the
elevated copy (see the R4 implementation record).

**Reading the source** (`Read-AtmRecoverRunLog`, `:933-1032`, read only). The checks, in order, each with its closed code
(`AtmRecoveryUndoSourceCodes`, `:724-735`):

| Check | Code |
|---|---|
| `-RunId` is a lowercase GUID in the `D` form | `UNDO_SOURCE_RUN_MISMATCH` |
| A plain absolute local path (`Test-AtmAllowListPathSyntax`: no relative path, wildcard or `~`), found and readable | `UNDO_SOURCE_UNREADABLE` |
| No reparse point in the path (`Get-AtmChainStatus`) nor on the file; not a directory (`AtmSharedRead.Open`, which follows no reparse point) | `UNDO_SOURCE_NOT_REGULAR` |
| At most 1 MiB (`AtmRecoveryUndoSourceMaxBytes`), checked on the open handle before reading | `UNDO_SOURCE_TOO_LARGE` |
| The provenance, on the same handle (see below) | `UNDO_SOURCE_PROVENANCE` |
| Read once. Strict UTF-8, no BOM, LF only with a final LF, no blank line, at most nine lines. Each line a strict JSON object (duplicate keys refused, a closed grammar, depth 8). `schema` = `atm.recoverlog/1`. One `runId` in every line, `recSeq` contiguous from 1, only the nine R2 record types, none twice, in R2's order | `UNDO_SOURCE_INVALID` |
| The log's run id equals `-RunId` | `UNDO_SOURCE_RUN_MISMATCH` |
| A strict prefix of a complete run, with no `run-end` (empty included) | `UNDO_SOURCE_INCOMPLETE` |
| `run-start` names `REC-SVC-START` (it also needs a target, a 64-hex plan id and `gateOpen` true, else `UNDO_SOURCE_INVALID`) | `UNDO_SOURCE_OPERATION_INVALID` |
| A run that ended before `intent` (refused phrase, failed revalidation): nothing was started | `UNDO_SOURCE_NOT_STARTED` |
| The same operation, target and plan id in every record that carries them. `accepted`, `matched` and `seamCalled` true. The outcome is one of R2's, the same in `result` and `run-end` | `UNDO_SOURCE_INVALID` |
| The outcome is `COMPLETE` or `PARTIAL` | `UNDO_SOURCE_OUTCOME_NOT_UNDOABLE` |
| The seam code `OK`. `before` and `after` are captures in R0's form (`ConvertFrom-AtmRecoverCaptureRecord`). `before` is `STOPPED`. A `COMPLETE` run's `after` is `RUNNING`; a `PARTIAL` run's is neither `RUNNING` nor `STOPPED` | `UNDO_SOURCE_INVALID` |

A refused source stops before anything is asked: the code goes into the plan's `Codes`, and `Aborted` is
`UNDO_SOURCE_REFUSED`. With the gate closed the same code appears in the plan. A source that is not `OK` makes no
collection.

**What the operator sees for a run that cannot be undone.** A `FAILED` run (another seam code, or back to `STOPPED`), a
`REFUSED` run (access denied) and an `EXCEPTION` run never started the service, as far as the engine knows. Their source
gives `UNDO_SOURCE_OUTCOME_NOT_UNDOABLE`, with no plan and nothing asked. The run's own log already holds the field by
field difference (R2's `result` and `after`). If the service runs anyway, the engine did not start it, and the engine
offers no stop for it: stopping a service outside the undo is V04-D1 (b), which was not chosen.

**The provenance, and the residual risk** (`Test-AtmRecoverSourceProvenance`, `:914-931`). The engine reads the
owner and the DACL through the open handle. The owner must be this process's user or Administrators. The DACL must be
protected. Allow entries may name no one but this user, SYSTEM, Administrators and OWNER RIGHTS. This is the security
descriptor `Open-AtmCleanLog` gives every log (`D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)`, owner the user). It refuses a
log copied or written by another account, and a plain copy, which inherits its folder's DACL. **It proves who could have
written the file, not that the engine wrote it.** The validation proves the log's form, not its origin. The residual
risk: this user, or an administrator, can write a log by hand that gives a stop plan for a declared service which is
running in the same state as the forged `after`. Four things limit that:

* the target must be a name a provider declares today, with a declared image that matches (R1);
* the current state must equal the forged `after`, field by field, and the service must be `RUNNING` with no dependent
  running;
* the plan is shown;
* the operator must type the phrase.

This touches V04-D1 (a): stop only as an undo. It is recorded as a residual risk, not as a new decision.

**The criteria of the inverse plan** (`Get-AtmRecoverUndoRefusals`, `:1040-1074`; the plan, `Get-AtmRecoverUndoPlan`,
`:1091-1122`; codes, `:738-744`):

* The R1 criteria the undo shares with a start: declared, one provider, coverage, a declared image that matches
  (`RECOVERY_IMAGE_NOT_DECLARED` and `RECOVERY_IMAGE_MISMATCH` refuse), listed once, properties and fault signals read,
  dependencies read in both directions (`RECOVERY_DEPENDENCIES_UNREADABLE`, `RECOVERY_DEPENDENCIES_CAPPED`). The three
  start-only codes are left out (`RECOVERY_NOT_STOPPED`, `RECOVERY_START_MODE_DISABLED`, `RECOVERY_DEPENDENCY_STOPPED`;
  `:746`). A target that is no longer declared gives only `RECOVERY_NOT_DECLARED`.
* **The current capture equals the recorded `after`,** field by field, by R2's log names (`Compare-AtmRecoverCapture`).
  Any difference gives `UNDO_STATE_CHANGED`, with the fields in `ChangedFields`. The undo never overwrites a newer
  state, as the isolation restore refuses newer content (ADR-0013 section 7).
* **The `PARTIAL` rule** (`:747-750`, `Test-AtmRecoverUndoPendingSource` `:1034-1038`). It applies only to a `PARTIAL`
  run whose recorded `after` is `PENDING`. The only accepted change is the natural continuation of that start, from
  pending to `RUNNING`. It may change exactly these fields, confirmed against R0's capture (`Get-AtmRecoverCapture` and
  the R0 record):
  * `state` (`PENDING` to `RUNNING`);
  * `checkPoint` and `waitHint`, the raw `dwCheckPoint` and `dwWaitHint`, which only a pending service advances;
  * `condition`, which R0 sets only for `STOPPED` (`STOPPED_*`) and `PENDING` (`PENDING_*`), and is null for `RUNNING`;
  * `acceptStop`, since a starting service usually accepts no stop yet.

  `exitCode` is **not** in the set. `dwWin32ExitCode` stays `NO_ERROR` through a normal start; a changed value reports a
  start-up error, not the natural transition. Any other changed field refuses (`UNDO_STATE_CHANGED`). A service still
  pending gives `UNDO_STILL_PENDING`: stopping a pending service is out (`REC-SVC-RESTART-PENDING` is Out). A `PARTIAL`
  run that ended `PAUSED`, or with the service unlisted, gets no exemption. The accepted set is shown in the plan and in
  the `plan` record (`acceptedTransition`).
* **It is `RUNNING`** (`UNDO_NOT_RUNNING`) **and accepts a stop** (`AcceptStop` `TRUE`, else `UNDO_ACCEPT_STOP_FALSE`).
* **No dependent active** (`UNDO_DEPENDENT_ACTIVE`). The dependents come from the capture, as R0's `name|STATE` labels
  (`Get-AtmServiceDependencies`), with no new query. Any state but `STOPPED` refuses: `RUNNING`, `PAUSED`, `PENDING`,
  `UNREADABLE`, `NOT_LISTED`, `NOT_QUERIED`, and a hidden name (`*`) in any of them. There is never a stop in cascade
  (section 3, the `REC-SVC-STOP` row).
* **The plan id** (`Get-AtmRecoverUndoPlanId`, `:1076-1089`). R1's encoding (SHA-256, each value length-prefixed,
  `$null` distinct from empty), over its own prefix `atm-recover-undo-plan/1`, the operation, the target, the source run
  id and every field of the current capture.
* **What the undo does not undo** (`NotUndone`): `WHAT_THE_SERVICE_DID_WHILE_RUNNING`, and `STATE_HELD_IN_MEMORY`
  (including a VM or a session it kept), shown in the plan and in the `plan` record.

**The steps past the gate, in this order.** These are R2's steps in R2's order. The undo differs where the table says
so.

| # | Step | Where | Stops with |
|---|---|---|---|
| 1 | The console, observed by the engine; then a confirmation reader | `:1204-1206` | `CONSOLE_NOT_OBSERVED`, `SEM_APRESENTACAO_OU_CONFIRMACAO` |
| 2 | A new `-LogFile`: not the `-SourceLog` (full paths compared, ignoring case), outside every base, and not existing | `:1207-1215` | `LOG_REQUIRED`, `LOG_SAME_AS_SOURCE`, `LOG_DESTINATION_NOT_ALLOWED`, `LOG_ALREADY_EXISTS` |
| 3 | The source read, a fresh collection and the undo's criteria | `:1216-1219` | `UNDO_SOURCE_REFUSED` (the source code in `RefusalCodes`), `UNDO_REFUSED` (the codes and `ChangedFields`) |
| 4 | The presenter shows the inverse plan | `:1220` | |
| 5 | Lock B8 (`Invoke-AtmUnderSharedLock`); the log (`Open-AtmCleanLog`); `run-start` (with `undoOf`, `sourceRunId` and `sourceOutcome` in fields of their own), `plan`, `before` | `:1224-1231`, `:1262-1275` | `CLEAN_LOCK_BUSY`, `CLEAN_LOCK_ABANDONED`, `LOG_OPEN_FAILED`, `LOG_WRITE_FAILED` |
| 6 | The typed phrase (`Test-AtmTypedPhrase`, exact); `confirmation` | `:1260`, `:1277-1290` | `CONFIRMACAO_AUSENTE_OU_DIVERGENTE` |
| 7 | The revalidation on a fresh collection: the undo's criteria again (`reasons`, so a dependent that started refuses) and R2's changed fields (`Get-AtmRecoverPlanCheck`); `plan-check` | `:1292-1302` | `REVALIDATION_REFUSED` |
| 8 | `intent` (with `sourceRunId`), written and flushed; then the stop seam, once, with the service name and nothing else | `:1304-1317` | `LOG_INTENT_FAILED` (no call) |
| 9 | The settle wait, bounded and injectable, after `OK` only | `:1319-1337` | |
| 10 | The outcome, the diff, `result` and `after` | `:1339-1355` | `LOG_RESULT_FAILED`, `LOG_AFTER_FAILED` |
| 11 | `run-end`, the log closed; the lock released by the caller | `:1357-1365`, `:1225-1230` | `LOG_END_FAILED`, `LOG_CLOSE_FAILED`, `LOCK_RELEASE_FAILED` |

With the gate closed (`:1197-1202`), the engine reads the source, collects only when the source is `OK`, builds the
inverse plan, calls the presenter, and returns `RECUPERACAO_REAL_DESABILITADA`. It asks nothing, takes no lock, writes no
log, reads no inventory and calls no seam. No presenter gives `SEM_APRESENTACAO` before anything else (`:1187`).

**The phrase:** `PARAR SERVICO <the first 8 characters of the undo's plan id, upper case>` (`:1260`). It binds the
confirmation to the presented inverse plan. R2's `INICIAR SERVICO` phrase, another plan's phrase, another spelling,
empty or cancelled are all refused.

**The stop seam.** `-ServiceStopImpl` (a scriptblock that receives the service name) replaces the default,
`Invoke-AtmRecoverServiceStopDefault` (`:1124-1139`). The default loads the native type with `Initialize-AtmNative`, on
its first call only, and calls `AgentTempManager.AtmServiceStop.Stop(name)` (`Native.cs:2361-2411`), a new narrow class
whose only public member is `Stop`:

* `OpenSCManagerW(null, null, SC_MANAGER_CONNECT)`: connect access only;
* `OpenServiceW(scm, name, SERVICE_STOP)`: the stop right only;
* one `ControlService(svc, SERVICE_CONTROL_STOP, ...)`;
* `CloseServiceHandle` on both handles, in `finally`.

It returns 0, or the Win32 error of the first call that failed, read right after that call. It never enumerates, opens or
stops a dependent service, never retries, and never waits. While a dependent runs, the manager refuses the stop with
`ERROR_DEPENDENT_SERVICES_RUNNING` (1051), which comes back as is. The installer already compiles all of `Native.cs` into
the DLL that the manifest pins by SHA-256 (`install/InstallCommon.ps1` `New-AtmNativeAssembly`), so R3 changes nothing
in `install/`, `tools/` or the build.

**Why not `ServiceController.Stop()`.** That method stops every running dependent service first, which is the cascade
section 3 forbids:

* .NET Framework reference source (microsoft/referencesource@ec9fa9ae770d522a5b5f0607898044b7478574a3,
  `System.ServiceProcess/ServiceController.cs`): `public unsafe void Stop()` (`:1184`) opens the service with
  `SERVICE_STOP` (`:1194`). Under the comment "Before stopping this service, stop all the dependent services that are
  running." (`:1198`), it loops over `DependentServices`, calls `currentDependent.Stop()` and waits up to 30 s for each to
  stop (`:1202-1207`). Only then does it send `ControlService(..., CONTROL_STOP, ...)` (`:1212`).
* .NET (dotnet/runtime@30d28af1a4405cfc256f1fe6c1475c5bb59480f9,
  `src/libraries/System.ServiceProcess.ServiceController/src/System/ServiceProcess/ServiceController.cs`):
  `public void Stop()` (`:918`) calls `Stop(stopDependentServices: true)` (`:920`). `Stop(bool)` (`:938`) stops each
  running dependent (`currentDependent.Stop()`, `:951`) before its own `ControlService` (`:958`).

**The stop seam's closed results** (`:753-758`). `OK`, or one of these Win32 errors:

| Win32 | Code | Outcome |
|---|---|---|
| 5 | `ACCESS_DENIED` | `REFUSED` |
| 1051 | `DEPENDENT_SERVICES_RUNNING` | `FAILED` |
| 1053 | `SERVICE_REQUEST_TIMEOUT` | `FAILED` |
| 1060 | `SERVICE_DOES_NOT_EXIST` | `FAILED` |
| 1061 | `SERVICE_CANNOT_ACCEPT_CTRL` | `FAILED` |
| 1062 | `SERVICE_NOT_ACTIVE` | `FAILED` (never `COMPLETE`) |
| 1072 | `SERVICE_MARKED_FOR_DELETE` | `FAILED` |
| any other | `SERVICE_WIN32_OTHER` | `FAILED` |

A result that is not one of these strings (exact case; a start code such as `SERVICE_ALREADY_RUNNING` included) is
`SEAM_RESULT_INVALID`, recorded as the exception type. An exception is recorded by its type only, never its message.

**The wait** (`:1319-1337`). After `OK` only: one read right after the seam, then one every 500 ms, with R2's limit (the
largest `WaitHint` read, at least 5 s, at most 30 s, on waited milliseconds and the clock) and R2's `-SettleWait`. It
ends at `STOPPED`, at `RUNNING` after a read that was not `RUNNING` (back to `RUNNING`), or at the limit. A service
that never leaves `RUNNING` runs to the limit. Any other seam code reads "after" once, with no wait.

**The outcomes** (`:1343-1344`), in this order:

* `EXCEPTION`: the seam threw or gave no closed code;
* `REFUSED`: `ACCESS_DENIED`;
* `FAILED`: another seam code, with no wait;
* `COMPLETE`: `STOPPED`;
* `FAILED`: `RUNNING` at the end (back to it, or never left);
* `PARTIAL`: anything else at the end of the wait, typically still stopping.

In every outcome "after" is read and compared field by field with the presented capture. Nothing is compensated or
retried: a failed undo starts nothing again. The undo of an undo does not exist. Its log names `REC-SVC-STOP`, which the
source reader refuses (`UNDO_SOURCE_OPERATION_INVALID`). A new start is a new `REC-SVC-START` run, with its own plan,
phrase and undo. A second undo of the same source is refused by the criteria, because the state is no longer the
recorded `after`.

**The log** is R2's `atm.recoverlog/1`, through the same writer (`Write-AtmRecoverRecord`), with the same nine record
types in the same order. The undo adds `undoOf`, `sourceRunId` and `sourceOutcome` to `run-start`. It adds `undoOf`,
`sourceRunId`, `sourceOutcome`, `acceptedTransition` and `notUndone` to `plan`, and `sourceRunId` to `intent`. Like R2's,
it never holds the token's name or SID, a command line, a path outside a known program location, a hidden related name
or an exception message.

**Tests:** the area `V0.4 R3` of `tests/Run-Tests.ps1` (`:19047-19714`), in both shells. Every source log is written by
the suite: either an R2 run with the start seam injected, or a log written through `Open-AtmCleanLog`. Providers,
identities, service rows, dependencies, the console, the confirmation, the wait and the stop seam are injected.

* The closed constants. `REC-SVC-STOP` is outside the catalog, `recover list`, `recover plan` and `Invoke-AtmRecover`.
* The closed gate by instrumentation: no inventory, console, lock, log, wait or seam (injected or default), with a
  positive control with the gate opened in the suite's process. R2's path never reaches the stop seam (a counter on the
  shadowed default, with a positive control through the undo).
* One case per outcome, each with the after, the diff and the records in order:
  * `COMPLETE`;
  * `PARTIAL` (still stopping at the limit);
  * `FAILED`, back to `RUNNING` and never leaving it;
  * every seam code, a throw, and invalid results.
* The source: one case per failure code. Unreadable, relative, wildcard, a junction in the path, over 1 MiB, a plain
  copy, invalid JSON, schema, run id (in a line and in `-RunId`), a `recSeq` gap, a duplicate or unknown record, a
  duplicate key, trailing data, an extra line, incomplete, empty, another operation, a mismatched outcome. Each outcome
  that cannot be undone uses a real R2 log, and so do the two runs stopped before the seam. In every case nothing is
  asked and the seam is not called.
* The criteria, one table:
  * the undo after `COMPLETE`, and a `PARTIAL` that became `RUNNING` with the transition's fields changed;
  * a `PARTIAL` still pending, and a `PARTIAL` with a field outside the set (`startMode`, `exitCode`);
  * a `PARTIAL` that ended `PAUSED`;
  * one case per changed field after a `COMPLETE`;
  * `acceptStop` false;
  * every dependent state that refuses, a hidden one included, and the `STOPPED` controls;
  * a target no longer declared, and an image no longer declared or no longer matching.
* AUT-2:
  * a wrong, empty, cancelled or other plan's phrase, and R2's start phrase;
  * no console, no reader, no presenter;
  * no `-LogFile`, an existing log, a log in a base, and a `-LogFile` equal to the `-SourceLog` (another spelling
    included).
* The revalidation, one case per field, including a dependent that started between the confirmation and the stop.
* A second undo of the same source, and an undo log given as a source.
* B8 busy and abandoned.
* The privacy of the undo's log.
* A static check: the stop class in `Native.cs` asks for no other right and sends no other control. It is called only
  by the default stop seam, which only `Invoke-AtmRecoverUndoLocked` calls. `ServiceController.Stop(` appears nowhere in
  `src/`. The read-only functions write nothing. The steps are in order. The suite never calls the class and the area
  has no real wait. The R1 and R2 static checks now allow `OpenService` and `ControlService` in the stop class of
  `Native.cs` only. R2's per-file single-call checks became per-function: one lock call in each of `Invoke-AtmRecover`
  and `Invoke-AtmRecoverUndo`.

**Not tested:**

* the default stop seam (`AtmServiceStop`) and its Win32 mapping: never called, by the suite or the CI; no real service
  is started, stopped or opened with a control right;
* the real pending-to-`RUNNING` transition of a service: the `PARTIAL` rule runs on injected rows that follow R0's
  capture;
* lock B8 between an elevated and a non-elevated holder: for the VM or the operator's e2e, as in R2;
* the stop of a real service, because no shipped provider declares an `ExpectedImage`;
* any command: no CLI verb calls `Invoke-AtmRecoverUndo` until R4.

## R4 implementation record (2026-11-18)

The line numbers in this record are those of the files as V04-R4 adds or changes them. R4 threads one parameter,
`-NewRunId`, through `Invoke-AtmRecover`, `Invoke-AtmRecoverLocked`, `Invoke-AtmRecoverUndo` and
`Invoke-AtmRecoverUndoLocked`, so lines after 497 of `Engine.Recover.ps1` moved by up to nine lines. The R2 and R3
records keep the numbers of their own rounds. R4 appends from line 1379 on.

R4 implements V04-D3 (b), elevation on demand through UAC, and two CLI verbs:

* `agent-temp recover start -Operation REC-SVC-START -Service <exact declared name>`;
* `agent-temp recover undo -RunId <run id>`.

Their only entry is `Invoke-AtmRecoverCommand` (`Engine.Recover.ps1:1606-1741`), called once per process by the
launcher (`agent-temp.ps1:492-510`). **The gate stays `$false` in every copy** (`Engine.Recover.ps1:15`, still its only
assignment), and so do the other seven. With the gate closed, both verbs show what they would do and stop with exit 27:
no copy requests elevation, asks, locks or logs. Only the suite opens the gate, in its own process, always with the
elevated launcher seam injected. R4 changes no finding state, eligibility, B1 or RECENT rule, and changes neither the
diagnose, the providers, `Native.cs`, `Engine.Clean.ps1` nor `src/bin/agent-temp.cmd`.

**The arguments** (`agent-temp.ps1:485-501`, again in `Engine.Recover.ps1:1671-1673`). One operation and one target per
call, from fixed sets:

* the operation: an id of the catalog. The catalog holds `REC-SVC-START` only; `REC-SVC-STOP` exists only as the undo;
* the service: 1 to 256 characters of `^[A-Za-z0-9_.\- ]+$`, then the exact name a provider declares today (the plan
  refuses any other);
* the run id: a GUID in the lower-case `D` form, exactly (`Test-AtmRecoverRunIdForm`, `:1412-1417`).

Any other option, a missing one, or `-RunId` with `start` (or `-Operation` or `-Service` with `undo`) is a usage error,
exit 2, before the engine is called.

**The fixed folder of the logs.** An R4 run never takes a log path from anyone. Its log is
`<CommonApplicationData>\AgentTempManager\recover\<run id>.log`:

* **Created only by the installer.** `Initialize-AtmRecoverLogDir` (`InstallCommon.ps1:381-407`) is called by
  `Install-AgentTempManager.ps1:50-52` before anything is installed. It creates the parent and then the folder, each
  with its security descriptor in the same call, never secured afterwards:
  `O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` (owner Administrators, a protected DACL, full control for SYSTEM and
  Administrators, nothing for anyone else; `:349`). An existing parent or folder is checked and kept as it is, never
  changed. A reparse point, a file, another owner or another DACL refuses the installation
  (`inst.recoverLogDirRefused`), because a standard user can create folders under CommonApplicationData before the
  installer runs.
* **The uninstaller keeps it** and says so (`Uninstall-AgentTempManager.ps1:27-29`): it is the record of what recovery
  did on the machine.
* **The engine checks it before every use and never creates or fixes it** (`Test-AtmRecoverLogDir`, `:1452-1479`).
  The parent and the folder must each be on a fixed local drive with no reparse point in the path
  (`AtmPathCheck.Chain`), be a directory, and pass `Test-AtmRecoverLogDirSecurity` (`:1430-1450`): owner Administrators,
  a protected DACL, allow entries for SYSTEM and Administrators only, each with full control on the folder itself. Deny
  entries only take rights away. Codes: `RECOVER_LOG_DIR_MISSING`, `_REPARSE`, `_OWNER`, `_DACL` and `_UNREADABLE`,
  exit 28.
* **The log writer is unchanged.** The run's log goes through `Open-AtmCleanLog` as in R2 and R3. The folder policy of
  `AtmCleanLog.Pin` accepts the fixed folder as it is, so `Native.cs` and `Engine.Clean.ps1` are not touched.
* **Deviation from section 3 (b).** A non-elevated token cannot read the fixed folder (Users have no access). So the
  requester reads no log: not the `run-end`, as section 3 (b) said, and not the source of an undo. It reports only by the
  elevated copy's exit code. With the gate closed, a non-elevated `recover undo` shows the request (the run id) and the
  folder's code instead of the inverse plan.

**The run id** is generated once per operation, by the copy that acts (`:1587`), and passed to the engine as
`-NewRunId`. It is the log's file name and its `runId`. The result shows it only when the log was created.

**The steps of the copy that acts** (`Invoke-AtmRecoverOneOperation`, `:1570-1604`), in this order:

| # | Step | Where | Stops with (exit) |
|---|---|---|---|
| 1 | The acting identity is shown (name, elevation type, integrity), with what is known of the requester when relaunched (PRIV-5) | `:1583` | |
| 2 | The fixed folder checked | `:1584-1586` | `RECOVER_LOG_DIR_*` (28) |
| 3 | One new run id, and the log path `<folder>\<run id>.log` | `:1587-1588` | |
| 4 | `start`: `Invoke-AtmRecover`, every R2 step (collection, criteria, plan, console, phrase in this console, lock B8, log, revalidation, seam, wait) | `:1590-1592` | the engine's result (below) |
| 4 | `undo`: the source `<folder>\<run id>.log`, then `Invoke-AtmRecoverUndo`, every R3 step | `:1594-1597` | `RECOVER_RUN_NOT_FOUND` (3); the engine's result |
| 5 | The result, then its exit code (`Get-AtmRecoverResultExitCode`, `:1559-1568`) | `:1599-1603` | |

**The command, past the gate** (`Invoke-AtmRecoverCommand`). After the argument checks (`:1671-1673`) and the closed
gate (`:1674-1685`), in this order:

1. **One operation per process (PRIV-9).** `$script:AtmRecoverOperationTaken` is checked and set on entry, before any
   other work (`:1689-1690`), and never cleared. A second call in the same process gives
   `RECOVER_SECOND_OPERATION` (30), even after a first call that was refused.
2. **The relaunched copy** (`-Elevated`, the launcher's marker `-AtmElevatedRecovery`; `:1693-1711`). The marker proves
   nothing: it only makes the copy stricter.
   1. Only the fixed arguments, as its launcher bound them (`AtmRecoverElevatedArguments`, `:1408`): anything else, or
      no marker, is `RECOVER_ELEVATED_ARGUMENTS` (29). `-Lang`, `-DeadlineSeconds`, `-NoProgress` and `-Ascii` are
      never relayed.
   2. Its own token must be an elevated administrator: otherwise `RECOVER_ELEVATED_NOT_ELEVATED` (29). With UAC
      turned off, `runas` starts a copy that is not elevated, and it stops here.
   3. An installed, verified copy (`-Installed` and `bin\agent-temp.cmd` listed by the launcher's manifest check):
      otherwise `RECOVER_NOT_INSTALLED` (31).
   4. The requester evidence (PRIV-5, below), then the one operation.
   5. In a `finally`: the "press a key" line and one key, so the elevated window shows how it ended. A key reader that
      throws is ignored.
3. **An elevated administrator token** (`:1713-1718`): the one operation in this process (the manual model (a)), with no
   relaunch and no key.
4. **Any other token, the requester** (`:1720-1740`). It is never elevated, changes nothing, takes no lock, reads no log
   and passes no path but the installed launcher's own.
   1. `start`: a fresh collection and the plan, shown (PRIV-2: the operator sees what will be asked for before UAC). Not
      declared: `RECOVERY_NOT_DECLARED` (2). Refused: `RECOVERY_REFUSED` (3). In both, nothing is requested.
   2. `undo`: the request, with the run id only (its token cannot read the fixed folder).
   3. An installed, verified copy with its folder known: otherwise `RECOVER_ELEVATION_NEEDS_INSTALL` (31) (PRIV-7).
   4. The file is `<InstallRoot>\bin\agent-temp.cmd`, the launcher of this installation. The argument line is fixed:
      `recover start -Operation <id> -Service "<name>" -AtmElevatedRecovery`, or
      `recover undo -RunId <run id> -AtmElevatedRecovery` (`:1729-1731`). The name's character set has no quote, so it
      cannot leave its quotes.
   5. The notice: UAC will be requested for this one operation, which one, on which target or run, and why (PRIV-2,
      PRIV-6; `:1732`).
   6. One call to the elevated launcher (`:1733-1736`), then its exit code (PRIV-4, below).

An unexpected failure on any side is `RECOVER_UNEXPECTED` (10), recorded by its exception type only.

**The elevated launcher seam.** `-ElevatedLauncherImpl` (a scriptblock that receives the file and the argument line and
returns `Started`, `ExitCode` and `Win32Error`) replaces the default, `Invoke-AtmRecoverElevatedLaunchDefault`
(`:1505-1531`): `ProcessStartInfo` with `UseShellExecute` and the verb `runas` (ShellExecuteEx, which shows the UAC
prompt), then a wait for that process and its exit code. A refused or failed request comes back as the Win32 error of
the failed start. The launcher never passes the seam, and the suite and the CI never reach the default: it is called
only past the gate, when no seam is given. No credential, saved password, scheduled task, created service or other
process's token is used (the static check below), and the requester relays nothing but the fixed argument line.

**PRIV-4: the prompt's outcomes, by exit code only** (`Get-AtmRecoverLaunchExitCode`, `:1533-1557`). The requester never
guesses a reason from one number:

| What the launcher gave | Code | Exit |
|---|---|---|
| Not started, Win32 error 1223 (usually a cancelled or refused prompt, not proof of it) | `UAC_ERROR_1223` | 40 |
| Not started, another Win32 error | `UAC_WIN32_ERROR` | 41 |
| The launcher threw, or gave an unreadable result (by exception type only) | `UAC_LAUNCHER_EXCEPTION` | 42 |
| Not started, no error | `UAC_NOT_STARTED` | 43 |
| Started, an exit code in `AtmRecoverRelayedExitCodes` (`:1400`) | that code, relayed | 2, 3, 5, 20-31 |
| Started, any other code or none (a crash, a closed window) | `ELEVATED_EXIT_UNKNOWN` | 44 |

In 40 to 43 no elevated copy ran. Exit 44 says that the elevated copy may have acted before it ended, so the operator
checks the service and the fixed folder.

**The exit codes** (`AtmRecoverExitCodes`, `:1394-1399`; `docs/USAGE.md` lists them for the operator):

| Exit | Meaning |
|---|---|
| 2 | Usage: an option, verb, operation, name or run id outside the fixed sets; for the requester only, a target no provider declares (a copy that acts refuses it through the engine, 3) |
| 3 | Refused before anything was asked: the plan or the undo's criteria, the undo's source, or no log for the run id |
| 5 | Integrity: the launcher's own manifest check failed (as for every command) |
| 10 | Unexpected failure, by exception type only |
| 20 / 21 / 22 / 23 / 24 | The seam was called: `COMPLETE`, `PARTIAL`, `FAILED`, `REFUSED`, `EXCEPTION` |
| 25 | Stopped before the seam, after the plan: console, phrase, lock, log, revalidation, intent |
| 26 | The seam was called but the run did not end cleanly (a log or lock step after it failed) |
| 27 | Recovery is disabled (the gate): the plan or the request was shown, nothing else |
| 28 | The fixed folder is missing or differs |
| 29 | A relaunched copy refused its arguments or its token |
| 30 | A second operation in one process |
| 31 | Not an installed, verified copy |
| 40 / 41 / 42 / 43 / 44 | The requester's UAC outcomes (PRIV-4, above) |

**PRIV-5: the requester and the acting identity.** The relaunched copy shows the identity that acts: the name, the
elevation type and the integrity of its own token (`Get-AtmRecoverActingIdentity`, `:1481-1485`). That is the only
identity it uses for decisions: every other profile is another user's. What it knows of its requester comes from
`Get-AtmRecoverRequesterEvidence` (`:1487-1503`), whose default reads nothing and answers `UNVERIFIED`: the window says
that the requester could not be verified. The suite injects `SAME`, `DIFFERENT` (with a name) and `UNREADABLE` (a
throw or an invalid answer). **PRIV-5 stays Partial** ([ELEVATION.md](../ELEVATION.md)). Why the requester's token is
not read:

* reading another process's token needs a handle to that process. `Native.cs` has no `OpenProcess(` (a static check of
  the suite), and R4's static check refuses `OpenProcess`, `OpenProcessToken`, `DuplicateToken`, `ParentProcessId`,
  `Win32_Process` and `Get-Process` in the engine and the launcher;
* the requester's identity would come from the parent process id, which can be forged (a process started with another
  parent) or reused (the parent exited and another process got its id);
* ShellExecuteEx with `runas` gives the elevated copy no channel from its requester other than the argument line, and
  R4 keeps that line fixed.

**Provenance of an undo's source.** R3's provenance check is unchanged: the log's owner must be this process's user or
Administrators, with the protected DACL `Open-AtmCleanLog` gives. In the fixed folder that proves that **some
administrator** wrote the log, not which one. An undo by administrator B of administrator A's start passes. That is not
an escalation: B could stop the service anyway, and the undo still shows the inverse plan, asks for the phrase,
revalidates and logs. A log whose owner is another user's SID is still refused (`UNDO_SOURCE_PROVENANCE`). The owner an
elevated copy's log really gets (the user or Administrators) is measured by the suite on the CI's elevated runner, in
the note of the fixed-folder case; this record does not assume it, and R4 does not harden the check.

**The gate closed** (`:1674-1685`), in every copy:

* `start`: `Invoke-AtmRecover` with the gate closed: a fresh read-only collection and the plan, then
  `RECUPERACAO_REAL_DESABILITADA`;
* `undo`: the fixed folder checked, read only. When it passes, `Invoke-AtmRecoverUndo` with the gate closed reads the
  source and shows the inverse plan. When it does not (always for a non-elevated token, which cannot read it), the
  request is shown with the folder's code;
* then exit 27. Nothing is asked, locked or logged, no inventory is read for a lock, no launcher is called, and no
  elevation is requested. The PRIV-9 guard is not taken.

**What the operator sees** (`Show-AtmRecoverCommandOutput`, `Report.ps1:1421-1455`; `Wait-AtmRecoverKey`, `:1457-1461`): the
plan or the inverse plan, the request, the acting identity, the UAC notice, the result (with the run id when its log
was created), the end line with the exit code and its text, and, in a relaunched copy, the key prompt. Both languages
(`I18n.ps1`, the `rec.*` keys and `help.recover3`, `help.recover4`).

**Tests:** the area `V0.4 R4` of `tests/Run-Tests.ps1` (`:19725-20390`), in both shells. Providers, identities, service
rows, the console, the confirmation, the key, the requester evidence, the elevated launcher and the seams are injected.
The fixed folder is a folder of the sandbox (`-LogDirBase`), except in the case marked elevated.

* The closed constants: exit codes, relayed codes, their texts in both languages, and "Nothing was changed" only where
  no control call can have happened.
* The gate closed: `start` and `undo` show the plan, the inverse plan, or the request with the folder's code, then 27,
  by instrumentation (no console, inventory, lock, log, launcher or mutex), with positive
  controls that open the gate in the suite's process.
* The requester: the plan, the notice, one call with the exact file and argument line (a name with a dot, a hyphen, an
  underscore and a space); no call for a name not declared (2), a refused plan (3) or a copy that is not installed
  (31).
* PRIV-4: one case per launcher outcome (40 to 44), and every relayed code.
* PRIV-5: the evidence table (default, `SAME`, `DIFFERENT`, unreadable, a throw), and relaunched runs with each.
* The relaunched copy: extra arguments, no marker, a token that is not elevated, not installed (29, 31), each with the
  key read; a full run (20) with its outputs in order; a presenter failure (10) with the key still read.
* The same process, and the cycle `start` then `undo`, each with its own new run id; `RECOVER_RUN_NOT_FOUND` (3); a
  refused folder (28) for both verbs.
* The exit code of every engine result (20 to 26, 3), with real flows.
* PRIV-9: a second operation (30), also after a first that was refused.
* The fixed folder: the security check over built descriptors; on disk, missing, a file, a junction, another owner or
  DACL; the installer's refusals (`OWNER`, `DACL`, `NOT_A_FOLDER`, `REPARSE`).
* Elevated only: the folder created by the installer's function in the sandbox, its exact owner and DACL, kept on a
  second call, used by `start` and `undo`, and the log's owner measured.
* Provenance across accounts: a log owned by Administrators is accepted from another user's process; a log owned by
  another user's SID is refused.
* The CLI, in a new process of each shell with every gate closed: `start` and `undo` exit 27 in both languages, with and
  without the marker; usage errors exit 2; the help; the service's state is unchanged.
* The install e2e: the installer creates the folder with its owner and DACL, keeps it on update, and the uninstaller
  keeps it.
* A static check: the elevation verb appears once in `src`, only in the default launcher, which only the command calls,
  once; no credential, scheduled task or token API; the launcher passes no seam; the argument literals; the steps in
  order on both sides; the engine never creates the folder; only the installer calls `Initialize-AtmRecoverLogDir`.

**Not tested:**

* the real elevation request (the default launcher, ShellExecuteEx with `runas`) and the UAC prompt: never called by the
  suite or the CI;
* the real relaunch of an installed `bin\agent-temp.cmd` in an elevated window, its key and the exit code returned to
  the requester; and a machine with UAC turned off;
* the real verification of the requester (PRIV-5): not implemented, by design;
* a real service started or stopped by either verb: no CI test controls a real service (R6), and no shipped provider
  declares an `ExpectedImage`;
* the fixed folder on this machine and on the CI runner's own `ProgramData`: the suite uses a folder of its sandbox, and
  the install e2e runs the installer only on the CI runner.

## R5 implementation record (2026-11-18)

The line numbers in this record are those of the files as V04-R5 adds or changes them. Earlier records keep the numbers
of their own rounds.

R5 is presentation only (section 6). The TUI and the desktop GUI show `recover list` and `recover plan` in a read-only
area. Executing stays in the CLI, as restore does (T-ISO-6). The recovery gate and the GUI gate stay closed in every
copy. R5 changes no engine function, finding state, eligibility, B1 or RECENT rule, no diagnose and no provider:
`Engine.Recover.ps1` is not touched.

**What each interface shows.**

* **Shared formatters** (`Report.ps1`): `Get-AtmRecoverListLines` (`:1349-1371`) and `Get-AtmRecoverPlanLines`
  (`:1373-1412`).
  * They return as data the lines `Show-AtmRecoverList` and `Show-AtmRecoverPlan` write, in the same order and with
    the same texts and codes, without the blank lines and rules. The CLI writers are unchanged.
  * `-View` adds two lines after them: that executing is CLI-only (`rec.view.cliOnly`) and, while the plan says the
    gate is closed, that `agent-temp recover start -Operation REC-SVC-START -Service "<name>"` shows the plan and exits
    27 (`rec.view.gateClosed`).
  * `GateOpen` is read from the plan or list data, as the CLI does. The TUI and GUI files never read the gate.
* **TUI** (`Tui.ps1`):
  * The menu item `S` (`:426`) opens the area. Entering it is the only collection, in `Invoke-AtmTuiRecover`
    (`:948-966`):
    * one fresh read-only collection per entry, through the runner of `Start-AtmTui`
      (`-RecoverCollectionRunner`, `:1069`), by default `Get-AtmRecoverCollection` with the engine's deadline (`:1088`);
    * then its list;
    * a failure keeps nothing and shows the exception code only.
  * The screen `recover` (`Get-AtmTuiFrame`, `:529-548`; rows from `Get-AtmTuiRecoverRows`, `:338-361`) shows, above
    the table:
    * the time of the collection;
    * the list lines except the rows;
    * the CLI-only note and a hint.
  * Each row has five columns: operation, service, provider, `OFFERED` or `REFUSED`, and the undo or the codes.
  * `Enter` on a row (`:1158-1166`) computes `Get-AtmRecoverPlan` from the kept collection for that exact declared name.
    It opens the text screen `rplan` (`:329-333`), which shows the plan lines with `-View`.
* **GUI** (`GuiModel.ps1`, `Gui.ps1`):
  * The navigation item `S` (`GuiModel.ps1:220`; its button `ScreenS` is made from the list) returns `RECOVER_OPEN`
    (`:530`). The form then calls `Invoke-AtmGuiRecover` (`Gui.ps1:329-352`):
    * one blocking call on the UI thread with the screens and Refresh disabled, as the preview does
      (`:828-833`, `:854-867`);
    * ignored while an audit, the preview or the diagnose runs;
    * a failure keeps the exception code only.
  * `Invoke-AtmGuiNavRecover` (`GuiModel.ps1:1166-1176`) opens the area over the dashboard with that collection in the
    screen's filter.
  * `Get-AtmGuiRecoverTable` (`:1119-1152`) gives the TUI's columns, rows and lines above the table.
  * `Enter` (`:560-571`) computes the plan from the kept collection. `Get-AtmGuiRecoverPlanText` (`:1154-1164`) gives
    its lines.
* **Launcher** (`agent-temp.ps1`): the engine is loaded for `gui` (`:254`, only past the GUI gate, which is closed in
  every copy) and `tui` (`:266`), besides `recover` (`:487`) and `version` (`:546`).
* **Texts** (`I18n.ps1`, `:314-329` and `:1540-1555`): `menu.recover`, `menu.recoverTitle`, `rec.col.*` and
  `rec.view.*`, translated in both languages, with the same placeholders.

**Why the area does not execute.**

* **Only three engine functions are reachable.** The UI files call only the engine's three read functions, each in one
  place: the collection in the entry function, the list right after it, and the plan on `Enter`.
* **No typed target.** The service is chosen from the list, so a name no provider declares cannot be chosen.
* **Nothing that executes is called.** No key, button or menu calls `Invoke-AtmRecover*`, the launcher, a service seam,
  the log, the lock B8, a confirmation or a line reader.
* **No other path collects.** Frames, view models, the GUI's ticker, `F5` and a re-audit never collect.

**Statics.**

* **The GUI's closed list** (`tests/Run-Tests.ps1:15236-15257`; ADR-0014 section 3):
  * `$guiAllowedEngine` gains five names: `Get-AtmRecoverCollection`, `Get-AtmRecoverList`, `Get-AtmRecoverPlan`,
    `Get-AtmRecoverListLines` and `Get-AtmRecoverPlanLines`. It now has 28 names, and the six count assertions say so.
  * `$guiForbidden` gains `Invoke-AtmRecover`, `AtmServiceStop`, `ServiceController`, the elevation verb,
    `ShellExecute`, `AtmRecoverOperationTaken` and `Open-AtmCleanLog`.
  * `$guiOtherGates` gains `AtmRecoveryEnabled`.
  * The tick check also refuses `Invoke-AtmGuiRecover` and `Get-AtmRecoverCollection` (`:15340-15341`).
* **The R1 static** (`:18519-18542`):
  * `Tui.ps1` and `Gui*.ps1` may name exactly the three read functions. The diagnose names none, and none loads the
    engine or names `AtmRecovery`.
  * The launcher loads the engine in exactly four blocks, `recover`, `version`, `tui` and `gui`, once each.
  * `version` kept its load: it shows the gate.
* **A new TUI static** (area `V0.4 R5`):
  * `Tui.ps1` contains none of the execution names, `AtmRecoveryEnabled` or `Wait-AtmRecoverKey`.
  * The six fragments of the area contain no `Read-AtmCleanAnswer`, line reader, key source or `Read-Host`. They are
    the two functions, the two `recover` cases, the `rplan` case and the `Enter` branch.
* **Placement of the reads.** Each read function is called only where expected, in both interfaces. The reads the view
  uses, and every function of `src` they call transitively, contain none of the execution names.
* **The seam.** `AtmGuiRecoverSource` is assigned once, to `$null`.
* **Old statics adjusted, none loosened:**
  * the TUI menu keys (`:14659`, `S` after `Z`);
  * the GUI navigation keys (`:16434`, `S` after `D`);
  * the window's tab order (`:18055`, `ScreenS` after `ScreenD`).

**Tests:** the area `V0.4 R5` of `tests/Run-Tests.ps1` (`:20413-20733`), in both shells.

* **Setup.** The collection is injected through the R1 helpers: providers, identity, service rows and dependencies. It
  has a declared and offered service, a declared and refused one (running), and a name no provider declares. No
  service is opened or queried.
* **Formatter parity.** In both languages, the list and plan lines equal the CLI's lines in order. This covers the
  offered, refused and undeclared targets, an empty list and a forged open gate. `-View` is the CLI's lines plus the
  CLI-only note.
* **TUI,** headless, in both languages:
  * the area and both plans are drawn with every expected line and the codes of `recover plan`;
  * the undeclared name never appears, and its plan screen equals the CLI's lines;
  * with the area closed there are zero collections, and two entries make two;
  * letters on both screens read no line and collect nothing;
  * a failure shows only the code.
* **GUI** (session and view model, no window), in both languages:
  * `S` alone collects nothing, and an opening collects once;
  * the rows and lines above the table equal the TUI's, and the plans equal the CLI's;
  * `Enter`, `Esc`, a live monitoring tick and `F5` collect nothing;
  * a busy session is ignored;
  * a failure keeps only the code.
* **Instrumentation.** No call reaches `Invoke-AtmRecover*`, the launcher, the service seams, the log, the lock, a
  confirmation, `Read-Host`, CIM or `Start-Process`.
  * There is no B8 mutex, with a positive control.
  * The sandbox is unchanged.
  * The default path calls the engine's collection, shadowed, once per entry.
* **The GUI statics.**
  * The real files pass.
  * Each new forbidden name, the gate and two tick plants are refused in a copy, and so is an engine name outside the
    list.

**Not tested:**

* **A real GUI window.** A window where `S` or its button is pressed, with the real collection, is never opened. The P6
  window case checks the button's place in the tab order only.
* **A real console.** The TUI never runs in a real console with a keyboard and the real collection.
* **Who covers it.** Both are left for the operator's VM (R6).

**Limit.** The GUI's collection blocks its window for up to the engine's deadline (120 s), with a fixed progress text.
That is the same as the preview.
