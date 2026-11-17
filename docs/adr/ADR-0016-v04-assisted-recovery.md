# ADR-0016: Assisted recovery (V0.4)

Status: PROPOSED. Decisions V04-D1 to V04-D8 are open and belong to the maintainer. Nothing is implemented, and no gate
is opened anywhere.
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
| 1 | `Service` in state `RUNNING`, `STOPPED`, `PAUSED` or `PENDING` (`Engine.Diagnose.ps1:36`, state map `:3133`, findings `:3378-3449`) | `claude-desktop`, the single name `CoworkVMService` (`src/providers/ClaudeDesktop.ps1:45`). `claude-code` declares no service (`src/providers/ClaudeCode.ps1:143-175`). | No: the services collector runs in every copy. | `SERVICE_STATE`, `SERVICE_START_MODE`, `SERVICE_DELAYED_AUTO_START`, `SERVICE_ACCOUNT_KIND`, `SERVICE_EXECUTABLE` or `_NAME`, `SERVICE_PROCESS_VERIFIED` (`:3413-3431`) | **No fault signal:** the query reads no exit code (`:3130` lists the properties read), so a `STOPPED` service that failed looks like one that was never started. **"Stuck" is not measurable:** `PENDING` is a single reading with no duration, checkpoint or wait hint. **Weak attribution:** the name is a publicly reported one, not documented by the vendor (`ClaudeDesktop.ps1:24-26`). **No proof of absence:** a name the account cannot see is `UNKNOWN`, never absent (`:3403-3406`; the collector never produces `NOT_PRESENT`, `:3126-3127`). |
| 2 | `Service` in state `UNKNOWN` (query denied, failed, timed out, or name not listed) | as row 1 | No | `SERVICE_NOT_QUERIED`, `SERVICE_NOT_LISTED` (`:3401-3406`) | Nothing is known, so there is nothing to act on. |
| 3 | `VirtualMachine` in state `RUNNING`, `OFF`, `SAVED`, `PAUSED` or `PENDING` (`:37`, `:3475`, `:3637-3775`) | **None.** No provider declares a virtualization hint (`ClaudeDesktop.ps1:46` returns an empty list; `ClaudeCode.ps1` has none), so every VM is `VM_UNATTRIBUTED` (`:3746`). The Cowork VM is a Host Compute Service system, not a Hyper-V VM, and is not expected in this query (`ClaudeDesktop.ps1:33-36`). | No | `VM_ENABLED_STATE`, `VM_WORKER_VERIFIED`, attribution codes (`:3708-3746`) | **Attribution.** Without an agent attribution, a VM is someone else's VM. The `RUNS_VM` graph relation is proposed and not implemented ([ADR index](README.md), ADR-0002). |
| 4 | `VirtualizationPlatform` `PRESENT` (`:38`, `:3773`) | none (engine) | No | hypervisor flag, namespace, `vmms` state (`:3682-3692`) | Context only. Platform features are system configuration, which V0.4 excludes. |
| 5 | `Process` in state `AGENT_PROCESS`, `AGENT_DESCENDANT` or `IDENTITY_UNVERIFIED` (`:35`, `:1288-1304`) | `claude-code`: the image name `claude.exe` (`ClaudeCode.ps1:148`), the session registry and path references. `claude-desktop`: `claude.exe` with a package marker (`ClaudeDesktop.ps1:44`). | No | `PROCESS_MATCHER_IMAGE`/`_MARKER`, `SESSION_PROCESS_MATCH`, `PATH_REFERENCE`, `PARENT_LINK_VERIFIED`. The key is `pid@creationTicksUtc` (`:323-328`). | **There is no "orphan" or "hung" state.** **Discovery is heuristic:** `agent-processes` coverage is never `COMPLETE` (`:1272-1279`). **Ambiguous attribution:** both providers match the same image name (`ClaudeDesktop.ps1:30-32`). **No responsiveness signal.** |
| 6 | `AgentSession` in state `LIVE`, `PID_REUSED`, `IDENTITY_UNVERIFIED` or `SESSION_PROCESS_NOT_FOUND` (`:41`, `:848-884`, `:1115-1137`) | `claude-code`: `<configDir>\sessions\<pid>.json` (`ClaudeCode.ps1:49-50`) | No | `SESSION_REGISTRY`, `SESSION_PROCESS` with its reason, `SESSION_PROCESS_KEY` | **The registry file is the agent's own**, and providers only read (`docs/ARCHITECTURE.md:30`). **The harm is not shown:** no evidence says a stale entry (`SESSION_PROCESS_NOT_FOUND`, given only with a `COMPLETE` snapshot, `:868`; or `PID_REUSED`) breaks anything. |
| 7 | `Worktree` in state `APPARENT_ORPHAN` (`:2700-2704`), with evidence `WORKTREE_LOCKED` (`:2756`), `WORKTREE_DIRECTORY_MISSING` (`:2757`) or `OPERATION_IN_PROGRESS` (`:2575`) | none (Git discovery from partitions and explicit paths) | **Yes:** `AtmWorktreeDiagnosticsEnabled` (`:1706`). Closed, discovery returns `NOT_OBSERVABLE` and reads nothing (`:2635-2637`). | `ADMINISTRATIVE_ENTRY_NOT_FOUND`, `LOCAL_WORK_UNKNOWN`. An orphan that is registered elsewhere drops to `UNKNOWN` (`:2867`). | **The gate must be open.** **Every repair would write to Git**, and Git use is read-only by design (ADR-0006). **Local work is unknown** by definition of the state. |
| 8 | Open-file holders (`FILE_HELD_OPEN`) | none (Restart Manager over sampled files) | **Yes:** `AtmHandleDiagnosticsEnabled` (`:4200`). Closed, the collector is `NOT_OBSERVABLE` (`:4255`). | a process key per holder | Releasing a holder means ending a process (row 5). |
| 9 | `TempPartition` in state `IN_USE` or `NO_DEPENDENCY_OBSERVED` (`:42`, `:4109-4184`) | `claude-code` temp bases | No | graph evidence (`GRAPH_*`) | Not recovery: clean (V0.3) and isolation (0.3.x) already act on these partitions behind their own gates. |
| 10 | A "stale lock" | **None.** No finding exists. The diagnose skips `*.lock` names when it reads references (`:2406`) and reports no lock. B8 is a kernel mutex (`src/lib/Engine.Clean.ps1:360`), and Windows reports it `ABANDONED` when its owner ends without releasing it (`:396-398`). | n/a | n/a | No lock file is left behind for a tool to recover. |

**Also relevant:** the diagnose JSON export is behind `AtmDiagnoseExportEnabled` (`src/lib/Report.ps1:1165`). The keys
in an export are keyed pseudonyms whose key exists only for that run unless the operator supplies one
(`Engine.Diagnose.ps1:4511-4513`). An export can therefore never be the input of an operation (section 3).

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
* **The proof of ownership is weak.** Agent discovery is heuristic and never complete (`Engine.Diagnose.ps1:1272-1279`).
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
  * account kind and executable, reduced as the diagnose reduces them (`Engine.Diagnose.ps1:3324-3325`);
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
* **Acting on an export or a pseudonymous key:** keys are per run (`Engine.Diagnose.ps1:4511-4513`), and an export is
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
