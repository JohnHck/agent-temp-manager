# Architecture

```
src/
├─ agent-temp.ps1            CLI dispatcher (no args -> TUI)
├─ bin/agent-temp.cmd        global launcher placed on the machine PATH
├─ config/                   projects.json (generic) + optional projects.local.json (never versioned)
├─ providers/ClaudeCode.ps1  provider: temp + runtime (contract v2)
├─ providers/ClaudeDesktop.ps1  provider: runtime only (V0.2, contract v2)
└─ lib/
   ├─ Native.cs              scanner / handle probe / deleter (C# 5, compiled in memory by Add-Type)
   ├─ Engine.Audit.ps1       AUDIT ENGINE  - discovery, inventory, evidence, classification (read-only)
   ├─ Engine.Clean.ps1       CLEAN ENGINE  - allowlist, gates, plan, confirmation, revalidation, deletion
   ├─ Engine.Diagnose.ps1    DIAGNOSE ENGINE (V0.2, read-only) - evidence/coverage/findings, identity, collectors,
   │                         dependency graph (correlation) and partition/worktree states from it
   ├─ I18n.ps1               message catalog (en-US, pt-BR) and language resolution
   ├─ Report.ps1             presentation: CLI text report
   └─ Tui.ps1                presentation: interactive TUI (V0.1 screens + the V0.2 diagnostics area, menu D)
```

## Layering rules (enforced by tests)

* `Engine.Audit.ps1` never writes to the terminal and never deletes. Progress goes through a callback.
* `Engine.Clean.ps1` contains clean's **only** call to the deleter, reached only after every gate, the plan
  presenter, the typed confirmation and a per-path revalidation. It refuses to run without both a plan
  presenter and a confirmation reader (`SEM_APRESENTACAO_OU_CONFIRMACAO`). Since 0.3.x P4 the only other product call
  to the deleter is the quarantine purge in `Engine.Isolate.ps1` (below), behind its own gate.
* `Report.ps1` and `Tui.ps1` never reference deletion APIs. The TUI's cleanup screen only collects an
  allowlist and forwards it to `Invoke-AtmClean`.
* Providers only read evidence. They never decide eligibility.
* `Engine.Diagnose.ps1` (and any `Diagnose.*.ps1`) never writes to the terminal, never deletes, never controls
  processes, services or virtual machines, never writes the registry or ACLs and never uses the clean engine or its
  handle probe. Presentation calls only `Invoke-AtmDiagnose`, never a collector. Design: [docs/adr](adr/README.md)
  (ADR-0001, ADR-0003, ADR-0008, ADR-0009).

## Inventory pipeline (`Invoke-AtmInventory`)

1. **Profiles**: `HKLM\...\ProfileList` (+ `.bak` entries), loaded hives in `HKU`, per-user `Environment`
   (unexpanded, expanded with *that* user's profile), `Public`/`Default` declared by Windows, residual
   directories under `ProfilesDirectory` (one level; reparse points recorded, not traversed). Hives are never loaded.
2. **Bases**: for every profile x provider: `<TEMP candidate>\<provider.TempSubdir>`, long-path normalised,
   whole ancestor chain validated (`Test-AtmPathChain`: exists, readable, not a reparse point, fixed drive).
   Shared bases are flagged.
3. **Filesystem**: one pass per partition root (`AtmScanner.ScanTree`): bytes, estimated allocation, files,
   dirs, direct children, newest write, reparse points (counted, never followed), read-only/system files,
   per-entry errors with bounded samples. Memory is O(depth + samples), not O(files).
4. **Processes**: one `Win32_Process` CIM query. Uninspectable processes are counted by name.
5. **Evidence**: an index of base paths (long + 8.3 forms) resolves every command line with `IndexOf` and
   component parsing: O(processes x bases), never O(files x processes), no per-file regex. Direct
   references, ancestor references and ambiguous references are kept apart; ancestor and ambiguous references that
   no partition carries (an empty base or project folder) are counted too (O2D). Provider evidence: live-session
   registry and activity (transcript) timestamps.
6. **Classification**: conservative classes + flags (hard flags block, soft flags require investigation).

Totals are computed bottom-up from partitions; nothing is enumerated twice.

## Partitions

Each base yields exclusive partitions: one per direct child of every scope directory
(`SessionRoot`, `UnrecognizedDir`, `LooseFile`, `ReparsePoint`, `Unmeasured`) plus one `BaseLooseFiles`
partition for files directly under the base. Only `SessionRoot` partitions can ever become eligible.

## Diagnose pipeline (`Invoke-AtmDiagnose`, V0.2)

Collection -> normalization -> evidence -> correlation -> presentation:

1. **Collection** (read-only): token identity, provider runtime hints, the V0.1 inventory (with profile discovery and
   its gaps), declared services, the virtualization platform and VMs, the process snapshot and sessions, and, behind
   closed gates, worktrees and open files (`NOT_OBSERVABLE` in every shipped copy); working directories are deferred.
2. **Normalization and evidence**: findings (ADR-0001) with evidence codes and the coverage records they depend on;
   identifiers are keyed pseudonyms or process keys (ADR-0010).
3. **Correlation**: the dependency graph (ADR-0002) over that evidence only: verified edges, strengths `DIRECT`,
   `ANCESTOR`, `AMBIGUOUS`, limits declared as coverage; partition and worktree states come from its summaries, and a
   no-dependency state is accepted only with conclusive coverage (checked twice).
4. **Presentation**: the text report (`Report.ps1`), the JSON export (`ConvertTo-AtmDiagnoseJson`, schema
   `atm.diagnose/2`) and the TUI area (rendered from that same export). None of them collects anything.

## Isolation engine (0.3.x; `lib\Engine.Isolate.ps1`)

**In place (phases P1 to P3a):**
* `isolate` (CLI only) plans one session root of the own profile against the clean gates. With the isolation gate closed
  (every copy) that is all it does.
* Past the gate (tests only), `Invoke-AtmIsolate` runs under the clean lock. Only the engine calls the mover, once, after
  the intent is recorded in the log and in the entry's manifest. The lock and console helpers live in `Engine.Clean.ps1`.

* P3b: `quarantine list`, `inspect` and `verify` are read-only engine functions (no record is written, T-ISO-4).
  `Invoke-AtmRestore` (CLI only) is the second and last product call to the mover, behind the same gate and lock, with
  the intent recorded before it. The TUI calls `Invoke-AtmIsolate` and the read-only functions only; it never restores
  (T-ISO-6).

* P4: `Invoke-AtmPurge` (CLI only) purges the payload of one entry. It sits behind the purge gate, its own and separate
  from the isolation and deletion gates (J-ISO-1 (C)), and runs under the same lock. It makes the second and last
  product call to the deleter (`AtmDeleter.DeleteTree` with the manifest's measurement), after the intent is recorded in
  the manifest and the log. The entry and its manifest stay as the trail.
  * The retention, the quota and the policy (`Get-AtmQuarantinePolicy`, `config\quarantine.policy.json`) are read-only
    engine functions. Retention only marks `EXPIRED`, and the quota only refuses new isolations.
  * The report and the TUI show `EXPIRED`, `PURGED` and the policy. They never call the purge or the deleter.

* P6a: the automatic purge. `bin\agent-temp-autopurge.ps1` is the only caller of `Invoke-AtmAutoPurge`, which acts only
  with `autoPurge = true` in the policy and reuses the plan, gates and deleter path of `quarantine purge`
  (`Invoke-AtmPurgeDeletion`), behind the same purge gate. The reports and the TUI show the notice while it is on.

* P6b: the user's optional scheduled task (J-ISO-7). The Task Scheduler is reached only through
  `Connect-AtmTaskScheduler` in `Engine.Isolate.ps1`. It is changed only by `Register-AtmAutoPurgeTask` and
  `Unregister-AtmAutoPurgeTask`, called by `Invoke-AtmAutoPurgeSchedule`/`Invoke-AtmAutoPurgeUnschedule` and only from the
  CLI's `quarantine schedule-autopurge` and `unschedule-autopurge`. `version`, `quarantine list` and the TUI only read its
  state (`Get-AtmAutoPurgeTaskState`); the TUI never schedules or unschedules (T-ISO-6). The uninstall
  (`InstallCommon.ps1`) only reads the folder and warns, about the automatic purge's task and, since V0.5 M4b, about
  the monitoring's tasks and history (`Get-AtmUninstallMonitorNotice`); it removes no task and no history.

### The scheduler layer: two tasks (V0.5 M3a, ADR-0017)

The Task Scheduler holds at most two tasks per user, both in the folder `\AgentTempManager`: the automatic purge's
(implemented, P6b above) and the preventive monitoring's (V05-D1, **implemented in phase M3a behind the gate**
`AtmMonitoringEnabled`, closed in every copy, so no distributed copy creates it; the real scheduler is validated by
phase M3b's CI harness). Each follows the same four steps:

| Step | Automatic purge (implemented, `Engine.Isolate.ps1`) | Monitoring (M3a, `Engine.Monitor.ps1`, behind the gate) |
|---|---|---|
| Build the definition, never registered by itself | `New-AtmAutoPurgeTaskDefinition` (name from `Get-AtmAutoPurgeTaskName`, action from `Get-AtmAutoPurgeTaskAction`) | `New-AtmMonitorTaskDefinition` (name from `Get-AtmMonitorTaskName`, action from `Get-AtmMonitorTaskAction`): interactive, limited, no password, one action running the entry point `src/bin/agent-temp-monitor.ps1`; `$null` with the gate closed |
| Register (`TASK_CREATE`, never replace) | `Register-AtmAutoPurgeTask`, called only by `Invoke-AtmAutoPurgeSchedule`, reached only from the CLI | `Register-AtmMonitorTask`, called only by `Invoke-AtmMonitorEnable`, reached only from the CLI's `monitor enable`, and only with the gate open (ADR-0017 section 5) |
| Read back and check the exact match | `Get-AtmAutoPurgeTaskObject`, `Test-AtmAutoPurgeTaskMatch`, `Get-AtmAutoPurgeTaskState` | `Get-AtmMonitorTaskObject`, `Test-AtmMonitorTaskMatch`, `Get-AtmMonitorTaskState`. Reading is allowed with the gate closed, so that a leftover is visible in `version` and `monitor status`. |
| Remove after the exact match | `Unregister-AtmAutoPurgeTask`, called only by `Invoke-AtmAutoPurgeUnschedule` | `Unregister-AtmMonitorTask` (phase M4a), called only by `Invoke-AtmMonitorDisable`, reached only from the CLI's `monitor disable`, and only with the gate open |

* **The scheduler connection.** The Task Scheduler is reached only through `Connect-AtmTaskScheduler`, in
  `Engine.Isolate.ps1`, the only place that creates `Schedule.Service`. Phase M3a decided **not to move it**: the
  monitoring engine calls it, with the purge's read-only helpers (`Test-AtmTaskNotFound`, `Get-AtmTaskSchedulerCode`,
  `Resolve-AtmTaskUserSid`), only from its task functions. The launcher loads `Engine.Isolate.ps1` before the
  `monitor` and `version` blocks. The P6b static pins the callers of `Connect-AtmTaskScheduler` and expects the
  registration calls in these two engines only; the M3a static pins where the monitoring engine uses each foreign
  helper.
* **The collector's entry point,** `src/bin/agent-temp-monitor.ps1` (phase M3a), is the only thing the monitoring task
  runs. It takes no arguments, checks the manifest before it loads any code, loads only `Engine.Audit.ps1`, the
  providers and `Engine.Monitor.ps1`, and calls `Invoke-AtmMonitorEntry`, which reads `AtmMonitoringEnabled` first on
  every run: closed, it exits without collecting, for example in a copy updated after the task was registered.
* **Presentation.** The TUI and the GUI never register, remove or run either task (T-ISO-6). Since phase M5 the GUI
  reads the monitoring through one read function, `Get-AtmMonitorStatus` (ADR-0014 section 3); the TUI reads the same
  status and, for display only, the collection task's state.
* **Removal.** Whether the uninstaller or the unschedule commands do more than today about the shared folder was
  **pending V05-D9** until 2026-11-18. Decided then, (a) plus (c): the uninstaller warns and names `monitor disable` and
  `monitor remove-history`, and the unschedule commands remove the folder `\AgentTempManager` when it is empty. Phase
  M4a implements (c): one helper in `Engine.Isolate.ps1`, `Remove-AtmEmptyTaskFolder`, called by
  `Invoke-AtmAutoPurgeUnschedule` and `Invoke-AtmMonitorDisable` after their task reads back absent. It acts only on
  the constant folder, removes it only when it holds no task (hidden ones included) and no subfolder, and leaves the
  final word to the Task Scheduler's `DeleteFolder`; its outcome never fails the command. Phase M4b implements (a):
  `Get-AtmUninstallMonitorNotice` in `install/InstallCommon.ps1` only reads and warns, naming `monitor disable` for
  this user's task (other users' tasks are counted, never named) and `monitor remove-history` for the history folder,
  shown as the literal `%LOCALAPPDATA%\AgentTempManager\Monitor`. The uninstaller removes nothing of the monitoring.

### Planned layering (ADR-0013)

[ADR-0013](adr/ADR-0013-isolation-quarantine-recovery-mode.md) (PARTIALLY ACCEPTED) adds a third operation next to
audit and delete: **isolate**, with restore, inspect, verify and purge. Isolation is the default operation (ISO-D5).
The own profile comes in 0.3.x; the guided Recovery Mode for another user's profile in V0.4 (ISO-D1). The planned
layering:

* An isolation engine of its own. It reuses the inventory, the clean gates other than gate 2 (it has its own target
  rule), the B2-1 evidence, the AUT-2 confirmation, the T1 log and pinned writer, and the B8 lock. It contains the
  only call that moves a target, through a pinned handle, behind its own closed release gate.
* **Purge**, a deletion of a quarantine entry, goes through the same deleter and pinning as clean. Decision J-ISO-1 (C)
  puts it behind a gate of its own rather than the deletion gate: one deleter call in the isolation engine, used only
  for the payload of an entry (0.3.x P4). That holds for a confirmed purge and for an opted-in automatic one (ISO-D4).
  Isolating and restoring never delete.
* Presentation never moves anything: the CLI and the TUI only collect the exact targets and forward them, as they do
  for clean.
* The diagnose engine stays read-only and never uses the isolation engine.

## Recovery engine (V0.4 phases R1 to R5; `lib\Engine.Recover.ps1`)

[ADR-0016](adr/ADR-0016-v04-assisted-recovery.md), assisted recovery of a service a provider declares. The eighth
release gate (`AtmRecoveryEnabled`) is closed in every copy. With it closed, the engine only reads (R1). The execution
path (R2) and the undo (R3) are in the engine too. Since R4, the verbs `recover start` and `recover undo` call them
through `Invoke-AtmRecoverCommand`, but only past the gate: with it closed, both show the plan or the request and stop
(exit 27). Only the test suite goes past the gate, with it opened in its own process and the seams and the elevated
launcher injected. In CI only, the R6 harness also does, on services it creates itself, with guard wrappers around the
default seams (ADR-0016's R6 record).

* **Loading.** The launcher loads the engine only for `recover`, `version` and, since R5, `tui` and `gui` (for their
  read-only recovery area; `gui` only past its own gate, which is closed in every copy). It is in the launcher's integrity
  check, `AtmRequiredFiles` and the manifest. It depends on `Engine.Audit.ps1`, `Engine.Diagnose.ps1` and, for the
  lock B8, the log writer and the console past the gate, `Engine.Clean.ps1`. It writes
  nothing to the terminal: `Report.ps1` presents the list and the plan (`Show-AtmRecoverList`, `Show-AtmRecoverPlan`),
  and every line of `recover start` and `recover undo` through the presenter the launcher passes
  (`Show-AtmRecoverCommandOutput`).
* **The command (R4)** (`Invoke-AtmRecoverCommand`): one operation per process. Past the gate, an elevated
  administrator token runs the operation in its own process. Any other token is a requester: it shows the plan (or,
  for undo, the run id only) and relaunches the installed `bin\agent-temp.cmd` once through UAC, with fixed arguments
  and a marker, through the elevated launcher seam (`Invoke-AtmRecoverElevatedLaunchDefault`, `ShellExecuteEx` with
  `runas`). It reports only by that copy's exit code. The relaunched copy redoes everything and waits for a key. The
  logs go to the fixed folder `<CommonApplicationData>\AgentTempManager\recover`, which only
  `Install-AgentTempManager.ps1` creates (`Initialize-AtmRecoverLogDir` in `InstallCommon.ps1`) and which the engine
  checks before every use (`Test-AtmRecoverLogDir`) and never creates or fixes.
* **Collection** (`Get-AtmRecoverCollection`): fresh, in the command's own process, read only. It calls the diagnose's
  functions for the token identity, the providers' runtime hints, one services query (`Invoke-AtmServiceQuery`, with
  the R0 signals, dependencies and image comparison) and its findings (`Get-AtmServiceFindings`). The engine itself has
  no CIM query, and it reads no inventory, process snapshot, export, pseudonym key or plan of another process.
* **Criteria and plan.** `Get-AtmRecoverRefusals` applies the criteria to one declared name and returns the closed
  `RECOVERY_*` codes. `Get-AtmRecoverList` lists every declared service. `Get-AtmRecoverPlan` gives one operation for one
  target: the "before" capture, the undo, the likely elevation and the plan id. The catalog has one operation,
  `REC-SVC-START`. Its undo, `REC-SVC-STOP`, exists only as `Invoke-AtmRecoverUndo` (R3) and stays outside the
  catalog: `recover list` never offers it, and `recover plan` and `Invoke-AtmRecover` never accept it. See ADR-0016's R3
  implementation record.
* **Layering rules** (static suite tests):
  * two service control APIs, each in one place and each reached only with the gate open:
    * the start: `ServiceController.Start()`, only in the default start seam of `Engine.Recover.ps1`;
    * the stop: `AtmServiceStop` (`OpenSCManagerW`, `OpenServiceW`, `ControlService`), only in its class in
      `Native.cs`, called only by the default stop seam;
    * never `ServiceController.Stop()`, which stops running dependent services first;
  * with the gate closed (`list`, `plan`, and `Invoke-AtmRecover` or `Invoke-AtmRecoverUndo`), the engine asks nothing,
    takes no lock, and writes no log or file. Past the gate, in the suite only, it requires AUT-2, takes the lock B8
    and writes the log `atm.recoverlog/1`;
  * the elevation verb (`runas`) appears once in `src/`, in the default elevated launcher, which only
    `Invoke-AtmRecoverCommand` calls, once. The launcher calls the command once and passes it no seam;
  * `Engine.Diagnose.ps1` neither loads nor calls it, and keeps its two `Win32_Service` queries. `Tui.ps1` and
    `Gui*.ps1` do not load it and, since R5, call only its three read functions (`Get-AtmRecoverCollection`,
    `Get-AtmRecoverList`, `Get-AtmRecoverPlan`), each in one place; no recovery execution name, the gate or the
    elevation verb appears in them.
* **Presentation in the TUI and the GUI (R5).** A read-only area, key `S`, shows `recover list` and `recover plan`
  through the shared formatters `Get-AtmRecoverListLines` and `Get-AtmRecoverPlanLines` (`Report.ps1`), which return
  the CLI's lines as data. The collection runs only when the area is entered (`Invoke-AtmTuiRecover`,
  `Invoke-AtmGuiRecover`), never per frame, from a view model or from the GUI's ticker; a plan is computed on `Enter`
  from that collection, for a service of its list. Executing stays in the CLI (T-ISO-6): the GUI's closed list
  ([ADR-0014](adr/ADR-0014-desktop-gui-winforms.md) section 3) refuses the execution names.

## Monitoring engine (V0.5 phases M1, M2 and M3a; `lib\Engine.Monitor.ps1`)

[ADR-0017](adr/ADR-0017-v05-preventive-monitoring.md), persistent preventive monitoring. The ninth release gate
(`AtmMonitoringEnabled`) is closed in every copy. Phase M1 adds the collector and the history storage, phase M2 the
trends, the thresholds and the alerts, and phase M3a the collection task, `monitor enable` and the collector's entry
point (the scheduler layer above); with the gate closed nothing is scheduled or collected.

* **Presentation in the TUI, the GUI and the audit (M5).** All read only, and none reads the gate: each shows the
  status's `GateOpen` field.
  * The TUI's screen `M` reads the status and the task's state on entry and on `U`, through two readers, and shows the
    shared formatter's lines (`Get-AtmMonitorStatusLines`).
  * The GUI's area `M` reads one status per opening (`Invoke-AtmGuiPrevmon`, a seam for the tests). Its view model
    builds the lines itself, without the task's. The ticker and F5 never read it.
  * `agent-temp audit` asks `Get-AtmMonitorAuditSummary`, whose first statement is the gate: closed, nothing is read.
    `Get-AtmMonitorAuditLine` (`Report.ps1`) turns the summary into at most one line under the first header. The line
    is never in `-ExportJson` and never changes the exit code.
* **Loading.** The launcher loads the engine only for `monitor`, `version`, `audit` (the alert line, since M5) and the
  TUI and GUI launch (the read-only views, since M5), and the collector's entry point
  `bin\agent-temp-monitor.ps1` loads it once; no other file loads it. It is in the launcher's integrity check,
  `AtmRequiredFiles` and the manifest. It depends on `Engine.Audit.ps1` and on the native pinned writer and folder
  policy of `Native.cs`; its task functions also call the scheduler helpers of `Engine.Isolate.ps1`, the console
  observation of `Engine.Clean.ps1` and the token state of `Engine.Diagnose.ps1`, which the launcher loads. It writes
  nothing to the terminal: `Report.ps1` presents `monitor status` (`Show-AtmMonitorStatus`), the task's lines
  (`Get-AtmMonitorTaskLines`) and `monitor enable`'s plan and result.
* **`monitor enable`** (`Invoke-AtmMonitorEnable`) reads the gate first; closed, it returns `MONITORING_GATE_CLOSED`
  before anything is read or asked. Past the gate, in the suite only: the interval, a standard token, an installed copy,
  the console the engine observes, no existing task, the plan, the phrase `ATIVAR MONITORAMENTO`, the registration and
  the read-back with an exact match.
* **The collector** (`Invoke-AtmMonitorCollection`) reads the gate first; closed, it returns `MONITORING_GATE_CLOSED`
  with no mutex, no audit and no folder. Past the gate, in the suite only: a per-user mutex tried without waiting
  (never the clean lock B8), the audit and nothing else (V05-D8 (a)), one new record file in the pinned folder
  `%LOCALAPPDATA%\AgentTempManager\Monitor`, then the rotation of the product's own history files.
* **The reader** (`Get-AtmMonitorHistory`, `Get-AtmMonitorStatus`) needs no gate and takes no lock. It never creates
  the folder, never reads a `.partial`, and skips an invalid record as `HISTORY_RECORD_INVALID`. It leaves out the
  user's thresholds file `monitor.json` (a plain file with the expected owner), which the rotation passes and never
  removes.
* **Trends, thresholds and alerts (M2)** are read-only functions over what the reader found. They are computed only by
  `Get-AtmMonitorStatus`, and only with the gate open, so in no copy:
  * `Get-AtmMonitorConfig` reads `monitor.json` and never writes it;
  * `Get-AtmMonitorTrends` computes the 7-day least-squares slopes, the gaps and the delta;
  * `Get-AtmMonitorAlerts` computes the alerts, each naming a command (`AtmMonitorAlertCommands`) that is never run.

  `Report.ps1` adds their lines to `monitor status`. With the gate closed, `monitor.json` is not read and nothing is
  computed.
* **Enforced by tests** (the suite's areas "V0.5 M1", "V0.5 M2" and "V0.5 M3a", static cases):
  * a single assignment of the gate and of each seam;
  * every writing function reads the gate before anything else (the M3a definition, registration, `monitor enable` and
    entry function included); the readers write nothing;
  * no diagnose, clean, isolation, recovery, lock B8 or network name in the engine, except the declared helpers of the
    task functions: `Connect-AtmTaskScheduler` and the purge's read-only scheduler helpers, the console observation, and
    `Get-AtmIdentityState` once, in `Test-AtmMonitorStandardToken`;
  * the removal of a file appears in one function only (`Invoke-AtmMonitorPrune`), and nothing in the engine removes a
    task or the task folder;
  * the engine is loaded exactly in the `monitor` and `version` blocks and once by the collector's entry point;
  * the M2 functions call only a closed list of read functions, with no `&` and no write. They are called only by the
    status, inside the gate's `if`. Each command an alert names is a verb the launcher accepts.
