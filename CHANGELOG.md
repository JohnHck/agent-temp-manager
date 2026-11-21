# Changelog

## Unreleased (0.3.x: 0.3.1, after 0.3.0)

Work for 0.3.x, which comes after 0.3.0 (ADR-0013, ROADMAP "0.3.x"). It is not part of 0.3.0.
The code in this section reports version 0.3.1, which is not published: 0.3.0 is the latest published version.
**A fifth release gate, `AtmIsolationEnabled`, is closed in every copy**: in every copy `isolate` only plans.
**A sixth, `AtmQuarantinePurgeEnabled`, is closed in every copy too**: in every copy `quarantine purge` only plans, and
no space is freed.

* Cross-user rows in CI, V10-S5 (ADR-0018 phase S5; V10-D7 (a)): **tests and docs only**. No file of `src`, `install/`, `tools/` or `.github/` changes, and no gate, format, classification, eligibility, B1 or RECENT change.
  * The install e2e creates a second disposable standard user exactly like the first (random name, `SecureString` password, Users only, not an administrator; disposable runners only, guard unchanged). Each user plants a dummy `claude-code` fixture in its own TEMP.
  * New e2e steps, gates closed: an elevated `audit` shows each base under its own owner with the planted partitions and classes; `preview` and `clean` with `-IncludeOtherUsers` stay at the gate's result, and without the switch the preview shows its requirement; an `audit` as the first user, not elevated, never reads the other profile's base and never reports it empty; F-05's owner rule with two real owners (one profile's `TEMP` pointed at the other's for one inventory, then restored); no new file in either base or product folder.
  * The second user's account and profile stay on the disposable runner. The raw outputs never go to the uploaded artifacts; the job log carries codes, counts and the labels A and B only.
  * New static case in the suite area "Ambiente de teste". [TESTING.md](docs/TESTING.md) lists the steps; the ADR-0018 section 6 row "Multi-user" moves the cross-user rows from the operator to CI.
* Generic test-only provider and the third-party guide, V10-S3 (ADR-0018 phase S3; V10-D1 (d), part (c)): **tests and docs only**. No file of `src`, `install/`, `tools/` or `.github/` changes, and no gate, format, classification, eligibility, B1 or RECENT change.
  * New suite area "Provider generico" (both shells). A test-only factory turns a JSON definition (data only) into a contract 2 provider whose members are fixed code. Two definitions, one with `runtime` and one without, go through the audit, preview and diagnose paths and the conformance checks of V10-S1, which are now shared functions. Bad definitions are refused with the exact key, including a shipped id or temporary subfolder. A generic root laid out like a `claude-code` root never gets the B1 restricted exception. Nothing of it is in `src` or the manifest.
  * The V10-S1 dry addition also adds both definitions to the copy of `src`; the engines stay byte for byte the same.
  * [PROVIDERS.md](docs/PROVIDERS.md#writing-a-provider): new section "Writing a provider", the guide for third parties.
* Format contracts, V10-S2 (ADR-0018 phase S2; V10-D3 (a)): every output and input format has a class (stable, internal or log), rules and a test, in the new [FORMATS.md](docs/FORMATS.md). No gate, classification, eligibility, B1 or RECENT change, and no other format changes.
  * `audit -ExportJson` gains `"schema": "atm.audit/1"` as its first member; the rest of the document is byte for byte the same. A reader that ignores unknown fields reads it unchanged. It still writes the machine, account names, SIDs and paths without pseudonyms (SECURITY-MODEL note).
  * The per-verb exit codes are a stable contract, published in FORMATS.md and USAGE.md (the same table), with the overloads of `2`, `3`, `6` and `10`. No code changes.
  * New suite area "Contratos de formato" (both shells): `atm.audit/1` against the export of before (byte for byte); one golden per version of `atm.audit/1` and `atm.diagnose/2`, field by field; the exit-code table against a static reading of every `exit` of the launcher and the two entry points (an undocumented or unreachable code fails); the recovery engine's codes both ways; readers of the current version of `monitor.json` and of the quarantine policy (unknown keys refused); fixed fixtures of the monitoring record and the quarantine manifest, with another version refused; the closed inventory of schema ids in FORMATS.md against `src`.
* Provider contract, V10-S1 (ADR-0018 phase S1; V10-D5 (b), V10-D8 (a)): contract 2 is frozen as the stable contract and documented completely in [PROVIDERS.md](docs/PROVIDERS.md). No gate, format, classification, eligibility, B1 or RECENT change.
  * `docs/PROVIDERS.md`: the inputs (`$ProfileInfo`, `$Snapshot`), the return shapes, "cannot look" versus "nothing found", the five `State` values and the provider-side liveness rule, `GetWorktreeHints` reserved (not called in 1.x), the provider-private fields, the versioning rules (v1 accepted in 1.x), and the B1 restricted exception tied to `claude-code`.
  * Stricter registration: with `temp`, the five `Get*` members must be script blocks (`err.providerTempMember`) and `ScopePattern`/`RootPattern` must compile (`err.providerPattern`); the messages name the member, never the value. `ContractVersion` must be the integer 2: text such as `'2'` or `' 2 '`, `2.0`, a list and `$null` are refused. Both shipped providers pass unchanged; a provider file that fails registration still stops the launcher.
  * New suite area "Contrato de provider" (both shells): every registration rule with its key, unknown versions in registration, diagnose and recover, "cannot look", liveness, no credential read, no write, no weaker gate, the static proof of provider literals in the engines, the dry addition of a provider to a copy of `src`, and a golden comparison of the inventory against rows generated before the change (identical). [ADR-0018](docs/adr/ADR-0018-v10-stabilization-multi-agent.md) is ACCEPTED.
* Design, V10-ADR (docs only): [ADR-0018](docs/adr/ADR-0018-v10-stabilization-multi-agent.md), PROPOSED, designs V1.0: the provider contract today and its versioning, the machine-readable formats and their stability classes, the conformance suite, candidate providers beyond Claude, the security review, the acceptance CI cannot prove, and "stable" with the gates closed. It asks the maintainer V10-D1 to V10-D8; nothing is implemented and no gate, format or code changes.
* Preventive monitoring, V05-M5 (ADR-0017 phase M5, the last phase of V0.5): the history and the alerts in the TUI, the GUI and the audit, **read only**, behind **the ninth gate, closed in every copy**. V0.5 is complete behind its gate.
  * TUI: new menu key `M`, "Preventive monitoring: history and alerts (view only)". Entering the screen reads the status and the collection task's state once; `U` reads again. It shows the lines of `monitor status`. A failed read shows its code only.
  * GUI (behind its own gate `AtmGuiEnabled`, closed in every copy): new area "Preventive monitoring", key `M` or its button. One status per opening. It shows the history, and with the gate open the total, the delta, the trend, up to 5 groups, the thresholds and the alerts, each command as text. The collection task's state is never shown. Nothing in the area runs.
  * The GUI's closed list gains exactly one name, `Get-AtmMonitorStatus` (28 to 29; ADR-0014 section 3).
  * `agent-temp audit`: at most one line under the first header, with the count of alerts, their codes and `agent-temp monitor status`, or a failure's code. With the gate closed (every copy) nothing is read and the output is unchanged. The line never enters `-ExportJson` and never changes the exit code.
  * New suite area "V0.5 M5". The M1, M2 and M3a statics allow the TUI and the GUI exact names only, the launcher loads the engine in `audit`, `gui` and `tui` too, and the six counts of the closed list are 29.

* Preventive monitoring, V05-M4b (ADR-0017 phase M4b; V05-D9 (a)): removal of the history, behind **the ninth gate, closed in every copy**, and the uninstaller's warning.
  * New subverb `agent-temp monitor remove-history`. With the gate closed (every copy) it refuses with `MONITORING_GATE_CLOSED` before it reads or asks anything (exit `3`).
  * Past the gate (the suite only, in its sandbox), in order:
    * the console the engine observes;
    * the collection task confirmed absent (`MONITOR_HISTORY_TASK_PRESENT` otherwise, naming `monitor disable`);
    * the history folder (`MONITOR_HISTORY_ABSENT`, or its code when the product refuses it; nothing created to check it);
    * the inventory: anything the product did not create refuses the whole removal with the count (`MONITOR_HISTORY_UNEXPECTED`);
    * the plan, then the phrase `REMOVER HISTORICO DO MONITORAMENTO`;
    * the collector's mutex without waiting (`MONITOR_HISTORY_BUSY`), and the inventory again under it (`MONITOR_HISTORY_CHANGED`);
    * each file through the engine's file removal, the first failure stopping the rest; then the empty history folder, through a second, non-recursive removal on its exact path.
  * The user's `monitor.json` is never removed, so with it the folder stays. `%LOCALAPPDATA%\AgentTempManager` is never removed. Exit codes `0`, `2` (`-IntervalHours`), `3` and `6`. The collection task is not touched.
  * The uninstaller only reads and warns: the current user's monitoring task (naming `monitor disable`), other users' counted and never named, and the history folder as the literal `%LOCALAPPDATA%\AgentTempManager\Monitor` (naming `monitor remove-history`). It removes nothing of the monitoring.
  * New suite area "V0.5 M4b"; the M1, M2, M3a and P6b statics now expect the monitoring engine's two exact removals. The install e2e checks there is no monitoring warning without task and history, and the warning with a planted history folder.
* Preventive monitoring, V05-M4a (ADR-0017 phase M4a; V05-D9 (c)): removal of the collection task, behind **the ninth gate, closed in every copy**, and the shared task folder removed when empty.
  * New subverb `agent-temp monitor disable`. With the gate closed (every copy) it refuses with `MONITORING_GATE_CLOSED` before it reads or asks anything (exit `3`).
  * Past the gate (the suite against an in-memory fake scheduler, and the M3b harness on the CI), in order:
    * the console the engine observes;
    * the product's exact task of this user (`MONITOR_TASK_ABSENT`, `MONITOR_TASK_UNREADABLE`, `MONITOR_TASK_DIVERGENT`, with nothing touched);
    * the plan;
    * the phrase `DESATIVAR MONITORAMENTO`;
    * the task checked again just before it is removed, and read back absent (`MONITOR_TASK_NOT_VERIFIED` otherwise).
  * It needs no standard token. Exit codes `0`, `2` (`-IntervalHours`), `3` and `6`, as `unschedule-autopurge`. The history is not touched.
  * `quarantine unschedule-autopurge` and `monitor disable` remove the Task Scheduler folder `\AgentTempManager` once their task reads back absent, only when it holds no task (hidden ones included) and no subfolder.
    * One helper does this, and it takes only the product's constant.
    * The scheduler's own `DeleteFolder` is the final limit: a refusal keeps the folder with the scheduler's code.
    * There is no second attempt, no elevation, no ACL change and no task removal.
    * The folder's outcome (removed, absent, not empty with the counts, kept with the code) is shown in one line and never fails the command.
    * `unschedule-autopurge` no longer says that the folder stays.
  * The task line of `version` and `monitor status` names `monitor disable` only where the gate is open.
  * The M3b harness now removes its test task with the product's removal and records the folder's state per leg.
  * New suite area "V0.5 M4a", plus CI-only cases:
    * the folder removed after the last task, and kept with another task;
    * the scheduler refusing `DeleteFolder` on a folder that holds a task;
    * `monitor disable` on the real scheduler under a test task name, with the gate opened only in the suite's memory.
  * **Nothing is scheduled or removed in any copy.** `monitor remove-history`, the uninstaller (V05-D9 (a)) and the TUI and GUI (M5) are not implemented.
* Preventive monitoring, V05-M3b (ADR-0017 phase M3b), test only: **no product code changed; the ninth gate stays closed in every copy.** A new CI-only harness, `tests/e2e/Invoke-MonitorE2E.ps1`, is on the build's CI-only list, so it is never shipped and an archive that contains it is refused. The install e2e runs it against the installed copy on disposable runners, under a test task name `MonitorTest-<8 hex digits>`, with the gate opened only in the harness's memory:
  * as the install e2e's standard user (no new account mechanism): the engine registers the user's own task, reads it back exactly (interactive, limited, no password, the exact action, `PT6H`), refuses a duplicate, runs it once (last result `3` expected, the installed gate closed; NOT_TESTED with the scheduler's state and code when the scheduler does not start it), and the harness removes it by its exact name and reads back absent;
  * as the elevated runner account: `monitor enable` is refused with `MONITOR_TASK_REQUIRES_STANDARD_TOKEN` before any plan or phrase;
  * in both legs, the installed `monitor enable` exits `3` with the gate closed.

  New suite area "V0.5 M3b": the harness's refusal path and its statics. In the first CI run, on all six install e2e jobs, the standard user's run once was NOT_TESTED (the scheduler did not start the interactive task: last result `0x00041303`), and the runner account's own test task ran with last result `3`.
* Preventive monitoring, V05-M3a (ADR-0017 phase M3a; V05-D2 (a) unchanged): the collector's scheduled task, behind **the ninth gate, `AtmMonitoringEnabled`, closed in every copy**. New subverb `agent-temp monitor enable [-IntervalHours 1|2|4|6|12|24]` (default 6): with the gate closed (every copy) it refuses with `MONITORING_GATE_CLOSED` before it reads or asks anything (exit `3`). Past the gate (the suite only, against an in-memory fake scheduler): an interval in the list, a standard token, an installed copy, the console the engine observes, no existing task (never replaced; `TASK_CREATE`), the plan, the phrase `ATIVAR MONITORAMENTO`, the registration and an exact read-back. The task, `\AgentTempManager\Monitor-<16 hex digits of SHA-256(SID)>`, is the user's own: interactive, limited, no password, every N hours with no end, a missed run at the next opportunity, one at a time, one hour at most, one action running the new entry point `bin\agent-temp-monitor.ps1` (no arguments; the manifest checked before anything is loaded, exit `5`; the gate read on every run, closed: exit `3` with nothing collected). `version` and `monitor status` show the task's state, read only; a task left by another copy is shown as a residue that this version has no command to remove. `Connect-AtmTaskScheduler` stays in `Engine.Isolate.ps1`. `-IntervalHours` is refused by `monitor status` and `recover` and ignored by the other verbs. New exit codes of `monitor`: `3` and `6` for `enable`. **Nothing is scheduled or collected in any copy.** The real scheduler is validated by M3b's CI harness, next; removal (M4) and the TUI and GUI (M5) are not implemented.
* Preventive monitoring, V05-M2 (ADR-0017 phase M2; V05-D10 (a)): trends, thresholds and alerts, computed only when the history is read with **the ninth gate, `AtmMonitoringEnabled`, open, which no copy has**. The thresholds live in `monitor.json` in the history folder, the user's own file: the product never writes, creates or fixes it, and the rotation never removes it. A file with a reparse point, another owner, over 4 KB, not strict UTF-8, not a JSON object, with an unknown member, a wrong type or a value outside its fixed bounds is refused as a whole: the defaults apply and `MON_CONFIG_INVALID` shows the reason. Trends are 7-day least-squares slopes from complete values only (`INSUFFICIENT_DATA` under 4 points or 24 hours; a gap is never a decrease; `CLOCK_SKEW` left out). The alerts `MON_TOTAL`, `MON_GROWTH`, `MON_ORPHAN_SUSPECTED`, `MON_LIVENESS_UNKNOWN`, `MON_COLLECTION` and `MON_CONFIG_INVALID` each **name a command and run none**; `MON_RECOVERY` is out of V0.5. With the gate open, `monitor status` adds the total and its delta, the trend, up to 5 groups, the thresholds' state and the alerts. With the gate closed (every copy), nothing changes: no trend, no alert, and `monitor.json` is not read. No new exit code. The `audit` header line is deferred to M5.
* CI, CI-BUDGET (no product code, test or gate changed): the suite jobs' time limits rise before V05-M2, since the measured margin fell under 10 minutes (`test ARM64 (powershell)` took 37m52s to 39m06s of 45; `test (powershell)` about 29.5 of 40): `test` 40 to 60 minutes, `test ARM64 (powershell)` 45 to 70, `test ARM64 (pwsh, subset)` 55 to 75. A limit only bounds a hang. The check names do not change. ADR-0016's four present-tense "eight gates" sentences now also say nine since V0.5 M1.
* Preventive monitoring, V05-M1 (ADR-0017 phase M1; V05-D8 (a)): a new engine `lib\Engine.Monitor.ps1` with **a ninth release gate, `AtmMonitoringEnabled`, closed in every copy** (checked by the build, the installer, the three e2e harnesses and `version`). Behind it, the collector runs the audit only and writes one `atm.monitor/1` record per collection (aggregates per provider, project display name and class; never a SID, account, path, slug, partition name or machine name) into the pinned folder `%LOCALAPPDATA%\AgentTempManager\Monitor`, then rotates the product's own history files (90 days, 400 files, 8 MB). New read-only verb `agent-temp monitor status` (exit `0`; any other `monitor` subverb is a usage error, `2`): with the gate closed it says monitoring is not available and shows what the history folder holds, without creating it. **Nothing is collected, written or scheduled in any copy.** ADR-0017 becomes ACCEPTED: V05-D8 (a), V05-D9 (a) plus (c) and V05-D10 (a) were decided on 2026-11-18, as recommended. Trends and alerts (M2), the scheduled task (M3), removal (M4) and the TUI and GUI (M5) are not implemented.
* Preventive monitoring, V05-M0 (ADR-0017 phase M0, documentation only; nothing implemented, no gate changed): ADR-0017 becomes ACCEPTED in part. V05-D1 to V05-D7 were decided on 2026-11-17, as recommended; V05-D8, V05-D9 and V05-D10 stay open. The amendments are: PRIV-3 in `docs/ELEVATION.md` admits two per-user scheduled tasks, the automatic purge's (implemented) and the monitoring's (planned for V0.5 M3, gate closed in every copy); the scheduler sections of `SECURITY-MODEL.md` and `ARCHITECTURE.md` name both tasks, the deliberate gate difference, and the shared `\AgentTempManager` folder, whose removal is pending V05-D9; ADR-0014 section 3 lists one future history-read function for the GUI (V0.5 M5); the ROADMAP records the reading of "never deletes" under V05-D4 (a). The monitoring gate will be the ninth, `AtmMonitoringEnabled`. ADR-0010 is unchanged (V05-D5 (a)).
* Assisted recovery, V04-R6 (ADR-0016 phase R6, V04-D8 (a), CI only; no product file changes): a CI-only harness, `tests/e2e/Invoke-RecoverE2E.ps1`, runs the real start (R2) and the real undo (R3) end to end in the six `install e2e` jobs. Elevated, it creates its own inert test services (an executable it compiles itself, always through Windows PowerShell 5.1, in a run root it creates atomically with a protected DACL; seven services named `AtmRecE2E-<nonce>-<key>`, each checked absent first, manual or disabled, the default account; their security descriptors never changed). Then leg A (the VM's standard user) and leg B (elevated) load the installed engine, open the recovery gate in their own process memory only, and call `Invoke-AtmRecover` and `Invoke-AtmRecoverUndo` with an in-memory test provider (`-Providers`) and guard wrappers (`-ServiceControlImpl`, `-ServiceStopImpl`) that accept only this run's names and call the default seams with exactly the engine's argument. Cases: a real start and its real undo; the refusals before the seam (not declared, image mismatch, disabled, already running) with zero seam calls; the dependencies (an undeclared stopped dependency refused; whether the service control manager starts a declared stopped dependency, measured; the undo of a dependency while its dependent runs, refused by R3 before the seam); leg A's start as a standard user; the undo of leg A's log by leg B (provenance). Leg B ends by stopping every own service that is not stopped; none is removed. The eight installed gates and the SHA-256 of every installed file are checked before and after; only a summary with codes and counts is uploaded. The harness is on the build's CI-only list, out of the package, and the install e2e checks that. A new suite area `V0.4 R6` runs its refusal path and its statics. **The recovery gate stays closed in every copy; real deletion stays disabled in every copy.**
* Assisted recovery, V04-R5 (ADR-0016 phase R5, presentation only): the TUI and the desktop GUI get a recovery area, key `S`, that shows `recover list` and, on `Enter` over a row, `recover plan` for that declared service, with the CLI's own lines (new shared formatters `Get-AtmRecoverListLines` and `Get-AtmRecoverPlanLines` in `Report.ps1`) and a note that executing is CLI-only (T-ISO-6) and, with the gate closed, that `recover start` shows the plan and exits 27. Entering the area makes one fresh read-only collection; moving, opening a plan, a re-audit, `F5` and the GUI's live monitoring never collect. No service name is typed, and no key, button or menu starts, undoes, relaunches, elevates, takes the lock or writes a log. The launcher also loads the recovery engine for `tui` and `gui`. The GUI's closed list (ADR-0014 section 3) gains the five read names and refuses the recovery execution names and `AtmRecoveryEnabled`; a new TUI static refuses them too. **The gates `AtmRecoveryEnabled` and `AtmGuiEnabled` stay closed in every copy; executing recovery stays CLI-only; real deletion stays disabled in every copy.**
* Assisted recovery, V04-R4 (ADR-0016 phase R4, V04-D3 (b) elevation on demand through UAC): two CLI verbs, `agent-temp recover start -Operation REC-SVC-START -Service <exact declared name>` and `agent-temp recover undo -RunId <run id>`, one operation per process, with no other option (usage errors exit 2). **The gate `AtmRecoveryEnabled` stays closed in every copy, and no shipped copy requests elevation**: both verbs show the plan, or for undo the inverse plan when the recovery log folder can be read and otherwise the request, then exit 27; nothing is asked, locked or logged. Past the gate (the suite only, with the elevated launcher injected): an elevated administrator token acts in its own process; any other token shows the plan and a UAC notice and relaunches the installed `bin\agent-temp.cmd` once with fixed arguments and a marker (default launcher: `ShellExecuteEx` with `runas`, never reached by the suite or the CI), reads no log and reports only by exit code (UAC outcomes 40 to 44, never a reason guessed from one number). The relaunched copy accepts only its fixed arguments, an elevated token and an installed, verified copy, shows the identity that acts (its requester is shown as not verified: PRIV-5 stays partial), redoes every step and waits for a key. The logs go to a fixed folder, `<CommonApplicationData>\AgentTempManager\recover\<run id>.log`, which only `Install-AgentTempManager.ps1` creates (owner Administrators, a protected DACL with full control for SYSTEM and Administrators only); the installer refuses an existing folder that differs, the uninstaller keeps it, and the engine checks it before every use and never creates or fixes it. Exit codes are listed in `docs/USAGE.md`. Tested in the suite (area `V0.4 R4`) and the install e2e. Real deletion stays disabled in every copy.
* Assisted recovery, V04-R3 (ADR-0016 phase R3): `Invoke-AtmRecoverUndo` in `lib\Engine.Recover.ps1` undoes one `REC-SVC-START` run by stopping its service (`REC-SVC-STOP`, which exists only as that undo: never in the catalog, `recover list`, `recover plan` or `Invoke-AtmRecover`). **The gate `AtmRecoveryEnabled` stays closed in every copy, and no command calls it yet** (the CLI verb comes in phase R4). The source is the run's log (`-SourceLog`, with `-RunId` as a cross-check), read once as untrusted data: a regular file of at most 1 MiB with no reparse point, the owner and protected DACL of a log, strict JSON lines of one complete R2 run whose outcome is `COMPLETE` or `PARTIAL`, each failure with its own `UNDO_SOURCE_*` code. The service must still be declared and in the recorded "after" state, field by field (for a `PARTIAL` run that ended pending, only the natural move to `RUNNING`: state, checkpoint, wait hint, condition and accept-stop), `RUNNING`, accepting a stop, with every dependent `STOPPED` (read from the capture). Past the gate, R2's steps in R2's order with the phrase `PARAR SERVICO <planid8>`; the default stop seam is a new narrow class in `Native.cs` (`AtmServiceStop`: connect access to the service control manager, the stop right only, one `SERVICE_CONTROL_STOP`), never `ServiceController.Stop()`, which stops running dependents first. The suite never reaches it. Tested in the suite (area `V0.4 R3`). Real deletion stays disabled in every copy.
* Assisted recovery, V04-R2 (ADR-0016 phase R2): `Invoke-AtmRecover` in `lib\Engine.Recover.ps1` starts one declared service past the recovery gate, through a service control seam. **The gate `AtmRecoveryEnabled` stays closed in every copy, and no command calls it yet** (the CLI verb comes with the UAC relaunch, phase R4): with the gate closed it returns the plan and `RECUPERACAO_REAL_DESABILITADA`, asks nothing, takes no lock and writes no log. Past the gate (the suite only, with the seam injected): a console observed by the engine, a new `-LogFile` outside the bases, a fresh collection with the R1 criteria (any refusal stops before asking, `RECOVERY_IMAGE_NOT_DECLARED` included, by the maintainer's decision of 2026-11-17), the plan, the clean lock (B8), the log `atm.recoverlog/1`, the phrase `INICIAR SERVICO <planid8>`, a revalidation that names each changed field, the seam with the service name only, a bounded settle wait, and the outcomes `COMPLETE`, `PARTIAL`, `FAILED`, `REFUSED` or `EXCEPTION` with a field-by-field diff of "before" and "after". Nothing is ever compensated. The default seam (`ServiceController.Start()`, the start right only) is never reached by the suite. Tested in the suite (area `V0.4 R2`). Real deletion stays disabled in every copy.
* Assisted recovery, V04-R1 (ADR-0016 phase R1): a new engine `lib\Engine.Recover.ps1` with **an eighth release gate, `AtmRecoveryEnabled`, closed in every copy** (checked by the build, the installer, both e2e and `version`). `agent-temp recover list` and `agent-temp recover plan -Operation REC-SVC-START -Service <exact declared name>` make a fresh read-only collection with the diagnose's functions and apply closed criteria (`RECOVERY_*` refusal codes); an offered plan shows the "before" capture, the undo (`REC-SVC-STOP`, state only) and what it does not undo, the likely elevation from the token and a plan id. Nothing is asked, locked, logged or written, no service is opened or controlled, and every run ends with "Nothing was changed." Exits: list 0, plan 0 offered or 3 refused, usage 2. No shipped provider declares an `ExpectedImage`, so every real plan is refused (`RECOVERY_IMAGE_NOT_DECLARED`, `CoworkVMService` included); by the maintainer's decision of 2026-11-17 that stays a refusal from R2 on. Tested in the suite (area `V0.4 R1`). Real deletion stays disabled in every copy.
* Documentation, DOCS-SYNC-R0: `docs/DIAGNOSE-SCHEMA.md` lists the V04-R0 service fault-signal codes (`SERVICE_CONDITION` and its nine conditions, exit codes, checkpoint and wait hint, second read, dependencies, image comparison, unreadable and not-collected codes) with their values, and says none changes a state or authorizes anything; the `file:line` citations of ADR-0016 and ADR-0017 that R0 shifted point at the same lines again. No gate changes.
* V5 pilot evidence tools, V5-TOOLS-ISO (maintainer decision of 2026-11-17: the isolation and purge pilot runs in the same V5 VM): `Get-AtmPilotSummary.ps1` also reads the isolate, restore and purge logs (`atm.isolatelog/1`, `atm.purgelog/1`), with a new `log.kind` and closed lists per kind; an entry id or a plan id is refused anywhere in a summary (summary schema 2). `Compare-AtmPilotSnapshot.ps1` accepts a root born whole under `-ExpectedNew '<label>:\'` and a new `-ExpectedTouched` for a folder whose last write time only changed (format 2). Tested in the suite (area `V5 tools`). No gate changes: real deletion, isolation and purge stay disabled in every copy.
* Diagnose, V04-R0 (ADR-0016 now ACCEPTED: decisions V04-D1 to V04-D8 decided, D3 (b) elevation on demand through UAC, the others as recommended; phase R0 only): read-only fault signals for each provider-declared service. The same CIM query now reads `ExitCode`, `ServiceSpecificExitCode`, `CheckPoint`, `WaitHint` and `AcceptStop`, and the dependencies are read in both directions (`Win32_DependentService`, `Win32_BaseService`); no method is called and no service handle is opened. A stopped service is classified `STOPPED_CLEAN`, `STOPPED_NEVER_STARTED`, `STOPPED_FAILED` or `STOPPED_EXIT_UNREADABLE`. A pending service gets one second read after its `WaitHint` (capped at 2 s, inside the deadline), classified `PENDING_PROGRESSING`, `PENDING_STALLED`, `PENDING_UNCHANGED`, `PENDING_STATE_CHANGED` or `PENDING_SINGLE_READ`. An unreadable value is reported as such. A related service is named only when declared or a system service. A new optional provider field `ExpectedImage` is compared in memory and gives `IMAGE_MATCH`, `IMAGE_MISMATCH` or `IMAGE_UNKNOWN`, never a path; `CoworkVMService` declares none, because no public source names its executable. The CLI shows one new line per service. No condition changes a state or authorizes anything, and no gate changes. Tested in the suite (area `V0.4 R0`).
* Documentation, V05-ADR: ADR-0017 (PROPOSED) designs V0.5 persistent preventive monitoring. It lists the audit metrics a per-user history would keep (sums and counts per provider, project display name and class; never a path, SID, account, machine name or session identifier), compares a per-user scheduled task, a Run entry, a Startup shortcut, a service (excluded) and no mechanism, specifies one new file per collection with bounded size, trends that never read a gap as a decrease, alerts that only name a command, a new gate `AtmMonitoringEnabled`, phases M0 to M6 and open decisions V05-D1 to V05-D10. It names the accepted texts V0.5 would amend (PRIV-3, ADR-0010, ADR-0014 section 3). Nothing is implemented; no gate changes.
* Documentation, V04-ADR: ADR-0016 (PROPOSED) designs V0.4 assisted recovery. It inventories what the V0.2 diagnose detects (states, not faults: no finding says a service, VM, process, lock or worktree is stuck), catalogs candidate operations (only starting a provider-declared agent service is a first-phase candidate; stopping is irreversible in effect and refused by default; ending a process stays out), reuses AUT-2, revalidation, the B8 lock and a log with T1's contract, proposes an eighth gate `AtmRecoveryEnabled` in a new engine file, phases R0 to R6, and open decisions V04-D1 to V04-D8. Nothing is implemented; no gate changes.
* V5 pilot evidence tools, V5-TOOLS (ADR-0015 now ACCEPTED: decisions V5-D1 to V5-D8 approved as recommended; the pilot is not executed): three read-only operator scripts in `tools/v5-pilot/`, shipped in the release archive. `Get-AtmPilotSnapshot.ps1` lists folders with each file's SHA-256 and records reparse points without following them. `Compare-AtmPilotSnapshot.ps1` says whether only the expected change happened, with counts only. `Get-AtmPilotSummary.ps1` turns a T1 log into typed codes, counts and yes/no. It refuses any path, SID, `@` or name of the environment, and the privacy scanner must pass before the summary gets its final name. None of them deletes, moves or writes outside its output, loads the engine or uses the network. Tested in the suite (area `V5 tools`). No gate changes: real deletion stays disabled in every copy.
* Documentation, V5-VM-DESIGN: ADR-0015 (PROPOSED) designs the V5 pilot of real deletion in a disposable VM (maintainer decision D-C). It covers what the pilot must prove, the VM options compared, RECENT kept as it is (no clock change, no ageing), the mechanism that opens the deletion gate only inside the VM, the real root, the operator's steps, the acceptance criterion and open decisions V5-D1 to V5-D8. Nothing is executed, and the gate stays closed in every copy.
* Desktop GUI, V021-P6 (V0.2.1 phase P6, the last; P1 to P6 implemented, gate still **closed in every copy**): languages, accessibility and the close. Every visible text, accessible name and column header comes from the catalog in the language chosen at start (`-Lang`, `ATM_LANG`, the UI culture). Every control has an accessible name, and the tab order follows the visual order (the monitoring controls moved under the header). `Enter` on a focused button presses it, as Space does; on the monitoring box and the interval it does nothing; on a list it opens the row. Only system colors are used. Fixed widths go through one DPI scale function. The suite checks every text on the real window in both languages, the whole keyboard walk, and six close paths that leave no process, file, registry value or timer behind. No new engine name or cmdlet.
* Desktop GUI, V021-P5 (V0.2.1 phase P5; gate still **closed in every copy**): the live monitoring. A check box (access key `M`), off every time the window opens, and a fixed interval list (30 s, 60 s by default, 2, 5, 10 and 15 min) that cannot be typed into; nothing is remembered. Turning it on runs nothing: one `System.Windows.Forms.Timer`, created in one place and only while the window is open, wakes a check that audits through the `F5` path once the interval has passed. The open screen stays (on a preview screen the preview is computed again); the diagnose never runs by itself. A tick during an audit, the preview or the diagnose is dropped, never queued. `STALE` now also says when the last audit was slow (the next one then waits twice its duration) or old (no good audit for twice the interval); a failure keeps everything, with the exception code only. Closing the window stops and releases the timer. No new engine name or cmdlet. CI: the `test` job's limit goes to 40 minutes, the ARM64 jobs' to 45 and 55.
* Desktop GUI, V021-P4b (V0.2.1 phase P4b; gate still **closed in every copy**): the diagnose area. Key and button `D` opens the TUI's diagnostics area with its categories, rows, order and text, read from the schema view only (no identity, path or machine name); `Enter` opens a row and `Esc` goes back. The diagnose runs once on the first `D` and again only on `U` inside the area; an audit keeps the result, and nothing runs by itself. Collectors kept off by a closed gate are shown as "disabled in this version", the one difference from the TUI. A failure shows only the exception code; a close during a run discards it. The closed list grows by two names and the allowed cmdlets by `ConvertFrom-Json`; no export and no Git run.
* Desktop GUI, V021-P4a (V0.2.1 phase P4a; gate still **closed in every copy**): the preview of the cleanup. Keys and buttons `P` (every root with its category) and `8` (the blocked paths), with the TUI's rows, order and text, and a fixed notice that the preview is an evaluation only; `Enter` opens the detail with a `Preview` line. Computed by `Invoke-AtmPreview` once per audit, when first opened, and discarded by the next audit; a failure shows only the exception type. No action over a root or a category; the closed list gains no name. The diagnose area came in P4b, above.
* Desktop GUI, V021-P3 (V0.2.1 phase P3; gate still **closed in every copy**): the drill-down. Screens of users, projects, roots (by user, project and class), the detail of a root and coverage and errors, with the TUI's rows, order and text; keys `1` to `7` and `9`, a button per screen, `Enter` to open a row, `Esc` to go back (it closes only on the dashboard), `F5` from any screen. A detail whose root is gone after an audit goes back to the list. Read-only: no action on roots, no preview. The closed list grows by four read-only engine helpers.
* Desktop GUI, V021-P2 (V0.2.1 phase P2; gate still **closed in every copy**): the window's dashboard. A header (identity, elevation, language and the view's state `UNKNOWN`, `CURRENT`, `PARTIAL` or `STALE`, as words), the automatic purge notice (GUI-D1), and the TUI dashboard's four groups and class counts in read-only lists, with the TUI's numbers. One audit when the window opens, then only on Refresh or `F5`, on the UI thread; a request during an audit is ignored, and a close cancels it. A failed audit keeps the earlier result, with the exception type only. No timer, diagnose, quarantine list or clipboard. ADR-0014 records GUI-D1 to GUI-D6 as decided by the maintainer. The real isolation harness checks seven installed gates.
* Desktop GUI, V021-P1 (V0.2.1 phase P1): `agent-temp gui` and a seventh release gate, `AtmGuiEnabled`, **closed in every copy**: the command prints `GUI_GATE_CLOSED` and exits with code `7`, with no window and no Windows Forms loaded. Past the gate (tests only): exit code `8` without an STA thread, an interactive desktop or Windows Forms (`GUI_NOT_STA`, `GUI_NO_INTERACTIVE_DESKTOP`, `GUI_WINFORMS_UNAVAILABLE`), else a minimal read-only window with the identity and elevation state. The build, installer, manifest, install e2e and `version` check the new gate; a static suite test holds `lib\Gui*.ps1` to ADR-0014's closed list.
* Documentation, V021-ADR: ADR-0014 records the V0.2.1 desktop GUI design: WinForms on Windows PowerShell 5.1 / .NET Framework (maintainer decision D-B), engine, view model and form layers with a closed list of callable functions, its own release gate closed in every copy (D-A), bounded live monitoring only while the window is open, phases P1 to P6 and open decisions GUI-D1 to GUI-D11. Nothing is implemented.
* Documentation, ROADMAP-SYNC: the ROADMAP records the amended order rule (each version lands on `main` dark, behind gates closed in every copy, with its acceptance proven in CI; each gate and each release is the maintainer's decision) and the current status of every version.
* Inventory, F05-OWNER-ATTRIBUTION (F-05 option a): a `<TEMP>\claude` base that was read, outside `%WINDIR%\Temp`, is attributed only to the profile that owns its folder, in any enumeration order. Another profile naming it gets `OWNER_NOT_PROFILE`, and the base stays shared with it (`SHARED_TEMP`); an owner that cannot be read gives `OWNER_UNREADABLE`, and the base is attributed to nobody. Attribution changes only in these cases; cleanup stays blocked for shared bases, and no gate, B1, RECENT or eligibility rule changes.
* Installation, F14-VERIFY-WARN (F-14 option a): `verify` walks the installation (hidden and system files included, reparse points never followed) and prints a yellow `WARN` line, with the relative name only, for every file the manifest does not list (`manifest.json` and `install-state.json` at the root left out), every reparse point and every folder it cannot list; `config\quarantine.policy.json` created in the installation gets a hint (the next update records it). The summary counts the warnings. Exit codes unchanged: `0` with warnings only, `5` with problems; no other command walks the installation, and nothing changes in what is loaded.
* Documentation, SUPPORT-POLICY-0.3X: `SECURITY.md` documents that only the 0.3.x line is supported (security fixes are released as 0.3.y); 0.2.x and 0.1.x are no longer supported, and their users update with the installer.
* Isolation, ISO-PLANCHECK-REASONS (log only): the isolate `plan-check` record (`atm.isolatelog/1`, an additive field) now says why the plan changed: `reasons` (`ROOT_NOT_SEEN_ONCE (N)`, `PLAN_ITEM_CHANGED` with the names of the `changedFields`, or the gates' leading codes, `B1_EXCEPTION_NEW_UNINSPECTABLE_PROCESS (N)` keeping its count), `[]` when it matched; only codes, counts and field names. The revalidation rule, its order, the gates, B1, eligibility, the console text and the exit codes are unchanged; clean's `plan-check` (`atm.cleanlog/1`) too.
* Isolation, phase P6b: `agent-temp quarantine schedule-autopurge` and `unschedule-autopurge`, the user's own optional task of the automatic purge (J-ISO-7): created only by that command in a non-elevated terminal (refused when elevated, `AUTOPURGE_TASK_REQUIRES_STANDARD_TOKEN`), with an interactive console, the plan and the phrase `AGENDAR EXPURGO AUTOMATICO` (and its own phrase when the policy is off); one per user, `\AgentTempManager\AutoPurge-<hash>`, run as the user, not elevated, only with the session open, no credential; never replaced (`AUTOPURGE_TASK_EXISTS`); removed only when it is exactly the product's task (`AUTOPURGE_TASK_DIVERGENT` otherwise). `version`, `quarantine list` and the TUI show its state; the TUI shows the automatic-purge notice on every screen; the uninstall warns and never removes a task. PRIV-3 reworded. Real tasks are created only in CI.
* Isolation, phase P6a: the entry point of the automatic purge, `bin\agent-temp-autopurge.ps1` (no arguments; run by hand only, **no scheduled task**), verified by the manifest; with `autoPurge: true` in a valid policy it purges only the user's own `EXPIRED` entries whose `verify` is `OK`, through the manual purge's plan, gates, lock and deleter, with `automatic: true` and `declaredBy: AUTOMATIC_POLICY` in the manifest and its own log (`atm.autopurgelog/1`); a 7-day minimum retention and `FUTURE_DATE` skip; with the purge gate closed (every copy) it only reports. `version` and every report show `AUTOMATIC PURGE ON` while the policy has it.
* Isolation, ISO-FIX-VOL: the isolate plan refuses a root on another volume than the quarantine (`MOVE_OTHER_VOLUME`, contract sections 4.2 and 5), under the B1 exception too, before any question, log or entry; the rule (drive roots compared, ignoring case) is shared with the restore plan. The mover's own check (`OTHER_VOLUME`, volume serial numbers) stays unchanged as the second barrier. The e2e case of the second volume now requires the refusal at the plan.
* Isolation, phase P5b (CI only, nothing shipped changes): the same harness adds the section 6.1 measurement to its summary, a file held open by a harness process (before the plan and in the move window), an interruption after `move-intent` reconciled by the restore, clean and isolate contending in both orders (`BUSY`), a junction swapped in the window, a second fixed volume, and 200,000 files timed in one x64 job.
* Isolation, phase P5a (CI only, nothing shipped changes): the real isolate, restore (free and conflict) and purge, and the base and scope refusals, run end to end on the disposable `install e2e` VMs by the CI-only harness `tests/e2e/Invoke-IsolateE2E.ps1`, in both legs, with the gates opened only in its own process.
* Isolation, phase P4: `agent-temp quarantine purge -Entry <id> -LogFile <new file>`, retention, quota and policy.
  * The purge has a gate of its own (J-ISO-1 (C)). It is independent of the isolation gate and of the deletion gate, and
    is checked by the build, the install e2e (six gates) and `version`.
  * With the gate closed, `purge` checks the entry and shows the plan, then stops (`EXPURGO_REAL_DESABILITADO`).
    Nothing is asked, locked, logged or purged.
  * Refusals are `PURGE_REFUSED_<reason>`: an `INCOMPLETE`, `FAILED`, `ABANDONED`, `UNRECOGNIZED`, `RESTORED` or
    `PURGED` entry, one that `DIFFERS`, or one whose payload is missing. The gates of the path, ACL and in-use probe on
    the quarantine also refuse, and so does a command line that names the quarantine (B2-1 extended).
  * Past the gate:
    * the run needs the clean lock, a console, a new log (`atm.purgelog/1`), the declarations of the purge itself and
      `EXPURGAR <id8> <files> ARQUIVOS`;
    * then a revalidation, and `purge-intent` in the manifest and the log;
    * then one call to the same deleter as clean, with the manifest's measurement, and `purge-result`
      (`automatic: false`);
    * the entry stays as the trail (`PURGED`).
  * Retention: 30 days by default. It only marks an `ISOLATED` entry `EXPIRED`, shown with its date in `list` and
    `inspect`, and never purges.
  * Quota (off by default): once reached, `list` warns and new isolations are refused (`QUARANTINE_QUOTA_REACHED`).
    Isolations are also refused below a free-space minimum fixed in code (`LOW_DISK_SPACE`). Neither rule ever purges.
  * Policy: optional `config\quarantine.policy.json` (`atm.quarantine-policy/1`: `retentionDays`, `quotaBytes`,
    `autoPurge`), with a strict schema. An invalid file counts as off, with a warning. `autoPurge: true` is shown and
    does nothing. `version` and `list` show the effective policy, and an update keeps the file.
  * TUI: shows `EXPIRED`, `PURGED`, the policy and the purge CLI command. It never purges.
* Isolation, phase P3b: `agent-temp quarantine list | inspect | verify | restore`.
  * list, inspect and verify only read, in every copy. restore shows the plan only while the isolation gate is closed.
  * Past the gate: lock, console, new log, `RESTAURAR <id8>`, revalidation, the same mover back; on a conflict an
    engine-generated `<name>.restored-<id8>` with its own phrase; reconciliation of an `INCOMPLETE` entry (T-ISO-5).
  * TUI: I isolates a root (plan only), Z shows the read-only Quarantine area and the restore CLI command.
* Fix (FIX-TRUSTED-SIDS): each engine now has its own list of trusted accounts.
  * The diagnose engine's Git location rule had reused the name of the clean engine's list (gate 4) without OWNER
    RIGHTS. Being loaded later, it replaced that list, so gate 4 refused an OWNER RIGHTS entry as a third-party writer.
  * Gate 4, and isolation through it, now uses the list declared in `Engine.Clean.ps1`. OWNER RIGHTS only grants rights
    to the owner, which the gate requires to be the profile SID, so no other writer is accepted.
  * The Git rule keeps its stricter list unchanged (`AtmGitTrustedWriterSids`).
* Isolation, phase P3a (past the isolation gate only; no distributed copy reaches it): one session root of the own
  profile per run.
  * The run takes the clean lock (the same name), needs an observed console and a new `-LogFile`
    (`atm.isolatelog/1`), and asks for `ISOLAR 1 CAMINHOS <plan id>` (no discard declarations). For a root under the B1
    exception it asks for that root's risk phrase first.
  * The plan is checked again, then the root is revalidated immediately before the move.
  * A new entry is created in `%LOCALAPPDATA%\AgentTempManager\Q` (created with protected DACLs, or checked and never
    fixed), with an `atm.quarantine/1` manifest that has no file names, contents or command lines.
  * The intent is written to the log and the manifest before the move. The move is a same-volume rename through the
    pinned handle, measured before and after. The result is recorded in both.
  * Anything but a moved and verified tree stops the run; nothing is undone.
* Isolation, phase P2: `agent-temp isolate -Path <session root>` plans and stops (exit code `3`). Own profile and
  session roots only; a scope or the whole base is refused with its own code. The same gates as clean apply, RECENT
  included. `version` shows `isolation: DISABLED`. The build and the installation tests check the new gate.
* Isolation, phase P1: native primitives in `Native.cs` (the mover, new directory, append to an existing record). Measured
  on every CI image: an open handle inside a tree makes the rename fail, and nothing moves.

## 0.3.0

Its publication is the GitHub Release `v0.3.0` (tag `v0.3.0`) only, created with the maintainer's explicit
approval. **Real deletion stays disabled in every copy**: with the deletion gate closed, `clean` still only validates
and shows the plan. What changes for users is listed in
[docs/release/V0.3.0-RELEASE-NOTES.md](docs/release/V0.3.0-RELEASE-NOTES.md): `ELIGIBLE_WITH_DECLARED_RISK` shown as "not
released" in preview, audit and the TUI; the `authorize` command; the V0.2 runtime evidence in preview and the plan. The
entries below that say "past the deletion gate" are inactive in every copy. The operator ran the dedicated base runbook
and the privilege-matrix rows with the gate closed (V4) on a real machine; a release with the gate open requires the
operator's pilot (V5) and its own gate. Release record: [docs/release/V0.3-RC.md](docs/release/V0.3-RC.md).

* Since the release candidate: no code change after `0c17a9f`. Up to `bc28523` only documentation changed (ADR-0013,
  PROPOSED, and the 2026-11-01 incident record). Isolation and quarantine (0.3.x) are not part of 0.3.0.

* Installer hardening (V0.3 BROADCAST-GUARD): the environment broadcast writes its child's script in the current TEMP
  and runs it elevated, so it now refuses (the existing compile-failure error) unless that TEMP is the private,
  administrator-only TEMP that `Enter-AtmPrivateTemp` created and still holds (remembered by it, not inferred from the
  name), before anything is written. Every current caller already runs inside it: no behaviour change.
* Installer fix (V0.3 INSTALL-RACE): the `WM_SETTINGCHANGE` broadcast after a machine `Path` change (a fresh install
  or an uninstall, never an update) compiled its P/Invoke type in the installer's own process. Under Windows PowerShell
  5.1 that compiler's temporary files could be removed after it returned, while the cleanup of the private TEMP walked
  it (reparse-point check), so a fresh install failed now and then with "could not find a part of the path". The type
  is now compiled and the broadcast sent from a child Windows PowerShell, with a TEMP/TMP of its own inside the private
  TEMP, removed once the child has exited. The cleanup's reparse-point check and the ACL and manifest checks are
  unchanged. The installers of 0.1.0, 0.1.1 and 0.2.0 are published and keep the old behaviour; the e2e makes ONE
  new attempt of their fresh install, only for that failure (recorded in the step), never for the installer under test.
* Tests only: the `install e2e` jobs also install the published 0.2.0 (GitHub Release asset, SHA-256 pinned from that
  release's `SHA256SUMS.txt`), update it to the package under test, roll back, update again and uninstall, checking
  `version`, `verify`, the installed manifest's version and the four installed gates, as for 0.1.0 and 0.1.1.
* V0.3 fix (past the deletion gate only; no distributed copy reaches it): `Invoke-AtmClean` loads the verified native
  library before taking the clean lock. The lock comes before any inventory, and the library was otherwise loaded only
  by the first inventory, so a clean with no `-LogFile` (the CLI makes no inventory before the engine then) failed with a
  missing-type error instead of `LOG_REQUIRED`. Nothing was ever deleted (it failed before any inventory). With the gate
  closed nothing changes.
* V0.3 V3, phase V3c (tests only, no product change), completing V3: outcomes of the real deleter (partial, an
  inconclusive verification and an exception, the last two provoked by the harness), the log folder pinned during a
  run, a run that ends by itself after the intent or after the deletion (the log ends at the intent; the next clean
  finds the lock abandoned, the one after starts from scratch), a second clean while the first holds the lock (same
  account, and across the standard user and an elevated account in both orders: always `BUSY`), another object under
  the lock name, and shared bases. Details: docs/TESTING.md, "V3 as a whole".
* V0.3 V3, phase V3b (tests only, no product change): new entries, changes, a third-party ACL (fixture ACE on planted
  roots only) and new processes (of the same account, and in leg A of another account, started by a watcher of the
  e2e and ending by themselves) after the plan, in each window, with the real deleter. Proves that the deleter does not
  read the ACL again once everything is pinned (a declared limit). Details: docs/TESTING.md, "New entries, ACL and
  processes after the plan".
* V0.3 V3, phase V3a (tests only, no product change): the CI-only harness also attacks planted roots with reparse
  points and links and with files and folders in use, in each window of the flow (before the plan, before the final
  confirmation, before the revalidation, before the deleter and inside it once everything is pinned). Inside the deleter
  it uses the real deleter through a wrapper with the engine's own arguments (compared by a static test). Each case
  asserts its code, the log read back from the file, the number of calls to the deleter and that nothing outside the
  planned root changed. Details: docs/TESTING.md, "Adversarial cases on disposable VMs (V0.3 V3, phase V3a)".
* V0.3 V2 (tests only, no product change): the `install e2e` jobs run the real clean end to end on disposable
  GitHub-hosted VMs, through the CI-only harness `tests/e2e/Invoke-CleanE2E.ps1`, on roots it plants itself in a run root
  it creates. It loads the installed engine and opens the deletion gate only in its own process memory; the installed
  copy stays closed (checked by SHA-256). Real deleter, T1 log file, B8 lock and revalidation; automated confirmation,
  never a human acceptance; simulated recency (write times set back). Leg A as a non-elevated standard user (B1
  restricted exception), leg B elevated (ELIGIBLE only with complete measured coverage). The harness never ships:
  `tools/Build-Release.ps1` leaves it out and refuses an archive that contains it. Only a summary is uploaded. Details:
  docs/TESTING.md, "Real clean on disposable VMs (V0.3 V2)".
* V0.3 T1 (F-04, not closed until released): `clean -LogFile` becomes a new file per run, required once real deletion
  is enabled; written through a handle kept for the run (append-only, flushed per record, JSON Lines). Per-root
  `intent` before the deletion and `result` after it; a refusal, a partial deletion, an exception, an inconclusive
  verification or a log failure stops the run (exit code `3`). With the deletion gate closed (every copy) the plan-only
  flow is unchanged. Details and limits: docs/USAGE.md, "Clean log".
* V0.3 B8: one clean run at a time per machine once real deletion is enabled: the named mutex
  `Global\AgentTempManager.Clean`, taken without waiting before the first inventory and released last; a lock that is
  not available, an abandoned lock (a previous run may have been interrupted) or a nested run refuses to start (exit
  code `3`). It excludes only cooperating clean runs; a local account can block it (denial of service). With the gate
  closed nothing changes. Details and limits: docs/USAGE.md, "One clean at a time".
* V0.3 B2-1: preview, the clean plan (also with the deletion gate closed) and each root's revalidation add reasons from
  the read-only V0.2 collectors: observed use or a live session of the root blocks; ambiguous relations, unverified
  sessions and failed or timed-out collection need investigation. Nothing is ever made eligible by it, and no
  evidence is not evidence of non-use. Details and the time limits: docs/USAGE.md, "Runtime evidence in preview and plan".
* V0.3 B1 restricted exception (**a change of the product contract**: until V0.2 incomplete process coverage had no
  override; past the deletion gate only, no distributed copy reaches it): a root whose only refusal is B1, in the own
  non-elevated profile, a Claude Code session root with no other refusal and complete process identities, is shown as
  `ELIGIBLE_WITH_DECLARED_RISK` (never `ELIGIBLE`, "not released" in preview, audit and the TUI). Only
  `clean -AcceptB1ResidualRisk` (CLI) past the gate can act: one root per run (fixed in code), the AUT-2 questions plus a
  per-root `ACEITO RISCO B1` with the count; the identities of the processes not inspected are recorded and bound to the
  plan id; any new one, or the process snapshot no longer complete, refuses before the deletion. Residual risk declared,
  no rollback. Details: docs/USAGE.md, "B1 restricted exception"; docs/SECURITY-MODEL.md, gate 6.
* V0.3 AUT-2 (past the deletion gate only; no distributed copy reaches it): the clean confirmation is bound to the plan.
  An interactive console is required (CLI) and observed by the engine; for each root of the executable set, with its
  path, the task and the content decision (AUT-1 meanings: results preserved, or nothing needed, neither verified);
  then one phrase `APAGAR <N> CAMINHOS <plan id>` for the exact set. Declarations and confirmation are logged and
  flushed before any deletion; a plan check refuses any change during the questions; any refusal aborts the whole run.
  A revalidation refusal after the confirmation now stops the run before that root (`REVALIDATION_REFUSED`) instead of
  skipping it and going on; not all-or-nothing and no rollback (earlier operations stay done; `run-end` names the root
  that stopped the run and the roots not attempted). The phrase carries the first 8 characters of the plan id.
  With the gate closed the plan-only flow is unchanged. Details and limits: docs/USAGE.md, "Plan-bound confirmation".
* V0.3 AUT-1: `agent-temp authorize -Path <root> -RecordFile <new file>` records the operator's discard authorization of
  one root bound to the plan shown (three confirmations, interactive console only, plan presented again and compared,
  new file). It deletes nothing, is read by nothing in the product and makes nothing eligible; the technical result
  (B1, RECENT included) is recorded apart. Schema `atm.discard-authorization/2`: two separate content declarations
  ("results preserved" or "nothing needed"), neither verified by the product (`TOOL_VERIFIED` reserved, never
  emitted); the process identity, not the respondent; the caller and its console requirement as reported, the console
  observed by the engine in that call; B1 recorded apart as the coverage observed and the gate's state (`BLOCKED`, `PASSED`,
  `NOT_EVALUATED`); the justification revalidated in a stable semantic form (runtime refusals carry the process keys they come from, field
  `Sources`, so the same code from another process is a change); success only when the line is written, flushed and
  the file closed (a file kept after a failure, even with a complete line, is not a recorded authorization). Details and
  limits: docs/USAGE.md, "Discard authorization".

## 0.2.0

Published only as the GitHub Release `v0.2.0` (tag `v0.2.0`), created with the maintainer's explicit authorization.
Details, limits and open decisions: [docs/release/V0.2.0-RELEASE-NOTES.md](docs/release/V0.2.0-RELEASE-NOTES.md).

* `agent-temp diagnose` and TUI area **D**: read-only runtime diagnostics with coverage per collector (process
  identity, agent processes and sessions from evidence, resource totals per verified tree, provider-declared Windows
  services, Hyper-V platform and VMs, dependency graph, temporary partitions with runtime evidence, profile
  discovery); keyed pseudonyms instead of paths; never elevates, runs no Git, writes no file.
* Runtime-only Claude Desktop provider; `CoworkVMService` identified by a provisional, publicly reported name.
* Closed gates in every copy, checked in source, build and installation: real deletion, worktree diagnostics, open-file
  diagnostics, diagnose JSON export. D-1 (process working directories) deferred.
* Security audit (FINAL-A, FINAL-B): F-01, F-02, F-03, F-06, F-07, F-08, F-11, F-13 fixed. F-04, F-05 and F-14 were
  deferred by the maintainer (F-04 to V0.3, before the deletion gate can open; F-05 and F-14 to a later 0.2.x) and
  stay listed as known limits. F-01 and F-02 also affected 0.1.0 and are fixed there in 0.1.1 (below).
* Job runner result contract (PR #54):
  * a refused termination, a reader error, output not read to its end, members terminated after the exit, and members
    still active at the end are reported, never taken for a complete run;
  * the Git mapping gives `COMPLETE` only for exit code 0 with none of them.
  * A real refusal of `TerminateJobObject` is NOT TESTED (synthetic results only).
* Installation: `verify` and the installer bootstrap run no unverified code (R-B5); update and rollback never destroy
  the only intact installation (R-B6); the staged copy is verified against the source manifest (F-07); the post-install
  verify runs `cmd.exe` from System32 (F-13); the release build refuses an archive unless all four gates are `$false`.
* Audit coverage (PR #57): a `TEMP` base that is not audited makes the coverage incomplete (`PROFILES_NOT_AUDITED`)
  and a profile with a base read and a base not audited is `AUDITADO_PARCIAL`.
* Read errors (PR #58, PR #59): in the path chain check, the Claude Code sessions folder, the activity evidence of a
  root and, behind closed gates, the post-delete verification and the export destination check, an access denied or an
  unexpected error is no longer taken for a confirmed absence (Windows PowerShell 5.1 could run a typed `catch` clause
  for the wrong exception); an unreadable project folder now leaves a root to investigate, never eligible.
* TUI (PR #59, PR #60): the dashboard puts four cards on a row only from 130 columns; the busy screen of R, D and U
  replaces the previous screen; keys typed while they run are discarded.
* Behaviour changes since 0.1.0 (stricter `audit -ExportJson` creation and protected DACL, network or device paths from
  other users' environment refused, control characters shown as `?`, `verify` exit code `5` for a missing library):
  listed with the gate that approved each one in the release notes.
* CI: ARM64 suite jobs (Windows PowerShell 5.1 full, PowerShell 7 subset with 16 cases NOT TESTED), install e2e with
  integrity variants, installed audit export, encoding and an update from the published 0.1.0 and from the published
  0.1.1 and back; artifacts
  sanitized and scanned before upload; the suite's child calls run inside their own Job Object.

## 0.1.1 (published 2026-10-26, 0.1.x line)

Security fix release of 0.1.0, built and published from the `release/0.1.x` line: tag `v0.1.1`, commit `5c18a6e`,
[GitHub Release](https://github.com/JohnHck/agent-temp-manager/releases/tag/v0.1.1). That commit is not part of this branch's history. 0.2.0 carries its own fixes for the
same findings (FINAL-A). It is recorded here as part of the version history.

* F-01, MEDIUM, CVSS 3.1: 5.0 ([GHSA-c68f-jj6j-92r7](https://github.com/JohnHck/agent-temp-manager/security/advisories/GHSA-c68f-jj6j-92r7)): another local user's `TEMP`,
  `CLAUDE_CONFIG_DIR` or `CLAUDE_CODE_TMPDIR` in network or device form is refused before any file API, and path
  normalization no longer traverses a reparse point. The higher-impact scenario (NTLM relay) was not demonstrated.
* F-02, MEDIUM, CVSS 3.1: 6.0 ([GHSA-5m78-qp92-5f9v](https://github.com/JohnHck/agent-temp-manager/security/advisories/GHSA-5m78-qp92-5f9v)): `audit -ExportJson` creates its file through a
  pinned, handle-relative writer. The create-or-truncate impact in 0.1.0 was identified by code inspection, not
  demonstrated dynamically.

## 0.1.0

* Initial limited release: audit, preview and TUI. `clean` is **plan only** (release gate); real deletion is
  disabled.
* `-AcceptProcessCoverageGap` removed: incomplete process coverage always blocks deletion.
* Deleter pins ancestors and the tree by handle, deletes by handle, and requires the pinned plan to match the
  validated measurement (security review H1 and TOCTOU hardening).
* Installer: precompiled, manifest-verified native assembly; allow-list ACL audit; rollback script; testable
  install/update/rollback/uninstall flow.
* Install/uninstall/rollback run with a private, administrator-only TEMP (no compiler intermediates in a
  user-writable %TEMP% of the elevating account).
* Interface in en-US and pt-BR (`-Lang`, `ATM_LANG`, Windows UI language; safe fallback to English). Engine
  decisions and codes are language-neutral.
* ASCII mode transliterates accented text.
* Clean-environment test kit for Windows Sandbox / VM (`tools/clean-env`).
* Portability: unidentified projects shown as `Projeto não identificado` (session working directory used as
  evidence when consistent); profiles whose environment cannot be read are reported as TEMP not verifiable
  (incomplete coverage) instead of "no agent temp"; path joins never depend on the drive existing.
* Privacy scanner (`tools/Test-AtmPrivacy.ps1`) gating every release build.
* Launcher pins `PSModulePath` for the Windows PowerShell child (works when invoked from PowerShell 7).
* Static analysis: PSScriptAnalyzer 1.25.0 pinned by version and package SHA-512, module signatures verified;
  0 findings in security and compatibility rules; one reviewed, per-file signature exception for
  `Newtonsoft.Json.dll` when a runner image resolves it through a Windows catalog (exact path and SHA-256; the signer
  allow-list is unchanged). Remediation: `$Profile` parameters renamed to `$ProfileInfo` (`-Profile` kept as an
  alias; providers written with `param($Profile)` keep working), unused variables removed, every empty `catch` made
  explicit with its conservative value; reviewed, narrow exceptions only.
* The privacy scanner warns when the Windows profile list cannot be read (previously a silently weaker scan).
* CI: commit identity check (no personal e-mail in author, committer or trailers); real installation, update,
  rollback, tamper detection, standard-user run and uninstall on disposable Windows Server 2025, Windows Server
  2022 and Windows 11 ARM64 VMs, installer under PowerShell 5.1 and 7, with one package built once.
* Documentation: privileges and UAC (`docs/ELEVATION.md`, PRIV-1 to PRIV-11), privilege matrix and runbook with a
  read-only probe (`tools/privilege-matrix`), roadmap V0.1 to V1.0 including Git worktree diagnostics (V0.2) and
  safety before deletion (V0.3), release notes and known limitations (`docs/release`).

## Initial development notes

* First version: `agent-temp` global command with TUI, `audit`, `preview`, `clean`, `verify`.
* Provider architecture; V1 provider: Claude Code on Windows.
* Multi-profile discovery through Windows (ProfileList, loaded hives, Public/Default, residual folders).
* Read-only single-pass inventory with exclusive partitions, reparse-point protection and bounded memory.
* Conservative classification (ACTIVE_EVIDENCE, RECENT, LIVENESS_UNKNOWN, ORPHAN_SUSPECTED).
* Fail-closed assisted cleanup with allowlist, exact plan, typed confirmation and per-path revalidation.
* Installer/uninstaller with manifest verification and ACL audit; release builder.
* Automated test suite for Windows PowerShell 5.1 and PowerShell 7.
