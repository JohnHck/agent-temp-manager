# ADR-0017: Persistent preventive monitoring (V0.5)

Status: ACCEPTED: V05-D1 to V05-D10 decided (D1-D7 2026-11-17, D8-D10 2026-11-18, as recommended); M0 to M3 (M3a and
the M3b real-scheduler CI harness) and M4 (M4a: `monitor disable` and the empty task folder; M4b: `monitor
remove-history` and the uninstaller's notice) implemented; M5 (the TUI and the GUI) next; gate closed in every copy. (Until 2026-11-17: PROPOSED, with V05-D1
to V05-D10 open. From 2026-11-17 to 2026-11-18: ACCEPTED in part, with V05-D8, V05-D9 and V05-D10 open and only M0
implemented.)
Date: 2026-11-17
Phase: V0.5 (phases M0 to M6 below, each a future round with its own contract and tests)

## Context

The ROADMAP's V0.5 ([ROADMAP](../ROADMAP.md#v05--preventive-monitoring), `docs/ROADMAP.md:405-433`) asks for:

* a persistent, periodic, read-only collection of the V0.2 metrics with a small local history;
* history and trends in the GUI and the TUI;
* configurable thresholds and alerts;
* growth trends per user, project and agent.

Its acceptance criteria (`:421-426`):

* monitoring is opt-in, uses bounded local storage and can be removed completely;
* it runs without elevation (PRIV-1);
* installing a scheduler entry is an explicit, separately confirmed step that never stores credentials (PRIV-3);
* it never deletes, recovers or changes anything, and only recommends the V0.3 and V0.4 actions;
* the history holds no personal data beyond what the audit already shows locally.

**Ordering.** The maintainer's decision D-A applies: V0.5 lands on `main` dark, behind a release gate of its own,
`$false` in every copy, with its acceptance proven in CI. Only a decision of the maintainer opens it.

**What already exists and is reused or contrasted:**

* **The live monitoring of V0.2.1** ([ADR-0014](ADR-0014-desktop-gui-winforms.md) section 5).
  * It runs only while the window is open, with "No service, task, scheduled job, background process or history"
    (`ADR-0014:118`).
  * It uses one timer, a `NextDueUtc` per session (`src/lib/Gui.ps1:115`, `:143`, `:157`, `:185`) and a fixed list of
    intervals from 30 seconds to 15 minutes (`src/lib/GuiModel.ps1:130-134`).
  * A failed refresh never erases an earlier finding (`ADR-0014:139`).
* **The diagnose JSON export**, behind `AtmDiagnoseExportEnabled` (`src/lib/Report.ps1:1180`). Its pseudonym key exists
  only for the run (`src/lib/Engine.Diagnose.ps1:4932-4934`).
* **The automatic purge's scheduled task**, the only precedent of a scheduler entry
  (`src/lib/Engine.Isolate.ps1:54-68`, `:1701-1712`, `:1719-1728`, `:1835-1862`, `:1917-1953`). It is:
  * one per user, named after a hash of the SID;
  * logon type Interactive and run level Limited, with no credential;
  * reached only through `Connect-AtmTaskScheduler`.
* [ADR-0012](ADR-0012-service-account-privacy.md) (service account privacy) and [ELEVATION.md](../ELEVATION.md) (PRIV-1
  to PRIV-11).

**Accepted text that V0.5, as the ROADMAP describes it, would contradict.** Each item needs an amendment that only the
maintainer can approve (phase M0, decisions below):

1. **PRIV-3** says the only scheduled task is the optional automatic purge one (`docs/ELEVATION.md:48`). SECURITY-MODEL
   says only two commands change the Task Scheduler (`docs/SECURITY-MODEL.md:873-877`), and a static suite test pins
   the callers of the single scheduler helper (`tests/Run-Tests.ps1:5410-5421`). A monitoring task is a second task.
2. **ADR-0010, D-7 = K1:** no persistent pseudonym key (`docs/adr/ADR-0010-pseudonymization-of-exported-identifiers.md:70-77`).
   A stable pseudonym across collections would be K2, which that record leaves "not built" and in need of its own
   evaluation.
3. **ADR-0014 section 3:** the GUI calls only the read functions of a closed list, and a static test checks it
   (`tests/Run-Tests.ps1:15227-15239`). A history-read function is not on that list.
4. **The ROADMAP itself.** "Never deletes ... anything" (`docs/ROADMAP.md:425`) and "uses bounded local storage"
   (`:422`) meet when the history is full. Section 3 states the reading and gives the alternatives (V05-D4).

All file and line references below are to commit `82dae56ff184db11a0cb21c964ea31f5e4de8f31`.

## Decision (proposed)

### 1. What is collected

**Who collects.** The collector runs on the user's own token, without elevation (PRIV-1). The audit sees what that
token can read, so in practice the user's own profile. Other profiles appear as not audited or inaccessible
(`src/lib/Engine.Audit.ps1:995-998`). "Trends per user" therefore means **one history per user, kept by that user**.
A machine-wide view needs an elevated collection, which V0.5 does not do.

**What the history keeps.** Only aggregates, and only values the audit already shows locally:

| # | Metric | Source in the code | Type and unit | Cost | Behind a closed V0.2 gate? | What the history keeps |
|---|---|---|---|---|---|---|
| 1 | Collection header: UTC time, duration, outcome code, tool version (the `AtmVersion` constant, `Engine.Audit.ps1:15`) | the collector | time (UTC), seconds, a code from a closed list | none | No | exactly that |
| 2 | Coverage: whether the audit's coverage is complete, process coverage, counts of profiles not audited, inaccessible or unverified | `Engine.Audit.ps1:994-998` | yes/no, counts | part of the audit | No | yes/no and counts; never which profiles |
| 3 | Base states per provider: how many bases are `OK`, `NOT_FOUND`, `NOT_DIRECTORY`, inaccessible or refused by policy | `Engine.Audit.ps1:658-662`, `:831` | counts per provider and state | part of the audit | No | counts; never a base path |
| 4 | Size per group (provider, project, class): bytes, allocated bytes (estimate), files, partitions | partition fields `Engine.Audit.ps1:613-615`; class `:1098`, `:1147-1150` (`ACTIVE_EVIDENCE`, `RECENT`, `ORPHAN_SUSPECTED`, `LIVENESS_UNKNOWN`, `NOT_SCANNED`) | bytes, counts | **the audit's walk of every file of each agent temporary base** (`:840-870`) | No | sums per group, with a per-group "complete" flag: every partition of the group measured completely (`:623`) |
| 5 | Age per group: hours since the newest write of the group's least recently written partition | `NewestWriteTimeUtc` (`Engine.Audit.ps1:612`) | hours | none (already read) | No | one number per group; never a time of an individual partition |
| 6 | Flags per group: counts of partitions with reparse points, read errors, incomplete measurement | `Engine.Audit.ps1:618-623`, flag lists `:21-24` | counts | none | No | counts; never the error or reparse samples (`:621-622`) |
| 7 | Diagnose counts (only if V05-D8 (b) is decided): services of the declared roles by state; agent sessions by state; agent processes by state; VMs by state | `Engine.Diagnose.ps1:35-41` | counts per kind and state | a diagnose run: deadline 300 s by default (`:3067`), a CPU sample of 500 ms (`:3068`), CIM queries bounded at 30 s each (`:327`, `:3175`, `:3890`) | No, for these kinds | counts; never a process id or key, a service account, a VM name or a session id |
| 8 | Worktrees ("leftover worktrees" in the ROADMAP) | `Engine.Diagnose.ps1:1722`, `:2651-2653` | — | — | **Yes:** `AtmWorktreeDiagnosticsEnabled`. Closed, discovery is `NOT_OBSERVABLE`. | `NOT_OBSERVABLE`, never zero |
| 9 | Open-file holders | `Engine.Diagnose.ps1:4621` | — | — | **Yes:** `AtmHandleDiagnosticsEnabled` | not collected |

**"Long-running agent VMs" are not observable as agent VMs.** No provider declares a virtualization hint, so every VM
is `VM_UNATTRIBUTED` (`Engine.Diagnose.ps1:4167`; [ADR-0016](ADR-0016-v04-assisted-recovery.md), inventory row 3). A VM
count says a VM ran, not that an agent's VM ran.

**Cost: not measured** when this record was written. (Phase M1 measured it: see the M1 implementation record. V05-D8
(a), decided 2026-11-18, keeps row 7 out of every collection: a collection runs the audit only.)

* The audit walks every file under each agent temporary base. Its cost grows with the number of files.
* The audit has no deadline today (`ADR-0014:124-126`, GUI-D9); the diagnose has one.
* Phase M1 measures both, on the CI runners, with planted trees of known size.
* Until then the only bound is the scheduler's time limit, which ends the process during a run. Section 3 makes such
  an end harmless.

**Never in the history.**

* From each partition (`Engine.Audit.ps1:596-633`):
  * `Sid`, `UserName`, `ProfilePath`, `TempPath`, `BasePath`;
  * `Slug`, which is derived from a working-directory path;
  * `Path`;
  * the partition `Name`: a session root's name is a session identifier.
* From the audit result: `Machine` (`:979`) and the identity block.
* Anything else: error and reparse samples, command lines, process ids, service accounts (ADR-0012), VM names.

**Names or pseudonyms (V05-D5).** A trend per project needs the same key in every collection. The diagnose's pseudonyms
cannot provide one, since they are keyed per run (K1). The options are:

* **(a) The project's display name, as the audit shows it.** That is:
  * a rule's name from `projects.json` or `projects.local.json`;
  * the localized "home" name;
  * the name from the agent's session evidence;
  * or "unidentified" (`Engine.Audit.ps1:262-278`).

  It is what the audit already shows locally, which is the ROADMAP's limit, and the history stays in the same user's
  profile. Unidentified projects are summed into one group.
* **(b) An HMAC of the slug, with a stable per-user key.** That is K2 of ADR-0010: a DPAPI-protected key and its own
  provisioning command. It needs an amendment of ADR-0010 and an evaluation of backup, rotation and multi-user
  machines.
* **(c) Totals per provider only**, with no per-project trend.

Recommendation: (a).

### 2. The persistent mechanism

The comparison below uses Microsoft's public documentation (Sources). Nothing was created, read or changed in any
scheduler, registry key, startup folder or service of any machine for this record.

| | (A) Per-user scheduled task | (B) `HKCU` Run entry | (C) Shortcut in the user's Startup folder | (D) Windows service | (E) No mechanism: collect when the TUI or GUI opens |
|---|---|---|---|---|---|
| **Install** | The user registers it with no elevation: logon type `TASK_LOGON_INTERACTIVE_TOKEN`, no password, run level LUA. A standard user can create a task for themselves. Precedent: `Engine.Isolate.ps1:1835-1862`. | A registry value in the user's hive | A file in a per-user known folder (`FOLDERID_Startup`, per user) | Creating a service needs `SC_MANAGER_CREATE_SERVICE`, which by default only administrators have | nothing |
| **Complete removal** | Delete the task, after an exact match (precedent `Unregister-AtmAutoPurgeTask` and `Invoke-AtmAutoPurgeUnschedule` in `Engine.Isolate.ps1`; since M4a, `Unregister-AtmMonitorTask` in `Engine.Monitor.ps1`) | Delete the value | Delete the file | An administrator deletes the service | nothing |
| **Left behind** | The task folder `\AgentTempManager`, shared with the automatic purge. Until M4a it stayed after unscheduling; since M4a both unschedule commands remove it when it is empty (`Remove-AtmEmptyTaskFolder`), and with another task in it, it stays. The history, until `monitor remove-history` removes it (section 3; since M4b). The user's `monitor.json` stays, and with it the history folder. | the history | the history | the service's registry entries if removal fails; the history | the history |
| **Sign-out and restart** | It runs only while the user's session is open. A missed time-based run starts when available. With battery saver on, only interactive-token tasks are triggered. | It runs at **each sign-in** of that user, with no promise of how soon. It does not run in Safe Mode. Periodic collection needs the started process to stay resident. | as (B) | It runs without a session, as a service account, for every user | only while open |
| **Visibility** | It is listed in Task Scheduler under the product's folder. `version` and `monitor status` show its state. It is not hidden. | in the Startup list of the system's settings | in the Startup folder | in the services list | the open window |
| **Consumption** | One short process per collection, which then exits. One instance at a time (`MultipleInstances` IgnoreNew). Bounded by `ExecutionTimeLimit` (72 hours unless set). | a resident process for the whole session, or one collection per sign-in only | as (B) | resident | none between openings |
| **Tests in a sandbox** | A definition built and never registered, checked field by field (precedent `tests/Run-Tests.ps1:5470`). A real task only on a disposable CI runner, with test names (precedent `:5596`). | a seam over the registry; real only in CI | a seam over the folder; real only in CI | — | as the GUI's P5 |
| **Fit with the ROADMAP** | Meets "persistent ... across sign-ins and restarts" while the user is signed in | Only at sign-in, unless a resident process is added | as (B) | **Excluded:** it needs elevation to install, against PRIV-1 (everything that can run without administrative rights does), and it runs outside the user's session, for every user | Not persistent: it does not meet the ROADMAP's objective |

**Repetition.** A task repeats with an interval from 1 minute to 31 days. The collector's own interval list
(V05-D2) stays inside that range.

**The precedent and how V0.5 differs.** `schedule-autopurge` registers its task even while the purge gate is closed
(`Engine.Isolate.ps1:1917-1953` has no gate check; the purge gate is read at `:1249`, `:1324`, `:1558` and `:1629`).
A run then only plans. V0.5 differs on purpose: **installing the monitoring entry needs the monitoring gate open and a
typed confirmation of its own** (section 5).

Recommendation (V05-D1): (A), with the PRIV-3 amendment in M0.

### 3. Storage

* **Location:** `%LOCALAPPDATA%\AgentTempManager\Monitor`, per user. It sits next to the quarantine root
  (`Engine.Isolate.ps1:121-126`) and outside every audited base. It is a pinned folder, as the T1 log's is:
  * no reparse point in its chain;
  * owned by the user;
  * created with a protected DACL;
  * refused when any of this is not so.
* **Format: one new file per collection, never appended to:**
  * JSON with schema `atm.monitor/1`;
  * the name is `<UTC time>-<8 random hex digits>.json`, created new (an existing name is refused);
  * written to `<name>.partial`, flushed, then renamed;
  * a run ended by the scheduler's time limit leaves only a `.partial` file, which no reader reads.
  * A record is bounded at 16 KB: at most 64 groups, with the rest summed into one "other" group.
* **Size and retention (V05-D3).**
  * Proposed: 90 days, and at most 400 files and 8 MB, whichever comes first.
  * At one collection every 6 hours, 90 days is 360 files of at most 16 KB, under 6 MB.
* **Keeping it bounded (V05-D4).** The ROADMAP says monitoring never deletes and also that storage is bounded. This
  record reads "never deletes, recovers or changes anything" as being about the user's system and the agents' data. It
  does not cover the history files the product itself created. The alternatives:
  * **(a) Remove the oldest history files after a new one is written.** Only files whose name matches the product's
    pattern, in the pinned folder, are removed, by exact name. A file with another name, a reparse point or another
    owner refuses the rotation and raises an alert. (As implemented in M1 and M2, the refusal is a code in the
    collector's result only; no M2 alert reads it. See the M2 implementation record.) Leftover `.partial` files older
    than a day are removed the same way.
  * **(b) A fixed ring of N files, overwritten in place.**
  * **(c) Stop collecting at the limit and alert.** The person then removes the history with the command below.

  Recommendation: (a).
* **Integrity.**
  * Each file is parsed and checked against its schema and bounds. A file that fails is counted as
    `HISTORY_RECORD_INVALID` and skipped; it is never read as zero.
  * A content hash inside the file catches accidental damage, **not** forgery. Anyone with the user's rights can write
    the folder.
  * That is acceptable only because the history authorizes nothing. It feeds alerts that recommend a command, and the
    command then makes its own collection, plan and confirmation.
  * An HMAC would need a persistent key (K2).
* **Concurrency.**
  * Collectors are serialized by a per-user mutex, `Global\AgentTempManager.Monitor-<16 hex digits of SHA-256(SID)>`,
    plus the task's `MultipleInstances` IgnoreNew. A busy mutex ends the run with nothing written.
  * It is not B8: monitoring changes nothing, and it must never block or wait for a clean, an isolation or a recovery.
  * A reader (CLI, TUI, GUI) takes no lock. It lists final names only, ignores `.partial`, and treats a file that
    vanished between listing and reading as skipped.
* **Complete removal.**
  * `agent-temp monitor disable` removes the scheduler entry. Like `unschedule-autopurge`, it first checks the entry
    is exactly the product's entry for this user, and confirms it with a typed phrase.
  * `agent-temp monitor remove-history` removes the history files the product created: matching names, in the pinned
    folder. It removes the folder when it is empty. Anything unexpected refuses, and the refusal says how many items
    were not touched. (As implemented in M4b: the user's `monitor.json` stays, and with it the folder; the parent
    `%LOCALAPPDATA%\AgentTempManager` is never removed. See the M4b implementation record.)
  * Both are explicit commands that the person runs, each with its own confirmation. The product removes only what it
    created.
  * This is not an agent removing files. Tests run the commands only against a sandbox folder and a test task name,
    and the real scheduler only on a disposable CI runner.
  * Until M4b, the uninstaller only read the auto-purge task folder and warned (`docs/ARCHITECTURE.md:107-108`).
    V05-D9 decided whether it does more. (Decided 2026-11-18, V05-D9 (a) plus (c): the uninstaller warns and names the two
    commands, and the unschedule commands remove the task folder when it is empty. M4a implements (c); M4b implements
    (a): the uninstaller only reads and warns, and removes nothing of the monitoring.)

### 4. Trends, thresholds and alerts

* **Trends.**
  * A trend is the least-squares slope of bytes per day over a window (proposed: 7 days), per group and in total.
  * It uses complete values only, and needs at least 4 points spanning at least 24 hours. Otherwise it is
    `INSUFFICIENT_DATA`.
  * The change since the previous collection is also shown, as a difference.
  * An incomplete or failed collection is a gap, never a decrease, never "resolved" (as `ADR-0014:139`).
  * A collection whose time is earlier than the previous one is excluded and flagged `CLOCK_SKEW`. The clock is a
    seam in the tests.
* **Thresholds** live in a per-user file, `monitor.json`, in the same folder. Each value has fixed bounds in code. A
  file with a value outside them is refused as a whole: the defaults apply, and the alert `MON_CONFIG_INVALID` says so.

  Proposed defaults (V05-D10; decided 2026-11-18, (a): these defaults, in the per-user file. Phase M2 implements them):

  | Alert code | Fires when | Default | Recommended command (never executed) |
  |---|---|---|---|
  | `MON_TOTAL` | the user's agent temporary data exceeds a size | 20 GiB | `agent-temp preview`, then `agent-temp clean` (V0.3, behind its gate) |
  | `MON_GROWTH` | the 7-day slope exceeds a rate | 2 GiB per day | `agent-temp audit` |
  | `MON_ORPHAN_SUSPECTED` | bytes in `ORPHAN_SUSPECTED` partitions exceed a size | 5 GiB | `agent-temp preview`; `agent-temp isolate` (0.3.x, behind its gate) |
  | `MON_LIVENESS_UNKNOWN` | bytes in `LIVENESS_UNKNOWN` partitions exceed a size | 5 GiB | `agent-temp diagnose` |
  | `MON_COLLECTION` | the last 3 collections failed or were incomplete | 3 | `agent-temp monitor status` |
  | `MON_RECOVERY` | only once V0.4 exists and only for what it can plan | — | `agent-temp recover plan` ([ADR-0016](ADR-0016-v04-assisted-recovery.md)) |

* **Alerts** are computed when the history is read: by `monitor status`, by a line under the header of `audit`, by the
  TUI and by the GUI. Each alert is a code plus a text in the catalog's language, and it names a command. The collector
  itself writes no alert. No alert ever runs a command.
* **System notification (V05-D6).** None in V0.5 is recommended.
  * The collector is a short process that exits. A tray balloon (`NotifyIcon.ShowBalloonTip`) belongs to a running
    process with a visible icon. Its timeout is deprecated, the display time follows the system's accessibility
    settings, and only one balloon shows at a time.
  * Toast notifications for an unpackaged desktop app were not confirmed from Microsoft's documentation in this round:
    the page consulted no longer exists. Nothing is assumed about them.
  * The alternatives: (b) a balloon from the GUI while it is open, which adds little since the GUI already shows the
    alerts; (c) a toast, after its own study, only if it needs no new dependency.

### 5. The new gate

* `$script:AtmMonitoringEnabled = $false`, a single assignment in a new `src/lib/Engine.Monitor.ps1`, with no switch,
  environment variable, configuration file or UI option.
  * Its ordinal (eighth or ninth) depends on whether ADR-0016's `AtmRecoveryEnabled` lands first. (M0 note,
    2026-11-18: **ninth**. ADR-0016's `AtmRecoveryEnabled` landed first, as the eighth, in V0.4 R1.)
  * The suite opens it only inside its own process, as it does for the others.
* **Closed (every copy):**
  * `agent-temp monitor status` says monitoring is not available in this version, shows an empty history, and explains
    what the opt-in will be;
  * `monitor enable` refuses with `MONITORING_GATE_CLOSED` before asking anything;
  * nothing is collected, written or registered;
  * reading whether an entry exists is allowed, so that a leftover is visible.
* **Open:** `monitor enable` needs, in this order:
  * the gate open **and**
  * a standard (non-elevated) token;
  * an installed copy;
  * a console observed by the engine (`Get-AtmEngineConsoleObservation`);
  * no existing entry (never replaced);
  * the plan shown;
  * **its own typed phrase**.
* **The collector's entry point** (`src/bin/agent-temp-monitor.ps1`) reads the gate on every run. A copy whose gate is
  closed, for example after an update, exits without collecting.

### 6. Implementation phases

Each phase is a future round with its own contract and tests, and names the files its round will need in ALLOWED_PATHS.

| Phase | Content | Files (future ALLOWED_PATHS) | Tests |
|---|---|---|---|
| M0 | Amendments, documentation only: PRIV-3 (a second scheduled task, monitoring's); SECURITY-MODEL's scheduler section; ARCHITECTURE's scheduler layering; ADR-0014 section 3's closed list (one history-read function); ADR-0010 only if V05-D5 (b) | `docs/ELEVATION.md`, `docs/SECURITY-MODEL.md`, `docs/ARCHITECTURE.md`, `docs/adr/ADR-0014-desktop-gui-winforms.md`, `docs/adr/ADR-0010-pseudonymization-of-exported-identifiers.md`, `docs/adr/README.md` | the documentation CI |
| M1 | The collector and the storage, gate closed, with seams for the clock, the folder and the audit. The cost is measured. An audit deadline (GUI-D9) only if decided. | `src/lib/Engine.Monitor.ps1`, `src/agent-temp.ps1`, `src/lib/Report.ps1`, `src/lib/I18n.ps1`, `src/lib/Engine.Audit.ps1` (deadline only), `tools/Build-Release.ps1`, `install/*`, `tests/Run-Tests.ps1`, `tests/e2e/Invoke-InstallE2E.ps1` | The record's shape. **Privacy:** planted SIDs, user names, paths, slugs and partition names never reach a file, checked by the privacy scanner over the folder. Size caps. A `.partial` left by an ended run. A corrupt file. Two collectors at once. A clock seam. No write outside the folder. The gate count in build, installer and e2e. Both shells. |
| M2 | Trends and thresholds | `src/lib/Engine.Monitor.ps1`, `src/lib/I18n.ps1`, `tests/Run-Tests.ps1` | Slope. `INSUFFICIENT_DATA`. A gap never a decrease. `CLOCK_SKEW`. Configuration bounds and `MON_CONFIG_INVALID`. Each alert names its command and runs none. |
| M3 | The scheduler entry through a seam: build, register, read back, exact match | `src/lib/Engine.Monitor.ps1`, `src/bin/agent-temp-monitor.ps1`, `src/lib/Engine.Isolate.ps1` (only if M0 moves `Connect-AtmTaskScheduler` to a shared place), `tests/Run-Tests.ps1` (the static case at `:5410-5421`), `tests/e2e/Invoke-MonitorE2E.ps1` (CI-only, out of the package, on the build's CI-only list like the V2 and V3 harnesses), `.github/workflows/*` | Local: the definition built and never registered; the refusals before any registration. **The real scheduler only in the CI harness**, on a disposable runner, with test names: register, read back, run once, remove, read back absent. |
| M4 | Complete removal: `monitor disable` and `monitor remove-history`, and the uninstaller per V05-D9 | `src/lib/Engine.Monitor.ps1`, `install/Uninstall-AgentTempManager.ps1`, `install/InstallCommon.ps1`, `tests/Run-Tests.ps1`, `tests/e2e/Invoke-InstallE2E.ps1` | After removal: no entry, no history file, and no folder (or, under V05-D9 (a), the documented residue only). Refusal on an unexpected file. Sandbox only. |
| M5 | Presentation: the history and the alerts in the TUI and the GUI, read only | `src/lib/Tui.ps1`, `src/lib/GuiModel.ps1`, `src/lib/Gui.ps1`, `src/lib/I18n.ps1`, `tests/Run-Tests.ps1` | View models over planted histories (empty, partial, corrupt, skewed). The GUI's closed list with the one new read function. The "never reaches a deletion, recovery or write API" test still passes. Both languages. |
| M6 (optional, V05-D6) | A system notification | to be named by its own study | its own |

### 7. Decisions for the maintainer

None was decided by this record when it was written. The column "Decided" was added by phase M0 (2026-11-18). It
records the maintainer's decisions of 2026-11-17 ("approved as recommended", V05-D1 to V05-D7) and, since phase M1, of
2026-11-18 (V05-D8 to V05-D10, as recommended). The recommendation column is left as it was.

| Id | Question | Evidence | Alternatives | Technical recommendation | Decided |
|---|---|---|---|---|---|
| V05-D1 | The persistent mechanism | Section 2. PRIV-3 today allows only the auto-purge task (`ELEVATION.md:48`). | (A) per-user task, interactive, limited; (B) Run entry; (C) Startup shortcut; (E) none. (D) service is excluded. | **(A)**, with the PRIV-3 amendment in M0 | **(A)**, 2026-11-17: a per-user task, interactive, no password, run level LUA (Limited). PRIV-3 amended in M0. |
| V05-D2 | Default interval and the allowed intervals | The audit's cost is not measured and it has no deadline. The GUI's live intervals are 30 s to 15 min. A task repeats from 1 minute to 31 days. | (a) 1, 2, 4, 6, 12, 24 hours, default 6 hours; (b) daily only; (c) the GUI's list | **(a)**, revisited after M1's measurement | **(a)**, 2026-11-17: 1, 2, 4, 6, 12 and 24 hours, default 6 hours, revisited after M1's measurement |
| V05-D3 | Maximum history size and retention | Section 3 arithmetic | (a) 90 days, 400 files, 8 MB, 16 KB per record; (b) 30 days and 2 MB; (c) a size limit only | **(a)** | **(a)**, 2026-11-17: 90 days, 400 files, 8 MB, 16 KB per record |
| V05-D4 | Keeping the history bounded | ROADMAP `:422` and `:425` | (a) remove the oldest own files by exact name; (b) a ring overwritten in place; (c) stop at the limit and alert | **(a)**, with the reading of section 3 recorded in the ROADMAP | **(a)**, 2026-11-17: the oldest own history files by exact name, in the pinned folder. The reading is recorded in the ROADMAP in M0. |
| V05-D5 | Names or pseudonyms in the history | ADR-0010 D-7 = K1; the audit already shows project names locally | (a) display names as the audit shows them; (b) K2 HMAC with a per-user key (amends ADR-0010); (c) totals per provider only | **(a)** | **(a)**, 2026-11-17: the project's display name as the audit shows it, with no persistent key. ADR-0010 stays unchanged. |
| V05-D6 | A system notification | NotifyIcon needs a running process; toast requirements not confirmed | (a) none in V0.5; (b) balloon from the open GUI; (c) toast after a study | **(a)** | **(a)**, 2026-11-17: no system notification in V0.5, so M6 is out of V0.5 |
| V05-D7 | Does V0.5 go ahead behind its gate without waiting for V0.3 and V0.4 (D-A)? | V0.5 changes nothing. Its alerts only name commands: V0.3's and 0.3.x's exist behind their gates; V0.4's is proposed. | (a) go ahead behind `AtmMonitoringEnabled`; an alert names only a command present in that copy; (b) wait | **(a)** | **(a)**, 2026-11-17: V0.5 goes ahead behind `AtmMonitoringEnabled`, and an alert names only a command present in that copy |
| V05-D8 | Does a collection include the diagnose? | Diagnose cost: deadline 300 s, CPU sample, CIM queries. VMs are unattributed. Worktrees and handles are behind closed gates. | (a) the audit only; (b) the audit plus diagnose counts (row 7), with no CPU sample and a short deadline | **(a)** first; (b) once a provider attributes VMs | **(a)**, 2026-11-18: the audit only; row 7 is not collected. (Pending until then.) |
| V05-D9 | What the uninstaller does, and the shared task folder | The uninstaller only reads and warns today. Until M4a, `\AgentTempManager` stayed after `unschedule-autopurge`; M4a removes it when empty. | (a) the uninstaller warns and names the two commands; the empty folder stays as declared residue; (b) the uninstaller runs the removal with its own confirmation; (c) the unschedule commands remove the task folder when it is empty (changes the auto-purge behaviour and its test) | **(a)** plus (c): the folder goes when empty, so "removed completely" holds | **(a)** plus **(c)**, 2026-11-18: the uninstaller warns and names the two commands; the unschedule commands remove the task folder when it is empty. Implemented in M4 (M4a: (c); M4b: (a)). |
| V05-D10 | Threshold defaults, and who sets them | Section 4 | (a) the per-user file with the defaults of section 4; (b) the installation's policy, set by the administrator, like `quarantine.policy.json` | **(a)** | **(a)**, 2026-11-18: the per-user file `monitor.json` with the defaults of section 4. Implemented in M2. (Pending until then.) |

### 8. Risks and limits

* **V0.5 does not:**
  * delete, move, isolate, recover or change any agent data, service, process or VM;
  * run with elevation;
  * collect other users' data;
  * send anything over the network;
  * notify outside the product (if V05-D6 (a) is decided);
  * say that a VM belongs to an agent;
  * observe worktrees while their gate is closed.
* **The history is the user's own file.** Anyone with the user's rights can change it, which can mislead an alert. No
  alert can cause an action without that command's own collection, plan and confirmation.
* **No collection while the user is signed out.** The gaps are shown as gaps.
* **The scheduler ends a run at its time limit.** The `.partial` design makes that harmless.
* **To be checked in M3, not assumed here:** how the console window of a hidden PowerShell started by the scheduler
  behaves (the precedent passes `-WindowStyle Hidden`, `Engine.Isolate.ps1:1726`).
* **NOT TESTED, by design, until a phase says otherwise:**
  * the real scheduler of any machine other than a disposable CI runner;
  * real sign-out, sign-in and restart cycles;
  * two sessions of the same user at once;
  * Safe Mode;
  * weeks of real growth;
  * any system notification.

## Rejected alternatives

* **A Windows service:** it needs elevation to install (against PRIV-1), and it runs outside the user's session and
  across users.
* **Appending to one history file:** a run ended by the scheduler could leave a torn record, and readers would need a
  lock. One new file per collection avoids both.
* **Reusing the B8 lock:** monitoring changes nothing and must never delay a clean, an isolation or a recovery.
* **Using the export or the diagnose's pseudonyms as history keys:** they are per run (K1).
* **Alerts that act:** excluded by the ROADMAP. Alerts name a command and never run it.

## Consequences (including new limits)

* **A new release gate,** and the amendments of M0:
  * PRIV-3, SECURITY-MODEL and ARCHITECTURE (a second scheduled task);
  * ADR-0014 section 3 (a history-read function);
  * ADR-0010 only under V05-D5 (b).
* **A per-user folder** under `%LOCALAPPDATA%\AgentTempManager`, next to the quarantine.
* **New limits:**
  * one history per user;
  * the history never holds a path, SID, account, machine name or session identifier;
  * the history authorizes nothing.

## Verification

* **This record:** the documentation-only CI, with the existing gates unchanged.
* **Each phase M0 to M6:** the tests in section 6, in both shells, with the gate closed in every copy and checked by
  the build, the installer and the install e2e.
* **The real scheduler:** only in M3's CI-only harness.
* **Opening the gate:** that waits for the maintainer.

## Sources

Microsoft documentation, read for this record:

* Security contexts for tasks (interactive token, no password; LUA; a standard user's own task):
  https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks
* `TASK_LOGON_TYPE`: https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type
* `ITaskSettings` (72-hour default time limit; battery saver):
  https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nn-taskschd-itasksettings
* `ExecutionTimeLimit`:
  https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itasksettings-get_executiontimelimit
* `StartWhenAvailable`:
  https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itasksettings-get_startwhenavailable
* `MultipleInstances` and its policy values:
  https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itasksettings-get_multipleinstances and
  https://learn.microsoft.com/en-us/windows/desktop/TaskSchd/taskschedulerschema-multipleinstancespolicy-settingstype-element
* Repetition interval (1 minute to 31 days):
  https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-interval-repetitiontype-element
* Run and RunOnce keys (each sign-in; no promise of timing; 260 characters; Safe Mode):
  https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys
* Known folders (`FOLDERID_Startup`, per user): https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid
* Service security and access rights (`SC_MANAGER_CREATE_SERVICE`, administrators):
  https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights
* `NotifyIcon.ShowBalloonTip` (timeout deprecated; one balloon at a time):
  https://learn.microsoft.com/en-us/dotnet/api/system.windows.forms.notifyicon.showballoontip

In this repository: [ROADMAP](../ROADMAP.md) (V0.2.1, V0.5), [ELEVATION.md](../ELEVATION.md),
[SECURITY-MODEL.md](../SECURITY-MODEL.md), [ARCHITECTURE.md](../ARCHITECTURE.md), [PROVIDERS.md](../PROVIDERS.md),
[ADR-0010](ADR-0010-pseudonymization-of-exported-identifiers.md), [ADR-0012](ADR-0012-service-account-privacy.md),
[ADR-0013](ADR-0013-isolation-quarantine-recovery-mode.md), [ADR-0014](ADR-0014-desktop-gui-winforms.md),
[ADR-0016](ADR-0016-v04-assisted-recovery.md).

## Decision record (2026-11-17)

The maintainer approved V05-D1 to V05-D7 as recommended on 2026-11-17. Section 7's "Decided" column records each.

* **Decided:**
  * **D1 (A):** a per-user scheduled task, interactive, with no password, run level LUA (Limited);
  * **D2 (a):** the intervals 1, 2, 4, 6, 12 and 24 hours, default 6 hours, revisited after M1's measurement;
  * **D3 (a):** 90 days, 400 files, 8 MB, and 16 KB per record;
  * **D4 (a):** the oldest files of the product's own history are removed by exact name, in the pinned folder. The
    reading of "never deletes" is recorded in the ROADMAP;
  * **D5 (a):** the project's display name, as the audit shows it, with no persistent key. ADR-0010 stays unchanged;
  * **D6 (a):** no system notification in V0.5, so phase M6 is out of V0.5;
  * **D7 (a):** V0.5 goes ahead behind `AtmMonitoringEnabled`, and an alert names only a command present in that copy.
* **Open, with the maintainer, until 2026-11-18:** V05-D8 (does a collection include the diagnose), V05-D9 (the
  uninstaller and the shared task folder) and V05-D10 (the threshold defaults and who sets them). No phase decided or
  presumed them. Where a text depended on one, it said "pending".

### Decision record (2026-11-18)

The maintainer decided V05-D8, V05-D9 and V05-D10 as recommended on 2026-11-18. Section 7's "Decided" column records
each. With them, every decision of this record is taken.

* **D8 (a):** a collection runs the audit only. Row 7 of section 1 (the diagnose counts) is not collected, and the
  collector calls no diagnose. Phase M1 implements it.
* **D9 (a) plus (c):** the uninstaller warns and names `monitor disable` and `monitor remove-history`; the unschedule
  commands remove the shared task folder `\AgentTempManager` when it is empty, so "removed completely" holds. Phase M4
  implements it: M4a implements (c), and M4b implements (a), in which the uninstaller only reads and warns.
* **D10 (a):** the thresholds live in the per-user file `monitor.json` with the defaults of section 4. Phase M2
  implements it.

## M0 implementation record (V05-M0, 2026-11-18)

Documentation only. No file outside `docs/` and `CHANGELOG.md` changed, nothing is implemented, and no gate changed: the
eight gates in `src/` are as they were, each a single `$false` assignment. The line numbers are those of the files as
V05-M0 leaves them.

* **PRIV-3** (`docs/ELEVATION.md:52`).
  * It admits two per-user scheduled tasks. Each is created only by an explicit, confirmed command of the user, refused
    in an elevated process, run limited and interactive, with no stored credential.
  * The tasks are the automatic purge's (implemented) and the monitoring's. The monitoring's status is "Planned (V0.5
    M3), gate closed in every copy", and its validation is "not implemented, nothing validated".
  * The rest of the row is unchanged: no task, service or credential to elevate or to get around UAC.
* **SECURITY-MODEL.**
  * `:881-882`: the "only two commands" bullet notes that they stay the only ones until V0.5's task is implemented.
  * New section "Preventive monitoring: the second scheduled task (V0.5, planned)" (`:925-956`). It covers:
    * the two tasks;
    * the deliberate difference: the purge registers its task with its gate closed, while `monitor enable` needs the
      monitoring gate open and its own phrase;
    * the shared folder `\AgentTempManager`;
    * removal, **pending V05-D9** (`:951-953`; decided 2026-11-18, (a) plus (c), and written there by M1);
    * what the task never does.
* **ARCHITECTURE.** New section "The scheduler layer: two tasks (V0.5 planned, ADR-0017)" (`:110-133`).
  * A table of who builds the definition, who registers, who reads back and checks, and who removes, for each task.
  * The collector's entry point, `src/bin/agent-temp-monitor.ps1` (future), reads the gate on every run.
  * Moving `Connect-AtmTaskScheduler` to a shared place is recorded as an **option of phase M3, not decided**.
  * The folder's removal is **pending V05-D9** (`:133`; decided 2026-11-18, (a) plus (c), and written there by M1).
* **ADR-0014 section 3** (`:90-94`, `:111`).
  * The closed list gains one future read function of the monitoring history, provisionally `Get-AtmMonitorHistory`,
    marked "future, V0.5 phase M5". Phase M5 adds it to the test's list; the list stays at 28 until then.
  * The name contains none of the GUI's forbidden names.
  * The GUI never reads `AtmMonitoringEnabled`, never registers, removes or runs the task, and never collects.
  * `AtmMonitoringEnabled` joins the forbidden gate variables from V0.5.
* **This record.**
  * The status line (`:3`).
  * The gate's ordinal: ninth (`:247-248`).
  * The "Decided" column of section 7 (`:281-298`).
  * The decision record above.
* **ROADMAP.**
  * The V0.5 status row (`:20`) and the section's status (`:408-414`).
  * The reading of "never deletes" under V05-D4 (a) (`:433-436`).
* **`docs/adr/README.md:29`** and a `CHANGELOG.md` bullet.
* **Not touched:** ADR-0010 (V05-D5 (a)).

**Left for M1 to M5:**

* **M1:** the collector, the storage and the gate `AtmMonitoringEnabled` in `src/lib/Engine.Monitor.ps1`. Also the
  cost measurement, and the gate in the build, the installer and the e2e.
* **M2:** trends, thresholds and alerts. The threshold defaults and who sets them are **pending V05-D10** (decided
  2026-11-18: (a), the per-user file with the defaults of section 4).
* **M3:** the scheduler entry. That includes the choice of how the monitoring engine reaches the Task Scheduler, the
  entry point and the CI-only scheduler harness.
* **M4:** `monitor disable`, `monitor remove-history` and the uninstaller. The uninstaller and the shared folder are
  **pending V05-D9** (decided 2026-11-18: (a) plus (c)).
* **M5:** the TUI and the GUI. The one read function joins the GUI's closed list.
* **Whether a collection includes the diagnose** is **pending V05-D8**. Row 7 of section 1 is neither in nor out of M1
  until it is decided. (Decided 2026-11-18: (a), the audit only; row 7 is out of M1.)
* **M6** is out of V0.5 (V05-D6 (a)).

## M1 implementation record (V05-M1, 2026-11-18)

The collector and the storage, behind the ninth gate, closed in every copy. Nothing is scheduled (M3), no trend,
threshold or alert is computed (M2), nothing removes the history on request (M4), and the TUI and the GUI are unchanged
(M5). `Engine.Audit.ps1` is unchanged: no audit deadline (GUI-D9 is not decided), no change to B1, `RECENT` or
eligibility. The line numbers are those of the files as V05-M1 leaves them.

* **The gate.** `$script:AtmMonitoringEnabled = $false`, a single assignment in `src/lib/Engine.Monitor.ps1:22`. The
  nine gates in `src/` are each a single `$false` assignment. The build (`tools/Build-Release.ps1:73-74`), the installer's
  required files (`install/InstallCommon.ps1:61`) and the three e2e harnesses check the ninth.
* **The collector** (`Invoke-AtmMonitorCollection`, `src/lib/Engine.Monitor.ps1:575`, and its core `:620`).
  * It reads the gate first. Closed, it returns `MONITORING_GATE_CLOSED` with no mutex, no audit and no folder.
  * It runs the audit only (V05-D8 (a)), through `Invoke-AtmInventory`, and never the diagnose.
  * The per-user mutex `Global\AgentTempManager.Monitor-<16 hex digits of SHA-256(SID)>` (`:109`) is tried without
    waiting. Busy: `MONITOR_BUSY`, nothing written. An abandoned mutex is taken and the collection goes on.
  * A failed audit still writes a record, outcome `AUDIT_FAILED`, with the exception's type name only.
  * Seams, `$null` in every copy (`:58-63`): the clock, the folder, the audit, the random suffix, the mutex name and the
    file owner.
* **The record** (`New-AtmMonitorRecord`, `:259`; `ConvertTo-AtmMonitorRecordText`, `:284`).
  * Schema `atm.monitor/1`: the header (UTC time, durations, outcome `OK`, `INCOMPLETE` or `AUDIT_FAILED`, tool
    version, the previous record's name), the coverage counts, the base states counted per provider, and per group
    (provider, project display name, class) the sizes, the age and the flag counts. Rows 1 to 6 of section 1. Row 8 is
    `NOT_OBSERVABLE`, never zero; rows 7 and 9 are not collected.
  * At most 64 groups, the largest first; the rest summed into one "other" group. At most 16 KB, else
    `MONITOR_RECORD_TOO_LARGE` and nothing written. 64 groups with 100-character project names measured 13,163 bytes.
  * A SHA-256 of the text, checked on the stored bytes. It detects damage, not forgery.
* **The folder and the file** (`Open-AtmMonitorFolder`, `:405`; `Write-AtmMonitorRecordFile`, `:439`).
  * `%LOCALAPPDATA%\AgentTempManager\Monitor`, pinned with the T1 log's folder policy, created with a protected DACL.
  * Each record is created new as `<name>.partial`, flushed, renamed and read back. An existing name is refused.
* **Rotation** (`Invoke-AtmMonitorRotation`, `:496`) after each write: 90 days, 400 files and 8 MB, whichever comes
  first, and `.partial` files older than a day (V05-D3 (a), V05-D4 (a)). A strange name, a reparse point or another
  owner refuses the whole rotation, and nothing is removed.
* **The single removal** is in `Invoke-AtmMonitorPrune` (`:469`). It checks the gate, the name pattern, the product's
  folder, that the item is a file and not a reparse point, and its owner, immediately before removing it by exact name.
  A static of the suite proves that no other function of the file removes anything.
* **The reader** (`Get-AtmMonitorHistory`, `:659`; `Get-AtmMonitorStatus`, `:727`) needs no gate and takes no lock.
  * An absent folder is an empty history, and it is never created.
  * It lists final names only and never reads a `.partial`.
  * A file that fails the schema, the bounds or the hash is `HISTORY_RECORD_INVALID` and skipped, never read as zero.
  * A record whose time is earlier than its previous record's is flagged `CLOCK_SKEW`. The trend is M2's.
* **The CLI.**
  * `agent-temp monitor status` (`src/agent-temp.ps1:536`; presentation `src/lib/Report.ps1:1528-1559`) reads the
    history and exits `0`. Closed, it says monitoring is not available in this release, shows the history the reader
    found, and promises no command this copy lacks (V05-D7 (a)).
  * Any other `monitor` subverb, or none, is a usage error, `2`. No new exit code.
  * `version` shows the ninth gate (`:561-562`).
  * The engine is loaded exactly in the `monitor` and `version` blocks, and listed in `$loadedLibs` (`:44`).
* **New codes:**
  * collector: `MONITORING_GATE_CLOSED`, `MONITOR_BUSY`, `MONITOR_IDENTITY_UNAVAILABLE`, `MONITOR_MUTEX_*`,
    `MONITOR_FOLDER_UNKNOWN`, `MONITOR_RECORD_TOO_LARGE`;
  * folder and file: `MONITOR_FOLDER_*`, `MONITOR_NAME_INVALID`, `MONITOR_NAME_EXISTS`, `MONITOR_WRITE_*`,
    `MONITOR_RENAME_*`, `MONITOR_RENAMED_NOT_VERIFIED`;
  * rotation: `MONITOR_ROTATION_LIST_FAILED`, `MONITOR_ROTATION_REPARSE`, `MONITOR_ROTATION_FOREIGN_OWNER`,
    `MONITOR_ROTATION_UNEXPECTED_ITEM`, and the removal's `MONITOR_PRUNE_*`;
  * reader: `HISTORY_RECORD_INVALID`, `CLOCK_SKEW`.
* **Tests.** The suite's area "V0.5 M1" (`tests/Run-Tests.ps1`). It opens the gate only inside its own process, around
  each call, with the folder in its sandbox and a mutex name of its own. It covers:
  * the gate closed, with a positive control;
  * the record, its bounds and privacy: a real audit of a planted profile, scanned by `tools/Test-AtmPrivacy.ps1` with
    the planted values as needles, with a positive control;
  * each rotation limit alone, the refusals, the `.partial`, the reader, the clock, two collectors, and no write
    outside the folder;
  * the CLI in both languages, and the statics.
* **Measured cost** (CI only; planted trees of 2,000 files on every job and 10,000 more on the x64 jobs; information,
  not a timing assertion). Each job prints the audit's and the whole collection's durations in its log (`V0.5 M1
  custo:`). The figures of CI run 44402312363 (2026-11-18, the phase's green run), per job; "12,000" is the 2,000
  plus the 10,000 planted on the x64 jobs:

  | Job (run 44402312363) | Runner, shell | 2,000 files: audit / whole collection | 12,000 files: audit / whole collection |
  |---|---|---|---|
  | `test (powershell)` | x64, Windows PowerShell 5.1 | 70 ms / 109 ms | 318 ms / 350 ms |
  | `test (pwsh)` | x64, PowerShell 7.6.9 | 32 ms / 82 ms | 167 ms / 179 ms |
  | `test ARM64 (powershell)` | ARM64, Windows PowerShell 5.1 | 87 ms / 150 ms | not run (2,000 only on ARM64) |
  | `test ARM64 (pwsh, subset)` | ARM64, PowerShell 7.6.10 | 72 ms / 104 ms | not run (2,000 only on ARM64) |

  The run before the fix (44394992914) gave the same order of magnitude, at most 313 ms for a whole collection. At
  these sizes a collection takes well under a second on every runner, far below V05-D2's shortest interval (1 hour).
  The figures are of planted trees on CI runners, not of a real user's profile; V05-D2 is revisited with them in M3.
* **NAO_TESTADO.**
  * The real folder under `%LOCALAPPDATA%`: the suite uses its sandbox through the seam and checks that the real folder
    is never created.
  * A run really ended by the scheduler's time limit: a planted `.partial` stands in for it.
  * Where the sandbox cannot get a single-owner ACL (a standard session whose TEMP lets other accounts change it), the
    cases that need the folder are NAO_TESTADO. On CI the ACL is adjusted, so a refusal there is a failure.

**Left for M2 to M5:** trends, thresholds and alerts (M2, V05-D10 (a)); the scheduler entry and its CI-only harness
(M3), which then revisits V05-D2 with the cost above; `monitor disable`, `monitor remove-history` and the uninstaller
(M4, V05-D9 (a) plus (c)); and the TUI and the GUI (M5).

## M2 implementation record (V05-M2, 2026-11-18)

Trends, thresholds and alerts, behind the same ninth gate, closed in every copy. They are computed only when the history
is read with the gate open, which happens only inside the test suite's process. Nothing new is scheduled (M3), nothing
removes the history on request (M4), and the TUI and the GUI are unchanged (M5). `src/agent-temp.ps1`,
`Engine.Audit.ps1`, B1, `RECENT` and eligibility are unchanged. The line numbers are those of the files as V05-M2 leaves
them. Besides the files of section 6's M2 row, M2 changes the `monitor status` lines in `src/lib/Report.ps1`.

* **`monitor.json` in the history folder.** The rotation (`src/lib/Engine.Monitor.ps1:549`) and the reader (`:728`)
  accept exactly the name `monitor.json` when it is a plain file, not a reparse point, with the expected owner (the
  user, or the token's default owner). The reader does not count it, and the rotation passes it.
  * A `monitor.json` with another owner, or a folder or a junction with that name, refuses as before. The rotation
    refuses as a whole and removes nothing, and the reader counts it as unexpected.
  * The rotation never removes it: the file is never in the rotation's plan, and `Invoke-AtmMonitorPrune` (`:498`)
    refuses the name because it is neither a record name nor a `.partial` name. A case of the suite proves both.
  * What `monitor remove-history` does with the user's `monitor.json` (leave it and report it, or remove it with the
    rest) is M4's to decide, with V05-D9. (Decided in M4b: it stays, and with it the folder. See the M4b
    implementation record.)
* **The thresholds** (`Get-AtmMonitorConfig`, `:883`, with `Get-AtmMonitorConfigFile`, `:806`, and
  `Get-AtmMonitorConfigValues`, `:853`). Read only: the product never writes, creates or fixes `monitor.json`.
  * No file: the defaults, no alert.
  * A present file is refused as a whole, with the defaults, `MON_CONFIG_INVALID` and the reason of the first check
    that failed. The checks, in order, with their reasons:
    * a reparse point in the folder's chain or on the file: `REPARSE`;
    * a folder with the name: `NOT_A_FILE`;
    * another owner: `OWNER`;
    * more than 4 KB: `SIZE`;
    * not strict UTF-8: `ENCODING`;
    * not JSON: `JSON`;
    * JSON but not an object: `TYPE`;
    * an unknown member, with names compared case-sensitively: `UNKNOWN_KEY`;
    * a value that is not a JSON number, or a `failedCollections` that is not whole: `TYPE`;
    * a value outside its bounds, both ends included: `RANGE`. A number too large for either shell's reader is also
      `RANGE`.

    A read error is `READ`, and a folder that cannot be known or checked is `FOLDER`.
  * A missing member takes its default. The bounds (`:55-61`) are the round's, unchanged:

    | Member | Default | Bounds |
    |---|---|---|
    | `totalGiB` | 20 | 1 to 4096 |
    | `growthGiBPerDay` | 2 | 0.1 to 1024 |
    | `orphanSuspectedGiB` | 5 | 1 to 4096 |
    | `livenessUnknownGiB` | 5 | 1 to 4096 |
    | `failedCollections` | 3 | 2 to 30, whole |
  * One leading UTF-8 byte order mark is accepted and dropped, because Windows PowerShell 5.1's `Out-File -Encoding
    utf8` writes one.
  * `3.0` counts as a whole number for `failedCollections`; `3.5` does not.
  * The trend window is fixed at 7 days, with no member.
* **The trends** (`Get-AtmMonitorTrends`, `:958`; the slope, `Get-AtmMonitorSlope`, `:918`).
  * The least-squares slope of bytes per day, rounded to whole bytes per day. The window is the 7 days up to the newest
    record that is not `CLOCK_SKEW`, both ends included.
  * The total sums every group, "other" included. Its points come only from `OK` records.
  * A group is keyed by provider, project, identified and class; "other" has no trend.
    * A group's points come from a record that is not `AUDIT_FAILED`, whose coverage is complete, and in which that
      group's flag is complete.
    * So an `INCOMPLETE` record with complete coverage still gives the points of its complete groups.
    * The reason: the writer marks a record `OK` only when every group is complete (`:306-308`). If only `OK` records
      gave group points, one incomplete group could never be a gap for its own trend alone.
    * A record with incomplete coverage gives no group point, because a missing profile can hide part of any group.
  * Gaps are never points, and never a decrease: `INCOMPLETE` and `AUDIT_FAILED` records for the total, invalid files,
    `CLOCK_SKEW` records, an incomplete group, and a record with incomplete coverage for the groups.
  * Fewer than 4 points, or points spanning less than 24 hours, give `INSUFFICIENT_DATA`. Exactly 4 points spanning
    24 hours are enough.
  * The delta compares the newest entry (a record or an invalid file, by name) with the entry before it. It is a value
    only when both are valid `OK` records and neither is `CLOCK_SKEW`. Otherwise it is a gap, never a decrease or
    "resolved"; with no entry before, it is none.
  * At most 5 groups with a trend are listed, the largest slope first.
* **The alerts** (`Get-AtmMonitorAlerts`, `:1040`; the commands they name, `:70-77`). A pure function: it calls no
  engine, process, command, scheduler or network. Each alert has a code, a catalog text in both languages, and the names
  of the commands it recommends; it never runs them. A value fires only when it is strictly greater than its threshold:

  | Code | Fires when | Names |
  |---|---|---|
  | `MON_TOTAL` | the total of the newest `OK` record > `totalGiB` | `agent-temp preview`, then `agent-temp clean` |
  | `MON_GROWTH` | the slope of the total > `growthGiBPerDay`; never with `INSUFFICIENT_DATA` | `agent-temp audit` |
  | `MON_ORPHAN_SUSPECTED` | the `ORPHAN_SUSPECTED` groups of the newest `OK` record > `orphanSuspectedGiB` | `agent-temp preview`, then `agent-temp isolate` |
  | `MON_LIVENESS_UNKNOWN` | the same, `LIVENESS_UNKNOWN` > `livenessUnknownGiB` | `agent-temp diagnose` |
  | `MON_COLLECTION` | none of the `failedCollections` newest entries is an `OK` record (an invalid file counts as not `OK`) | `agent-temp monitor status` |
  | `MON_CONFIG_INVALID` | `monitor.json` was refused | no command; the text names the format in `docs/USAGE.md` |

  * The groups summed into "other" have no class, so the two class sums are a lower bound when a record summed any
    groups.
  * `MON_RECOVERY` is out of V0.5 (V05-D8 (a)), so the table of section 4 is not implemented for it.
  * A static of the suite checks that each command named is a verb the launcher accepts.
* **Only with the gate open.** `Get-AtmMonitorStatus` (`:776`) computes the thresholds, the trends and the alerts only
  inside `if ($script:AtmMonitoringEnabled)`.
  * With the gate closed, `monitor.json` is not read, and no trend or alert is computed: a history left by another copy
    feeds no alert in a copy that does not collect.
  * `monitor status` then shows what it showed in M1: the notice, and the residue count when records are present.
* **`monitor status` with the gate open** (only in the suite; `src/lib/Report.ps1:1557-1594`) shows:
  * the latest complete total and the delta;
  * the trend of the total;
  * up to 5 groups with the largest trend;
  * the state of the thresholds: the defaults, the file, or refused with the code and the reason;
  * the alerts, each followed by the command it names.

  The exit code stays `0`, and there is no new exit code.
* **Not in M2.**
  * The line under the header of `audit` (section 4) is deferred to M5, with the TUI and the GUI.
  * A refused rotation raises no alert. Section 3 says it "raises an alert", but no M2 code exists for it. The
    rotation's code lives only in the collector's result, and the alerts are computed from the history as the reader
    finds it.
    * What the user sees instead: the item that refused it is counted as unexpected by the reader (`monitor status`
      says how many other items the folder holds), and a reparse point in the folder's chain makes the history unread.
    * Whether a refused rotation needs an alert of its own, perhaps from M3's scheduled run, is left open for the
      maintainer.
* **New codes:**
  * alerts: `MON_TOTAL`, `MON_GROWTH`, `MON_ORPHAN_SUSPECTED`, `MON_LIVENESS_UNKNOWN`, `MON_COLLECTION`,
    `MON_CONFIG_INVALID`;
  * reasons of a refused `monitor.json`: `REPARSE`, `NOT_A_FILE`, `OWNER`, `SIZE`, `ENCODING`, `JSON`, `TYPE`,
    `UNKNOWN_KEY`, `RANGE`, `READ`, `FOLDER`;
  * trend state: `INSUFFICIENT_DATA`.
* **Tests.** The suite's area "V0.5 M2" (`tests/Run-Tests.ps1`), in both shells. Histories are planted as record text
  in a sandbox folder through the folder seam, and the gate is opened only around a status or a rotation call. It
  covers:
  * the slope: linear, constant and decreasing series, points off whole days, and "other";
  * `INSUFFICIENT_DATA` at 3 points, at 4 points in 24 hours less 1 ms, and at the exact boundary;
  * the gaps and the delta;
  * `CLOCK_SKEW` and the window's two edges;
  * every check of `monitor.json`, each bound at and just past it, and a snapshot proving the file is never written;
  * `monitor.json` in the folder, for the rotation, the reader and the single removal;
  * each alert at its threshold and just above, with its command;
  * instrumentation showing that nothing is run, with a positive control;
  * the gate closed, with a positive control;
  * the `monitor status` lines in both languages;
  * the statics. The M1 static also lists the new functions among the readers.
* **NAO_TESTADO.**
  * `monitor status` through the CLI with the gate open: the gate opens only inside the suite's process, and the
    launcher runs in a child process with the copy's closed gate. The lines are checked through the presentation
    function in the suite's process.
  * The real folder under `%LOCALAPPDATA%`, as in M1.

## M3a implementation record (V05-M3a, 2026-11-18)

The first half of phase M3: the collector's scheduled task, `monitor enable` and the entry point, behind the same ninth
gate, closed in every copy. The scheduler is a seam: the suite registers only into an in-memory fake, and the real
scheduler is only read. M3b, the CI-only harness that registers, runs and removes a real task on a disposable runner,
comes next. Nothing removes the task or its folder (M4), and the TUI and the GUI are unchanged (M5). `Engine.Isolate.ps1`,
`Engine.Audit.ps1`, B1, `RECENT` and eligibility are unchanged. The line numbers are those of the files as V05-M3a leaves
them.

* **How the engine reaches the scheduler** (the choice M0 left to M3). `Connect-AtmTaskScheduler` is **not moved**: it
  stays in `Engine.Isolate.ps1`, the only place that creates `Schedule.Service`. The monitoring engine calls it and the
  purge's read-only helpers (`Test-AtmTaskNotFound`, `Get-AtmTaskSchedulerCode`, `Resolve-AtmTaskUserSid`), plus
  `Get-AtmEngineConsoleObservation` (`Engine.Clean.ps1`) and `Get-AtmIdentityState` (`Engine.Diagnose.ps1`), only inside
  its task functions; the launcher already loads those engines before the `monitor` block. A static of the suite lists
  them and where they may appear. Moving the connection would have changed `Engine.Isolate.ps1` and the P6b static for
  no gain in M3a.
* **Constants and seams** (`src/lib/Engine.Monitor.ps1:86-91`, `:109-110`).
  * The task folder `\AgentTempManager` (shared with the purge's task), the prefix `Monitor-`, the intervals
    `1, 2, 4, 6, 12, 24` and the default 6 (V05-D2 (a), unchanged), the time limit `PT1H` and the phrase
    `ATIVAR MONITORAMENTO`.
  * Two seams, `$null` in every copy: the suite's task name (only the exact form `MonitorTest-<8 hex digits>`, `:1140`;
    any other value throws) and the token source.
* **The task name** (`Get-AtmMonitorTaskName`, `:1134`): `Monitor-` and the first 16 hex digits of the SHA-256 of the
  user's SID, never the SID.
* **The definition** (`New-AtmMonitorTaskDefinition`, `:1260`), built and never registered by itself; `$null` with the
  gate closed or an interval outside the list.
  * Principal: the user's SID, logon type interactive (3), run level limited (0), no password.
  * One time trigger (`Triggers.Create(1)`) starting at the next whole minute at least one minute ahead, local time
    without an offset (`Get-AtmMonitorTaskStart`, `:1164`), repeated every `PT<N>H` with no duration (no end).
  * Settings: enabled; `StartWhenAvailable` (a missed run starts at the next opportunity);
    `DisallowStartIfOnBatteries` and `StopIfGoingOnBatteries` false; `ExecutionTimeLimit` `PT1H`; `MultipleInstances` 2
    (IgnoreNew: one run at a time).
  * One action (`Get-AtmMonitorTaskAction`, `:1153`): Windows PowerShell 5.1 by its absolute path under the system
    folder, with `-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "<copy>\bin\agent-temp-monitor.ps1"`,
    and no working directory.
* **The registration** (`Register-AtmMonitorTask`, `:1293`), the only one, called only by `Invoke-AtmMonitorEnable`.
  It reads the gate first, creates `\AgentTempManager` when missing (a folder created meanwhile by another process is
  used), and registers with `TASK_CREATE` (2), logon type 3, no password. A task already there, or registered meanwhile
  (`TASK_CREATE` refuses), is `MONITOR_TASK_EXISTS`: never replaced. Other scheduler errors return the purge's code form
  (for example `TASK_SCHEDULER_0x80070005`).
* **The state** (`Get-AtmMonitorTaskState`, `:1233`, with `Test-AtmMonitorTaskMatch`, `:1201`), read only, with the
  gate open or closed, and never creating the task folder: `ABSENT`, `PRESENT`, `DIVERGENT` with its reasons
  (`TASK_PATH`, `TASK_USER`, `TASK_LOGON_TYPE`, `TASK_RUN_LEVEL`, `TASK_ACTION_COUNT`, `TASK_ACTION_TYPE`,
  `TASK_ACTION_PATH`, `TASK_ACTION_ARGUMENTS`, `TASK_ACTION_DIRECTORY`, `TASK_TRIGGER_COUNT`, `TASK_TRIGGER_TYPE`,
  `TASK_INTERVAL`), or `UNREADABLE` with the scheduler's code. It also gives the path, enabled or not, the interval,
  the next run and the last run with its result. Never the SID or the account name.
* **`monitor enable`** (`Invoke-AtmMonitorEnable`, `:1331`; CLI `src/agent-temp.ps1:551-567`). In this order:
  1. the gate closed: `MONITORING_GATE_CLOSED`, before anything is read or asked (`:1343`);
  2. an interval outside the list: `MONITOR_INTERVAL_INVALID`;
  3. a token that is not standard (elevated, full, or not medium integrity, or unreadable):
     `MONITOR_TASK_REQUIRES_STANDARD_TOKEN`;
  4. a copy that is not installed, or without its entry point: `MONITOR_TASK_NOT_INSTALLED`;
  5. no presenter or reader: `SEM_APRESENTACAO_OU_CONFIRMACAO`;
  6. the console, observed by the engine itself: `CONSOLE_NOT_OBSERVED`;
  7. the task unreadable: `MONITOR_TASK_UNREADABLE`; present in any state: `MONITOR_TASK_EXISTS`;
  8. the plan shown (`src/lib/Report.ps1:1634`);
  9. the phrase `ATIVAR MONITORAMENTO`, typed exactly, else `MONITOR_TASK_NOT_CONFIRMED`;
  10. the registration, then the read-back: anything but `PRESENT` is `MONITOR_TASK_NOT_VERIFIED`.

  Nothing is asked before the plan. `-IntervalHours` is accepted only by `monitor enable` (`src/agent-temp.ps1:29`,
  `:559-562`); a value that is not one of the six whole numbers is a usage error. `monitor status` and `recover` refuse
  it (exit 2); the other verbs ignore it, as they ignore other foreign options. Exit codes of `monitor enable`: `0` the
  task created and read back, `2` usage, `3` refused or not confirmed, `6` no interactive console. With the gate closed
  it is always `3`.
* **The entry point** `src/bin/agent-temp-monitor.ps1`, in the pattern of `agent-temp-autopurge.ps1`.
  * No parameter block: any argument is exit `2`, before anything is read.
  * It checks `manifest.json` before loading anything: every listed file's SHA-256, its own listing and that of every
    file it loads (`:32`), and no unlisted provider. A failure, or no manifest (a source checkout), is exit `5`.
  * It then loads only `Engine.Audit.ps1` (with `I18n.ps1`), the providers and `Engine.Monitor.ps1`, and calls
    `Invoke-AtmMonitorEntry` (`src/lib/Engine.Monitor.ps1:712`), which reads the gate first: closed, exit `3`, with no
    native types, no folder, no mutex and no audit. Open, one collection: `0` recorded, `3` refused.
  * Output goes through `Write-Output` (a scheduled run has no console); an unexpected failure is exit `10`, with the
    exception's type only.
  * It is in the installer's required files (`install/InstallCommon.ps1:61`); the package list is built from the tree,
    so `tools/Build-Release.ps1` is unchanged.
* **Presentation** (`src/lib/Report.ps1`): `Get-AtmMonitorTaskLines` (`:1604`) in `version` (`src/agent-temp.ps1:589`)
  and in `monitor status`, right after the gate lines (`Get-AtmMonitorStatusLines`, `:1528`). A present or divergent
  task with the gate closed is a residue of another copy: the text says its collector exits without collecting and that
  this version has no command that removes it (superseded by M4a: `monitor disable` removes it, and with the gate
  closed it refuses, so the task stays). The plan and the result are `Show-AtmMonitorEnablePlan` (`:1634`) and
  `Show-AtmMonitorEnableResult` (`:1647`). Texts in both languages (`src/lib/I18n.ps1:293-324`, `:1592-1623`).
* **New codes:** `MONITOR_INTERVAL_INVALID`, `MONITOR_TASK_REQUIRES_STANDARD_TOKEN`, `MONITOR_TASK_NOT_INSTALLED`,
  `MONITOR_TASK_UNREADABLE`, `MONITOR_TASK_EXISTS`, `MONITOR_TASK_NOT_CONFIRMED`, `MONITOR_TASK_NOT_VERIFIED`,
  `MONITOR_TASK_TEST_NAME_INVALID` (suite only), the twelve `TASK_*` divergence reasons above, and the reused
  `MONITORING_GATE_CLOSED`, `CONSOLE_NOT_OBSERVED`, `SEM_APRESENTACAO_OU_CONFIRMACAO` and `TASK_SCHEDULER_0x<hex>`.
* **V05-D2 is unchanged.** M1's measured cost (section "M1 implementation record": at most 350 ms for a whole
  collection of 12,000 planted files, on CI runners) is far below the shortest interval of 1 hour, so it gives no
  reason to change the list or the default. That evidence is of planted trees, not of a real user's profile.
* **Tests.** The suite's area "V0.5 M3a" (`tests/Run-Tests.ps1`), in both shells, with an in-memory fake scheduler
  whose methods throw real COM HResults. The gate is opened only inside the suite's process, around each call. It
  covers:
  * the definition, built from the real scheduler's `NewTask` and never registered, checked field by field in its XML
    for each interval and the default;
  * the name, the test-name form, every divergence reason, and the token rule;
  * every refusal of `monitor enable` in order, with counters proving nothing later was read or asked;
  * the happy path, the races (the folder and the task created by another process), the read-back failure and a
    scheduler code;
  * `Invoke-AtmMonitorEntry` in process, and the entry point in a child process from a staged copy with its manifest
    (an argument, the gate closed, no manifest, a changed file, an unlisted provider);
  * the state read from the real scheduler under a test name (absent; the folder never created), then the fake;
  * the lines and the CLI in both languages;
  * the statics: the P6b static (`:5427`) now expects the registration calls in `Engine.Isolate.ps1` and
    `Engine.Monitor.ps1` only; the GUI's forbidden list gains the four new exact names (`:15259`); and the M3a static
    proves the call order, no removal, the declared foreign helpers, the entry point's facts, and that the suite never
    registers a real task. (Superseded by M4a: the M3a area never registers a real task; since M4a, one CI-only case
    does, outside that area.)
* **NAO_TESTADO.**
  * The real scheduler registering, running and removing the task: M3b's CI-only harness. The suite never registers a
    real task, so the real `RegisterTaskDefinition` call, the scheduler's acceptance of the definition, a real
    scheduled run of the entry point with a hidden window, and the console a scheduled run gets (section 8) are not
    validated by M3a.
  * `monitor enable` through the CLI with the gate open: only the gate-closed path runs in a child process.
  * The real history folder under `%LOCALAPPDATA%`, as in M1.

**Left for M3b to M5:** the CI-only real-scheduler harness (M3b); `monitor disable`, `monitor remove-history` and the
uninstaller (M4, V05-D9 (a) plus (c)); and the TUI and the GUI (M5).

## M3b implementation record (V05-M3b, 2026-11-19)

The second half of phase M3: the real Task Scheduler, only in a CI-only harness, on disposable runners, under a test
task name. No product code changes: `src/`, `install/` and the ninth gate are as V05-M3a left them, and the gate stays
`$false` in every copy, the copy installed on the runner included. The line numbers below are those of the files as
V05-M3b leaves them.

* **The harness** `tests/e2e/Invoke-MonitorE2E.ps1`, CI-only and never shipped. It is on the build's CI-only list
  (`tools/Build-Release.ps1:35`), so the stage leaves it out and an archive that contains it is refused. The install
  e2e checks that the package does not contain it. It refuses to run outside a GitHub-hosted runner unless
  `-DisposableMachine` is given.
* **Containment.**
  * Each leg loads the installed engine into its own process. It opens the monitoring gate there, in memory, after
    `Engine.Monitor.ps1` is loaded. The nine installed gates and the SHA-256 of every installed file are compared before
    and after.
  * The only seam set is the engine's test task name, `MonitorTest-<8 random hex digits>` of the run. The token,
    console, clock, folder and other seams are never set, so the token checks are the real ones.
  * Every touch of the scheduler goes through a wrapper of the harness whose first statement checks the name:
    * the exact form;
    * the run's name as the engine's override, so the engine names the test task and never the product's.
  * The product removes no task until M4. The harness's own `Remove-TestTask` is the only `DeleteTask`, of the test name
    only. The `\AgentTempManager` folder stays. (Superseded by M4a: the harness removes its task with
    `Unregister-AtmMonitorTask` and runs the empty-folder helper.)
  * The harness writes only booleans, codes and counts.
* **Leg A, the install e2e's temporary standard user.** It reuses the mechanism of the step
  `autopurge-task-standard-user` (`Start-Process -Credential`); there is no new account or credential mechanism. The
  harness checks, in order:
  * the token is standard (`Test-AtmMonitorStandardToken`, with the elevation type and integrity recorded);
  * `Register-AtmMonitorTask` with the user's own SID, the installed entry point and 6 hours returns `$null`;
  * the read-back is `PRESENT`, with:
    * that user, logon type 3 and run level 0;
    * no `<Password>` in the XML;
    * the exact action, with `-WindowStyle Hidden`;
    * `PT6H` and a next run in the future;
  * a second registration is `MONITOR_TASK_EXISTS`;
  * the task is run once and polled for at most 45 seconds. Its own trigger starts at least 61 seconds after
    registration, so a result in that window comes from this run. The expected result is last result `3` (the
    installed gate is closed) with the user's history folder unchanged. A run the scheduler does not start, refuses
    or keeps queued is NOT_TESTED, with the observed state and code. The logon type, the account and the password are
    never changed to make it run. A small exit code other than 3 fails the case as a product defect;
  * the test task is removed by its exact name;
  * the read-back is `ABSENT`.
* **Leg B, the elevated runner account.**
  * `Invoke-AtmMonitorEnable`, with the gate open in memory, refuses with `MONITOR_TASK_REQUIRES_STANDARD_TOKEN`. The
    plan is not shown, the phrase is not asked, and nothing is registered (read back `ABSENT`). The token is recorded
    as a readable elevated one, so the refusal is not an unreadable token's.
  * Then, optionally, the same cycle for a test task of that account, registered with run level 0 (the product's
    definition), to prove the exit code 3 on a runner where the scheduler starts it. The runners have UAC enabled, so
    run level 0 gives the filtered token; the run's own token is not read.
* **The gate closed, from outside (both legs).** The installed `agent-temp monitor enable -Lang en-US`, through
  `cmd /c` as a new process, exits `3` with `MONITORING_GATE_CLOSED`, asking no phrase. The product's task folder lists
  the same tasks before and after; the harness compares a count and a hash of the names.
* **The hidden window (section 8):** NOT_TESTED by design. The action read back carries `-WindowStyle Hidden`. The
  entry point ends at the gate check within seconds, and the harness does not trace or capture windows, so whether a
  console window appeared is not observed.
* **The install e2e** (`tests/e2e/Invoke-InstallE2E.ps1`) adds:
  * the package check;
  * `Read-MonSummary`;
  * the steps `monitor-m3b-leg-A-standard-user` and `monitor-m3b-leg-B-elevated`, after the R6 legs and before X2 and
    the uninstall.

  Only the harness summaries are kept.
* **Measured** (first CI run 44452989213). All six install e2e jobs agreed: windows-2025, windows-2022 and
  windows-11-arm, each with the installer in powershell and in pwsh.
  * Leg A: 12 PASS and 2 NOT_TESTED.
    * The token, the registration, the read-back, the duplicate, the removal and the absence all held.
    * **The run once was NOT_TESTED.** `Run` was accepted with no error, but within the 45 seconds the task stayed
      Ready (state 3) with last result `0x00041303` (never run). The likely cause, not observed directly: the scheduler
      does not start an interactive task for a user with no interactive session, and that user exists on the runner
      only as a secondary-logon process.
    * The window was NOT_TESTED, as above.
  * Leg B: 15 PASS and 1 NOT_TESTED (the window).
    * The refusal held, and nothing was registered.
    * **Its own test task ran once and ended with last result 3**, the installed gate closed, with the account's
      history folder unchanged.
  * Both legs: the installed `monitor enable` exited 3, and the installed copy was unchanged.
  * The artifact privacy step (FINAL-B) scanned the summaries with no finding.
* **Tests.** The suite's area "V0.5 M3b" (`tests/Run-Tests.ps1`), after the scale area. It covers:
  * the harness's refusal outside a disposable machine, in a child process with the runner markers cleared, which
    creates no summary;
  * a static case:
    * the harness is in `$ciOnly` before the stage exclusion, and out of the package;
    * the guard comes before anything;
    * there is one gate assignment, in memory, after the installed engine;
    * the test name is the only seam;
    * every scheduler call is inside a wrapper whose first statement is the name check;
    * `DeleteTask` appears once, in `Remove-TestTask`, on the test name;
    * there is no definition, folder, account, password, logon-type change or file write other than the summary;
    * the install e2e's monitoring steps remove no task and create no account;
    * `src` never cites the harness;
  * the real run, NOT_TESTED in the suite.
* **NOT_TESTED.**
  * The hidden window, as above.
  * A scheduled run by the standard user: the scheduler did not start it on any runner (state 3, `0x00041303`). The
    only real scheduled run proven is in the runner's own account.
  * The real scheduler of any machine other than a disposable CI runner.

**Left for M4 and M5:** `monitor disable`, `monitor remove-history` and the uninstaller (M4, V05-D9 (a) plus (c)); and
the TUI and the GUI (M5).

## M4a implementation record (V05-M4a, 2026-11-19)

The first part of phase M4: `agent-temp monitor disable`, and V05-D9 (c), the shared task folder removed when it is
empty by both unschedule commands. The ninth gate stays `$false` in every copy, and `monitor disable` sits behind it.
`install/` is unchanged; the uninstaller (V05-D9 (a)) and `monitor remove-history` come in a later M4 phase. The line
numbers below are those of the files as V05-M4a leaves them.

* **The removal** `Unregister-AtmMonitorTask` (`Engine.Monitor.ps1:1371`), the monitoring engine's only `DeleteTask`.
  * It checks the gate first (`MONITORING_GATE_CLOSED`, before the scheduler is reached).
  * It reads the task again and removes it only when `Test-AtmMonitorTaskMatch` finds no divergence, in the same read.
  * It refuses with nothing touched on any divergence (`MONITOR_TASK_DIVERGENT`) and when the task is absent
    (`MONITOR_TASK_ABSENT`).
  * It returns `$null` or a code, and never touches the folder.
* **`monitor disable`,** `Invoke-AtmMonitorDisable` (`:1389`), called only from the CLI's `monitor` block
  (`agent-temp.ps1:560`). In order:
  1. the gate closed refuses with `MONITORING_GATE_CLOSED` before anything is read or asked;
  2. no presenter or reader;
  3. the console, observed by the engine (`CONSOLE_NOT_OBSERVED`, exit 6);
  4. the task: absent (`MONITOR_TASK_ABSENT`), unreadable (`MONITOR_TASK_UNREADABLE`) or divergent
     (`MONITOR_TASK_DIVERGENT`, with the reasons).

  Then the plan is shown (task, interval, action, folder, and that the history is not touched), and the phrase
  `DESATIVAR MONITORAMENTO` (`:92`) is asked (`MONITOR_TASK_NOT_CONFIRMED`). Only then:
  * the task is removed (`Unregister-AtmMonitorTask`);
  * it is read back until it is `ABSENT` (`MONITOR_TASK_NOT_VERIFIED` otherwise);
  * only after that, the empty folder is handled (below).

  No standard token is required: removing the user's own task elevates nothing, and the strict match keeps it from
  touching another user's. Exit codes as `unschedule-autopurge`: `0` done (whatever the folder's outcome), `2` usage
  (`-IntervalHours`), `3` refused or not confirmed, `6` no console.
* **The empty folder (V05-D9 (c)),** `Remove-AtmEmptyTaskFolder` (`Engine.Isolate.ps1:1910`). It is called only by
  `Invoke-AtmAutoPurgeUnschedule` (`:1983`) and `Invoke-AtmMonitorDisable`, each after its own task is read back
  `ABSENT`.
  * It takes no parameter. It acts only on the product's constant folder (`\AgentTempManager`, the same constant in
    both engines).
  * Empty means no task, hidden ones included (`GetTasks(1)`), and no subfolder (`GetFolders(0)`), each read by its
    count; nothing is enumerated or named.
  * The Task Scheduler's `DeleteFolder` is the final limit. A task this account cannot see, one registered meanwhile,
    or a denied access makes it refuse, and the folder is kept with the scheduler's code.
  * It makes one attempt, with no retry, no elevation, no ACL change and no task removal.
  * Its outcome, `ABSENT`, `NOT_EMPTY` (with the counts), `REMOVED` or `KEPT` (with the code), is the result's `Folder`
    field. It never fails the command.
  * `unschedule-autopurge` keeps its own gate rules (none) and only gains this step.
* **Presentation.** `Show-AtmMonitorDisablePlan` and `Show-AtmMonitorDisableResult` (`Report.ps1:1682`, `:1692`), and
  one folder line for both commands (`Get-AtmTaskFolderLine`, `:456`). `ap.task.removed` no longer says that the
  folder stays. The task line of `version` and `monitor status` names `monitor disable` only where the gate is open;
  with the gate closed it still says that no command of this copy removes a leftover task.
* **The M3b harness** (`tests/e2e/Invoke-MonitorE2E.ps1`) now removes its test task with the product's removal:
  * `Invoke-TestUnregister` (`:205`) calls `Unregister-AtmMonitorTask`, behind the name check;
  * then the read-back `ABSENT`;
  * then `Invoke-TestFolderCleanup` (`:210`) calls the product's helper between two listings of the folder, and the
    state must agree with them. The state per leg is in the summary.

  `Remove-TestTask` remains only as the safety net of a `finally` around each leg's cycle.
* **Tests.** The suite's area "V0.5 M4a" (`tests/Run-Tests.ps1`), after M3b, uses a fake scheduler in memory for
  every removal, and a static of the area checks it. It covers:
  * the helper: absent, empty, a visible or hidden task, subfolders, a refused `DeleteFolder` with no second attempt,
    and unreadable counts;
  * each refusal of `disable` in order, the closed gate proven with seams that fail if called;
  * the divergence read again just before `DeleteTask`;
  * a wrong phrase that removes nothing;
  * `unschedule-autopurge` with the folder;
  * the presentation in both languages;
  * the CLI with the gate closed.

  The P6b and M3a statics now expect two `DeleteTask` and one `DeleteFolder`, and pin the callers and the order. On
  the CI only:
  * the P6b real-task case removes the folder after the last task, and keeps it (`NOT_EMPTY`) with another task;
  * a new case shows the scheduler's own `DeleteFolder` refusing a folder that holds a task;
  * a new case, "M4a real", runs `monitor disable` on the real scheduler.
    * Setup: a test task `MonitorTest-<8 hex>` with the product's definition, registered by the test code, and the gate
      opened only in the suite's memory.
    * A wrong phrase removes nothing.
    * With another test task in the folder, the disable removes its own task and the folder stays `NOT_EMPTY`.
    * Alone, the disable removes the task and then the folder (`REMOVED`).
    * The runner's elevated token reaches the question.
    * A static allows this case alone, outside the area, to reach the removal.
* **NOT_TESTED.**
  * `monitor disable` with the gate open through the CLI.
  * The real removal of the monitoring task outside the CI (the suite's real case and the harness).
  * A folder holding another user's task on a real machine. The CI shows the scheduler's refusal for a folder with a
    task of the same account.

**Left for M4 and M5:** `monitor remove-history` and the uninstaller (V05-D9 (a)); and the TUI and the GUI (M5).
(Superseded by M4b, below: only the TUI and the GUI (M5) are left.)

## M4b implementation record (V05-M4b, 2026-11-21)

The second and last part of phase M4: `agent-temp monitor remove-history`, and V05-D9 (a), the uninstaller's notice.
The ninth gate stays `$false` in every copy, and `monitor remove-history` sits behind it, so in every distributed copy
it refuses before it reads or asks anything. The uninstaller only reads: it removes nothing of the monitoring. The line
numbers below are those of the files as V05-M4b leaves them.

* **The decisions of this phase** (the auditor's, within V05-D9 (a) plus (c)):
  * the user's `monitor.json` is never removed, so it stays, and with it the history folder (`KEPT_CONFIG`);
  * a collection task in any state other than `ABSENT` refuses (its next run would create the history again);
  * the collector's mutex is taken without waiting, after the phrase, and the inventory is taken again under it;
  * the files go only through the engine's file removal (`Invoke-AtmMonitorPrune`, `Engine.Monitor.ps1:520`), and the
    folder only through a second, non-recursive removal on its exact path;
  * the parent folder `%LOCALAPPDATA%\AgentTempManager` is never removed. Besides `Monitor`, it holds the quarantine
    root `Q` and the automatic purge's log `AutoPurgeLog` (`Engine.Isolate.ps1:52`, `:124-126`), neither of which
    belongs to the monitoring.
* **`monitor remove-history`,** `Invoke-AtmMonitorRemoveHistory` (`Engine.Monitor.ps1:1514`), called only from the
  CLI's `monitor` block (`agent-temp.ps1:571`). In order, with nothing asked before the plan:
  1. the gate closed refuses with `MONITORING_GATE_CLOSED` before anything is read or asked;
  2. no presenter or reader (`SEM_APRESENTACAO_OU_CONFIRMACAO`);
  3. the console, observed by the engine (`CONSOLE_NOT_OBSERVED`, exit 6);
  4. the collection task not `ABSENT` (`MONITOR_HISTORY_TASK_PRESENT`; the text names `monitor disable`);
  5. the history folder: unknown (`MONITOR_FOLDER_UNKNOWN`), absent (`MONITOR_HISTORY_ABSENT`, nothing to do), or
     refused by its chain (`MONITOR_FOLDER_<status>`);
  6. the identity (`MONITOR_IDENTITY_UNAVAILABLE`), then the record folder's rule, checked by the same pin the
     collector uses and released at once, which creates nothing (`MONITOR_FOLDER_<error>`);
  7. the inventory, `Get-AtmMonitorHistoryInventory` (`:1441`), read only: a listing failure
     (`MONITOR_HISTORY_LIST_FAILED`), or anything unexpected (another name, a folder, a reparse point, another owner, a
     `monitor.json` that is not the user's plain file) refuses the whole removal with the count of the items not
     touched (`MONITOR_HISTORY_UNEXPECTED`). Names never reach the result: only counts.

  Then the plan is shown (the folder, the counts of records and `.partial` files and their bytes, whether
  `monitor.json` stays, whether the folder goes, and that the parent stays), and the phrase
  `REMOVER HISTORICO DO MONITORAMENTO` (`:95`) is asked (`MONITOR_HISTORY_NOT_CONFIRMED`). Only then:
  * the collector's per-user mutex is taken without waiting: held by a collection or another removal, it refuses with
    nothing removed (`MONITOR_HISTORY_BUSY`); an abandoned one is taken, as the collector does;
  * the inventory is taken again under it: any difference refuses with nothing removed (`MONITOR_HISTORY_CHANGED`);
  * each file of the plan goes through `Invoke-AtmMonitorPrune`, which checks its name, chain and owner again; the
    first failure stops the rest, with its code and the count of the files already removed;
  * with every file removed: with `monitor.json` the folder stays (`KEPT_CONFIG`); without it, the folder goes through
    the empty-folder removal below;
  * the mutex is released in a `finally`.

  Exit codes: `0` done (whatever the folder's outcome), `2` usage (`-IntervalHours`), `3` refused or not confirmed, `6`
  no console.
* **The empty history folder,** `Remove-AtmMonitorEmptyFolder` (`:1479`), the monitoring engine's second and last
  removal, called only by `Invoke-AtmMonitorRemoveHistory`. Immediately before the removal it checks, in order: the
  gate; that the path is exactly `Get-AtmMonitorFolder`'s; the chain (no reparse point); the item (a folder, not a
  reparse point); its owner; that it is empty (`monitor.json` in it gives `KEPT_CONFIG`). The removal is .NET's
  non-recursive `[IO.Directory]::Delete($path, $false)`, so a folder that is no longer empty makes the system refuse
  (`MONITOR_FOLDER_REMOVE_<type>`). The product's recursive deleter is not used: a static forbids it in the monitoring
  engine. It makes one attempt, with no retry. Its outcome, `REMOVED`, `KEPT_CONFIG` or `KEPT` with the code, is the
  result's `Folder` field and never fails the command.
* **The uninstaller (V05-D9 (a)),** `Get-AtmUninstallMonitorNotice` (`install/InstallCommon.ps1:860`), called by
  `Invoke-AtmUninstallUnlocked` (`:930`) right after the automatic purge's notice. It only reads, and each line is a
  warning:
  * this user's collection task, by its path, naming `agent-temp monitor disable`;
  * other users' collection tasks (`^Monitor-[0-9a-f]{16}$` in `\AgentTempManager`), counted and never named;
  * the history folder, shown as the literal `%LOCALAPPDATA%\AgentTempManager\Monitor`, never expanded, naming
    `agent-temp monitor remove-history`;
  * a read that fails, with the exception's type only.

  Each warning says that the item is the user's and stays after the uninstall, which command removes it, and that in a
  copy where the monitoring is not available that command refuses (the gate is closed) and the item stays. The
  installer repeats the engine's constants (`:848-851`); a static checks they are equal. The uninstaller runs
  elevated, so "this user" is the elevated account.
* **Presentation.** `Show-AtmMonitorRemoveHistoryPlan` and `Show-AtmMonitorRemoveHistoryResult` (`Report.ps1:1723`,
  `:1734`), with `Get-AtmMonitorHistoryFolderLine` (`:1710`). Texts in both languages. The usage and the help name the
  four subverbs.
* **Tests.** The suite's area "V0.5 M4b" (`tests/Run-Tests.ps1`), after M4a. It covers:
  * each refusal of `remove-history` in order, the closed gate proven with seams that fail if called;
  * every kind of unexpected item, counted and never named;
  * `MONITOR_HISTORY_BUSY`, with a child process holding the mutex, and `MONITOR_HISTORY_CHANGED`, with a file planted
    between the phrase and the second inventory;
  * the removals in the suite's sandbox only: all files and the folder; `monitor.json` kept with the folder; an empty
    folder; a removal that fails on an open handle and stops the rest; an abandoned mutex;
  * the empty-folder function on its own;
  * the presentation and the CLI in both languages;
  * the uninstaller's notice through seams (no task, own task, other users' tasks, the folder, unreadable);
  * the statics: the call order; the two removals and their exact places (the M1, M2, M3a and P6b statics now expect
    two `::Delete(` in the monitoring engine, one of them `Directory]::Delete(` with `$path, $false`); that
    `monitor.json` is never removed; the callers; and that the uninstaller's notice removes nothing.

  The install e2e asserts that the uninstall shows no monitoring warning with no task and no folder, and that an empty
  history folder, planted in the disposable runner's account before the cross-version steps' final uninstall of this
  build, makes that uninstall warn with the literal (never the expanded path) and leaves the folder in place.
* **NOT_TESTED.**
  * `monitor remove-history` with the gate open through the CLI: only the gate-closed path runs in a child process.
  * The real history folder under `%LOCALAPPDATA%` of any machine: the removals run only in the suite's sandbox.
  * The uninstaller's warning for a real collection task: no copy can create one with the gate closed, so the install
    e2e covers only the folder's warning and the absence of both.
  * The warning names `monitor disable` and `monitor remove-history`, which the uninstall itself takes away from the
    machine. The text says the items stay; it does not say how to remove them once the product is gone.

**Left for M5:** the TUI and the GUI.
