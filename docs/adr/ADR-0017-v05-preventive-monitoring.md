# ADR-0017: Persistent preventive monitoring (V0.5)

Status: ACCEPTED: V05-D1 to V05-D10 decided (D1-D7 2026-11-17, D8-D10 2026-11-18, as recommended); M0 and M1
implemented; gate closed in every copy. (Until 2026-11-17: PROPOSED, with V05-D1 to V05-D10 open. From 2026-11-17 to
2026-11-18: ACCEPTED in part, with V05-D8, V05-D9 and V05-D10 open and only M0 implemented.)
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
| **Complete removal** | Delete the task, after an exact match (precedent `Engine.Isolate.ps1:1893-1896`, `:1955-1980`) | Delete the value | Delete the file | An administrator deletes the service | nothing |
| **Left behind** | The task folder `\AgentTempManager`, shared with the automatic purge. Today it stays after unscheduling (`Engine.Isolate.ps1:1896`), and a suite case checks that (`tests/Run-Tests.ps1:5644`). The history, until it is removed (section 3). | the history | the history | the service's registry entries if removal fails; the history | the history |
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
    owner refuses the rotation and raises an alert. Leftover `.partial` files older than a day are removed the same
    way.
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
    were not touched.
  * Both are explicit commands that the person runs, each with its own confirmation. The product removes only what it
    created.
  * This is not an agent removing files. Tests run the commands only against a sandbox folder and a test task name,
    and the real scheduler only on a disposable CI runner.
  * The uninstaller today only reads the auto-purge task folder and warns (`docs/ARCHITECTURE.md:107-108`). V05-D9
    decides whether it does more. (Decided 2026-11-18, V05-D9 (a) plus (c): the uninstaller warns and names the two
    commands, and the unschedule commands remove the task folder when it is empty. Phase M4 implements it.)

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
| V05-D9 | What the uninstaller does, and the shared task folder | The uninstaller only reads and warns today. `\AgentTempManager` stays after `unschedule-autopurge` (`tests/Run-Tests.ps1:5644`). | (a) the uninstaller warns and names the two commands; the empty folder stays as declared residue; (b) the uninstaller runs the removal with its own confirmation; (c) the unschedule commands remove the task folder when it is empty (changes the auto-purge behaviour and its test) | **(a)** plus (c): the folder goes when empty, so "removed completely" holds | **(a)** plus **(c)**, 2026-11-18: the uninstaller warns and names the two commands; the unschedule commands remove the task folder when it is empty. Implemented in M4. (Pending until then.) |
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
  implements it; until then the uninstaller is unchanged.
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
