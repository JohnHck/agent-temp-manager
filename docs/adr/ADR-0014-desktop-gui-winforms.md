# ADR-0014: Desktop GUI and live monitoring in WinForms (V0.2.1)

Status: ACCEPTED for the technology and the architecture (maintainer decisions D-B and D-A, 2026-11-16).
GUI-D1 to GUI-D6 are ACCEPTED (decided by the maintainer as recommended, 2026-11-16); GUI-D7 to GUI-D11 are ACCEPTED
(technical decisions accepted by the auditor as recommended, 2026-11-16). P1 to P6 implemented, gate closed: P1 (the
skeleton), P2 (the dashboard), P3 (the drill-down), P4a (the preview), P4b (the diagnose area), P5 (the live monitoring)
and P6 (languages, accessibility and the close end to end). The gate stays closed in every copy.
Date: 2026-11-16
Phase: V0.2.1, phases P1 to P6 (section 10)

## Context

* **What V0.2.1 asks for.** The [ROADMAP](../ROADMAP.md#v021--desktop-gui-and-live-monitoring) asks for a native
  Windows desktop window. It shows the V0.1 audit and preview and the V0.2 diagnostics, refreshes them live while the
  window is open, and is a presentation layer only. The ROADMAP left the technology to a documented design, with
  Windows PowerShell 5.1 and .NET Framework compatibility as a constraint. This record is that design.
* **Maintainer decisions of 2026-11-16:**
  * **D-B:** the GUI uses **WinForms** on Windows PowerShell 5.1 and .NET Framework. This record keeps the WPF
    alternative and why it was not chosen.
  * **D-A:** each version lands on `main` behind a release gate of its own, `$false` in every copy, with its
    acceptance proven in CI.
* **What the product has today.**
  * Two presentations over the same engines: the CLI (`Report.ps1`) and the TUI (`Tui.ps1`).
  * The layering rule "engines decide, presentation shows" is checked by static tests
    ([ADR-0009](ADR-0009-diagnose-engine-command-schema.md) rule 5).
  * The TUI diagnostics area renders only the schema view of a diagnose result (ADR-0009, P5-A).
  * The installed launcher (`bin\agent-temp.cmd`) always starts the absolute Windows PowerShell 5.1 path with
    `-NoProfile`. `agent-temp.ps1` checks every installed file against the manifest before it loads any code.
* **What the TUI does that the GUI must not.** The TUI's clean (`L`) and isolate (`I`) actions leave the full-screen
  view and hand over to `Invoke-AtmClean` and `Invoke-AtmIsolate`. With the gates closed they show a plan and stop. The
  GUI offers neither (section 3).

## Decision

### 1. Technology: WinForms on .NET Framework 4.x

* `System.Windows.Forms` and `System.Drawing` from the .NET Framework 4.x that ships with Windows 10 and 11.
  * No new dependency, no download, nothing for the installer to fetch.
  * No XAML and no markup file: the form is built in PowerShell code, which the layering tests can read.
* **The installed product runs the GUI in Windows PowerShell 5.1.** The launcher always starts
  `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`. Its main thread is STA by default; this was checked
  on Windows 10 with Windows PowerShell 5.1, where `System.Windows.Forms` also loads.
* **PowerShell 7 only matters for source checkouts and the suite.** The `pwsh` documentation says STA is the default on
  Windows (`-STA`, and `-MTA` to opt out). WinForms under `pwsh` was not verified for this record; P1 measures it on
  the CI `pwsh` jobs. The rule, either way:
  * the GUI opens when the thread is STA and the assembly loads;
  * otherwise it refuses with a reason code and an exit code of its own, before any window exists (GUI-D7, GUI-D8);
  * it never relaunches itself in another shell. A relaunch starts a process, which the layering rules forbid, and the
    new process would not go through the launcher's integrity check.

### 2. Entry point

* **A new command, `agent-temp gui`.** Order of a run:
  1. the launcher's integrity check, unchanged, before any code is loaded;
  2. the release gate (section 4). Closed: a message, an exit code, no window, and no WinForms assembly loaded;
  3. the environment checks: STA thread and an interactive desktop;
  4. `Add-Type -AssemblyName System.Windows.Forms, System.Drawing`, and only then the form.
* **New library files:**
  * `src/lib/GuiModel.ps1`: the view models, plain PowerShell objects, with no WinForms type;
  * `src/lib/Gui.ps1`: the form, `Start-AtmGui` and the release gate.
* **They load for every command**, like every other library: they are added to `$loadedLibs`, so the manifest check
  covers them. They only define functions and variables when loaded:
  * no `Add-Type`, no `using assembly`;
  * no PowerShell `class` that derives from a WinForms type.

  Loading them never loads WinForms.
* **The installer and the release manifest** list the two new files. The build's file list gains them.
* **No `bin\` script and no shortcut** in V0.2.1 (GUI-D6): `agent-temp gui` is the only entry point.

### 3. Layers and the closed list

* **Engine, then view model, then form.**
  * The form reads view models only.
  * The view models call only the engine read functions in the allowed list below.
  * Nothing in the GUI computes a class, an eligibility, a gate or a coverage verdict: it shows the engine's.
* **Allowed (the closed list).** `src/lib/Gui*.ps1` may call these engine and catalog functions and no other:
  * `Invoke-AtmInventory`;
  * `Invoke-AtmPreview` (it lives in `Engine.Clean.ps1`; it is the preview's read-only gate evaluation, and it is
    named here so the test can allow it alone from that file);
  * `Invoke-AtmDiagnose`, and `ConvertTo-AtmDiagnoseJson` for the schema view (as in the TUI, P5-A);
  * `Get-AtmIdentityState` and `Get-AtmCurrentIdentity`;
  * `Get-AtmAutoPurgeNoticeLines`, for the automatic purge notice (GUI-D1);
  * `Get-AtmText`, `Get-AtmLanguage` and `Set-AtmLanguage`, plus the pure formatting helpers that P1 names in the
    test;
  * since V0.4 R5 ([ADR-0016](ADR-0016-v04-assisted-recovery.md), the R5 implementation record), for the read-only
    recovery area: `Get-AtmRecoverCollection`, `Get-AtmRecoverList` and `Get-AtmRecoverPlan` (the recovery engine's
    collection, list and plan, all read only), and `Get-AtmRecoverListLines` and `Get-AtmRecoverPlanLines` (the
    shared formatters of the CLI's `recover list` and `recover plan` texts, in `Report.ps1`);
  * since V0.5 M5 ([ADR-0017](ADR-0017-v05-preventive-monitoring.md), its M5 implementation record; announced by the
    amendment of its phase M0, which named the function provisionally `Get-AtmMonitorHistory`): **one** read function
    for the monitoring, `Get-AtmMonitorStatus`. It returns the stored history as it is and, only where the monitoring
    gate is open, the trends, the thresholds' state and the alerts computed when it is read; it writes nothing. The GUI
    builds its own lines from that object: no formatter of `Report.ps1` joins the list. The test's list has 29 names.
    The GUI never reads `AtmMonitoringEnabled` (it shows the status's `GateOpen` field), never reads the collection
    task's state, never registers, removes or runs the monitoring task, and never collects;
* **Forbidden, by name.** A static test fails if `src/lib/Gui*.ps1` mentions any of these:
  * `Invoke-AtmClean`, `Invoke-AtmIsolate`, `Invoke-AtmRestore`, `Invoke-AtmPurge`, `Invoke-AtmAutoPurgeSchedule`,
    `Invoke-AtmAutoPurgeUnschedule`, `Invoke-AtmDiscardAuthorization`, `AtmDeleter`, `AtmLockProbe`, and any other
    engine function not in the allowed list;
  * deletion and move APIs: `Remove-Item`, `Move-Item`, `[IO.File]::Delete`, `[IO.Directory]::Delete`,
    `[IO.Directory]::Move`, `[IO.File]::Move`, and the deleter's native entry points;
  * file, registry and ACL writes: `Set-Content`, `Add-Content`, `Out-File`, `New-Item`, `Set-ItemProperty`,
    `Set-Acl`, `[IO.File]::Write*`, `[IO.File]::Create`, `CreateSubKey`, `SetValue`;
  * process, service, task and VM control: `Start-Process`, `Stop-Process`, the service cmdlets,
    `Register-ScheduledTask` and the other scheduled-task cmdlets, `Invoke-CimMethod`, `Invoke-WmiMethod`, `*-VM`;
  * the clipboard (`Clipboard`, `Set-Clipboard`): no copy in V0.2.1 (GUI-D4);
  * since V0.4 R5, recovery execution: `Invoke-AtmRecover` (so every engine name that starts with it, such as the
    undo and the command), `AtmServiceStop`, `ServiceController`, the elevation verb, `ShellExecute`,
    `AtmRecoverOperationTaken` and `Open-AtmCleanLog`. Executing recovery stays CLI-only (T-ISO-6), and the live
    monitoring's tick never calls the recovery collection;
  * the release-gate variables of the other features (they are read only by the engines and `version`), since V0.4
    R5 including `AtmRecoveryEnabled`, and from V0.5 (ADR-0017) `AtmMonitoringEnabled` too;
  * since V0.5 M5, the monitoring's other functions by their exact names: the collection task's state and lines
    (`Get-AtmMonitorTaskState`, `Get-AtmMonitorTaskLines`), the history reader itself (`Get-AtmMonitorHistory`), the
    collector's functions, and the functions that enable, register, run, disable, remove or list for removal.
* **The existing tests stay as they are.** The TUI keeps its clean and isolate hand-over; the layering tests of
  ADR-0009 are extended to the new files, never relaxed.

### 4. Release gate (D-A)

* `$script:AtmGuiEnabled = $false` in `src/lib/Gui.ps1`, with exactly one assignment.
* Checked:
  * by the build (`tools/Build-Release.ps1`, the gate list);
  * by the install e2e: the table of installed gates becomes seven, plus the single-assignment assertion for the new
    file. The old-package checks of 0.1.1 and 0.3.0 do not change;
  * by `version`, which prints the gate's state in both languages.
* **With the gate closed** (every copy), `agent-temp gui` prints that the GUI is disabled in this version, with the
  reason code `GUI_GATE_CLOSED`, and exits with its own code (GUI-D8). It opens no window and loads no WinForms
  assembly.
* Tests open the gate only in their own process memory, as the current harnesses do for the other gates.
* **This gate is not a gate over the engine.** The ROADMAP says V0.2.1 "adds no decision, no gate". That means no new
  product gate over what the engines decide: no class, no eligibility rule, no coverage verdict. A release gate for the
  presentation itself is what D-A asks of every version, so the two do not conflict.

### 5. Live monitoring

* **Only while the window is open.** No service, task, scheduled job, background process or history.
* **One timer**, a `System.Windows.Forms.Timer` owned by the form. It refreshes the audit (inventory and preview). The
  diagnose refreshes on an explicit action only (GUI-D3).
* **Bounds** (numbers in GUI-D10):
  * a minimum and a maximum interval;
  * **no overlap:** a tick while a refresh runs is skipped, never queued;
  * **time:** every refresh is measured. The diagnose already takes `-DeadlineSeconds`. The inventory has no deadline
    today, and adding one is an engine change (GUI-D9). Until then a refresh slower than the limit marks the view as
    stale, and the next tick waits at least twice the last duration;
  * **memory:** PowerShell cannot cap it, so it is measured, not promised. The GUI keeps at most the current result and
    the previous one, and a suite case checks that managed memory does not grow over many refreshes.
* **Off the UI thread, or time-limited, without freezing the window** (GUI-D9). The recommended model runs the refresh
  on the UI thread. The inventory's existing `ProgressCallback` pumps the window's messages, the refresh controls are
  disabled while it runs, and a close request cancels it at the next callback. A single blocking call inside an engine
  (for example a bounded Git run in the diagnose) can still delay repainting until it returns. That limit is declared,
  and the engines' own bounds limit it.
* **State of every view**, shown as text, never by color alone:
  * `CURRENT`, with the UTC time of the refresh;
  * `PARTIAL`, when coverage is incomplete (the engine's verdict);
  * `STALE`, when the last refresh failed, was slower than the limit, or is older than twice the interval;
  * `UNKNOWN`, before the first refresh.
* **A failed refresh never erases an earlier finding.** The previous result stays, marked `STALE`, with the exception
  type only (as the TUI does in P5-A). Nothing is retried in a weaker way.
* **Closing:**
  * `FormClosing` stops and disposes the timer and cancels a running refresh;
  * the GUI starts no process. A child of a diagnose collector (the bounded Git runner) is bounded and ended by that
    runner, as today;
  * the GUI writes no file and no registry value. Window size, position and language are not remembered;
  * the process exits with code 0.

### 6. Screens

* The same as the TUI's read-only screens:
  * dashboard;
  * drill-down by user, project and root;
  * detail of a root;
  * preview (the preview gates, read-only);
  * coverage and errors;
  * the V0.2 diagnose, rendered from the schema view as in the TUI.
* **Not in the GUI:** clean, isolate, restore, purge, discard authorization, quarantine management and the
  auto-purge task commands. The GUI shows the auto-purge notice on every screen while the policy has it on, and no
  quarantine list (GUI-D1).
* **A header on every screen:** the process identity, whether the token is an elevated administrator, the token
  elevation type (PRIV-10, as `version` shows), the language, and the view's state (section 5).
* **Features behind a V0.2 gate show as "disabled in this version", never as "nothing found":**
  * worktree diagnostics (`WORKTREE_DIAGNOSTICS_GATE_CLOSED`);
  * open-file diagnostics (`HANDLE_SECURITY_GATE_CLOSED`);
  * the diagnose JSON export (`EXPORT_SECURITY_GATE_CLOSED`);
  * Git execution (`GIT_EXECUTION_GATE_CLOSED`).

  The view model maps these codes to that text. `UNKNOWN` is never shown as free, and `NOT_OBSERVABLE`, `DENIED` or
  `TIMEOUT` are never shown as zero items (ADR-0009, P5-A).
* **Real deletion is not offered in the V0.2.1 GUI**, at any gate state. The ROADMAP's dependency sentence ("when it
  is, it goes through the same plan, confirmation and re-validation") is a limit on any future change, not a promise.
  Any destructive action in the GUI needs a new record that supersedes this one.

### 7. Languages and accessibility

* **One catalog:** every visible text comes from `I18n.ps1`, with the same keys in en-US and pt-BR, through the same
  parity tests.
* **Language:** chosen at start by the CLI rules (`-Lang`, `ATM_LANG`, the UI culture). There is no switch inside the
  window in V0.2.1.
* **Keyboard:**
  * every action reachable without a mouse;
  * a defined tab order;
  * access keys, and the TUI's read-only keys where they apply (screens `1` to `9`, `P`, `D`);
  * `F5` to refresh and `Esc` to go back.
* **Assistive technology:** every control has an `AccessibleName` from the catalog.
* **Color:**
  * system colors, so high-contrast themes apply;
  * no information by color alone. The TUI's text markers (`[D]`, `[A]`, `[?]`) and the state words of section 5
    carry the meaning.
* **DPI:** `AutoScaleMode` by DPI, so text stays legible at 125% to 200%.

### 8. Privacy

* The GUI shows what the TUI shows and nothing more.
  * The diagnose area renders the schema view only (ADR-0009, P5-A). The identity block and the machine name of the
    diagnose result are not rendered there.
  * Progress shows a percentage and a fixed text. The inventory's own progress messages name temporary bases and are
    not shown.
  * A failure shows the exception type, never its message.
* **No export, no file and no clipboard** without an explicit action. V0.2.1 has no export control: the audit export
  and `diagnose -ExportJson` stay in the CLI, behind their own rules and the closed export gate.
* **Copying:** none in V0.2.1 (GUI-D4). If it is ever allowed, it follows the export rules (ADR-0010, the sanitizer and
  the privacy scanner).
* **Display surfaces:** read-only `ListView` and `Label` controls, not editable text boxes, so nothing is selectable
  and copied by accident.
* Examples, fixtures and screenshots in the repository are synthetic.

### 9. Tests

* **View models, no window:** fed by dubbed engine results (complete, partial, denied, unknown). They check the
  counts, the state words and the "disabled in this version" mapping.
* **Parity with the TUI:** over the same dubbed inventory, the dashboard, user, project and root counts of the view
  models equal the TUI's.
* **Refresh:** interval bounds, a skipped tick while a refresh runs, the stale marking (failure, slow, old), a failure
  that keeps the previous result, and managed memory over many refreshes.
* **Static:**
  * the closed list and the forbidden names of section 3;
  * the single assignment of `$script:AtmGuiEnabled = $false`;
  * the new files in `$loadedLibs`, the build list and the manifest;
  * no `Add-Type`, `using assembly` or WinForms-derived class in code that runs at load.
* **Gate closed:** `agent-temp gui` exits with its code and message in both languages. A fresh child process has no
  `System.Windows.Forms` assembly loaded afterwards.
* **Real window, on CI:** the gate opened in memory. Open the real form, refresh with dubbed sources, close it, and
  check:
  * no child process left;
  * the timer disposed;
  * no file created in the sandbox, the configuration directory or the user's TEMP.

  It runs in both languages. If a runner cannot show a window, the case is `NOT_TESTED`, never a pass.
* **Shells:** the suite runs on both shells, as today. The real-window cases run on the Windows PowerShell jobs; on
  `pwsh` they stay `NOT_TESTED` until P1 has measured WinForms there (GUI-D7).
* **Read-only:** the existing read-only case (sandbox byte- and timestamp-identical) is extended to a GUI session with
  many refreshes.

### 10. Phases

Each phase is one round and one PR, with the gate closed:

* **P1:** skeleton:
  * `agent-temp gui`, the gate, the exit codes, the load order;
  * the two files in `$loadedLibs`, the build, the manifest and the installer;
  * the seventh gate in the build, the install e2e and `version`;
  * the closed-list test;
  * the WinForms measurement on `pwsh`.
* **P2:** the audit view models and the dashboard.
* **P3:** drill-down by user, project and root, and the detail.
* **P4:** preview and the diagnose area.
* **P5:** live monitoring: timer, bounds, states, cancel on close.
* **P6:** languages, accessibility and the close e2e on the real window.

## Open decisions

Kind: **product** decisions go to the maintainer; **technical** ones are the auditor's.

| Id | Kind | Decision | Alternatives | Recommendation |
|---|---|---|---|---|
| GUI-D1 | product | Quarantine and automatic purge in the GUI | (a) a read-only quarantine list (as the TUI's `Z`, no inspect, restore or purge) plus the automatic purge notice; (b) the notice only; (c) neither | **ACCEPTED** (2026-11-16, decided by the maintainer as recommended): (b). The notice says that something deletes automatically, so it belongs on every screen while it is on, as in the TUI. The quarantine list is a 0.3.x feature whose gates are closed in every copy; it can come in a later version |
| GUI-D2 | product | Live monitoring when the window opens, and its default interval | (a) off, turned on by a control in the window; (b) on, at the default interval | **ACCEPTED** (2026-11-16, decided by the maintainer as recommended): (a), with a default interval of 60 seconds once turned on: the first refresh is the one the person asked for, and nothing runs repeatedly unless they choose it |
| GUI-D3 | product | Does live monitoring also refresh the diagnose? | (a) no: the timer refreshes the audit, and the diagnose runs only on an explicit action, as in the TUI; (b) yes, at its own longer interval | **ACCEPTED** (2026-11-16, decided by the maintainer as recommended): (a). The diagnose reads processes, services and handles and costs much more; the TUI also runs it only on request |
| GUI-D4 | product | Copy to the clipboard | (a) none in V0.2.1; (b) an explicit copy per detail, through the export rules | **ACCEPTED** (2026-11-16, decided by the maintainer as recommended): (a). No new way for data to leave the window. The CLI already gives the same text, and the export rules stay in one place |
| GUI-D5 | product | The GUI in an elevated process | (a) it runs, as the TUI does, with the elevation shown in the header and other profiles under the same rules as the TUI; (b) it refuses an elevated process | **ACCEPTED** (2026-11-16, decided by the maintainer as recommended): (a). The GUI shows what the TUI shows. PRIV-1 is met because nothing needs elevation, and refusing would be a new rule that the TUI does not have |
| GUI-D6 | product | How the GUI is started | (a) `agent-temp gui` only, with the console staying open behind the window; (b) also a `bin\` script; (c) also a Start-menu shortcut created by the installer | **ACCEPTED** (2026-11-16, decided by the maintainer as recommended): (a) for V0.2.1. (c) changes the installer and the machine's Start menu, and (b) adds a launcher that needs the same integrity path; both can follow later |
| GUI-D7 | technical | PowerShell 7 | (a) open when STA and WinForms loads, refuse with a code otherwise, never relaunch; (b) refuse on `pwsh` always; (c) relaunch in Windows PowerShell | (a). The installed product always runs Windows PowerShell 5.1, so this covers source checkouts and the suite. The real-window cases stay `NOT_TESTED` on `pwsh` until P1 measures it. (c) starts a process outside the integrity check |
| GUI-D8 | technical | Exit codes and reason codes | New codes after the current set (0, 1, 2, 3, 4, 5, 6, 10) | `7` with `GUI_GATE_CLOSED` for the closed gate; `8` for an environment that cannot show the window: `GUI_NOT_STA`, `GUI_WINFORMS_UNAVAILABLE`, `GUI_NO_INTERACTIVE_DESKTOP`. `6` stays "a console is required" |
| GUI-D9 | technical | Where the refresh runs | (a) on the UI thread, pumped through the inventory's `ProgressCallback`, with cancel on close; (b) in a second runspace given the libraries' already-verified content; rejected: a runspace that loads the libraries from disk again | (a): one thread, nothing to leave behind, no second copy of the code. The inventory gets no engine deadline in V0.2.1: the GUI measures it and marks the view stale (section 5) |
| GUI-D10 | technical | Refresh bounds | Interval, slow limit, memory check | Interval from 30 seconds to 15 minutes. A refresh slower than half the interval marks the view `STALE`, and the next tick waits at least twice its duration. The diagnose keeps its current default deadline. Memory: managed memory after 20 dubbed refreshes, with the bound set in P5 from measurement on the CI runners |
| GUI-D11 | technical | View models shared with the TUI | (a) new view models in `GuiModel.ps1`, with the TUI unchanged and a parity test; (b) move the TUI onto shared view models | (a): the TUI and its tests stay as they are in V0.2.1, and the parity test keeps the two from drifting. A later refactor can merge them |

## Rejected alternatives

* **WPF.** It is also in .NET Framework and draws better at high DPI, but:
  * it is usually written in XAML: a second language, loaded at run time, that the layering tests would have to parse
    too;
  * a XAML file is markup the launcher would load as data and the integrity check would have to cover as code;
  * its threading model (a `Dispatcher` per thread) adds more ways to leave a thread behind after close.

  WinForms does the same work in plain PowerShell code. D-B chose WinForms.
* **A local web page** (an HTTP listener and a browser): it opens a port, which is network access, and leaves a
  process and a listener to manage. The ROADMAP forbids network access.
* **A Windows App SDK, WinUI or .NET 6+ desktop app:** a new runtime and a compiled product outside PowerShell 5.1,
  with its own installer and update path.
* **Relaunching in another shell or elevated:** a process start outside the integrity check; never.
* **A background service or scheduled task for monitoring:** persistent monitoring is V0.5, and the ROADMAP forbids it
  here.

## Consequences (including new limits)

* Two new library files, a new command and a seventh release gate. The build, the manifest, the installer, the install
  e2e and `version` change in P1.
* The installed GUI always runs in Windows PowerShell 5.1. `pwsh` support covers source checkouts and the suite, and is
  measured, not assumed.
* With the refresh on the UI thread, a long blocking call inside an engine can delay repainting until it returns.
  The engines' own bounds limit it, and the view is marked stale when a refresh is slow.
* Memory is measured, not capped.
* The GUI offers fewer actions than the TUI (no clean, isolate or quarantine management), by design.
* The ROADMAP's V0.2.1 sentences "adds no decision, no gate" and "when it is, it goes through the same plan" are read
  as stated in sections 4 and 6. This record does not rewrite them.

## Verification

* The tests of section 9, phase by phase, on CI, with the gate closed in every copy.
* Before any phase is accepted: the closed-list test and the gate tests are green on both shells, and the install e2e
  checks seven gates.
* The V0.2.1 acceptance criteria of the ROADMAP: the same engines, no deletion, recovery or write API, PRIV-1 and
  PRIV-10, stale data labelled, nothing left after close. Each one is mapped to a named suite or e2e case in the phase
  that implements it.

## Implementation record: P1 (V021-P1, 2026-11-16)

What P1 implements, with the gate closed in every copy:

* `src/lib/Gui.ps1` and `src/lib/GuiModel.ps1`. Loading them defines functions and constants only:
  * no assembly is loaded at load time, no type is declared, and there is no `using`;
  * the single assignment `$script:AtmGuiEnabled = $false` is in `Gui.ps1`;
  * three test seams (apartment, desktop, assembly loader) are `$null` in every copy.
* `agent-temp gui` runs in this order:
  1. the launcher's integrity check;
  2. the gate: closed gives `GUI_GATE_CLOSED`, exit code `7`, no window and no Windows Forms (GUI-D8);
  3. the STA thread and the interactive desktop (`[Environment]::UserInteractive` and a session other than 0), else
     exit code `8` with `GUI_NOT_STA` or `GUI_NO_INTERACTIVE_DESKTOP`;
  4. `Add-Type` of System.Windows.Forms and System.Drawing in `Import-AtmGuiAssemblies` only, else `8` with
     `GUI_WINFORMS_UNAVAILABLE`;
  5. the minimal modal window: the title, the identity, the elevation state (PRIV-10) and a read-only notice, with a
     Close button that `Esc` also triggers. It is disposed on close.

  The native helper is initialized only past the gate. Nothing is relaunched.
* The seventh gate is checked by:
  * the build (its gate list, and the archive must contain both files);
  * the installer's file list and the manifest;
  * the install e2e (step `shipped-gui-gate`, and the installed gates table has seven rows);
  * the suite;
  * `version`, in both languages.
* The closed list that the static suite test applies to `src/lib/Gui*.ps1`:
  * the files' own functions;
  * the engine and catalog functions `Invoke-AtmInventory`, `Invoke-AtmPreview`, `Invoke-AtmDiagnose`,
    `ConvertTo-AtmDiagnoseJson`, `Get-AtmIdentityState`, `Get-AtmCurrentIdentity`, `Get-AtmText`, `Get-AtmLanguage`
    and `Set-AtmLanguage`;
  * the cmdlets `Write-Host`, `New-Object` and `Add-Type`. `Add-Type` is allowed only inside
    `Import-AtmGuiAssemblies`.

  The test also fails on:
  * the deletion, move, write, process, task and clipboard APIs of section 3;
  * the gate variables of the other features;
  * a load-time statement other than a function definition or a constant assignment.

  Eleven planted violations in temporary copies are each detected. Two notes on the list:
  * `Get-AtmIdentityState` is an identity collector. The TUI and report layering test keeps forbidding it there; the
    GUI may call it for the header, as `version` does.
  * `Get-AtmAutoPurgeNoticeLines` is left out of the list until GUI-D1 is decided.
* GUI-D7 measurement. CI run 43821833767 (PR #101) measured each job in a new process of its own shell, started with
  `-File` as the launcher starts it:

  | Job | Edition and version | CLR | Apartment | Environment | System.Windows.Forms |
  |---|---|---|---|---|---|
  | test (powershell), x64 | Desktop 5.1 | 4.0.30319 | STA | OK | loads (4.0.0.0) |
  | test ARM64 (powershell) | Desktop 5.1 | 4.0.30319 | STA | OK | loads (4.0.0.0) |
  | test (pwsh), x64 | Core 7.6.9 | 10.0.14 | STA | OK | loads (10.0.0.0) |
  | test ARM64 (pwsh, subset) | Core 7.6.10 | 10.0.15 | STA | OK | loads (10.0.0.0) |

  On these runners `pwsh` runs STA and Windows Forms loads, so GUI-D7 (a) would open the window there. The real-window
  case ran on both Windows PowerShell jobs, where the window opened and closed in en-US and pt-BR. That case stays
  `NOT_TESTED` on `pwsh` in P1, as GUI-D7 sets out; whether to run it on `pwsh` is decided in a later phase. The
  installed product always runs Windows PowerShell 5.1.

## Implementation record: P2 (V021-P2, 2026-11-16)

What P2 implements, with the gate closed in every copy:

* **GUI-D1 to GUI-D6 recorded as decided** (see the status line and the open decisions table). Only D1, D3 and D4 shape
  P2: the notice without a quarantine list, no diagnose here, and no clipboard.
* **View models** in `GuiModel.ps1`, plain objects that are testable without a window:
  * `Get-AtmGuiDashboard`: the four groups of the TUI dashboard (profiles; files, directories and partitions; space;
    errors and coverage), the count and MB of each class and the audit time. They are counted and formatted with the
    helpers the TUI uses, through the same catalog keys. With no audit yet, every value is the word `UNKNOWN`, never
    zero;
  * `Get-AtmGuiViewState`: `UNKNOWN` before any audit has finished (a first failed audit stays `UNKNOWN`, with the
    exception type); `STALE` when the last audit failed (the earlier result stays, with the type only); `PARTIAL` when
    the engine's coverage is incomplete; otherwise `CURRENT` with the UTC time. There is no `STALE` by slowness or age:
    that needs the interval of P5;
  * `Get-AtmGuiAutoPurgeNotice`: the lines of `Get-AtmAutoPurgeNoticeLines` (GUI-D1), read once when the window
    opens;
  * the identity header gains the language.
* **Window** (`Gui.ps1`):
  * the header (identity, elevation, language, the view's state) and the notice under it;
  * the dashboard in read-only `ListView` controls, plus labels and two buttons. There is no editable text field;
  * system colors only, and the class is always written out;
  * a fixed tab order, `F5` to refresh, `Esc` to close, and an `AccessibleName` from the catalog on every control.
* **Audits (GUI-D9, without the timer):**
  * one audit when the window opens, as the TUI does when it starts. After that, only Refresh or `F5`;
  * they run on the UI thread, in `Invoke-AtmGuiRefresh`. Each inventory progress callback pumps the window's messages
    and shows the percentage with a fixed catalog text, never the engine's message;
  * the refresh controls are disabled while an audit runs, and a second request is ignored, never queued. The guard is
    in the function, because `F5` reaches the form through `KeyPreview` even while the button is disabled;
  * a close request sets a flag that the next callback honours by ending the audit. The cancellation is recognised by
    that flag, never by an exception's text, and then the window closes with exit code 0.
* **The inventory arguments.** The launcher was outside this round's paths, so `Get-AtmGuiInventoryArgs` builds the
  launcher's own inventory arguments from the GUI file's location: the self markers `agent-temp.ps1` and
  `bin\agent-temp.cmd`, and the `config` folder next to `lib`. A suite case checks that they equal the values derived
  from the source tree and that the launcher still builds them the same way.
* **Test seam:** `$script:AtmGuiInventorySource = $null`, a single assignment like the P1 seams.
* **Closed list:** the allowed names gain exactly `Get-AtmAutoPurgeNoticeLines`, `Get-AtmSum`, `Format-AtmMB`,
  `Format-AtmGB`, `Format-AtmTime`, `Get-AtmProfileStatusLabel`, `Get-AtmStatusText` and
  `Get-AtmIncompleteProfileCount`. The allowed cmdlets stay `Write-Host`, `New-Object` and `Add-Type`. The planted
  violations gain a call to a quarantine function of the report.
* **P1 leftovers:**
  * the real isolation harness's table of installed gates has seven rows;
  * the purge subsection of the security model now points to the current list of gates;
  * `Gui.ps1` joins the existing presentation exceptions of the static analysis (`Write-Host`, and the in-memory
    constructors and loops for ShouldProcess).

## Implementation record: P3 (V021-P3, 2026-11-16)

What P3 implements, with the gate closed in every copy:

* **View models** in `GuiModel.ps1`, testable without a window, with the same rows, order and text as the TUI. They
  compute no class, eligibility, gate or coverage; they only arrange the engine's values through the TUI's catalog keys:
  * users (`Get-AtmGuiUserTable`), projects (`Get-AtmGuiProjectTable`, grouped as the TUI groups them) and roots
    (`Get-AtmGuiRootTable`, with the TUI's filters: by user, by project and by class);
  * the detail of a root (`Get-AtmGuiRootDetail`): the TUI's field lines, then the evidence, the ancestors, the
    ambiguous references and the samples of errors and reparse points. It leaves out the cleanup preview, the
    isolation hint and the hint to the CLI path drill-down: the GUI offers neither action;
  * coverage and errors (`Get-AtmGuiCoverageLineList`): the lines of the TUI's errors screen;
  * `Get-AtmGuiScreen` returns one of these for the current screen, or no rows with a catalog note before the first
    audit.
* **Order.** Sorting goes through `System.Collections.Generic.List[object].Sort` with a comparison equal to the TUI's
  sort keys. It is unstable in the same way as `Sort-Object` (neither is stable on Windows PowerShell 5.1 nor on
  PowerShell 7 without `-Stable`), so ties come out in the same order as in the TUI; the multi fixture has one.
  Grouping by project keeps the first-seen order and compares keys without case, as `Group-Object` does.
* **Navigation** in the view model (`Initialize-AtmGuiNav`, `Invoke-AtmGuiNavKey`, `Invoke-AtmGuiNavRefreshed`), a
  stack of screens:
  * `1` dashboard, `2` users, `3` projects, `4` roots, `5`, `6` and `7` the roots of `ACTIVE_EVIDENCE`, `RECENT` and
    `LIVENESS_UNKNOWN`, `9` coverage and errors. A digit starts again from the dashboard. Each screen also has a button
    with the digit as its access key;
  * `Enter` (or a double click) on a user or a project opens its roots, and on a root its detail;
  * `Esc` goes back one screen, with the earlier row selected again, and closes the window only on the dashboard. This
    changes P2, where `Esc` closed the window: the form no longer has a cancel button; the close button still closes;
  * keys do nothing while an audit runs;
  * `F5` and Refresh audit again from any screen and then compute the current screen again. If the root of an open
    detail is not in the new audit, the window goes back to the list and says so with a catalog text.
* **Window** (`Gui.ps1`): the header and the automatic purge notice stay on every screen; the screen title, a message
  label and one read-only `ListView` for the rows. Only `Label`, `ListView` and `Button` controls, a fixed tab order,
  an `AccessibleName` from the catalog on each new control, the class written out, no timer and no action on roots.
* **Closed list:** the allowed names gain exactly `Get-AtmYesNo`, `Get-AtmInventoryProfileList`, `Get-AtmBaseIndex`
  and `Get-AtmNotAuditedBaseStates`, 21 in all. The allowed cmdlets stay `Write-Host`, `New-Object` and `Add-Type`.
  The planted violations gain a call to `Show-AtmPathDetail`, the CLI path drill-down.
* **Catalog:** new `gui.*` keys only, in en-US and pt-BR (the navigation hint, the screen buttons and title, the
  message, the rows' name, the detail that is gone, the note before an audit and three column headings).

## Implementation record: P4a (V021-P4a, 2026-11-16)

Phase P4 of section 10 was split by the auditor into two rounds: **P4a**, the preview of the cleanup, and **P4b**, the
diagnose area. P4b is not implemented. What P4a implements, with the gate closed in every copy:

* **View model** in `GuiModel.ps1` (`Get-AtmGuiPreviewTable`), testable without a window, with the rows of the TUI's
  `gates` screen: category, user, root (`slug\name`), MB, and the reasons and requirements joined by `; `. It filters
  by category (`8` keeps `BLOCKED`, `P` keeps all) and sorts as the TUI does: by category, then by bytes descending,
  through `List[object].Sort` with a comparison equal to the TUI's sort keys, so ties come out in the TUI's order.
  `ELIGIBLE_WITH_DECLARED_RISK` is written with the TUI's short label (`tui.catDeclaredRisk`). The view model computes
  no category, gate or eligibility: every row comes from the result of `Invoke-AtmPreview`.
* **Detail.** `Enter` on a preview row opens the root's detail with one more line, `Preview`: the raw category, then the
  reasons and requirements, as the TUI's detail writes it. A detail opened from any other screen has no such line.
* **When the preview runs** (`Invoke-AtmGuiPreview` in `Gui.ps1`, the only place that calls `Invoke-AtmPreview`):
  * only when `P` or `8` is opened and no result is kept for the current audit: one call, on the UI thread, with the
    session's inventory and the launcher's own inventory arguments. Before the first audit it makes no call, and the
    screens show P3's text for that;
  * the result is kept in the window's session until the next audit. A successful audit discards it; if a preview
    screen (or a detail opened from one) is open, the window goes back to the dashboard with a catalog text, so that no
    stale category stays on screen and no preview runs without an explicit opening. A failed audit keeps the result
    and the screen;
  * while it runs, the screen keys, the screen buttons and Refresh are disabled, and the window shows a fixed catalog
    text (`tui.computingPreview`, the TUI's own), with no percentage. The engine offers no progress callback, so the
    limit of section 5 applies as declared: a single blocking call can delay repainting until it returns. The
    preview's runtime collection (a read-only diagnose pass, which starts no process) is bounded by its own deadline,
    60 seconds by default;
  * a close request during the call is deferred: `FormClosing` cancels it and records it, and the window closes once
    the call ends. The close button stays enabled;
  * a failure shows only the exception type, never its message; nothing is changed, and the next opening of `P` or
    `8` calls again. Nothing repeats by itself;
  * a test seam, `$script:AtmGuiPreviewSource`, is a single `$null` assignment, as the inventory seam.
* **Window:** a fixed notice on both preview screens (`gui.previewNotice`): the preview is an evaluation only, and the
  window deletes and isolates nothing. Buttons for `8` and `P` with their access keys; the form's key handler takes
  `P` as it takes the digits. Only `Label`, `ListView` and `Button` controls, no timer, no editable text field, and no
  action over a root or a category.
* **Closed list:** unchanged, 21 names; `Invoke-AtmPreview` was already in it. The static test checks it appears in
  one place only. The planted violations gain a call to `Test-AtmCandidate`, an engine helper outside the list.
* **Catalog:** new `gui.*` keys only, in en-US and pt-BR: the navigation hint, the notice, the failure, the discarded
  result and the note before the preview is computed.

## Implementation record: P4b (V021-P4b, 2026-11-16)

The second half of phase P4: the diagnose area. What P4b implements, with the gate closed in every copy:

* **The area,** key `D`, with the TUI's nine screens (the menu of categories, each category's list, the summary and
  the details of a coverage record, a finding and a node). `Enter` opens a row as the TUI's area does, and `Esc` goes
  back one screen. Each screen has the TUI's lines, columns, order and text, and the lines the TUI writes above the
  table (the time of the last run, the outdated mark, the missing authorization, the legend of the edges, the coverage
  note). The suite checks this cell by cell over eight dubbed views, in en-US and pt-BR.
* **The tables are GuiModel functions,** copies of the TUI's: the kinds and collectors of each category, the edge
  strengths (`[D]`, `[A]`, `[?]`), the gate codes and the screen names. The GUI never reads a TUI variable: the static
  test refuses any variable of the GUI files whose name starts as the TUI's (a planted read is detected), and a case
  checks each copy equals the TUI's table. The edge limit per node is `$script:AtmGuiDiagMaxEdges = 40`, the TUI's.
* **Sorting without pipeline cmdlets.** The TUI sorts and groups with pipeline cmdlets, which are outside the closed
  list. The GUI uses loops with `List.Sort` and a culture comparison that ignores case, as the TUI's sort does, and
  groups in first-seen order with a dictionary that ignores case. The order and the ties equal the TUI's, checked by
  the parity case.
* **Times through `Format-AtmGuiUtc`,** an exact copy of the TUI's `Format-AtmTuiUtc`, with an equality test. On
  Windows PowerShell 5.1 and PowerShell 7, `ConvertFrom-Json` reads dates differently; the copy formats both the same
  way, so the parity holds in both shells.
* **`ConvertFrom-Json` added to the allowed cmdlets** (three to four), approved by the auditor: it only converts text
  into objects in memory, has no system effect, and is the TUI's own path. It appears in one place,
  `Invoke-AtmGuiDiagnose`, next to `ConvertTo-AtmDiagnoseJson`, which the static test checks; a planted use elsewhere is
  detected. No other cmdlet was added: no JSON serializer, `Out-*` or `Export-*`.
* **The closed list grows by two names, to 23:** `Get-AtmCodeText` (the catalog text of a code, as the TUI writes it)
  and `ConvertTo-AtmExceptionCode` (the code of an exception type). A planted call to another JSON export of the engine
  is detected.
* **When the diagnose runs** (`Invoke-AtmGuiDiagnose` in `Gui.ps1`, the only place that calls `Invoke-AtmDiagnose`):
  * the first `D` runs it once, on the UI thread, with the session's inventory arguments and a progress callback;
    the next `D` shows the kept result. `U`, only inside the area, runs it again (GUI-D3). An audit keeps the result
    and does not run it; moving between screens runs nothing. Nothing repeats by itself;
  * while it runs, the screen keys, the buttons and Refresh are disabled, a second request is ignored, and the window
    shows the TUI's fixed text with the percentage of the inventory phase;
  * the result is read through the schema view: `ConvertTo-AtmDiagnoseJson`, then `ConvertFrom-Json`, as the TUI.
    The identity block and the machine name are never rendered (section 3); a privacy case checks it;
  * a close request during a run stops the inventory phase at its next callback. The collectors still run, within the
    diagnose deadline (300 seconds by default); then the result is discarded and the window closes. This is the limit
    of section 5, declared: the engine offers no callback inside the collectors;
  * a failure keeps an earlier result, marked outdated, with the exception code only; with no earlier result the area
    does not open and the window says so. The test seam `$script:AtmGuiDiagnoseSource` is a single `$null` assignment.
* **The one difference from the TUI: the gate lines.** Each collector that a closed V0.2 gate keeps off
  (`WORKTREE_DIAGNOSTICS_GATE_CLOSED`, `HANDLE_SECURITY_GATE_CLOSED`, and `EXPORT_SECURITY_GATE_CLOSED` and
  `GIT_EXECUTION_GATE_CLOSED` when a result names them) gets a line "Disabled in this version" ("Desabilitado nesta
  versão"), with the code, the collector and the catalog reason, in the summary and in the category it affects. The
  parity case allows only these lines. A second case follows from it: a category whose collector is conclusive but
  carries a gate code shows `tui.diag.emptyNotObserved` when it has no rows, where the TUI would show `common.none`,
  so that a disabled collector is never read as an empty result.
* **Digit keys inside the area.** In the GUI, `1` to `9` and `P` work inside the area and leave it for their screen,
  as they do from every other screen; the TUI ignores them there. `D` from inside the area goes back to its menu.
* **Window:** a `U` button (enabled only inside the area), a navigation hint and a label for the lines above the
  table. Only `Label`, `ListView` and `Button` controls, no timer, no editable text field, no cancel button and no
  action. The form's key handler takes `D` and `U`.
* **Catalog:** new `gui.*` keys only, in en-US and pt-BR: the hint, the button, the progress, the label's name, the
  "disabled in this version" line, and the reasons of the two gates the catalog had no text for (export and Git).

## Implementation record: P5 (V021-P5, 2026-11-16)

Phase P5: the live monitoring of section 5, with GUI-D2, GUI-D3 and GUI-D10. What P5 implements, with the gate closed in
every copy:

* **Controls,** under the buttons:
  * a check box, "Live monitoring" ("Monitoramento ao vivo"), with the access key `M`. The suite checks that it collides
    with no other key in either language;
  * a `DropDownList` with six fixed intervals: 30 s, 60 s, 2 min, 5 min, 10 min and 15 min. It cannot be typed into;
  * a status line: off, or on with the interval and the UTC time of the next audit.

  When the window opens, the box is off and the list shows 60 s. Nothing is remembered.
* **One ticker,** a `System.Windows.Forms.Timer` created in one place, `Start-AtmGui`.
  * **What it does.** It only wakes the check: the decision is `Invoke-AtmGuiTick`, which compares the time with the
    session's `NextDueUtc`. The ticker is restarted whenever that time is set (turning on, a new interval, the end of an
    audit), and its period equals the interval.
  * **Seams.** A wake up to 500 ms early counts as due (`$script:AtmGuiTickToleranceMs`). The clock is a test seam,
    `$script:AtmGuiClockSource`, a single `$null` assignment.
  * **Results.** The tick returns `SKIPPED_NOT_DUE`, `SKIPPED_BUSY`, `SKIPPED_BACKOFF`, `REFRESHED` or `FAILED`.
  * **Two deviations from the round.** The tick also returns `CANCELLED` when the window is closed during its own audit.
    It returns `SKIPPED_NOT_DUE` while the monitoring is off or the window is closing, since no time is due then.
  * **Turning it on** runs nothing: the first audit is due one interval later. Before the first audit has finished, a
    due tick audits normally.
  * **Changing the interval** starts the count from that moment. Turning the monitoring off stops it, and an audit
    already running ends normally.
* **What a due tick runs: the `F5` audit, never the diagnose** (GUI-D3).
  * The tick calls `Invoke-AtmGuiRefresh`. The result of `D` is kept as the same object, never marked outdated, not even
    by a failed tick. The static test refuses any diagnose function inside a function named `Invoke-AtmGuiTick` (three
    plants).
  * A tick while an audit, the preview or a `D` or `U` run is in progress is dropped (`SKIPPED_BUSY`), never queued.
    The suite fires it from inside the progress callbacks of the dubbed inventory and diagnose, and from inside the
    dubbed preview.
* **Navigation: the tick keeps the screen; `F5` is unchanged.**
  * The tick keeps the navigation stack. The open screen is computed again over the new result, as P3 does after any
    audit: a detail whose root is gone goes back to its list with the catalog text, and the roots of a user or project
    that is gone are an empty list.
  * `F5` keeps its P4a behavior: from `P`, `8` or a detail opened from them it goes back to the dashboard (the preview
    is discarded), and from any other screen the screen stays. The round assumed that `F5` always goes back to the
    dashboard. The code never did; this phase does not change it, and records the difference here.
* **The preview in the tick.**
  * On a preview screen (the stack holds `P` or `8`), the same tick runs the preview again over the new result. Its time
    counts in the duration, so a slow preview makes the cycle slow.
  * On any other screen, the audit discards the kept preview, which runs again the next time `P` or `8` is opened. A
    failed audit keeps it, as in P4a.
* **States and limits** (GUI-D10):
  * **Slow:** an audit (with its preview) longer than half the interval marks the view `STALE`, with its duration. The
    next tick then waits max(interval, 2 x duration) from the end of that audit; earlier ticks return
    `SKIPPED_BACKOFF`, and the status line shows the later time.
  * **Old:** more than twice the interval with no good audit marks the view `STALE` (old), with the time of the audit
    shown. This happens only while the monitoring is on, and is evaluated on every tick, skipped ones included.
  * **Failure:** the result and its lines stay, and the view is `STALE` with the exception code only. The audit now
    keeps `ConvertTo-AtmExceptionCode` of the type, as the diagnose does, instead of the type name; the P2 pins were
    updated. The next due tick tries again.
  * **Recovery:** a good, fast audit clears the slow and old marks and the backoff.
  * **When the marks apply:** both apply only while the monitoring is on. An `F5` with it off is measured, never
    marked slow.
* **Memory.** The session keeps one result: the last good one, which a failed audit leaves in place.
  * The suite runs 20 due ticks. Each audit returns a new dubbed inventory with 1 MB of ballast, and managed memory is
    read with `[GC]::GetTotalMemory($true)` after the first audit and after the twentieth.
  * The first inventory must be collected; a weak reference checks it.
  * Local measurement (Windows PowerShell 5.1, x64): growth from the first to the twentieth audit 0.02 to 0.05 MB, and
    the first inventory collected.
  * The declared limit is 8 MB of growth. Keeping every result would grow by at least 19 MB from the ballast alone.
  * On the CI runners (first run of the PR), the growth from the first to the twentieth audit was:

    | Job | Growth |
    |---|---|
    | `test (powershell)`, x64 | 0.02 MB |
    | `test (pwsh)`, x64 | 0.03 MB |
    | `test ARM64 (powershell)` | 0.01 MB |
    | `test ARM64 (pwsh, subset)` | 0.02 MB |

    The first inventory was collected in all four. The 8 MB limit stays: it is more than 200 times the largest number
    measured, and still well under the 19 MB that keeping every result would add.
* **Close.** `FormClosing` marks the session as closing, turns the monitoring off, and stops and releases the ticker. The
  `finally` block of `Start-AtmGui` does the same if the form never closed. A tick that arrives after that does nothing
  (`SKIPPED_NOT_DUE`), and the real-window case checks it.
* **What did not change:**
  * the closed list (23 names) and the allowed cmdlets;
  * the engines, the TUI, the reports and the launcher.

  The static test now counts exactly one timer creation in the GUI files, in `Start-AtmGui`. The word "timer" appears
  nowhere else in them. It refuses `System.Timers`, `System.Threading.Timer`, `Register-ObjectEvent`, `Start-Job`,
  `Start-ThreadJob` and `runspacefactory`. The earlier phases' checks for no timer now read the files without the one
  creation.
* **CI times.** The suite grew with the GUI phases, so the job limits change:
  * `test`: 30 to 40 minutes;
  * `test ARM64 (powershell)`: 30 to 45;
  * `test ARM64 (pwsh, subset)`: 40 to 55.

  The check names do not change.
* **Catalog:** new `gui.*` keys only, in en-US and pt-BR:
  * the check box, the interval label and list name, the two interval formats;
  * the three status lines;
  * the slow and old `STALE` texts.

## Implementation record: P6 (V021-P6, 2026-11-17)

Phase P6: section 7 (languages and accessibility) and the close end to end. It is the last phase of V0.2.1. What P6
implements, with the gate closed in every copy:

* **One catalog for every visible text.**
  * Every `Text`, `AccessibleName`, column header, title and message comes from `I18n.ps1`. The TUI's literal terms
    the tables used (`SID`, `Roots`, `Root`, `MB`, `A/R/U/O`, `Flags`, `Preview`) are now `gui.term.*` keys. Their
    values are the same in both languages, as the TUI writes them. The time line before the first audit comes from the
    dashboard's own text instead of a literal `-`.
  * The language is chosen at start (`-Lang`, then `ATM_LANG`, then the UI culture). There is no switch inside the
    window.
  * The suite declares the 12 `gui.*` keys whose value is the same in both languages: formats with no word of their own,
    units, the product's name and the `gui.term.*` keys. Any other equal value fails.
* **Accessibility.**
  * **Names.** Every control has an `AccessibleName` from the catalog, panels included. A label that starts empty gets
    a name of its own (screen title, message, progress).
  * **Tab order.** The `TabIndex` values are unique in each container and follow the visual order: header, state,
    monitoring, screen buttons, title, table, then Refresh and Close. The monitoring controls moved from under the
    buttons to under the header, so the visual order and the tab order agree.
  * **Focus.** The list gets the focus by `Form.ActiveControl`, not by `Focus()`. `Focus()` depends on the window being
    the active one.
  * **GUI-ENTER-ON-BUTTON (the fix).** `KeyDown` used to treat `Enter` as "open the selected row" whatever had the
    focus. Now:
    * on a focused button, `Enter` presses the button, like Space;
    * on the check box or the interval it changes nothing and opens nothing (Space toggles the box);
    * on the list it opens the row, as before.

    On the real message path, Windows already presses a focused button with `Enter` before `KeyDown` runs, through the
    form's default button. The bug showed when the key reached `KeyDown` directly. The real-window case covers both
    paths.
  * **Color.** Only system colors or each control's default. The static check refuses `Color.FromArgb`, `FromName`,
    `FromKnownColor`, any `[System.Drawing.Color]` type, and `ForeColor` or `BackColor` set to anything other than
    `[System.Drawing.SystemColors]`.
  * **DPI.**
    * `AutoScaleMode` stays `Dpi`.
    * Every fixed width goes through one function, `Get-AtmGuiScaled` (pixels at 96 DPI × DPI / 96, rounded half away
      from zero). That covers the column widths, the list sizes, the width of the screen-button strip and the interval
      list.
    * The DPI comes from `Get-AtmGuiDpi`: `DeviceDpi` where .NET has it, otherwise the `DpiX` of a graphics object of the
      form, released at once. It is read once per window.
* **The static check also refuses visible literals.** A `Text`, `AccessibleName` or `AccessibleDescription` set to a
  non-empty literal, a label or list built with a literal text or name, and a column added with a literal header all
  fail, each with a refused plant.
* **Close end to end** on the real window (Windows PowerShell jobs, the gate opened only in each child, dubbed
  sources). One child per path and language:
  * `Esc` on the dashboard;
  * `Form.Close()`;
  * close during an audit, which is cancelled at its next callback;
  * close during the preview, which finishes first;
  * close during the diagnose, which is cancelled at its next callback;
  * close with the monitoring on, right after a tick that audited.

  In every path the window closes with exit code 0. The ticker is released, and a tick an hour later does nothing. No
  child process is left behind, no new file appears in the sandbox, the configuration or TEMP, and no new key or value
  appears under `HKCU\Software\AgentTemp*`. The product writes nothing to the registry. On PowerShell 7, or on a runner
  where no window can open, the case is `NOT_TESTED`.
* **What did not change:**
  * the closed list (23 names) and the allowed cmdlets;
  * the engines, the TUI, the reports and the launcher.

## Implementation record: V0.5 M5 (V05-M5, 2026-11-21)

The monitoring area of [ADR-0017](ADR-0017-v05-preventive-monitoring.md) phase M5 (its M5 implementation record has
the details). The GUI's gate `AtmGuiEnabled` and the monitoring's `AtmMonitoringEnabled` stay `$false` in every copy.

* **The closed list** gains exactly `Get-AtmMonitorStatus` and goes from 28 to 29 names (section 3). No `Report.ps1`
  formatter joins it. The forbidden list gains the monitoring's other functions by their exact names, never a prefix.
* **The area** "Preventive monitoring", view only, opened by `M` or its button (screen `prevmon`). The button has no
  access key: Alt+M stays the live monitoring check box's.
  * One status is read per opening, in `Invoke-AtmGuiPrevmon` only, through the seam `$script:AtmGuiPrevmonSource`
    (`$null` outside the tests). It is ignored while an audit, the preview or the diagnose runs.
  * The ticker and F5 never read it. The static check of the ticker now also refuses `Invoke-AtmGuiPrevmon` and
    `Get-AtmMonitorStatus`.
  * The view model (`Get-AtmGuiPrevmonLines`) writes the lines of `monitor status`, in the same order, without the
    collection task's. With the gate closed: "not available in this release" and the history as it is, with no alert.
    With it open: the total and the delta, the trend, up to 5 groups, the thresholds' state and the alerts, each
    command as text. A closing line says that nothing in the area runs.
  * A failed read shows the exception's code only, and the window stays where it is.
* **Tests.** The models and the session without a window, in both languages. The closed list of 29 with planted
  forbidden names refused, and the one seam. The P5 access-key check now reads the keys from the buttons' real texts.
  The P6 window test's tab order includes `ScreenM`, and its texts check includes the button's text.
* **NOT_TESTED:** pressing `M` or `ScreenM` in a real window with the engine's real status.
