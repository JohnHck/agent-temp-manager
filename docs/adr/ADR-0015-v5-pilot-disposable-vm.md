# ADR-0015: V5 pilot of real deletion in a disposable VM

Status: PROPOSED. The maintainer's decision D-C (2026-11-16) sets the class of environment: a disposable VM, with the
deletion gate open only inside it. Everything else in this record is a design waiting for the maintainer: V5-D1 to
V5-D8 are open. Nothing is executed, created, enabled or downloaded, and no gate is opened anywhere.
Date: 2026-11-17
Phase: V0.3, validation stage V5 (the operator's pilot on one real root)

## Context

* **What V5 is.** The [ROADMAP](../ROADMAP.md#v03--selective-real-cleanup) lists V5, the operator's pilot of real
  deletion on one real root, as a prerequisite for any release with the deletion gate open. V2 and V3 ran the real
  clean in CI, on roots planted by a CI-only harness ([TESTING.md](../TESTING.md#real-clean-on-disposable-vms-v03-v2)).
  V4 ran the privilege rows with the gate closed on a real machine ([V0.3-RC.md](../release/V0.3-RC.md), section G).
* **What CI could not prove** (TESTING.md, V2 "Not tested here" and "V3 as a whole"; V0.3-RC.md, section F):
  * the CLI past the gate, with a person typing the answers (every confirmation in CI is automated, `TEST_SEAM`);
  * the engine's own console check (`ENGINE_CONSOLE_CHECK`) on a real console;
  * a root created by a real Claude Code session, old by real elapsed time (CI sets write times back by 120 hours and
    records `recencySimulated`);
  * UAC prompts and filtered tokens (the runners run as administrators with UAC disabled);
  * the TUI past the gate.
* **Maintainer decision D-C (2026-11-16).** V5 becomes a pilot in a disposable VM, as V2 already is in CI, with the
  gate open only in the VM.
  * It keeps the non-elevated condition of the B1 restricted exception.
  * It takes the process churn of the operator's machine (finding F-A) out of the pilot.
  * It replaces the environment part of the earlier operator decision J1. The choice of the mechanism that opens the
    gate stays open and is made again here, for the VM (section 4).
* **F-E is fixed on `main`.** Commit `8fc48c2` loads the verified native library before the clean lock. In
  `src/lib/Engine.Clean.ps1`, `Invoke-AtmClean` checks the gate at line 416, calls `Initialize-AtmNative` at line 419
  and `TryAcquire` at line 420. A clean with no `-LogFile` past the gate now ends with `LOG_REQUIRED`. The fix is in
  `v0.3.0`. The pilot still always passes `-LogFile`: the T1 log is the evidence.
* **Three code facts that shape the design** (all on `main` at `95900b9`):
  1. **Redirection refuses the clean past the gate.** `src/agent-temp.ps1:340` stops with `cli.cleanNeedsConsole` and
     exit code `6` when `Test-AtmTuiInteractive` (`src/lib/Tui.ps1:37-44`) is false. That is any host other than
     `ConsoleHost`, or stdin or stdout redirected. So the real clean runs in a plain console, its output is never
     redirected to a file, and the console evidence comes from the T1 log and a transcript.
  2. **The TUI cannot delete a B1 root.** `src/lib/Tui.ps1:940` calls `Invoke-AtmClean` without
     `-AcceptB1ResidualRisk`. Past the gate, the TUI treats a root of the B1 exception as B1 itself and refuses it. In
     this pilot the TUI can only be checked as a refusal.
  3. **An edited installed copy refuses to run.** `src/agent-temp.ps1:36-38` and `:170-182` check every installed file
     against the manifest before any code is loaded, for every command. A copy with the gate line changed fails that
     check. And `tools/Build-Release.ps1` refuses any gate that is not a single assignment to `$false`.

## Decision (proposed design)

### 1. What V5 must prove, and what stays out

**Must prove**, on one root, in one VM, with the gate open only there:

| # | Proof | Evidence |
|---|---|---|
| V5-P1 | The CLI past the gate, with a person typing every answer | console transcript; T1 log `confirmation` |
| V5-P2 | `ENGINE_CONSOLE_CHECK`: the engine observes the real console | T1 log `consoleBy = ENGINE_CONSOLE_CHECK`, never `TEST_SEAM` |
| V5-P3 | The AUT-2 questions per root, `ACEITO RISCO B1`, and the final phrase `APAGAR 1 CAMINHOS <planId8>` | T1 log `declaration` (`b1ResidualRiskAccepted: true`) and `confirmation` (full planId) |
| V5-P4 | The T1 log read back from the file | record types in order: `run-start, plan, declaration, confirmation, plan-check, intent, result, run-end` |
| V5-P5 | The B8 lock: `CLEAN_LOCK_BUSY` for a second clean during a run, and free after it | row V4-11 below; a later run acquires the lock |
| V5-P6 | Outcome `COMPLETE` on a root created by a real, non-elevated Claude Code session | T1 log `result`; exit code `0`; the root is gone |
| V5-P7 | Nothing changed outside the root | snapshots before and after (section 6) |

**The privilege rows that need the gate open** (operator script, section 2.3):

| Row | In or out | Why |
|---|---|---|
| V4-8, standard user, interactive console, `clean -AcceptB1ResidualRisk` | **In.** It is the deleting run | It is V5-P1 to V5-P3 |
| V4-9, console not observed | **In**, in two forms: stdout redirected to a file, and stdin piped. Each must end with exit code `6` (`cli.cleanNeedsConsole`), with no question and no log | It costs two short runs, deletes nothing, and runs on the same root before the deleting run |
| V4-9, a really non-interactive session (scheduled task, SSH, WinRM) | **Out** | It needs a task or a remote-management service set up in the VM just for this. The CLI check it reaches is the same `Test-AtmTuiInteractive` |
| V4-10 and V4-12, elevated through UAC, `clean -AcceptB1ResidualRisk` | **In**, as one run, before the deleting run. Expected: the root `BLOCKED` by B1 as today, and no risk question | The VM has UAC on, unlike the runners. How the elevated session is opened depends on the account model (V5-D4) |
| V4-11, a second clean while the first is at its questions | **In**, in a rehearsal run that the operator ends with a wrong final phrase. Expected: `CLEAN_LOCK_BUSY` in the second, with no plan and no log; the first aborted, nothing deleted | Not during the deleting run: a second process during that run could also change its revalidation |

**Stays out** (still not tested after V5): the TUI deleting anything (fact 2: it only refuses a B1 root); `ELIGIBLE`
(unreachable without full process coverage, F-B); more than one root per run (the exception's fixed limit); the V3
cases left out by design (N7, O4, L1, K4, S2); a really non-interactive session; credentials of another account beyond
the UAC row.

### 2. Environment: the disposable VM options

Each option is led by the constraint that decides it.

| | Hyper-V VM on the operator's machine | Windows Sandbox | Cloud VM | GitHub-hosted runner (as V2) |
|---|---|---|---|---|
| **Deciding constraint** | Enabling the feature is a change to the operator's machine | Closing it, or restarting the host, discards everything; the container account is meant to be an administrator | Licence for a Windows 11 guest, and an hourly cost for at least three days | A job ends after 6 hours: 72 real hours are impossible |
| **Host isolation** | Hypervisor. A basic VMConnect session shares no clipboard and no drive: clipboard, drives and devices are shared only in enhanced session mode, which needs that mode on the host and Remote Desktop Services in the guest. No shared folder unless one is set up. Network: the VM's adapter can be disconnected | Hypervisor. Networking, clipboard redirection and audio input are **on** by default; a `.wsb` file turns them off and maps folders read-only. Changes to a writable mapped folder stay on the host | Provider's isolation. RDP clipboard and drive redirection are client settings to turn off. The VM is reachable over the network: access must be restricted | Full; nothing of the operator's machine is involved |
| **Disposal** | The operator deletes the VM and its virtual disks; until then the disk file sits on the host | Automatic when the window closes | The operator deletes the VM and its disks (or the whole resource group) | Automatic at the end of the job |
| **Persistence for 72 h** | Yes. The VM can run for days, or be saved and resumed; the time synchronization service keeps the guest clock on the host's | Fragile. Only restarts started inside the sandbox keep data; a host restart (for example an update) loses the root | Yes, while it is paid for | **No** (6-hour job limit). Self-hosted runners allow 5 days, but they are a VM of the operator's anyway |
| **What the maintainer must do** | Enable Hyper-V (Windows 10 or 11 Pro or Enterprise, 64-bit CPU with SLAT, virtualization on, at least 4 GB of RAM; administrator and restart). A guest image and its licence: the Windows 11 Enterprise 90-day evaluation (registration; its page says it is meant for IT professionals and that setup signs in with a Microsoft account) or the maintainer's own licence. Some memory and disk for a few days. Note: other hypervisors (VMware Workstation, VirtualBox) may not run reliably while Hyper-V's hypervisor runs | Enable the feature (Pro, Enterprise or Education; administrator and restart). No image: it reuses the host's own Windows | A cloud account and payment. A Windows 11 image needs qualifying licences (multitenant hosting rights) or a dev/test entitlement; a Windows Server image carries its own licence | Nothing new |
| **Evidence out without personal data** | The operator reads the summary inside the VM and brings out only that (section 6) | Same, or a read-only output folder | Same; the summary only | Artifacts through the sanitizer, as V2 |
| **Real session and a person typing** | Yes: Claude Code installed and signed in inside the VM by the maintainer; a console the operator types into | Partly: a person can type, but the default account is meant to be an administrator, so the B1 exception (non-elevated) needs a second, standard account inside a sandbox that will not survive a host restart. Its token state was not verified for this record | Yes, over RDP | **No**: no person, and signing Claude Code in would put a credential in CI secrets, which is ruled out |

**Recommended: Hyper-V on the operator's machine** (decision V5-D1). It is the only option that is local, survives 72
hours, keeps the clipboard and drives out by default, and lets the maintainer type. The cloud VM is the alternative if
the machine must not change. Windows Sandbox and the hosted runner do not meet the 72-hour rule.

### 3. RECENT is not worked around

RECENT (72 hours since the last write to the root **and** to its transcript, `TRANSCRIPT_RECENT`) stays as it is. In the
pilot it is reached only by real elapsed time. **Forbidden:**

* changing the VM's clock, by hand or by any tool;
* turning the time synchronization service (`vmictimesync`) off, or changing its source, in order to set the clock;
* changing the dates of files or folders (no `LastWriteTime`, no touch tool, no copy that keeps or sets old dates);
* "ageing" the root by any other means: restoring a checkpoint taken after the root exists, copying the root in from
  elsewhere, or planting it by script.

**Also forbidden between the end of the root's session and the deleting run:** resuming that Claude Code session (it
writes its transcript, and the 72 hours start again), and starting any other Claude Code session between the two
snapshots.

**When the wait is over** is read from the product's own preview: the root leaves `RECENT` only when the preview no longer
shows it. It is never computed by hand. The evidence records the difference between the guest clock and the host clock
at the deleting run (a number of seconds, nothing else).

If an environment cannot hold the root for 72 real hours, it does not run V5. B1, RECENT and the eligibility rules do
not change in this record.

### 4. The mechanism that opens the gate inside the VM

Under D-C the copy with the gate open exists only inside a VM that is thrown away. The four mechanisms of the operator
script (section 3.2), seen again:

| | What it is in the VM | Proves | Does not prove | Risk left |
|---|---|---|---|---|
| **A. Pilot checkout** | A checkout of the pinned SHA inside the VM, with the one line `$script:AtmRealDeletionEnabled = $false` changed to `$true` there, by the operator; run as `src\agent-temp.ps1 clean` | The real CLI past the gate: `Read-Host`, `ENGINE_CONSOLE_CHECK`, AUT-2 typed by a person, the exit code. Also the TUI's refusal of a B1 root | The installed engine verified by its manifest (the checkout compiles `Native.cs` in memory). Deletion through the TUI (fact 2) | A copy with the gate open on the VM's disk, so inside the disk file on the host, until the VM is disposed of. Mitigated: never in a writable shared folder or the clipboard; disposed of right after the evidence is out; the diff from the pinned SHA must be exactly that one line (`git diff --numstat` gives `1 1`), recorded as yes/no |
| **B. V2/V3 harness with `-DisposableMachine`** | The CI harness run in the VM | What CI already proves | A real root (it plants its own), recency (it sets dates back, which section 3 forbids for the pilot), a person typing (`TEST_SEAM`) | Not a pilot of a real root. **Ruled out** |
| **C. Separate script on the installed engine** | A new script that loads the **installed** engine, opens the gate in memory and calls `Invoke-AtmClean` with a `Read-Host` reader and no console seam | The installed engine verified by its manifest, a person typing, `ENGINE_CONSOLE_CHECK`, with no product file changed | The CLI wiring (`agent-temp.ps1 clean`, fact 1) and the TUI | New code that opens a gate. It would need its own round (contract, review, tests, kept out of the release archive like the V2 harness) |
| **D. Pilot package with the gate open** | A package whose gate is `$true` and whose manifest is rebuilt, installed in the VM | The whole installed path: launcher, manifest and CLI | The TUI deleting (fact 2); nothing more in the engine than A | An installable artifact with the gate open. `Build-Release.ps1` refuses it, so it needs a changed build or a manual one. It is the largest leak risk, even inside a VM |

**Recommended: A** (decision V5-D3), with the installed copy of the same SHA, gate closed, in the same VM for the
closed-gate checks (`version`, `verify`, `preview`). A is the only mechanism that runs the real CLI with a person typing,
with no new code that opens a gate (C) and no installable artifact with the gate open (D). Under D-C its old risk, a
copy with the gate open left on the operator's disk outside a VM, shrinks to the VM's disk file until disposal. C is
the alternative if the maintainer wants the installed engine proven too; it adds a code round.

**The gate stays `$false` in every copy of the repository, the package and the release.** The change to `$true` exists
only in the checkout inside the VM, made by the operator, and is never committed, pushed, packaged or copied out.

### 5. The real root

* **The VM.** A Windows 11 guest with UAC on (its default). Two local accounts created by the operator: an
  administrator for set-up, and the **pilot account**, the one Claude Code and the pilot run as (V5-D4: a standard user,
  recommended, or an administrator with a filtered token).
* **The dedicated base, inside the VM**, by the runbook (`RUNBOOK-BASE-DEDICADA.md`, section 3, steps 0 to 5), as the
  pilot account, in a non-elevated console: `<base>` created with its protected ACL already at creation, then
  `CLAUDE_CODE_TMPDIR` set to `<base>` in that account's user environment. Claude Code then writes under
  `<base>\claude\` (it appends `\claude\` on Windows). The product reads the variable from the Windows user environment,
  not from Claude Code's settings.
* **Signing in to Claude Code** inside the VM is the maintainer's: the maintainer's own account and credential, typed by the maintainer. The
  agent never types, sees or stores it, and has no access to the VM.
* **The session that makes the root.** A new, non-elevated Claude Code session of the pilot account, started after the
  variable is set, with its working folder outside `<base>`. A short real task with synthetic content only, for example
  writing a small file in that folder and running one shell command, so that Claude Code uses its temp directory. Then
  the session is ended and never resumed. The closed-gate preview must then show a new root under `<base>`, `RECENT`.
  Its content is decided by the operator as not needed (`NADA NECESSARIO`): it is synthetic.
* **What stays in the VM, and for how long.** Claude Code, its credential and transcripts, the root, the installed
  copy, the pilot checkout, the T1 logs, the transcripts of the consoles and the snapshots. All of it from the VM's
  creation until its disposal: at least 72 hours plus the runs. Disposal comes right after the summary is out and
  checked. Before it, the operator signs Claude Code out or revokes its credential, as the operator judges. Network: on for set-up
  (updates, Claude Code, the package), then the adapter is disconnected from the end of the root's session to the
  disposal; recorded as yes/no.

### 6. The operator's steps

**Prerequisites** (all, before any run):

1. The VM as in section 5, the pinned SHA recorded (`git rev-parse HEAD` in the checkout), and the package of that SHA
   installed. `agent-temp verify` exits `0`; `version` shows real deletion disabled.
2. The root: made by section 5's session; no live session; out of `RECENT` by the preview (section 3).
3. The closed-gate checks with the installed copy, as the pilot account (this is V4-1 in the VM): the probe says not
   elevated; the preview shows the root as `ELIGIBLE_WITH_DECLARED_RISK`, not released; a closed-gate `clean` on it does
   not delete (`NENHUM_CAMINHO_ELEGIVEL`, as in V0.3-RC section G).
4. A new log path for every run, under `<evidence folder>`, outside every base (the CLI refuses a log inside a base).
5. The root's path given to `clean` from a console variable, never in a parent process's command line (V0.3-RC section
   G, method note: a path there makes the root "in use").
6. Exactly one root, the exception's limit.

**Snapshots.** Each is a listing of `<base>`, the installed copy, the pilot checkout and `<evidence folder>`, with the
relative path, type, size, last write time and SHA-256 of each file. Reparse points are recorded, never followed. They
are taken before any run (S0), right before the deleting run (S1) and after it (S2). S0 to S1: only new logs and
transcripts. S1 to S2: only the root removed and the new log. A snapshot never runs at the same time as a clean.

**Runs**, in this order, each with a new `-LogFile` (`$co` is the checkout, `$root` and `$log` console variables):

1. **V4-9, stdout redirected:** `powershell -NoProfile -File "$co\src\agent-temp.ps1" clean -Path $root
   -AcceptB1ResidualRisk -LogFile $log > <file>`. Expected exit `6`, no question, no log file.
2. **V4-9, stdin piped:** the same command fed by a pipe. Expected exit `6`, no question, no log file.
3. **V4-10 and V4-12, elevated through UAC** (as V5-D4 sets): expected the root `BLOCKED` by B1 and no risk question. If
   a risk question ever appears: answer with a wrong phrase, stop and report.
4. **TUI past the gate** (optional): the checkout's `tui`, `L` on the root. Expected: refused as B1; nothing deleted.
5. **V4-11 rehearsal:** a clean in console 1. At its questions, a clean in console 2 (same account, same root, another
   new log): expected `CLEAN_LOCK_BUSY`, no plan, no log. Console 2's command must have ended before console 1 goes on.
   Console 1 then gets a wrong final phrase: aborted, nothing deleted.
6. **The deleting run (V4-8):** S1, then a plain console, transcript on (never `>`), `powershell -NoProfile -File
   "$co\src\agent-temp.ps1" clean -Path $root -AcceptB1ResidualRisk -LogFile $log`. The operator types the phrases
   shown: the task, the content, `ACEITO RISCO B1`, `APAGAR 1 CAMINHOS <planId8>`. Expected `COMPLETE` and exit `0`.
   Then S2, the post-audit shown by the CLI, `verify` of the installed copy, and a later preview: the root is gone.

**Stop and report, with no new attempt**, on: any code other than the one expected; `CLEAN_LOCK_BUSY` or
`CLEAN_LOCK_ABANDONED` outside run 5 (first look in the earlier log for an `intent` with no `result`);
`CONSOLE_NOT_OBSERVED` in runs 3 to 6; any `LOG_*`; an outcome other than `COMPLETE`; any change outside the root in
the snapshots; a risk question in run 3.

**Refusals caused by new processes (F-A):** `PLAN_CHANGED_BEFORE_EXECUTION` or `REVALIDATION_REFUSED` with
`B1_EXCEPTION_NEW_UNINSPECTABLE_PROCESS`. At most 3 new runs, each decided by the operator, each with a new log; the
number of new identities is recorded each time. At the third refusal, stop.

**Evidence.** Stays in the VM and goes with it: the T1 logs (they hold the account, its SID and paths), the console
transcripts and the snapshots. **Comes back to the agent:** the pinned SHA; per run, the record types of its log, the
outcome, the reason codes and the exit code; the counts (processes not inspectable, new identities on each F-A refusal,
files and bytes deleted); and yes/no for: anything changed outside the root, the checkout differs from the pinned SHA by
exactly the gate line, `consoleBy` is `ENGINE_CONSOLE_CHECK`, the guest clock within a few seconds of the host's, the
network disconnected at the deleting run. **Never:** a SID, an account name, a machine name or a path.

**Disposal** of the VM and its disks is the operator's, after the summary is out (GOV-INC-01: destructive actions are
the operator's only).

### 7. Acceptance of V5, and what it unlocks

**V5 passes** when every one of these holds:

* V5-P1 to V5-P7 hold in the deleting run (`COMPLETE`, exit `0`, the log's records in order, `ENGINE_CONSOLE_CHECK`,
  nothing outside the root changed);
* the in-rows of section 1 give their expected results;
* no stop criterion fired (F-A refusals within the limit of 3 do not fail the pilot; they are recorded);
* the pilot checkout differed from the pinned SHA by the gate line only;
* the summary passes the repository's privacy scanner.

**Where it is recorded:** a new release record, `docs/release/V5-PILOT.md`, written by the agent from the summary in a
later round, with the pinned SHA, the results per run and the NOT TESTED list. The ROADMAP's V5 line then says it was
done. Nothing in it names a person, an account or a machine.

**What it unlocks:** only a decision of the maintainer's own about a release with the gate open (decisions D-A and D-D,
and J4 of the operator script). **Accepting V5 opens no gate.** Opening the deletion gate in a release is a separate,
reviewed change with its own gate and the maintainer's explicit word.

### 8. Decisions for the maintainer

None of these is decided by this record.

| # | Decision | Evidence | Alternatives | Technical recommendation |
|---|---|---|---|---|
| V5-D1 | The environment | Section 2: Sandbox discards on a host restart and its account is meant to be an administrator; a hosted runner cannot hold 72 h; Hyper-V and a cloud VM both can | (a) Hyper-V on the operator's machine; (b) a cloud VM; (c) Windows Sandbox; (d) a hosted runner | **(a).** Local, holds 72 h, no clipboard or drive shared by default, and the maintainer types in it. (b) if the machine must not change. (c) and (d) do not meet RECENT |
| V5-D2 | The guest image and its licence | The evaluation is 90 days, needs registration and a Microsoft account at setup, and its page aims it at IT professionals | (a) Windows 11 Enterprise evaluation; (b) a Windows 11 licence of the maintainer's own | The maintainer's licence judgement. Technically either works: the pilot needs a few days, well inside 90. The guest must be Windows 11 with UAC on |
| V5-D3 | The mechanism that opens the gate | Section 4 and facts 1 to 3 | A, B, C, D | **A**, with the installed copy of the same SHA for the closed-gate checks. C if the installed engine must also be proven (adds a code round). B ruled out; D not recommended |
| V5-D4 | The pilot account and the elevated row | V4-1 (standard user) was never run on a real machine; V4-2 showed a filtered administrator token is treated as not elevated | (a) a standard user; the elevated row through the UAC credential prompt of the VM's administrator; (b) an administrator with a filtered token; the elevated row through "Run as administrator" | **(a).** It is the strictest case, it closes V4-1, and the UAC credential prompt also exercises a second identity. With (a) the elevated process belongs to the administrator account, so the root is another profile's: run 3 adds `-IncludeOtherUsers` and still expects B1 `BLOCKED` |
| V5-D5 | Who runs, and where | GOV-INC-01; the agent cannot type the confirmations or the credential | (a) the maintainer, in the VM's console on the operator's machine; the agent prepares the script and reads the summary; (b) another person under the maintainer's authority | **(a).** The agent never operates the VM |
| V5-D6 | The RECENT wait | Section 3 | (a) the VM keeps running through the wait; (b) the VM is saved or shut down during the wait and resumed; (c) nothing that shortens it | **(a)**, with (b) allowed: real time passes either way and the time service corrects the clock on resume. The end of the wait is read from the preview, and the clock difference is recorded. (c) holds in every case |
| V5-D7 | The evidence tools | The snapshots and the summary are where personal data could leak | (a) reviewed scripts in the repository (below), written and tested in their own round before the pilot; (b) commands written into the operator script only | **(a).** A summary typed by hand from a log that holds SIDs and paths is the likeliest leak. Scripts give the same output every time and can be tested |
| V5-D8 | A complement on a real machine | The VM is a favourable environment for B1 (section 9) | (a) the VM pilot is enough for the decision about an open-gate release, with the limit declared; (b) also a run on the operator's machine later; (c) also measure F-A on the operator's machine with the gate closed (J2 (c)) | **(a) with (c).** (c) changes nothing and tells how often a real machine would refuse. (b) brings back the churn D-C took out |

**Future code (V5-D7 (a)), specified here and not written.** A round of its own, `V5-TOOLS`, would add under
`tools/v5-pilot/`:

* `Get-AtmPilotSnapshot.ps1 -Root <dir> -Out <file>`: read only; for each item the relative path, type, size, last
  write time (UTC) and SHA-256; reparse points recorded, never followed; refuses an output inside `-Root`.
* `Compare-AtmPilotSnapshot.ps1 -Before <file> -After <file> -ExpectedRemoved <relative path> -ExpectedNew <relative
  path>`: yes/no for "only the expected change", plus counts.
* `Get-AtmPilotSummary.ps1 -LogFile <file> [-Compare <file>]`: reads the T1 log and writes only record types, outcome,
  codes, counts and booleans. It refuses to write any value with a path separator, an `S-1-` prefix or a name taken
  from the environment.
* **Tests in the suite, non-destructive, on synthetic fixtures:** each script's output; the summary refusing planted
  paths, SIDs and names; and static tests that none of them assigns a gate, a seam or the lock name, or calls the
  engine's clean.
* **Contract:** none of them deletes, moves or writes outside `-Out`. Whether they ship in the release archive is
  decided in that round, as for the V2 harness.

### 9. Risks and limits

**What the VM does not prove about a real machine:**

* **Process churn (F-A).** A fresh VM runs fewer services, updaters and other accounts' processes than a working
  machine, and its network is off at the deleting run. It is a **favourable** environment for the B1 exception: fewer
  processes it cannot inspect, fewer new ones during the questions. The pilot proves the flow, not how often a busy
  machine refuses. That failure is fail-closed (a refusal, never a deletion), so it is a usability limit, not a safety
  one.
* **The operator's own environment:** its services, antivirus and indexers, other agents' sessions, the real roots and
  history of the operator's base, other profiles (F-05), and any Windows version other than the guest's.
* **The processes not inspected stay unobserved** in the VM as everywhere: the residual risk of the B1 exception
  (`CONTRATO-EXCECAO-B1-RESTRITA.md`, section 5) is not reduced by the pilot, only exercised once.

**Still NOT TESTED after the pilot:** the TUI deleting a root (it cannot, fact 2); the installed engine past the gate
(with A); a really non-interactive session; `ELIGIBLE`; more than one root; the V3 cases left out by design; a second
real machine.

**Is that acceptable for a release with the gate open?** It is the maintainer's decision (V5-D8, D-A, D-D). The
technical reading: the safety properties that matter (nothing outside the planned root, fail-closed refusals, the lock,
the log, the typed confirmation) are proven in CI across three images and two shells, and V5 adds the two things CI
cannot: a person at a real console and a root of a real Claude Code session, old by real time. The open part is how
often a real machine refuses, which J2 (c) measures without opening anything. A release with the gate open would have
to state these limits in its notes.

## Rejected alternatives

* **V5 on the operator's machine** (the earlier J1 environment): replaced by D-C, which takes that machine's process
  churn (F-A) out of the pilot. Under the B1 exception, each new process that cannot be inspected refuses the run.
* **An elevated pilot:** the B1 exception never applies elevated, and `ELIGIBLE` was unreachable even elevated (F-B,
  V4-3).
* **Simulated recency in the pilot:** forbidden (section 3). It is what V2 does, declared, and it is why V2 does not
  replace V5.
* **Opening the gate by a variable, an option or a file:** no such path exists or is added. The only change is one line
  in a checkout inside the VM.
* **A pilot package with the gate open (D)** and **the CI harness as a pilot (B):** section 4.

## Consequences (including new limits)

* Nothing changes in the product, the package, the CI or any gate. This record is documentation only.
* The pilot needs the maintainer's machine change (Hyper-V), an image and a licence, or a cloud account (V5-D1, V5-D2).
* If V5-D7 (a) is chosen, a `V5-TOOLS` round comes before the pilot.
* The operator script (`ROTEIRO-V4-V5-OPERADOR.md`, outside the repository) needs a VM version of its section 3 built
  from section 6 here once the decisions are taken. Two of its points change: no output redirection for the deleting
  run (fact 1), and no TUI deletion in any mechanism (fact 2).
* A copy with the gate open exists, for a few days, on the VM's disk inside the operator's machine. That is the price
  of mechanism A, bounded by the disposal.

## Verification

* **This record:** the diff is documentation only (this file, one index row, the ROADMAP's V5 line and one CHANGELOG
  line). The seven gates stay single assignments to `$false` in `src/`, checked by the suite in CI.
* **The pilot, once run:** section 7's criteria, recorded in `docs/release/V5-PILOT.md`, from a summary that passed the
  privacy scanner.

## Sources

Public documentation read for this record (2026-11-17):

* Windows Sandbox: https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/
* Windows Sandbox configuration (defaults, `.wsb`, logon command and its account):
  https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file
* Windows Sandbox architecture (the host's own Windows image):
  https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-architecture
* Install Hyper-V: https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/install-hyper-v
* Hyper-V system requirements: https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/system-requirements-for-hyper-v-on-windows
* Hyper-V checkpoints: https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/checkpoints
* VMConnect local resources and enhanced session mode:
  https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/use-local-resources-virtual-machine-connection
* Hyper-V integration services (time synchronization, PowerShell Direct):
  https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/integration-services
* Windows 11 Enterprise evaluation: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise
* Windows client images in Azure (dev/test entitlement; it links Microsoft's page on multitenant hosting rights for
  production): https://learn.microsoft.com/en-us/azure/virtual-machines/windows/client-images
* GitHub Actions limits (job execution time): https://docs.github.com/en/actions/reference/limits
* GitHub-hosted runners (a new VM per job; Windows runs as administrator with UAC disabled):
  https://docs.github.com/en/actions/reference/runners/github-hosted-runners
* Claude Code environment variables (`CLAUDE_CODE_TMPDIR`): https://code.claude.com/docs/en/env-vars
