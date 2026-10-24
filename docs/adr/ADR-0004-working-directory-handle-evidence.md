# ADR-0004: Working-directory and open-handle evidence

Status: ACCEPTED IN PRINCIPLE (maintainer gate 2026-10-20, after PR #19): D-1 and D-2 only in P1-C, after an isolated prototype proves safety and compatibility; not implemented before that
Date: 2026-10-20
Phase: P1 (after the maintainer decides D-1 and D-2)

## Context

The roadmap asks for processes' working directories and open-handle evidence "where Windows exposes it". Today:

* `docs/SECURITY-MODEL.md` (*Known limits*) states that process working directories and environment variables are
  **not observable without debugging privileges (not used)**.
* The only in-use evidence V0.1 has is the clean engine's **handle probe** (`AtmLockProbe`): it opens every file and
  directory of a candidate with `DELETE` access and share mode 0. It detects data handles and a directory used as a
  working directory, but it briefly makes the agent's own opens fail (documented "probe interference"), and it only
  runs on eligible candidates.

Windows offers three ways to learn more, with very different risks:

| Option | What it sees | Privilege | Risk |
|---|---|---|---|
| A. Read `RTL_USER_PROCESS_PARAMETERS.CurrentDirectory` from the process PEB (`NtQueryInformationProcess` + `ReadProcessMemory`) | Working directory of processes the caller may open with `PROCESS_QUERY_LIMITED_INFORMATION \| PROCESS_VM_READ` (normally the caller's own non-elevated processes) | None beyond the default | Undocumented structure layout; WOW64/ARM64 variants; the same structure also holds the command line and the environment block, which must never be read |
| B. Restart Manager (`RmStartSession`, `RmRegisterResources`, `RmGetList`, `RmEndSession`) | Processes holding a given **file** open | None beyond the default; coverage of other accounts' processes to be measured | Documented API, read-only as long as `RmShutdown`/`RmRestart` are never called; files only (not directories, not working directories); cost grows with the number of files registered |
| C. System handle enumeration (`NtQuerySystemInformation` + `DuplicateHandle` + `NtQueryObject`) | Every handle, including directories | `PROCESS_DUP_HANDLE` on each target | Undocumented; `NtQueryObject` can block forever on some pipe handles (needs a watchdog thread); duplicating a handle keeps the target's file object alive while we hold it |

## Decision

1. **`diagnose` never uses the V0.1 handle probe** (no `DELETE`/share-mode-0 opens), so diagnostics cannot interfere
   with an agent. The probe stays exclusive to the clean engine.
2. **D-1 (proposed: accept Option A, restricted):**
   * read **only** the `CurrentDirectory.DosPath` string of the process parameters, with a length cap of 32,767
     characters; the `CommandLine` and `Environment` fields are never read, not even their lengths;
   * open each process with `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ` only; no privilege is enabled;
     access denied gives coverage `DENIED` for that process (`ElevationWouldHelp` = `YES` for other accounts,
     `NO` for protected processes);
   * supported: a reader and target of the same architecture, and 32-bit targets from a 64-bit reader (WOW64,
     `ProcessWow64Information`); anything else (for example x64-emulated processes on ARM64 if the layout cannot be
     proven) is `NOT_OBSERVABLE` for that process;
   * the value is used in memory to match against indexed paths (temporary partitions, worktrees, repositories);
     it is **reported only when it falls inside one of those paths**, and then as that path; otherwise it is
     discarded (not exported, not printed);
   * the read is a point-in-time observation; a process may change directory right after.
   If D-1 is rejected, working directories stay `NOT_OBSERVABLE` (current documented limit) and only options B/C
   evidence applies.
3. **D-2 (proposed: accept Option B, bounded):** Restart Manager is used for file-level evidence on the paths a
   finding needs (for example a worktree's index and in-progress operation files, or a bounded sample of files of a
   temporary partition), at most a fixed number of files per node and per run; `RmShutdown` and `RmRestart` are never
   referenced (static test). A path with more files than the cap is `PARTIAL`.
4. **Option C is rejected for V0.2.** It may be reconsidered in a later ADR with a watchdog design and tests.
5. `docs/SECURITY-MODEL.md` (*Known limits* and *Privacy*) is updated **in the same pull request** that implements
   D-1 or D-2, so the documentation never contradicts the code.

## Rejected alternatives

* *Using the V0.1 probe in diagnose:* interferes with agents and only answers for one tree at a time.
* *Enabling `SeDebugPrivilege` when elevated:* violates PRIV-9 and exposes far more of other processes.
* *Reading the full process parameters block and filtering afterwards:* the command line and environment would be in
  our memory; the restriction must be in what is read, not in what is printed.

## Consequences

* With D-1 accepted, a standard user sees working directories of their own non-elevated processes only; the
  coverage record says so. Elevated sessions see more but protected processes stay `DENIED`.
* Restart Manager results are per file; "a directory is in use" can only be inferred from files inside it or from
  working directories (D-1).

## Verification

* Native tests in the sandbox: a child process started with its working directory inside a sandbox worktree is
  found (D-1); the same with a 32-bit child where a 32-bit PowerShell is available, otherwise `NAO_TESTADO`.
* A child holding a sandbox file open is listed by Restart Manager (D-2); a file not held is not.
* Static tests: `Native.cs` never references the `CommandLine` or `Environment` offsets of the process parameters,
  `RmShutdown`, `RmRestart`, `SeDebugPrivilege`; `Engine.Diagnose.ps1` never references `AtmLockProbe`.
* Privacy test: diagnose output for a process whose working directory is outside indexed paths contains no part of
  that directory.

## Amendment (P1-C, 2026-10-24)

The decisions above are kept as history; this records what P1-C did with them.

* **D-1: DEFERRED.** The PEB reading was not implemented. Cause, as observed: while the prototype's native code was
  being written in the P1-C session, the generation of code that reads another process's memory was stopped by the
  coding assistant's safety filter, twice; no D-1 code was produced, applied or tested, and nothing of it is in the
  repository. The maintainer decided (gate of 2026-10-24) not to integrate D-1 in V0.2 for now and not to compensate
  with more invasive methods. The diagnose reports the collector `process-cwd` as `NOT_OBSERVABLE`
  (`WORKING_DIRECTORY_DEFERRED`): a working directory that is not observed is never an absence of dependency.
  *Future alternative, documented only (not implemented, never full coverage):* cooperating agents could declare their
  own working directory through an authenticated interface bound to the process identity (PID and creation time),
  covering only the processes that take part.
* **D-2: implemented (bounded).** `AtmRestartManager` uses only `RmStartSession`, `RmRegisterResources`, `RmGetList`
  and `RmEndSession` (static test), ends the session in every case, and returns per holder only the PID and the start
  time (application and service names are not returned). The collector `handles` checks a sample of at most 16 files
  directly in each indexed node (temporary partitions; a worktree's index when discovery runs), at most 256 files and
  64 sessions per run, one session at a time, 64 holders per query, and stops at the deadline before the next node.
  Every path goes through the resolver (local fixed drive, no reparse point). A holder is matched with the process
  snapshot by PID and start time (`-CimPrecision`); otherwise it is `FILE_HELD_OPEN_UNVERIFIED`. Its coverage is never
  `COMPLETE`: a sample of files, and Restart Manager does not see directories or working directories. `RmGetList` has
  no cancellation: the time of one query is bounded only by the small number of files registered. The evidence does
  not change any state (dependencies are P4) and authorizes nothing.
  When more processes hold the files than can be listed (at most 4,096 after one retry with the size Restart
  Manager reports), the item is still marked held (`FILE_HELD_OPEN_UNVERIFIED`, `HOLDERS_CAPPED`). A sampled file
  name is taken as listed (names such as `~$doc.docx` are kept), its chain checked natively; at most four times the
  sample size of entries is looked at. `RmStartSession` writes a transient session key under
  `HKCU\Software\Microsoft\RestartManager`, removed by `RmEndSession`; no file is written.
