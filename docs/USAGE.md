# Usage

## Language

The interface is available in **English (en-US)** and **Portuguese (pt-BR)**. Order of precedence:
`-Lang en-US|pt-BR` > environment variable `ATM_LANG` > Windows UI language. `pt-*` selects pt-BR; any other or
unknown value selects English. Missing translations fall back to English. Reason, flag, class and status
**codes** (e.g. `COBERTURA_DE_PROCESSOS_INCOMPLETA`, `ACTIVE_EVIDENCE`, `AUDITADO`) are stable identifiers and are
the same in every language; JSON exports always use them.

```powershell
agent-temp audit -Lang en-US
$env:ATM_LANG = "pt-BR"; agent-temp
```

## Interactive dashboard

```powershell
agent-temp            # opens the TUI (requires an interactive console)
agent-temp -Ascii     # ASCII frames for fonts/terminals without box-drawing glyphs
```

Keys: arrows / PgUp / PgDn / Home / End to move, **Enter** to open, **Esc** or Backspace to go back,
**R** to re-audit, **Q** to quit. Menu shortcuts: `1` Dashboard, `2` Users/SIDs, `3` Projects, `4` Roots,
`5` ACTIVE_EVIDENCE, `6` RECENT, `7` LIVENESS_UNKNOWN, `8` Blocked paths, `9` Errors & coverage,
`P` Preview, `D` Diagnostics V0.2, `L` Assisted cleanup, `H` Help.

**Diagnostics V0.2 (`D`, read-only).** Entering the area runs `diagnose` once (it can take a while: the V0.1
inventory cannot be interrupted); navigating, paging and opening details reuse that result and run nothing.
**U** collects a new observation on request. The area shows a summary, the coverage of every collector (with
`NOT_OBSERVABLE`, `DENIED`, `TIMEOUT` and their reasons), agent processes and sessions, services, the virtualization
platform and VMs, repositories and worktrees, temporary partitions, the graph nodes and their edges (`[D]` direct,
`[A]` reference to a parent path, `[?]` ambiguous), and why items are `UNKNOWN`. It shows only what the
`diagnose` JSON export contains (pseudonyms and codes: no path, account, machine name or command line). A node
marked "reference" has no finding of its own. If a refresh fails, the previous result stays, marked as outdated,
with the exception type only. The results do not authorize deleting files or terminating processes.

The TUI uses console colors (no ANSI escape sequences), so it works on Windows PowerShell 5.1 conhost,
PowerShell 7 and Windows Terminal. Set `ATM_ASCII=1` (or `-Ascii`) to force ASCII: frames and text are
transliterated (accents removed) and anything outside printable ASCII is shown as `?`.

## Audit (read-only)

```powershell
agent-temp audit
agent-temp audit -User alice                  # one user (name or SID)
agent-temp audit -Project "My Project"         # one project
agent-temp audit -Root 0b1c...-uuid            # one root
agent-temp audit -Path "C:\Users\alice\AppData\Local\Temp\claude\C--src-app\<uuid>"   # children breakdown
agent-temp audit -ExportJson D:\reports\audit.json   # optional, explicit, outside audited dirs
```

Sections: general summary (exclusive partitions), per user/SID, per project, per direct root,
LIVENESS_UNKNOWN older than 72 h, errors/ambiguities/coverage, final summary.

**Export safety (V0.2 FINAL-A).** The audit export keeps its rules (a new file outside the audited directories, no
reparse point in its folders) and is now created with the folder and its ancestors pinned, relative to the folder, with
access limited to its owner, SYSTEM and Administrators; a folder swapped during the export, or a `subst` drive letter, is
refused with the same message, now preceded by a refusal code. A refusal after the file was created (code
`EXPORT_CREATE_CREATED_...`) says that an empty or partial file may remain at the destination; nothing is deleted
automatically. Also refused now (accepted by V0.1): a file directly in
a volume root (`C:\x.json`), a folder path of 240 characters or more, a network or non-fixed drive, and a folder that
cannot be opened (reported as a refusal, not as an error). A file exported from an elevated window may not be readable
from a non-elevated one (its owner is then usually Administrators).

## Preview (no deletion)

```powershell
agent-temp preview
```

Paths are grouped into **A. blocked**, **B. needs investigation**, **C. technically eligible** (for human
review). Eligible paths are printed as allowlist lines `path|fingerprint`.

### Runtime evidence in preview and plan (V0.3 B2-1, unreleased)

`preview`, the plan of `clean` and the TUI preview also run the read-only V0.2 collectors once (the same ones as
`diagnose`, over the inventory just taken, without CPU sampling) and add reasons to refuse. They never remove one and
never make a path eligible. With the deletion gate closed they are shown too.

* **Blocked:** `RUNTIME_USE_OBSERVED` (a verified process is directly related to the root; its key, the service or VM it
  hosts when there is one, and the agent processes above it are shown) and `RUNTIME_SESSION_LIVE` (the agent session
  whose id is the root's own name is running, with an exact process identity).
* **Needs investigation:** `RUNTIME_ASSOCIATION_AMBIGUOUS` (the process or holder could not be verified),
  `RUNTIME_ANCESTOR_REFERENCE` (a process names a parent folder), `RUNTIME_SESSION_UNVERIFIED`, `RUNTIME_KEY_COLLISION`,
  `RUNTIME_OBSERVATION_INCOMPLETE` (a collector this root depends on failed, or a reference could not be read),
  `RUNTIME_TIMEOUT` (not finished before the deadline) and `RUNTIME_NOT_COLLECTED`.
* Each reason says which collector and evidence it comes from, the relation to the root, whether it is direct, derived,
  ambiguous or a coverage gap, when it was observed and the coverage status. The reasons found before stay first.
* Printed once by `preview` and by the plan (the TUI preview lists only each root's reasons; a clean started from the TUI
  prints the plan with them), not per root: what was not observed for any root (the open-file and worktree collectors, closed in every
  copy, and process working directories, deferred), what was observed with no relation to any root (services and
  virtual machines: they only appear inside a reason when the process that hosts them is itself related to the root),
  and what was incomplete for the whole run.
* No runtime reason for a root is **not** evidence that it is unused.
* Before each deletion the root's revalidation runs the collectors again; the plan's evidence is never reused.
* Time: the collectors run under a deadline of 60 s, checked between collectors; it does not interrupt one that already
  started. What is actually bounded: each CIM query by its own timeout (processes 30 s, services 30 s, each of the up to
  five virtualization queries 30 s) and the dependency correlation by 30 s (checked every 256 steps). The file-system
  inventory before them has no bound. A run is therefore normally short, but nothing guarantees a total maximum, and it is
  repeated for each root at revalidation.
* Output: the preview and plan rows keep their fields; a gate also has `RuntimeReasons` (the same reasons with their
  provenance) and a preview row has `Runtime` (the run). The diagnose command and its JSON schema do not change.

## Diagnose (read-only, V0.2)

`diagnose` is part of version 0.2.0 (published only as the GitHub Release `v0.2.0`). It is read-only and reports the
coverage of every observation; its output may change in later versions.

```powershell
agent-temp diagnose
agent-temp diagnose -Lang en-US -NoProgress
agent-temp diagnose -DeadlineSeconds 60                     # global deadline (default 300 s), see below
agent-temp diagnose -PseudonymKeyFile D:\private\atm-pseudonym.key   # comparable pseudonyms between runs
```

Options of `diagnose`: `-DeadlineSeconds <seconds>`, `-PseudonymKeyFile <file>`, `-NoProgress`, `-Lang en-US|pt-BR`;
`-ExportJson <new file>` exists but is refused in every copy (see *Export*). There is no option to give repository paths, to open a security gate or to request
elevation. In the TUI, the same diagnostics are under **D** (see *Interactive dashboard*).

### What it adds to V0.1

V0.1 already audits every profile's temporary directories, classifies them conservatively and shows a cleanup plan
without deleting anything. `diagnose` adds, read-only:

* the identity of the process (user, elevated administrator, token elevation type, integrity level, session);
* the Windows profile discovery and its gaps (`profile-discovery`);
* the agent runtime: agent processes and sessions found through evidence (provider matchers, session registries,
  path references of the audit, verified parent links), and their resource totals;
* Windows services that providers declare (for example `CoworkVMService` for Claude Desktop), the virtualization
  platform and its virtual machines;
* a dependency graph (`graph`) that correlates that evidence, and from it the state of each temporary partition.

### What it does not observe (yet)

* Process working directories: deferred (`process-cwd` is `NOT_OBSERVABLE`).
* Open files: the collector exists but is behind a closed security gate in every copy (`handles` is
  `NOT_OBSERVABLE`, `HANDLE_SECURITY_GATE_CLOSED`).
* Git worktrees: behind a closed security gate in every copy (`worktree-discovery` is `NOT_OBSERVABLE`,
  `WORKTREE_DIAGNOSTICS_GATE_CLOSED`); no Git command is run.
* Remote Cowork sessions, and the Cowork VM itself (an HCS compute system, not a Hyper-V Manager VM).

The three gates (real deletion, open-file diagnostics, worktree diagnostics) are closed in every copy, and no option,
environment variable or configuration file opens them.

### How to read the results

* **Coverage first.** Each collector reports `COMPLETE`, `PARTIAL`, `DENIED`, `TIMEOUT`, `NOT_PRESENT`,
  `NOT_OBSERVABLE`, `UNAVAILABLE` or `FAILED`, with reason codes. Only `COMPLETE` and `NOT_PRESENT` are conclusive.
  `PARTIAL` means some items were seen and some were not; `NOT_OBSERVABLE` means the source was not read at all (a
  gate, a deferred collector, a missing prerequisite). Neither is ever "nothing there": **the absence of evidence does
  not show that something is unused**, because the evidence that would show use may simply not have been observed.
* **Temporary partitions.** `IN_USE`: a verified process references it directly (or holds a file in it, or works in
  it). `UNKNOWN`: anything else (a reference to a parent folder, ambiguous evidence, incomplete coverage, a limit of the
  graph, a key collision); `UNKNOWN` never means free. `NO_DEPENDENCY_OBSERVED` needs every relevant collector to be
  conclusive, so it does not appear while open files and working directories are not observable. The V0.1 class and
  flags of the partition stay next to it, unchanged.
* **Providers are not dependencies.** A finding attributed to a provider says which agent the evidence points to; it
  does not prove that a temporary partition depends on that agent. When the evidence fits two providers (a `claude.exe`
  can belong to Claude Code or to Claude Desktop), the attribution is ambiguous and no provider is chosen.
* **Claude Code, Claude Desktop and Cowork.** Claude Code is the CLI agent (temporary directories and runtime).
  Claude Desktop is the desktop app (runtime only: its packaged processes and its service). Cowork is a Claude Desktop
  feature that runs in a VM managed by the app; the tool sees only the local `CoworkVMService` service, which is
  identified by a **publicly reported** name (provisional, not documented by Anthropic): a running service with a
  verified process is evidence of the local Cowork service, never of a running VM.
* **Privileges.** `diagnose` never asks for elevation. Without it, other accounts' processes and some services may be
  unreadable; that is reported as `PARTIAL` or `DENIED` with `elevationWouldHelp` (`YES`, `NO` or `UNKNOWN`: unknown
  means it is not known whether elevation would help).
* **Nothing is authorized.** No state, coverage or graph result authorizes deleting files, terminating processes,
  stopping services or shutting down VMs.

**The deadline is not a maximum duration.** Collectors that have not started when it passes are skipped and reported
as `TIMEOUT`. The V0.1 temporary-directory inventory cannot be interrupted once it has started: it runs to the end and
is reported as `PARTIAL` (`DEADLINE_EXCEEDED`) if it finishes after the deadline. `-DeadlineSeconds 0` reads only the
process identity.

### Export

**Disabled in every copy (security gate closed).** `agent-temp diagnose -ExportJson <file>` is refused at once with
`EXPORT_SECURITY_GATE_CLOSED` and exit code `10`: nothing is collected, no destination is checked and no file is
created. Reason: the export checks the destination folders by name and then creates the file by name, so a folder
replaced by a junction in between could redirect the new file (an ancestor race, not resolved), and the document holds
the machine name, the account and its SID. Creating a *new* file does not prevent that redirection. The export is
implemented and tested on disposable fixtures only; enabling it needs a demonstrated mitigation and a maintainer
decision. This concerns the export only: `diagnose` itself and the TUI area (D) are read-only and unaffected. Without
`-ExportJson`, no file is written.

The rules below are those the export applies when its gate is open (tests only). The destination must be a **new** file (an existing file is never overwritten), given as an absolute local
path (no network, device or relative path, no wildcard, stream or `..`), whose folders contain no junction or other
reparse point, outside every audited temporary directory, and not inside a Git repository or worktree (no folder above
it holds a `.git` entry, and no folder above it is a bare repository; Git itself is not run), and not on a drive letter
made with `subst`. The export is also refused when the inventory did not run, because the audited directories are then
unknown. A refusal prints a code (`EXPORT_INVENTORY_NOT_RUN`, `EXPORT_DESTINATION_NOT_ALLOWED`,
`EXPORT_SUBSTITUTED_DRIVE`, `EXPORT_INSIDE_REPOSITORY`, `EXPORT_ANCESTOR_UNREADABLE`), creates no file and exits with
`10`; a write failure prints the exception type only and exits with `10` (a file it already created may then be
incomplete; it is not deleted). A folder replaced by a junction after the check redirects the new file: this ancestor
race is NOT RESOLVED, which is why the gate is closed (SECURITY-MODEL, *Diagnose export gate*).

The export contains the machine name, the user name and SID and the token elevation state; temporary partitions and
agent sessions appear only as keyed pseudonyms, and no path, command line, token or session id is exported. Review it
before sharing.

**Pseudonyms (ADR-0010).** Temporary partitions and agent sessions appear only as keyed pseudonyms
(`<provider>/p-<32 hex>`, `<provider>/s-<32 hex>`): no path and no session identifier is shown or exported. By default
the key exists for one run only, so two runs cannot be compared item by item, and partition findings, which are
listed in pseudonym order, come in another order each run. To correlate runs, keep a key file of
32 to 4096 bytes from a random generator (not a passphrase: the exported `keyId` lets anyone test guesses of a weak
key offline) that only you, SYSTEM and Administrators can read or change, and pass it every time with
`-PseudonymKeyFile`.

The file is only read, never created or changed; it is refused (exit code `2`, nothing run, only a code is shown) when
the path is not a drive-absolute path on a fixed drive, a folder in the path or the file is a reparse point, it is not a
regular file, its size is out of range, its owner is not you, SYSTEM or Administrators, or any other account may read
or change it. While `diagnose` runs, the progress line shows no path. With the same key, the pseudonyms of two runs are
the same (and an export, while disabled, would carry the same `keyId`). Anyone holding the key file can compute the pseudonyms from known identifiers: protect it like a password.
Process keys, counts and coverage are not pseudonymized.

Exit codes of `diagnose`: `0` when it ran (partial coverage is a result, not an error), `2` key file refused, `10`
export refused (`EXPORT_SECURITY_GATE_CLOSED` in every copy) or not written, or an unexpected failure (reported by its
exception type only; nothing is deleted).

## Clean (assisted, fail-closed)

1. Run `agent-temp preview`, copy the eligible lines you **reviewed** into a text file (UTF-8), one per line.
   Lines starting with `#` are comments.
2. Run:

```powershell
agent-temp clean -AllowListFile C:\review\allowlist.txt
agent-temp clean -Path "C:\Users\alice\AppData\Local\Temp\claude\C--src-app\<uuid>"
agent-temp clean -AllowListFile list.txt -LogFile D:\logs\clean.jsonl
```

3. Read the plan. It ends with **NADA FOI APAGADO AINDA**. Type the exact phrase shown
   (e.g. `APAGAR 2 CAMINHOS`) to proceed; anything else aborts.
4. Each path is revalidated immediately before deletion; paths that changed are preserved. A read-only audit
   runs afterwards.

**V0.1 and V0.2:** `clean` runs every gate and prints the exact plan, then stops with
`EXCLUSAO_REAL_DESABILITADA_V0_1`; no confirmation is requested and nothing is deleted. Steps 3-4 above describe
the behaviour of a future release in which deletion is explicitly authorized.

Administrator-only switch: `-IncludeOtherUsers`. Incomplete process coverage cannot be overridden.

### Discard authorization (`authorize`; V0.3 AUT-1, unreleased)

```powershell
agent-temp authorize -Path "C:\Users\alice\AppData\Local\Temp\claude\<slug>\<uuid>" -RecordFile D:\records\auth-1.jsonl
```

Records **your decision** about **one** root and the plan shown; it deletes nothing, makes nothing eligible and is not a
credential for a future deletion (nothing in the product reads it; a future run would need a current confirmation and
its own revalidation).

1. Interactive console only (no redirected input or output; exit code `6` otherwise). This is required, but it does not
   prove that a person answered. The record (`interaction`) keeps the caller and its console requirement as the caller
   reported them (`callerFieldsVerified: false`) and the engine's own console observation in that call; a caller that
   requires a console when the engine observes none is refused before any question (`AUTH_CONSOLE_NOT_OBSERVED`).
2. The root is presented: exact path, provider, profile SID, session id (the root name), counts, size, newest write and
   its age (information only), fingerprint, evidence, the **technical result** of every gate (B1, RECENT and the
   runtime evidence included), the run notices and the limits of the record.
3. The association root -> session is the provider's naming convention (root name = session id), corroborated by a
   readable transcript of the same id. Without one, or with the same id under another project scope, the root cannot be
   authorized (`AUTH_ASSOCIATION_UNKNOWN`, `_AMBIGUOUS`). The task is **your declaration**, never read from a record.
4. Three separate confirmations, each with an exact phrase:
   * the task has finished (`TASK COMPLETED`);
   * the content decision, one of two declarations: what you need from the root is preserved outside it
     (`RESULTS PRESERVED`, recorded as `OPERATOR_DECLARED`), or nothing in it needs to be kept (`NOTHING NEEDED`,
     recorded as `NOTHING_NEEDED_DISCARD_ACCEPTED`). The product verifies no copy, and neither says that the root is
     unused. `TOOL_VERIFIED` is reserved for a verification by the product itself; no such verifier exists, so it is
     never recorded, whatever is typed or whatever external report or manifest exists;
   * you authorize discarding the content presented (`DISCARD <plan>`, this plan only).

   Then an optional short description (at most 200 characters, stored as text). Any other answer or an empty one
   records nothing.
5. The root is presented again and compared: path, kind, SID, provider, session id, counts, bytes, newest write,
   creation, fingerprint, class, flags, association, session registry, technical result (category and runtime codes)
   and the **justification** in a stable semantic form: the gate reasons as given (principal, path, status), without the
   counts that vary between collections (processes not inspectable, items found by the lock probe); each runtime refusal
   by code, decision, collector, evidence, relation, nature, coverage and **sources**, the process keys
   (`pid@creationTicksUtc`) the evidence comes from, so the same code from another process is a divergence (never its
   time, nor its localized detail text); the process coverage state. Not compared: a refusal whose collector gives no
   process key (coverage gaps, an unverified session) beyond its other fields, and the V0.1 evidence lines of the
   inventory (localized text; the references they show are the ones the runtime refusals carry by process key when
   the runtime collection observes them). An equivalent new collection does not refuse;
   new evidence or a changed justification refuses (`AUTH_PLAN_CHANGED`, `TECHNICAL_REASONS`); present it again. The
   comparison uses statistics: a write that keeps them all (same size and modification time) is not detected, equal
   statistics do not prove equal content, and read-only use is not seen.
6. The record is a new file (never an existing one; an unsafe folder is refused and not changed) holding one JSON line,
   schema `atm.discard-authorization/2`: identifiers (authorization, plan), `processIdentity` (the account the process
   ran as, `identifiesRespondent: false`), `interaction`, root, association, what was presented, the technical result
   with its semantic signature and `processCoverage` (B1 apart: `observed` is the process coverage of that inventory,
   `COMPLETE`, `INCOMPLETE` or `FAILED`; `gate` is what the B1 gate did in that evaluation: `BLOCKED`, `PASSED`, or
   `NOT_EVALUATED` when an earlier gate, such as `ACTIVE_EVIDENCE` or `RECENT`, refused first, which is never an
   approval of B1), `declarations` (received from you: `status: ALL_PHRASES_TYPED`, the content decision),
   `preservation` (`basis`, `verifiedByTool: false`, `evidence: null`), the revalidation and the limits. No conversation
   or file content. Processes running as you can change it afterwards: it is not tamper-proof.
7. **Recording succeeded only when the command says so** (exit code `0`): the line was written and flushed and the file
   closed without error. After a failure once the file exists, the command says that the file is kept as it is and that
   recording did not finish; the file is never reopened or deleted, and it may hold nothing, part of a line or **a
   complete line**. Nothing in the record says whether recording finished, and the format provides no atomicity or
   authenticity: neither a line nor the existence of the file is proof of a recorded authorization, and no future
   consumer may rely on either.

Synthetic example (paths, SIDs and ids shortened):

```json
{"schema":"atm.discard-authorization/2","authorizationId":"6f1c…","planId":"5dc6f2aa-…","tool":"…",
 "presentedUtc":"…","revalidatedUtc":"…","composedUtc":"…",
 "processIdentity":{"name":"PC\\alice","sid":"S-1-5-21-…","elevated":false,"identifiesRespondent":false},
 "interaction":{"caller":"CLI","consoleRequiredByCaller":true,"callerFieldsVerified":false,"interactiveConsoleObserved":true,"observedBy":"ENGINE_CONSOLE_CHECK"},
 "root":{"path":"C:\\Users\\alice\\AppData\\Local\\Temp\\claude\\C--work-proj\\0d0b…","provider":"claude-code","profileSid":"S-1-5-21-…","sessionId":"0d0b…","kind":"SessionRoot"},
 "association":{"kind":"NAME_CONVENTION_CORROBORATED","transcriptLastWriteUtc":"…","basis":"ROOT_NAME_EQUALS_SESSION_ID"},
 "presented":{"files":2,"dirs":1,"bytes":2148,"fingerprint":"B34D2D015552A3BE","ageHours":120,"class":"ORPHAN_SUSPECTED","flags":[],"sessionRegistry":null,…},
 "technical":{"category":"BLOCKED","runtimeCodes":[],"processCoverage":{"observed":"INCOMPLETE","gate":"BLOCKED"},"recentBlock":false,
   "reasonSignature":["B1_GATE:BLOCKED","COVERAGE:INCOMPLETE","GATE:COBERTURA_DE_PROCESSOS_INCOMPLETA"],"reasons":["COBERTURA_DE_PROCESSOS_INCOMPLETA (<n> …)"]},
 "declarations":{"declaredBy":"OPERATOR","status":"ALL_PHRASES_TYPED","taskCompleted":true,"contentDecision":"NOTHING_NEEDED","discardAuthorized":true,"taskDescription":null},
 "preservation":{"basis":"NOTHING_NEEDED_DISCARD_ACCEPTED","verifiedByTool":false,"evidence":null},
 "revalidation":{"planRevalidated":true,"compared":"STATISTICS_FINGERPRINT_AND_SEMANTIC_REASONS"},
 "limitations":["ASSOCIATION_BY_NAME_CONVENTION","TASK_DECLARED_BY_OPERATOR","PRESERVATION_NOT_VERIFIED_BY_TOOL","STATISTICS_NOT_CONTENT","READ_ONLY_USE_NOT_OBSERVED","NO_EVIDENCE_IS_NOT_NON_USE","RECORD_ALTERABLE_BY_SAME_IDENTITY","RECORD_LINE_MAY_REMAIN_AFTER_FAILURE","NOT_A_DELETION_CREDENTIAL","PROCESS_IDENTITY_IS_NOT_THE_RESPONDENT","CALLER_AND_REQUIREMENT_REPORTED_BY_CALLER","INTERACTIVE_CONSOLE_IS_NOT_PROOF_OF_PRESENCE"]}
```

A root can be **authorized and still technically blocked**: the result says so (`Technical result: BLOCKED`) and is never
shown as eligible. Today, on a real machine, process coverage (B1) blocks every root, and a root written less than 72 h
ago is RECENT; no exception to either has been approved (see SECURITY-MODEL, "Discard authorization").

Exit codes of `authorize`: `0` recorded (written, flushed and closed), `2` missing `-Path` or `-RecordFile`, `3` not
recorded (refused, declined, cancelled, plan changed, or a recording failure; a file kept after a failure is said so and
is not a recorded authorization), `6` no interactive console.

### Clean log (`-LogFile`; V0.3 T1, unreleased)

With the deletion gate closed (every published copy, 0.2.0 included) `-LogFile` keeps the plan-only behaviour: the
destination is only checked against the audited directories, and no log is required, created or opened.

In a future release in which real deletion is explicitly enabled:

* `-LogFile` is **required** and names a **new** file. An existing name (file, folder or link) is refused; nothing is
  ever appended to an existing file; no destination is chosen automatically. The folder must be owned by you, SYSTEM,
  Administrators or TrustedInstaller, and no other account may add or delete entries in it or change its permissions or
  owner; otherwise the run is refused and the folder's ACL is not changed. The TUI cleaning screen asks for this file
  in that case (an empty answer: the run is refused with `LOG_REQUIRED`); with the gate closed it asks nothing new.
* The log is created and its first records are written **before** the confirmation is requested: a run that cannot be
  logged never asks for confirmation.
* Format: JSON Lines, UTF-8 without BOM, LF, at most 64 KiB per record. Every record has `schema` (`atm.cleanlog/1`),
  `type`, `runId`, `recSeq` and `utc`. Types: `run-start`, `plan` (one per root, with its `opId`), `confirmation`
  (accepted or not), `skip` (preserved at the final revalidation), `intent`, `result`, `run-end`. One record per root:
  the log never lists the files of a tree.
* Before a root is deleted its `intent` is written and flushed; if that fails, the root is never started. After the
  deleter returns, `result` records the outcome: `COMPLETE` (deleted, absence confirmed), `REFUSED` (nothing deleted),
  `PARTIAL` (some entries deleted), `EXCEPTION` (state unknown) or `VERIFICATION_FAILED` (absence not confirmed).
* Anything but `COMPLETE`, and any log failure, stops the run before the next root (exit code `3`; the console shows
  the reason and, for a log failure, the operation it belongs to). Nothing is retried or continued automatically.
* An `intent` without a `result` (power loss, the process ended during the deletion) means the outcome of that root is
  **unknown**: none, part or all of it may have been deleted. Check the path itself.
* Nothing can be undone from the log; there is no rollback. Each record is written through and flushed
  (`FlushFileBuffers`) before the next step, but whether it survives a power loss depends on the disk and its cache: the
  last record can be missing or incomplete.
* A log file created before a refusal or a failure is kept as it is; it is never deleted.

### One clean at a time (V0.3 B8, unreleased)

With the deletion gate closed (every published copy) nothing changes: no lock is taken.

In a future release in which real deletion is enabled, one clean run at a time per machine (every user, session and
elevation level) holds the named kernel mutex `Global\AgentTempManager.Clean`:

* It is taken without waiting, before the first inventory, and held through the plan, the confirmation and the
  deletions; it is released last, after the log is closed, on every path (refusal, failure, exception).
* When it is not available the run starts nothing (no inventory, plan or log) and ends with exit code `3`
  (`CLEAN_LOCK_BUSY`, `_DENIED`, `_TYPE_MISMATCH`, `_POLICY_*`, `_ERROR_*`). The message never claims that another clean
  is running: another process may hold the name or block it (see the limits below). Wait and try again; never end
  processes to free it.
* `CLEAN_LOCK_ABANDONED`: the previous holder ended without releasing it, so a previous run may have been interrupted
  and its outcome must be checked (in its log, if it had one: an `intent` without a `result` is an unknown outcome).
  This run stops before any inventory and releases the lock; nothing records the event and nothing is recovered. A new
  attempt starts from scratch. This signal is only opportunistic: Windows destroys the mutex when its last handle is
  closed, so when the interrupted run held the only handle (the usual case, since refused runs close theirs at once) the
  next run creates a new mutex and sees nothing. Never rely on it to detect an interruption: the persistent evidence is
  the T1 log (an `intent` without a `result`).
* `CLEAN_LOCK_NESTED`: a clean run is already in progress in the same process.
* Limits: it excludes only cooperating clean runs; it does not stop other processes (agents, the user, other tools)
  from changing the trees, which stays with the revalidation and the deleter. Any local account can create that name
  first or keep it, which refuses every clean run (denial of service; never two runs at once). The automated tests run
  two processes of the same identity; other users, sessions and elevation levels are not tested.

## Exit codes

`0` ok (for `diagnose`, partial coverage included) · `1` unknown command · `2` invalid clean invocation, or a refused
`-PseudonymKeyFile`, or `authorize` without `-Path`/`-RecordFile` · `3` clean aborted (nothing deleted) or, only with
deletion enabled (not in any published copy), stopped before completing (Clean log, above); `authorize`: nothing recorded ·
`4` no manifest (source checkout, `verify` only) · `5` integrity mismatch (a listed file missing, altered or
unreadable, a missing or unreadable `providers` directory, an unlisted library or provider, an unreadable or
invalid manifest, or an installed copy without one; nothing is loaded) · `6` TUI or `authorize` needs an interactive console · `10` unexpected error,
or a `diagnose` export refused or not written (nothing deleted because of it).

## Project names

Project recognition is informational and never affects eligibility. Order: the owner's home profile
(`Perfil (home)`), optional site rules, the agent's own session evidence (a recorded working directory whose
scope matches; conflicting evidence is ignored), otherwise **`Projeto não identificado`** (reports keep each
unidentified scope separate and show its directory name). No configuration is required.

### Optional site-specific rules

Project recognition is informational. Put local rules in `config\projects.local.json`
(see `projects.local.example.json`) or pass `-ProjectsFile` to the installer. This file is never versioned.
