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
`P` Preview, `D` Diagnostics V0.2, `L` Assisted cleanup, `S` Recovery (view only, V0.4 R5), `H` Help.

**Recovery (`S`, view only, V0.4 R5).** Entering the area makes one fresh, read-only collection of the services the
providers declare, each time it is entered, and shows what `recover list` shows; `Enter` on a row shows what
`recover plan` shows for that service. See [Recover](#in-the-tui-and-the-gui-v04-r5).

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

**Base owner (F05-OWNER-ATTRIBUTION, 0.3.x).** A `<TEMP>\claude` base that was read is listed under a user only when
that user owns its folder, whatever the order in which profiles are read; `%WINDIR%\Temp` is always shared, as before.
In the TEMP folders table a user whose TEMP names a folder of another account shows `OWNER_NOT_PROFILE` (if the owner's
profile has the base too, the base is listed under the owner and its partitions are `SHARED_TEMP`); an owner that
cannot be read shows `OWNER_UNREADABLE`, and the base is listed under nobody. Either way the coverage says what was
not audited; nothing becomes cleanable.

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

### Runtime evidence in preview and plan (V0.3 B2-1; 0.3.0)

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

3. Read the plan. It ends with **NADA FOI APAGADO AINDA**. Then (V0.3 AUT-2, see below) answer, for each root of the
   executable set, the task and the content decision, and type the final phrase shown (e.g.
   `APAGAR 2 CAMINHOS 3F9A0C1B`) to proceed; anything else aborts.
4. Each path is revalidated immediately before deletion; a path that changed is preserved and stops the run (later
   paths are not attempted; earlier deletions are not undone). A read-only audit runs afterwards.

**V0.1 and V0.2:** `clean` runs every gate and prints the exact plan, then stops with
`EXCLUSAO_REAL_DESABILITADA_V0_1`; no confirmation is requested and nothing is deleted. Steps 3-4 above describe
the behaviour of a future release in which deletion is explicitly authorized.

### Plan-bound confirmation (V0.3 AUT-2; 0.3.0; past the deletion gate only, which is closed in every copy)

With the deletion gate closed (every distributed copy) nothing below happens: the plan is shown and the run stops, with
no question, no console requirement and no log. Past the gate, after the B8 lock, the gates, the plan and the log
(`-LogFile`, T1):

1. **Interactive console:** required by the CLI (exit code `6`) and observed again by the engine
   (`CONSOLE_NOT_OBSERVED`, before any log or question). Never proof that a person answers.
2. **Per root**, only for the roots of the executable set (blocked roots are listed in the plan and never asked about),
   with the root path shown: the task has finished (`TAREFA CONCLUIDA`), and the content decision with the AUT-1
   meanings: `RESULTADOS PRESERVADOS` (what you need is preserved outside the root; a declaration, not verified) or
   `NADA NECESSARIO` (nothing needs to be kept; discard explicitly accepted). `TOOL_VERIFIED` is never recorded.
3. **One final phrase for the exact set:** `APAGAR <N> CAMINHOS <first 8 characters of the plan id>`. The plan id is the
   full SHA-256 (64 hex characters) of the run id and, per root in plan order, its path, fingerprint, counts, bytes and
   newest write; the state and the log keep the full value and those data (run-start `planId`, one `plan` record per
   root). The phrase carries only its first 8 characters (upper case) so that it can be typed: it ties the answer to
   this run's plan, it is not the full hash, not a cryptographic signature and not proof of who typed it. A phrase of
   another run, another count or without the plan prefix is refused.
4. **Any refusal, cancellation or wrong phrase** (any root, any step) aborts the whole run before the first deletion
   (`DECLARATION_DECLINED`, `DECLARATION_CANCELLED`, `CONFIRMACAO_AUSENTE_OU_DIVERGENTE`); a `confirmation` record with
   `accepted: false`, the step and the root is written.
5. **Recorded before any operation:** one `declaration` record per root (path, fingerprint, `declaredBy: OPERATOR`,
   `contentDecision`, `preservation.basis`, `verifiedByTool: false`) and a `confirmation` record (`planId`, number of
   roots, interaction as reported by the caller and observed by the engine, limits), each written and flushed; a
   failure stops the run (`LOG_WRITE_FAILED`) before any `intent`.
6. **Plan check:** a fresh inventory, the same gates and fresh runtime evidence, root by root against the plan. If any
   root is missing, its statistics changed or it is no longer eligible, nothing is executed
   (`PLAN_CHANGED_BEFORE_EXECUTION`, record `plan-check`): a change during the questions is never absorbed by reducing,
   extending or updating the plan under the old confirmation. Statistics only: a write that keeps every statistic is
   not seen.
7. **Then, root by root:** the revalidation immediately before each root, the `intent` before the deleter, the `result`
   after it. The declarations never replace the revalidation. **A revalidation refusal stops the run** before that root
   and every later one: the `skip` record (path and reasons) is written and flushed and the run ends with
   `REVALIDATION_REFUSED` (`Aborted` when no root was deleted yet, `StoppedBy` after one). Any outcome other than a
   complete, verified deletion, or a log failure, also stops the run. **Nothing is all-or-nothing and nothing is undone:**
   a refusal before any operation deletes nothing; a stop after earlier operations leaves them done (no rollback). The
   result and the `run-end` record keep the completed operations, the root that stopped the run (`stoppedAtOpId`) and
   the roots not attempted (`notAttempted`: never revalidated nor processed).

Log order of a run: `run-start`, `plan`…, `declaration`…, `confirmation`, `plan-check`, then `intent`/`result` per root
until the end or the first stop (a `skip` ends the sequence), `run-end`. Synthetic example of two roots:

```json
{"type":"run-start","planned":2,"planId":"3f9a0c1b…",…}
{"type":"plan","opId":"<run>:1","path":"C:\\Users\\alice\\AppData\\Local\\Temp\\claude\\C--work\\0d0b…","fingerprint":"B34D2D015552A3BE","files":2,"dirs":1,"bytes":2148,…}
{"type":"plan","opId":"<run>:2","path":"C:\\Users\\alice\\AppData\\Local\\Temp\\claude\\C--work\\7c1e…","fingerprint":"91E0A44C2B7F0D13","files":2,"dirs":1,"bytes":2148,…}
{"type":"declaration","opId":"<run>:1","path":"…\\0d0b…","declaredBy":"OPERATOR","taskCompleted":true,"contentDecision":"RESULTS_PRESERVED","preservation":{"basis":"OPERATOR_DECLARED","verifiedByTool":false},…}
{"type":"declaration","opId":"<run>:2","path":"…\\7c1e…","declaredBy":"OPERATOR","taskCompleted":true,"contentDecision":"NOTHING_NEEDED","preservation":{"basis":"NOTHING_NEEDED_DISCARD_ACCEPTED","verifiedByTool":false},…}
{"type":"confirmation","accepted":true,"planId":"3f9a0c1b…","roots":2,"interaction":{"caller":"CLI","consoleRequiredByCaller":true,"callerFieldsVerified":false,"interactiveConsoleObserved":true,"observedBy":"ENGINE_CONSOLE_CHECK","identifiesRespondent":false},"limitations":[…]}
{"type":"plan-check","planId":"3f9a0c1b…","matched":true,"changed":[]}
```

Nothing reads an AUT-1 record as permission: `authorize` stays an independent record.

Administrator-only switch: `-IncludeOtherUsers`. Incomplete process coverage can only be accepted through the B1
restricted exception below.

### B1 restricted exception (`-AcceptB1ResidualRisk`; V0.3; 0.3.0; past the deletion gate only, which is closed in every copy)

A change of the product contract (until V0.2: "no override"). A root whose only refusal is the incomplete process
coverage (B1) is shown as **`ELIGIBLE_WITH_DECLARED_RISK`** (never `ELIGIBLE`) when every condition holds: own profile,
token not elevated, no `-IncludeOtherUsers`; a Claude Code session root of class `ORPHAN_SUSPECTED` without flags; no
runtime refusal; `process-snapshot` COMPLETE and `processes` incomplete only because command lines cannot be read; every
such process has an identity (`pid@creationTicksUtc`); the lock probe passes (checked by `clean` only: preview never
opens real roots for it and shows the category unprobed). RECENT is unchanged (it refuses first).

* **Preview, audit, TUI:** a block of its own, "NOT RELEASED", never in the allowlist suggestions (TUI label `B1-RISK`).
* **clean without `-AcceptB1ResidualRisk`, or with the gate closed, or from the TUI:** B1 exactly as before.
* **clean with `-AcceptB1ResidualRisk` past the gate (CLI):** at most **one root per run** (fixed in code; a larger set
  is refused before any question, `B1_EXCEPTION_LIMIT_EXCEEDED`). The AUT-2 questions, plus, for that root, its path and
  the number of processes not inspected, the exact phrase `ACEITO RISCO B1` (en-US `ACCEPT B1 RISK`); a refusal or
  cancellation aborts the run. The switch answers nothing and skips no console requirement.
* **Bound to what was accepted:** the identities of the processes not inspected are recorded in the `plan` record
  (`uninspectableKeys`, never names or command lines), counted in `run-start` and the `declaration`
  (`b1ResidualRiskAccepted`), and part of the plan id. A new process that cannot be inspected, `process-snapshot` no longer
  COMPLETE, or any other change refuses at the plan check (`PLAN_CHANGED_BEFORE_EXECUTION`) or at the revalidation
  (`REVALIDATION_REFUSED`, `B1_EXCEPTION_NEW_UNINSPECTABLE_PROCESS` / `B1_EXCEPTION_NO_LONGER_APPLIES`). A process that
  disappeared neither widens the acceptance nor skips the revalidation.
* **Residual risk (not observed, accepted, no rollback):** the processes not inspected themselves (services, other
  accounts, elevated or protected processes; the root's own session is still detected through the session registry),
  working directories, handles shared for delete, IPC and environment, read-only use, writes that keep every statistic.

### Discard authorization (`authorize`; V0.3 AUT-1; 0.3.0)

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

### Clean log (`-LogFile`; V0.3 T1; 0.3.0)

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

### One clean at a time (V0.3 B8; 0.3.0)

With the deletion gate closed (every published copy) nothing changes: no lock is taken.

In a future release in which real deletion is enabled, one clean run at a time per machine (every user, session and
elevation level) holds the named kernel mutex `Global\AgentTempManager.Clean`:

* It is taken without waiting, before the first inventory, and held through the plan, the confirmation and the
  deletions; it is released last, after the log is closed, on every path (refusal, failure, exception). The native
  library that provides it is loaded first, verified against the manifest like everywhere else, so a run with no
  `-LogFile` ends with `LOG_REQUIRED` and not with a missing-type error.
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

## Isolate (0.3.x, unreleased; plan only in every copy)

```
agent-temp isolate -Path <exact session root> [-AllowListFile <file>] [-AcceptB1ResidualRisk]
```

Isolation takes an agent's temporary data out of the active environment and keeps it intact in a quarantine
([ADR-0013](adr/ADR-0013-isolation-quarantine-recovery-mode.md)). In this version the command **only plans**. A new
release gate, `AtmIsolationEnabled`, is closed in every copy. Like the other gates, it is a single assignment to `$false`
that no option, variable or file changes, and the build, the installation tests and `agent-temp version`
(`isolation: DISABLED`) all check it.

What `isolate` does:

1. It checks the syntax of each exact path, with the same rules as the clean allowlist.
2. It takes a fresh inventory and runtime evidence.
3. It applies the 0.3.x target rule:
   * **your own profile only** (`ALVO_FORA_DO_PROPRIO_PERFIL`; `-IncludeOtherUsers` is refused with exit code `2`);
   * **a session root only**;
   * a project's scope directory is refused with `ISOLAMENTO_ESCOPO_NAO_LIBERADO_0_3X`, the whole `<TEMP>\claude` base
     with `ISOLAMENTO_BASE_NAO_LIBERADA_0_3X`, and any other entry with `ALVO_NAO_ISOLAVEL_0_3X`.
4. It runs **the same gates as clean**:
   * nothing is relaxed because isolation is reversible;
   * RECENT blocks;
   * runtime evidence blocks or needs investigation;
   * the B1 restricted exception per root, with `-AcceptB1ResidualRisk`, is considered only past the isolation gate, as
     clean considers it only past the deletion gate.
5. It refuses a root on another volume than the quarantine (`MOVE_OTHER_VOLUME`), under the B1 exception too: the move
   would be a copy plus a deletion. The drive roots are compared, so the rule holds before the quarantine exists.
6. It shows the exact plan with its plan id, followed by `NOTHING HAS BEEN MOVED`.

It then stops, with exit code `3`:
* `ISOLAMENTO_REAL_DESABILITADO` when a path passed every check;
* `NENHUM_CAMINHO_ISOLAVEL` when none did.

What it does not do, in any copy:
* It asks nothing.
* It takes no lock (the B8 clean lock is not used) and opens no log (`-LogFile` is not used). Like clean's plan, the
  gates' in-use probe still opens each entry of a candidate root for a moment, with `DELETE` access and no sharing, and
  reads no data.
* It creates no quarantine and moves, creates or removes nothing.

### Past the isolation gate (not in any copy; tested in the suite)

`agent-temp isolate -Path <session root> -LogFile <new file>`, from an interactive console (exit code `6` otherwise). One
session root per run.

1. **Lock and log.** The run takes the clean lock (one clean or isolation at a time). Its log is a new file outside the
   audited directories and the quarantine (`atm.isolatelog/1`).
2. **Confirmation.** You type `ISOLAR 1 CAMINHOS <first 8 characters of the plan id>`. For a root under the B1
   exception (with `-AcceptB1ResidualRisk`), you type that root's risk phrase first. No discard declaration is asked:
   nothing is discarded.
3. **Checks.** The plan is checked again, and the root is revalidated immediately before the move. Any difference
   stops the run with nothing moved.
   * The plan check stops the run with `PLAN_CHANGED_BEFORE_EXECUTION`. Its log record `plan-check` has `matched` and
     `reasons`, the first check that failed, in this order:
     * `ROOT_NOT_SEEN_ONCE (N)`: the root is seen N times (0, or more than 1) in the fresh inventory;
     * `PLAN_ITEM_CHANGED`: its statistics changed. `changedFields` names which ones: `path`, `fingerprint`, `files`,
       `dirs`, `bytes`, `newestWrite`;
     * the gates' refusals, each as its leading code. For example: `B1_EXCEPTION_NEW_UNINSPECTABLE_PROCESS (N)` (a
       new process not inspectable, with the count) or `B1_EXCEPTION_NO_LONGER_APPLIES`. A reason without a leading
       code is `UNCODED_REASON`.
   * A matched plan check records `reasons: []`.
   * The record holds only codes, counts and field names: never process identities, names or command lines, accounts,
     SIDs, paths or localized text.

   ```
   {"type":"plan-check","planId":"5e0c…","matched":false,"reasons":["PLAN_ITEM_CHANGED"],"changedFields":["files","bytes"]}
   ```
4. **Quarantine.** The root is moved, intact, on the same volume, to a new entry
   `%LOCALAPPDATA%\AgentTempManager\Q\<yyyyMMddTHHmmssZ>-<8 hex>\payload`. Next to it is a `manifest.jsonl`
   (`atm.quarantine/1`), which records the original path, the acting identity, the intent and the result, with no file
   names or contents. A quarantine folder that already exists is checked and used as it is, never changed.
5. **Outcome.** The output names the entry. A refusal by the mover (for example a file open inside the root) leaves the
   root where it was and an entry whose manifest records the attempt. Any outcome other than moved and verified stops
   the run (exit code `3`), and nothing is undone.

### Quarantine (0.3.x, unreleased)

```
agent-temp quarantine list
agent-temp quarantine inspect -Entry <id>
agent-temp quarantine verify  -Entry <id> | -All
agent-temp quarantine restore -Entry <id> -LogFile <new file>
agent-temp quarantine purge   -Entry <id> -LogFile <new file>
```

* `-Entry` takes only an entry id (`yyyyMMddTHHmmssZ-<8 hex>`), never a path (exit code `2` otherwise).
* `list`, `inspect` and `verify` only read, with the isolation gate open or closed: bytes and times stay identical,
  manifests included, and a missing quarantine is not created. Each entry shows its derived state (`ISOLATED`,
  `EXPIRED`, `INCOMPLETE`, `FAILED`, `RESTORED`, `PURGED`, `ABANDONED`, or `ENTRY_MANIFEST_INVALID`). `verify` compares
  the payload with the measurement and metadata digest the manifest recorded (`OK`, `DIFFERS`, `PAYLOAD_MISSING`, ...); a
  differing entry is a result (exit code `0`). `list` and `version` also show the effective quarantine policy.
* `restore`, with the isolation gate closed (every copy), shows the plan and stops (exit code `3`). Past the gate it needs a
  console, a new log and the phrase `RESTAURAR <id8>`. When the original path exists (`RESTORE_CONFLICT`) the engine
  offers `<name>.restored-<id8>` next to it, with its own phrase; nothing is ever overwritten or merged. An `INCOMPLETE`
  entry is reconciled by the restore itself when its payload matches the intent and the original is absent.
* The TUI: **I** isolates the selected root (the default action; plan only in every copy), **Z** opens the read-only
  Quarantine area (list, detail, **V** verify), with `EXPIRED`, `PURGED` and the policy. The TUI never restores or
  purges: it shows the CLI commands.

### Purge (0.3.x, unreleased; plan only in every copy)

`agent-temp quarantine purge -Entry <id>` frees the space of **one** quarantine entry per run. A sixth release gate,
`AtmQuarantinePurgeEnabled`, is closed in every copy. It is separate from the isolation gate and from the deletion gate
of `clean`: neither of them opens it, and it opens neither of them. The build, the installation tests and `version`
(`quarantine purge: DISABLED`) all check it.

With the purge gate closed (every copy), `purge` checks the entry and shows the plan: its state, the measurement the
manifest recorded, the processes whose command line could not be read (a count), the plan id and the phrase
`EXPURGAR <id8> <files> ARQUIVOS`. Then it stops with `EXPURGO_REAL_DESABILITADO` (exit code `3`). Nothing is asked, no
lock or log is taken, nothing is purged and **no space is freed**.

The plan refuses with `PURGE_REFUSED_<reason>` (exit code `3`, `EXPURGO_RECUSADO`) when the entry:

* does not exist (`ENTRY_NOT_FOUND`), is not an entry or is a reparse point (`UNRECOGNIZED`), or has an invalid manifest;
* belongs to another identity (`ABANDONED`);
* is `INCOMPLETE`, `FAILED`, `RESTORED` or already `PURGED`;
* does not verify in this run (`DIFFERS`, `PAYLOAD_MISSING`).

It also refuses when one of the purge's own checks fails:

* the path down to the payload (fixed drive, no reparse point);
* the owner and ACL of the quarantine and of the entry;
* the in-use probe of the payload;
* the runtime evidence was not collected, or a process command line names the quarantine (`RUNTIME_QUARANTINE_REFERENCED`,
  a count only).

A refused entry is never retried with weaker checks.

Past the purge gate (not in any copy; tested in the suite) the run needs an interactive console (exit code `6`
otherwise) and a new `-LogFile` (`atm.purgelog/1`, outside the audited directories and the quarantine). It takes the clean
lock, then asks:

1. the declarations of **this** purge (the task finished; the content needed is preserved, or nothing in it needs to be
   kept). Those given when the entry was isolated do not count;
2. the phrase bound to the entry.

Then it checks the plan again. A `purge-intent` record goes to the manifest and the log **before** the deleter runs. The
deleter is the same one `clean` uses, given the measurement the manifest recorded. A difference stops it before the first
deletion. The payload's absence is confirmed, and a `purge-result` record (`automatic: false`) goes to both. The entry
folder and its manifest stay as the trail, and the entry becomes `PURGED`. Anything else stops the run, and nothing is
retried. An entry that ended `REFUSED` stays `ISOLATED`; any other outcome makes it `FAILED`.

### Quarantine policy, retention and quota

The optional file `config\quarantine.policy.json` of the installation sets the policy. Example (synthetic values):

```json
{ "schema": "atm.quarantine-policy/1", "retentionDays": 30, "quotaBytes": 10737418240, "autoPurge": false }
```

* Strict schema: `schema` is required. `retentionDays` is a whole number of days, 1 to 3650. `quotaBytes` is a whole
  number of bytes, at least 1. `autoPurge` is `true` or `false`. No other key is allowed.
* A missing file means the default: 30 days, no quota, `autoPurge` false. A file that breaks the schema counts as **off**
  (the same defaults) and shows `QUARANTINE_POLICY_INVALID`.
* **Retention** only marks an `ISOLATED` entry `EXPIRED` once its days have passed since the isolation completed. `list`
  and `inspect` show the date. Retention never purges, and only `ISOLATED` entries become `EXPIRED`. An `EXPIRED` entry
  leaves the quarantine only through `restore` or a confirmed `purge`.
* **Quota:** when the quarantine holds `quotaBytes` or more, or a new isolation would exceed it, `list` warns and
  `isolate` refuses the root (`QUARANTINE_QUOTA_REACHED`; `QUARANTINE_QUOTA_UNMEASURED` when the quarantine's usage
  cannot be measured). `isolate` also refuses when the quarantine's volume has less
  free space than a minimum fixed in code (`LOW_DISK_SPACE`). Neither rule ever purges anything.
* `autoPurge: true` turns the automatic purge on (below). It acts only when `bin\agent-temp-autopurge.ps1` is run, by
  the user's optional scheduled task or by hand. While it is on, `version`, `quarantine list`, every screen of the TUI
  and every report show `AUTOMATIC PURGE ON`.
* An update keeps the installed policy file as it is, like `projects.local.json`. A policy file edited after an update
  makes `verify` report the copy as modified, as an edited `projects.local.json` does.
* A policy file created directly in the installation is not in the manifest until the next update, which records it
  (running the installer again with `-Update`). Until then `verify` shows it as a `WARN` line with that hint, and still
  exits `0`; an edit to it is not detected until it is recorded.

### Automatic purge (0.3.x phases P6a and P6b)

`bin\agent-temp-autopurge.ps1` in the installation is the entry point of the automatic purge. It runs when the user's
optional scheduled task runs it (below) or when a person runs it by hand. It is not a command or a parameter of
`agent-temp` and of the TUI, and it asks nothing: the administrator's policy is the authorization.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\AgentTempManager\bin\agent-temp-autopurge.ps1"
```

* **No arguments.** Any argument is refused (exit 2) before anything is read.
* **Integrity first.** It loads the installed library only if every file of the manifest matches its SHA-256, every
  library it loads (and the entry point itself) is listed and no unlisted provider exists, the launcher's rules (exit
  5). A copy without `manifest.json` is refused too: it runs only from an installation.
* **Off unless the policy says so.** With no policy file, an invalid one, or `autoPurge: false`, it does nothing,
  creates no log and exits 0 with one status line.
* **Minimum retention.** With `retentionDays` below 7 (a minimum fixed in code) nothing expires automatically: it is
  refused (exit 3) with nothing read or done.
* **The purge gate governs.** With the gate closed (every distributed copy) the pass reads the quarantine of the user
  who runs it and only reports, for each entry, what it would purge (`WOULD_PURGE`) or why it skips it. It takes no lock,
  writes no log and purges nothing (exit 0).
* **Past the gate** (the suite only, in its own process) the pass:
  1. takes the clean lock (B8, the same name) without waiting; busy: it ends with nothing purged and no log (exit 3);
  2. writes a new log of the pass, `atm.autopurgelog/1` (the T1 writer), in `%LOCALAPPDATA%\AgentTempManager\AutoPurgeLog`,
     next to the quarantine and outside it;
  3. purges only the user's own `EXPIRED` entries whose `verify` is `OK` in the same pass, through the plan, gates and
     deleter of `quarantine purge` (without the declarations and the phrase). The plan is checked again just before the
     deleter; `purge-intent` and `purge-result` carry `automatic: true` and `declaredBy: AUTOMATIC_POLICY` in the manifest
     and in the log.
* **Skipped, with the reason, never retried with weaker checks:** an entry whose id or any manifest record is dated after
  the clock (`FUTURE_DATE`); any state but `EXPIRED` (`STATE_ISOLATED`, `STATE_INCOMPLETE (...)`, `STATE_FAILED`,
  `STATE_ABANDONED`, `STATE_UNRECOGNIZED (...)`, ...); any refusal of the purge plan (`PURGE_REFUSED_<reason>` and the
  gates); a plan that changed before the deleter (`REVALIDATION_REFUSED`); a deleter that refused before deleting
  anything (`DELETER_REFUSED`). Any other outcome stops the pass, and the remaining entries are `NOT_REACHED`.
* **Exit codes:** `0` off, report only, quarantine absent, or done; `2` an argument; `3` the minimum retention, the lock
  not available, or a pass that ended or stopped on an error; `5` integrity; `10` unexpected (its type only).

#### The scheduled task (phase P6b)

Each user may create **one** task of their own that runs the entry point daily (decision J-ISO-7). It is optional: the
installer never creates one, and the TUI only shows its state. Creating it needs no elevation and no credential.

```powershell
agent-temp quarantine schedule-autopurge
agent-temp quarantine unschedule-autopurge
```

* **`schedule-autopurge`** runs in a terminal that is **not** elevated. An elevated process, or one whose token cannot
  be read, is refused (`AUTOPURGE_TASK_REQUIRES_STANDARD_TOKEN`, exit 3); so is a copy that is not installed
  (`AUTOPURGE_TASK_NOT_INSTALLED`). It needs an interactive console (exit 6 without one). It then shows the plan:
  * the task: `\AgentTempManager\AutoPurge-<16 hex digits>` in the Task Scheduler. The name comes from a hash of your
    SID and does not show your account;
  * the trigger: daily at 12:00 local time with a random delay of up to 60 minutes. A missed run starts at the next
    opportunity; the first run is the next 12:00, so creating the task never runs it. A run is stopped after 120 minutes;
  * the action: Windows PowerShell 5.1 by its absolute path running the installed entry point, with no arguments;
  * it runs as you, on your own token, **not elevated** (run level Limited), and **only while your session is open**
    (logon type Interactive). No password or other credential is asked for, stored or passed.

  If the task already exists, in any form, it is refused and never replaced (`AUTOPURGE_TASK_EXISTS`). With the policy
  not on (`autoPurge` is not `true`), the plan warns that nothing will happen until the administrator turns it on, and
  that warning needs its own phrase, `AGENDAR COM EXPURGO DESLIGADO`. The task is created only after the phrase
  `AGENDAR EXPURGO AUTOMATICO`, then read back. Exit 0 when created, 3 when refused or not confirmed.
* **`unschedule-autopurge`** needs an interactive console and the phrase `DESAGENDAR EXPURGO AUTOMATICO`. It removes
  **only** the task with the product's exact folder and name for you, set to run as you, interactive, limited, with the
  installed entry point as its only action. Anything else (`AUTOPURGE_TASK_DIVERGENT`, with the reasons in `version`),
  or no task (`AUTOPURGE_TASK_ABSENT`), is refused with nothing touched (exit 3). Once the task is read back absent,
  the Task Scheduler folder `\AgentTempManager` is removed if it is empty: no task, hidden ones included, and no
  subfolder (V0.5 M4a). Otherwise it stays, and the result says so with the counts it saw (no task is named). If the
  Task Scheduler refuses to remove it (for example, it holds a task of another user that your account cannot see), it
  stays with the scheduler's code, and nothing else is tried. The folder never makes the command fail: the task is
  already removed (exit 0).
* **State.** `version`, `quarantine list` and the TUI's quarantine screens show whether your task exists, whether it is
  enabled and its next and last run: `ABSENT`, `PRESENT`, `DIVERGENT` (not exactly the product's task; check it in Task
  Scheduler) or unreadable. The policy line next to it says whether a run would do anything.
* **Uninstall** never removes a task, yours or another user's. If yours exists, it warns and says how to remove it; other
  users' tasks are only counted. Without the installation a task fails closed: its action, the entry point, no longer
  exists, so it does nothing. Run `unschedule-autopurge` before uninstalling, or remove the task in Task Scheduler.

## Desktop GUI (V0.2.1, unreleased; disabled in every copy)

`agent-temp gui` is the entry point of the desktop window that V0.2.1 adds
([ADR-0014](adr/ADR-0014-desktop-gui-winforms.md)). It ships behind a release gate of its own, `$script:AtmGuiEnabled`,
which is `$false` in every copy. With the gate closed, the command prints
`GUI_GATE_CLOSED: the desktop GUI is disabled in this release. No window was opened.` and exits with code `7`. It opens
no window and loads no Windows Forms assembly. `agent-temp version` shows the gate (`desktop GUI: DISABLED in this
release`).

Order of a run:

1. the launcher's integrity check, as for every command;
2. the release gate (`7` when it is closed);
3. the environment: the PowerShell thread must be single-threaded (STA) and an interactive desktop must exist. Otherwise
   the command exits with code `8` and the reason: `GUI_NOT_STA`, `GUI_NO_INTERACTIVE_DESKTOP` (a service, session 0 or
   a non-interactive session) or `GUI_WINFORMS_UNAVAILABLE`. It is never relaunched in another shell;
4. Windows Forms is loaded, and the window opens.

What the window shows in this version (phases P1 to P6):

* **A header:**
  * the process identity and its elevation state (elevated administrator, token elevation type, integrity level);
  * the language;
  * the state of the view, as a word, never by color alone:
    * `UNKNOWN` before an audit has finished;
    * `CURRENT` with the UTC time of the audit;
    * `PARTIAL` when the engine's coverage is incomplete;
    * `STALE` when the last audit failed. The earlier result stays on screen, with the exception code only. With the
      live monitoring on (phase P5), `STALE` also says why when no audit failed: the last audit was slow (its duration
      in seconds), or no audit has succeeded for more than twice the interval (the time of the audit shown).
* **The automatic purge notice,** under the header, while the policy of this copy has `autoPurge: true`. It is the
  same text the TUI and the reports show.
* **The dashboard of the TUI** (menu `1`), in read-only lists:
  * profiles: discovered, audited, with incomplete coverage;
  * files, directories and partitions;
  * space: MB logical, GB logical, MB on disk (estimated);
  * read errors, incomplete measurements and coverage;
  * the count and MB of each class (`ACTIVE_EVIDENCE`, `RECENT`, `LIVENESS_UNKNOWN`, `ORPHAN_SUSPECTED`), with the
    class written out;
  * the audit time.

  The numbers are the TUI's, from the same engine.
* **The TUI's other read-only screens (phase P3),** each with the same rows, order and text as the TUI:

  | Key | Screen |
  |---|---|
  | `1` | the dashboard |
  | `2` | users: name, SID, profile state, roots, files, MB and the count of each class (`A/R/U/O`) |
  | `3` | projects: grouped as in the TUI, by size, with the user and the newest write |
  | `4` | roots: class, agent, user, project, root, MB, files, newest write and number of flags |
  | `5`, `6`, `7` | the roots of `ACTIVE_EVIDENCE`, `RECENT` and `LIVENESS_UNKNOWN` |
  | `8` | the blocked paths: the roots the preview of the cleanup puts in `BLOCKED` (phase P4a) |
  | `9` | coverage and errors: the coverage and the processes, references, incomplete profiles, temporary directories, discovery notes, partitions with issues and the limits |
  | `P` | the preview: every root with its category (phase P4a) |
  | `D` | the diagnostics area: the TUI's `Diagnostics V0.2` (phase P4b) |
  | `U` | inside the diagnostics area only: run the diagnose again (phase P4b) |
  | `S` | the recovery area, view only: the TUI's `S` (V0.4 R5; see [Recover](#in-the-tui-and-the-gui-v04-r5)) |

  Each screen also has a button, with its digit as the access key. `Enter` on a row opens it: a user or a project shows
  its roots, and a root shows its detail (the TUI's fields, then the evidence, the references and the samples of errors
  and reparse points). `Esc` goes back one screen, and closes the window only on the dashboard. The header and the
  automatic purge notice stay on every screen.

  After an audit, the current screen is computed again. If the root of an open detail is not in the new audit, the
  window goes back to the list and says so. Before the first audit has finished, the screens show no rows.
* **The preview of the cleanup (phase P4a),** keys `P` and `8`, with the same rows, order and text as the TUI's
  screens `P` and `8`: category, user, root, MB, and the reasons and requirements. The category is written out
  (`BLOCKED`, `INVESTIGATE`, `ELIGIBLE`, and the short label of `ELIGIBLE_WITH_DECLARED_RISK`), never by color alone.
  * Both screens show a fixed notice: the preview is an evaluation only; the window deletes and isolates nothing, and
    the cleanup stays in the CLI, behind its own gate.
  * `Enter` on a row opens the detail of that root, with one more line, `Preview`: the category, then the reasons and
    requirements. A detail opened from the other screens has no `Preview` line.
  * The preview is computed by the cleanup engine, once per audit, the first time `P` or `8` is opened after it. While
    it runs, the window shows a fixed text, with no percentage, and the screen keys, the buttons and Refresh do
    nothing. Closing the window during the preview closes it when the preview ends.
  * The result is kept until the next audit. A new audit discards it: if a preview screen is open, the window goes
    back to the dashboard and says so, and the next `P` or `8` computes it again. A failed audit keeps it. A due
    audit of the live monitoring (phase P5) is the exception: on a preview screen it stays there and computes the
    preview again.
  * A failed preview shows only the exception type, and changes nothing. The next `P` or `8` tries again; nothing
    repeats by itself.
  * Before the first audit has finished, `P` and `8` show the same text as the other screens, and compute nothing.
* **The diagnostics area (phase P4b),** key `D`, with the same categories, rows, order and text as the TUI's area
  `D`: the summary, the coverage of every collector, agent processes and sessions, services, the virtualization
  platform and VMs, repositories and worktrees, temporary partitions, the graph nodes and their edges, and the
  `UNKNOWN` items. `Enter` opens a row as in the TUI, and `Esc` goes back one screen.
  * **When the diagnose runs:** only when you ask. The first `D` runs it once, as the TUI's area does; after that, `D`
    shows the kept result and runs nothing. Moving between the area's screens and opening details run nothing.
    **U** (or its button, enabled only inside the area) runs it again. An audit (`F5` or Refresh) keeps the result
    and does not run the diagnose. Nothing repeats by itself.
  * While it runs, the window shows the TUI's fixed text and a percentage, and the screen keys, the buttons and
    Refresh do nothing; a second request is ignored. Closing the window then stops the inventory phase at its next
    progress step; the collectors still run within the diagnose deadline (300 seconds by default), then the result is
    discarded and the window closes.
  * It shows only the schema view, the same content as the `diagnose` JSON export: pseudonyms and codes, with no path,
    account, identity, machine name or command line.
  * Collectors that a closed release gate keeps off are listed with **"Disabled in this version"** ("Desabilitado
    nesta versão" in pt-BR), the gate's code, the collector and the reason: worktree diagnostics and handles today,
    and also the diagnostics export and running Git when a result names them. These lines are the one addition to
    the TUI's text, so that a disabled collector is never read as an empty result: a category with such a line says
    "not observed" instead of "none".
  * A failed run shows only the exception code. A result already shown stays, marked as outdated; nothing repeats
    by itself.
  * The digits `1` to `9` and `P` work inside the area too, and leave it for that screen (the TUI ignores them
    there).

* **The live monitoring (phase P5),** under the header (above the screen buttons since phase P6): a check box **Live monitoring** (**Monitoramento ao vivo**,
  access key `M`), an interval list and a status line.
  * The box is off every time the window opens, and the list shows 60 s. The list has six fixed values: 30 s, 60 s,
    2 min, 5 min, 10 min and 15 min. It cannot be typed into. Nothing is remembered.
  * Turning it on runs nothing: the first audit comes one interval later. Changing the interval starts the count again
    from that moment. Turning it off stops it; an audit already running ends normally.
  * Each due audit is the same audit as `F5`. The open screen stays and is computed again over the new result (a detail
    whose root is gone goes back to its list). On `P`, `8` or a detail opened from them, the preview is computed again
    in the same audit. On any other screen, the kept preview is discarded and is computed again the next time `P` or
    `8` is opened.
  * **The diagnose never runs by itself.** A due audit never runs it, and the diagnostics area keeps its result.
  * A due time that arrives while an audit, the preview or the diagnose runs is dropped, never queued.
  * The status line says `off`, or `on` with the interval and the UTC time of the next audit.
  * Limits: an audit that takes more than half the interval marks the view `STALE` (slow), and the next audit waits
    twice that duration (at least one interval) after it ends. More than twice the interval with no good audit marks it
    `STALE` (old). A failed audit keeps everything shown, marks it `STALE` with the exception code only, and the next
    due audit tries again. A good, fast audit clears these marks.

**Audits.** The window runs one audit when it opens, as the TUI does. After that, an audit runs only when you ask for
it, with **Refresh** or `F5`, or when the live monitoring is on and its interval has passed.
* While an audit runs:
  * the window shows only a percentage;
  * the refresh controls are disabled;
  * a second request is ignored, not queued.
* Closing the window during an audit cancels it, and the window closes.
* `F5` audits again from any screen. On `P` or `8`, it goes back to the dashboard (the preview is discarded); on any
  other screen, the screen stays. While an audit runs, the screen keys and buttons do nothing.

**Language and accessibility (phase P6).**
* **Language:** chosen when the command starts, by the same rules as the CLI: `-Lang pt-BR|en-US`, then `ATM_LANG`,
  then the Windows UI language. The window has no language switch; close it and start it again with another `-Lang`.
  Every text in it comes from the product's catalog in that language.
* **Keyboard:** everything works without a mouse.
  * `Tab` follows the visual order: the monitoring box and interval, the screen buttons, the lists, then **Refresh**
    and **Close**.
  * Screen keys `1` to `9`, `P` and `D`; `U` inside the diagnostics area; `F5` to audit; `Esc` to go back (it closes
    the window on the dashboard).
  * `Enter` on a row opens it. `Enter` on a focused button presses it, as Space does. On the monitoring box `Enter`
    does nothing; Space toggles it.
  * Access keys (`Alt` and the underlined letter): `Alt+M` the monitoring box, `Alt+I` the interval (then the arrow
    keys change it), `Alt+1` to `Alt+9`, `Alt+P` and `Alt+D` the screen buttons, `Alt+U` diagnose again, and the
    underlined letter of **Refresh** and **Close** (`R` and `C` in en-US, `A` and `F` in pt-BR).
* **Screen readers:** every control, list and group has an accessible name from the catalog; the state, status, title
  and message lines update their name with their text.
* **High contrast:** the window uses only the system colors, so a Windows high-contrast theme applies to all of it.
  Nothing is told by color alone.
* **DPI:** the window scales with the display (125% to 200%). Fixed widths, such as the list columns, are scaled by the
  window's DPI.

**What it does not do:**
* any action over a root or a category: clean, isolate, restore, purge or open its folder. The preview only shows
  the categories; it offers no button to act on them;
* the path drill-down of `agent-temp audit -Path`, and the isolation hint of the TUI's detail;
* list the quarantine;
* run the diagnose by itself, export it, or run Git: the export and Git stay behind their closed gates;
* copy to the clipboard;
* export;
* remember its size or position;
* write any file;
* start any process.

Closing it leaves no process, timer or file behind. The installed command always runs in Windows PowerShell 5.1, and
there is no other entry point (no `bin\` script, no shortcut).

## Recover (V0.4 R1 to R5, unreleased; nothing is changed in any copy)

Assisted recovery of a service a provider declares ([ADR-0016](adr/ADR-0016-v04-assisted-recovery.md)). The recovery
gate is closed in every copy, and `agent-temp version` shows it: `assisted recovery: DISABLED in this release (recover
only lists and shows the plan)`. `recover list` and `recover plan` open, start, stop or change no service, whether the
gate is open or closed. Nothing is asked, no lock is taken, and no log or file is written.

Phase R2 added the start path to the engine (`Invoke-AtmRecover`, ADR-0016's R2 implementation record). Phase R3 added
the undo of one start (`Invoke-AtmRecoverUndo`, ADR-0016's R3 implementation record): it reads the run's log, checks
that the service is still exactly as that run left it, `RUNNING`, with no dependent running, and stops that one service,
never its dependents. Phase R4 added the two verbs that reach them, `recover start` and `recover undo` (below), and the
elevation through UAC that they need. With the gate closed, both verbs stop before acting. Only the test suite goes past
the gate, in its own process, with the seams and the elevated launcher injected. In CI only, the R6 harness also does,
on services it creates itself, with guard wrappers around the default seams (ADR-0016's R6 record). `REC-SVC-STOP` is
never offered by
`list` nor accepted by `plan`.

```text
agent-temp recover list
agent-temp recover plan -Operation REC-SVC-START -Service <exact declared name>
agent-temp recover start -Operation REC-SVC-START -Service <exact declared name>
agent-temp recover undo -RunId <run id>
```

Each run makes a fresh, read-only collection in its own process: the token, the providers' service hints, and one
services query with its fault signals, dependencies and image check (as `diagnose` reads them). `-DeadlineSeconds`
bounds it (default 120 s).

* **The catalog** has one operation, `REC-SVC-START`: start one stopped service that a provider declares. It is undone
  by stopping the service (`REC-SVC-STOP`), which restores its state only. Whatever the service did while it ran is
  not undone. Ending processes and operating virtual machines are not offered.
* **`list`** shows, for each declared service, the operation, offered or refused with its `RECOVERY_*` codes. It also
  shows the services coverage, the likely elevation and the not-offered line.
* **`plan`** takes one operation from the catalog and one target. The target is only the exact name a provider
  declares, compared case-sensitively: never a path, wildcard, file or plan. An offered plan shows:
  * the "before" capture (state, start mode, fault signals, account kind, executable, image, dependencies);
  * the undo and what it does not undo;
  * the likely elevation, from the token only (`LIKELY_HAS_RIGHT`, `NEEDS_ELEVATION` or `UNKNOWN`);
  * a plan id.

  A refused plan shows its codes.
* Every run ends with `Nothing was changed.`

The refusal codes, closed:

* `RECOVERY_NOT_DECLARED` (a usage error, exit 2);
* `RECOVERY_ATTRIBUTION_AMBIGUOUS`, `RECOVERY_COVERAGE_INCOMPLETE`, `RECOVERY_NOT_LISTED`, `RECOVERY_DUPLICATE_ROW`;
* `RECOVERY_PROPERTY_UNREADABLE`, `RECOVERY_SIGNALS_UNREADABLE`;
* `RECOVERY_NOT_STOPPED`, `RECOVERY_START_MODE_DISABLED`;
* `RECOVERY_IMAGE_NOT_DECLARED`, `RECOVERY_IMAGE_MISMATCH`, `RECOVERY_IMAGE_UNKNOWN`;
* `RECOVERY_DEPENDENCY_STOPPED`, `RECOVERY_DEPENDENCIES_UNREADABLE`, `RECOVERY_DEPENDENCIES_CAPPED`.

No shipped provider declares an expected image, so every real plan is refused, at least with
`RECOVERY_IMAGE_NOT_DECLARED`. That includes Claude Desktop's `CoworkVMService`. This refusal is the maintainer's
decision (2026-11-17), and it holds from phase R2 on, where the start path exists: a service whose providers declare no
executable is never started. `CoworkVMService` stays refused until a provider declares its executable.

Example (synthetic; the rule lines are shortened):

```text
==========
 Recovery plan: REC-SVC-START for ExampleSvc
==========
  Starts one stopped service declared by a provider.
  Declared by: example-provider
==========
 Refused: this operation is not offered for this service
==========
  - RECOVERY_IMAGE_NOT_DECLARED
  - RECOVERY_NOT_STOPPED
Recovery is DISABLED in this release: recover only lists and shows the plan; nothing is asked, locked or logged.
Nothing was changed.
```

Exit codes of `recover list` and `recover plan`:

* `0`: the list was shown, or a plan was offered;
* `3`: the plan was refused;
* `2`: a usage error (a missing or other subcommand, `-Operation` or `-Service` on `list`, an operation outside the
  catalog, a target that is not a plain name or that no provider declares, or an option `recover` does not take);
* `10`: the collection failed.

### recover start and recover undo (V0.4 R4)

`recover start` takes exactly `-Operation REC-SVC-START` and `-Service` with the exact name a provider declares (1 to
256 letters, digits, `_`, `.`, `-` or spaces). `recover undo` takes exactly `-RunId`, the run id that a start showed: a
GUID in lower case. Never a path, file, log or plan. Any other option is a usage error (exit 2). Each command does one
operation.

**In every copy (recovery disabled):**

* `start` shows the plan, as `recover plan` does;
* `undo` shows the inverse plan when this window can read the recovery log folder. Otherwise (a window without
  elevation cannot) it shows only the request, with the folder's code;
* then `Exit 27: recovery is DISABLED in this release`. Nothing is asked, locked or logged, no UAC prompt appears and no
  service is changed.

**What the verbs do past the gate** (not in any copy; ADR-0016, R4 implementation record):

* **From an elevated administrator console**, the command acts in that window: the identity that acts, the plan, the
  typed phrase, the run, the result with its run id.
* **From any other window**, that window is only a request. `start` shows the plan first. Then the window says that it
  asks Windows (UAC) to start the installed `agent-temp` elevated for this one operation, and why. If the prompt is
  accepted, a new elevated window collects, checks and shows everything again, says which account acts (and that the
  account that asked is not verified), asks for the typed phrase, acts once, shows the result and the run id, and waits
  for a key. The first window then shows only the exit code. Only an installed copy, verified by its manifest, can ask
  for elevation (exit 31 otherwise).
* **The logs** go to `<CommonApplicationData>\AgentTempManager\recover\<run id>.log` (usually under `C:\ProgramData`),
  a folder that only the installer creates, owned by Administrators and readable by SYSTEM and Administrators only. A
  copy never creates or fixes it: a missing or different folder gives exit 28. Uninstalling keeps it, as the record of
  what recovery did on the machine.

Exit codes of `recover start` and `recover undo`:

| Exit | Meaning |
|---|---|
| `2` | Usage: an option, operation, name or run id outside the fixed sets; past the gate, in a window without elevation, also a service no provider declares (an elevated window refuses it with `3`). Nothing was changed. |
| `3` | Refused before anything was asked (the plan, the undo's criteria or its source, or no log for this run id). Nothing was changed. |
| `5` | The installation failed its integrity check. Nothing was changed. |
| `10` | Unexpected error (its type only). The result shown, if any, says what ran. |
| `20` | `COMPLETE`: the service reached the expected state. |
| `21` | `PARTIAL`: the service had not reached the expected state when the wait ended. |
| `22` | `FAILED`: the operation was requested and failed. |
| `23` | `REFUSED`: the service control manager denied access. |
| `24` | `EXCEPTION`: the service control call failed with an exception; the service may have changed. |
| `25` | Stopped before any service control call (console, phrase, lock, log, revalidation): the service was not changed. |
| `26` | Stopped after the service control call: the run is incomplete and the service may have changed. |
| `27` | Recovery is disabled in this release (every copy). Nothing was changed. |
| `28` | The recovery log folder is missing or differs from what the installer creates. Nothing was changed. |
| `29` | An elevated recovery copy refused its arguments or its token (for example with UAC turned off). Nothing was changed. |
| `30` | This process already ran one recovery operation. Nothing was changed. |
| `31` | Not an installed copy verified by its manifest. Nothing was changed. |
| `40` | The UAC request ended with Windows error 1223 (usually a cancelled prompt, not proof of it). No elevated copy ran. |
| `41` | The UAC request failed with another Windows error. No elevated copy ran. |
| `42` | The UAC request failed with an exception. No elevated copy ran. |
| `43` | No elevated process started. No elevated copy ran. |
| `44` | The elevated copy ended without a known result: it may have acted. Check its window and `recover plan`. |

From a window without elevation, codes `2`, `3`, `5` and `20` to `31` can also be the elevated copy's own, passed on as
they are.

### In the TUI and the GUI (V0.4 R5)

The TUI (`agent-temp`) and the desktop GUI (`agent-temp gui`, disabled in every copy) have a recovery area, key `S`,
that only shows. Executing stays in the CLI (T-ISO-6), as restore does.

* **Entering the area** (`S`, or the GUI's `S` button) makes one fresh, read-only collection of the services the
  providers declare, with the engine's own deadline, and shows its time. Each entry collects again; nothing else
  collects: moving, opening a plan, `F5`, a re-audit and the GUI's live monitoring do not. While it runs, the TUI shows
  a waiting line and the GUI disables its screens (one blocking call, as the preview). A failed collection shows its
  exception code only, and the area does not open.
* **The list:** the lines of `recover list` (header, coverage, elevation, what is never offered, the gate line and
  "Nothing was changed."), then one row per declared service: the operation, the service, the provider that declares it,
  `OFFERED` or `REFUSED`, and the undo (`REC-SVC-STOP`) or the `RECOVERY_*` codes. A service no provider declares is
  never in the list.
* **The plan** (`Enter` on a row): the lines of `recover plan` for that exact declared name, computed from the
  collection of that entry, with the same codes, then a note that executing is CLI-only and, while the gate is closed,
  that `agent-temp recover start -Operation REC-SVC-START -Service "<name>"` shows the plan and exits with code `27`.
* **Nothing else:** no service name is typed, and no key, button or menu starts, undoes, relaunches, elevates, takes the
  lock or writes a log.

## Monitor (V0.5 M1 to M5, unreleased; nothing is collected, scheduled or removed in any copy)

Preventive monitoring ([ADR-0017](adr/ADR-0017-v05-preventive-monitoring.md)) will keep a small local history of what
the audit shows, one history per user. Phase M1 adds the collector and the history storage behind the **ninth release
gate**, `AtmMonitoringEnabled`, closed in every copy; phase M3a the command that turns it on, `monitor enable`; phase
M4a the command that turns it off, `monitor disable`; and phase M4b the command that removes the history, `monitor
remove-history`. `agent-temp version` shows the gate: `preventive monitoring: DISABLED in this release (monitor status
only reads the history; nothing is collected or scheduled)`. With the gate closed, as in every copy, `monitor enable`,
`monitor disable` and `monitor remove-history` refuse before asking anything, so nothing is scheduled or removed.

```powershell
agent-temp monitor status
agent-temp monitor enable [-IntervalHours 1|2|4|6|12|24]
agent-temp monitor disable
agent-temp monitor remove-history
```

`monitor status` only reads. It says whether monitoring is available, the state of your collection task (also shown by
`version`), and what it finds in the history folder `%LOCALAPPDATA%\AgentTempManager\Monitor`:

* **No folder:** an empty history. The command never creates the folder.
* **Records** (left by another copy, since this one writes none): how many, and the latest one's time, outcome, number
  of groups and size measured. A record that is damaged or not of this schema is counted as `HISTORY_RECORD_INVALID`
  and skipped, never read as zero; one whose time is earlier than the record before it is counted as `CLOCK_SKEW`;
  unfinished `.partial` files and other items are counted and not read.
* **A folder the product refuses** (a reparse point in its chain, another owner, or an ACL that lets other accounts
  change it): its code, and the folder is left as it is.

The collection task's line says one of:

* **none for this user;**
* **present:** its path in the Task Scheduler (`\AgentTempManager\Monitor-<16 hex digits>`; the name does not show your
  account), enabled or disabled, the interval, the next run and the last run with its result;
* **divergent:** a task with that name exists but is not exactly the product's collection task of this user, with the
  reasons; it is never touched;
* **unreadable,** with the scheduler's code.

A present or divergent task with the gate closed was left by another copy: the line says its collector exits without
collecting, and that no command of this copy removes it, since `monitor disable` is behind the same gate (it can be
removed in Task Scheduler). Where the gate is open, a present task's line names `monitor disable`, and a divergent
one's says that `monitor disable` removes only the product's exact task.

It ends with "Nothing was collected, created or changed." Example, with the gate closed, no task and no history:

```
Monitoring is not available in this release: nothing is collected, scheduled or written.
It is opt-in, through agent-temp monitor enable, which in this release refuses before asking anything.
Collection task: none for this user.
History: none (the folder %LOCALAPPDATA%\AgentTempManager\Monitor does not exist; this command never creates it).
Nothing was collected, created or changed.
```

### `monitor enable` (V0.5 M3a; refused in this release)

`monitor enable` creates your own collection task. **With the gate closed, as in every copy, it refuses first**, before
it reads your token, the console or the Task Scheduler and before it asks anything:

```
NOTHING WAS SCHEDULED: MONITORING_GATE_CLOSED
  Monitoring is not available in this release: nothing was read, asked or created.
```

Where the gate is open (only inside the test suite), it checks, in this order, and refuses with nothing registered:

1. `-IntervalHours`, when given, is one of 1, 2, 4, 6, 12 or 24 (default 6): `MONITOR_INTERVAL_INVALID`;
2. a standard token, not elevated: `MONITOR_TASK_REQUIRES_STANDARD_TOKEN`;
3. an installed copy with its collector: `MONITOR_TASK_NOT_INSTALLED`;
4. an interactive console, observed by the engine: `CONSOLE_NOT_OBSERVED`;
5. no collection task of yours, in any form (never replaced): `MONITOR_TASK_EXISTS`, or `MONITOR_TASK_UNREADABLE`
   when the Task Scheduler cannot be read.

It then shows the plan (the task's path; every N hours with no end date, a missed run at the next opportunity, also on
battery, one run at a time, the first run and the one-hour limit; the action; that it runs as you, not elevated, only
while your session is open, with no password; and what a run writes to the history and never writes), and asks you to
type `ATIVAR MONITORAMENTO` (anything else: `MONITOR_TASK_NOT_CONFIRMED`). Only then it registers the task and reads it
back; a task that does not read back exactly as planned is `MONITOR_TASK_NOT_VERIFIED`. Registering never starts a
collection: the first run is at least one minute later.

`-IntervalHours` is an option of `monitor enable` only: it takes a whole number from the list, and anything else (`5`,
`6.5`, `abc`) is a usage error (exit code `2`, nothing read). `monitor status` and `recover` refuse it (`2`); the other
commands ignore it, as they ignore other options they do not use.

### `monitor disable` (V0.5 M4a; refused in this release)

`monitor disable` removes your own collection task. **With the gate closed, as in every copy, it refuses first**,
before it reads the console or the Task Scheduler and before it asks anything:

```
NOTHING WAS REMOVED: MONITORING_GATE_CLOSED
  Monitoring is not available in this release: nothing was read, asked or removed.
```

Where the gate is open (only inside the test suite and the CI harness), it checks, in this order, and refuses with
nothing removed:

1. an interactive console, observed by the engine: `CONSOLE_NOT_OBSERVED`;
2. your collection task: none (`MONITOR_TASK_ABSENT`), the Task Scheduler unreadable (`MONITOR_TASK_UNREADABLE`), or a
   task that is not exactly the product's collection task of this user, with the reasons (`MONITOR_TASK_DIVERGENT`;
   it is never touched).

It needs no standard token: removing your own task elevates nothing. It then shows the plan (the task's path and
interval, the action, what happens to the task folder, and that the history is not touched) and asks you to type
`DESATIVAR MONITORAMENTO` (anything else: `MONITOR_TASK_NOT_CONFIRMED`). Only then it checks the task again, removes it
if it is still exactly the product's task (otherwise `MONITOR_TASK_DIVERGENT` or `MONITOR_TASK_ABSENT`, with nothing
removed), and reads it back; a task that does not read back absent is `MONITOR_TASK_NOT_VERIFIED`. Once it is absent,
the Task Scheduler folder `\AgentTempManager` is removed if it is empty, as `quarantine unschedule-autopurge` does: no
task, hidden ones included, and no subfolder. Otherwise, or if the Task Scheduler refuses, it stays, the result says
so with the counts or the scheduler's code, and nothing else is tried; the folder never makes the command fail. The
history in `%LOCALAPPDATA%\AgentTempManager\Monitor` is not touched: `monitor remove-history` removes it.

### `monitor remove-history` (V0.5 M4b; refused in this release)

`monitor remove-history` removes the history files the product created in `%LOCALAPPDATA%\AgentTempManager\Monitor`.
**With the gate closed, as in every copy, it refuses first**, before it reads the console, the Task Scheduler or the
folder and before it asks anything:

```
NOTHING WAS REMOVED: MONITORING_GATE_CLOSED
  Monitoring is not available in this release: this command refuses, and the history stays as it is.
```

Where the gate is open (only inside the test suite), it checks, in this order, and refuses with nothing removed:

1. an interactive console, observed by the engine: `CONSOLE_NOT_OBSERVED`;
2. your collection task, which must be confirmed absent: one that exists, differs or cannot be read refuses with
   `MONITOR_HISTORY_TASK_PRESENT`, since a run of it would create the history again. Run `monitor disable` first;
3. the history folder: none (`MONITOR_HISTORY_ABSENT`, nothing to remove), or one the product refuses (a reparse point
   in its chain, another owner, or an ACL that lets other accounts change it: `MONITOR_FOLDER_<code>`). Nothing is
   created to check it;
4. what is in it: records and unfinished `.partial` files with the product's names and your ownership are the
   product's; your `monitor.json` is yours and stays. Anything else (another name, a folder, a link, another owner, a
   `monitor.json` that is not your plain file) refuses the whole removal with how many items the product did not
   create (`MONITOR_HISTORY_UNEXPECTED`); nothing is touched, and no name is shown.

It then shows the plan (how many records and `.partial` files, and their bytes; whether `monitor.json` stays and so
the folder too, or the folder goes when empty; and that `%LOCALAPPDATA%\AgentTempManager` is never removed) and asks
you to type `REMOVER HISTORICO DO MONITORAMENTO` (anything else: `MONITOR_HISTORY_NOT_CONFIRMED`). Only then:

* it takes the collectors' lock without waiting: a collection or another removal running refuses with nothing removed
  (`MONITOR_HISTORY_BUSY`);
* it lists the folder again: anything different from the plan refuses with nothing removed
  (`MONITOR_HISTORY_CHANGED`);
* it removes each file, one by one, each checked again just before. The first failure stops the rest: the result says
  its code and how many files had been removed, and the folder stays;
* with every file removed: with your `monitor.json` the folder stays; without it, the folder is removed if it is still
  empty (not recursively; if the system refuses, it stays and the result says why). The folder never makes the command
  fail.

**What stays:** your `monitor.json`, and with it the history folder; the folder `%LOCALAPPDATA%\AgentTempManager`,
which also holds the quarantine and the automatic purge's logs; and your collection task, which this command never
touches.

### The collector's entry point: `bin\agent-temp-monitor.ps1`

The task's only action runs the installed `bin\agent-temp-monitor.ps1` with Windows PowerShell 5.1 (`-NoLogo -NoProfile
-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File`), with no arguments. It can also be run by hand. It
takes no arguments, checks the installation's manifest before it loads anything, loads only the audit, the providers
and the monitoring engine, and reads the gate on every run. With the gate closed (every copy) it says so and exits
without collecting, creating the history folder or taking the collectors' lock. Its exit codes: `0` one collection
recorded; `2` an argument was given; `3` the gate is closed, or the collection was refused (another collection running,
the folder refused, a record too large); `5` installation integrity (also a source checkout, which has no manifest);
`10` unexpected.

With the gate closed, as in every copy, `monitor status` shows no trend and no alert, and it does not read `monitor.json`
(below): a history left by another copy feeds no alert in a copy that does not collect.

### Trends and alerts (V0.5 M2; only where monitoring is on)

Phase M2 adds trends, thresholds and alerts. They are computed when the history is read, and only where the monitoring
gate is open, which no copy has. With the gate open, `monitor status` also shows:

* **The latest complete total** (the newest record with outcome `OK`) and the **difference since the collection
  before**. The difference is a value only when both collections are complete. Otherwise it is a gap, never a decrease.
* **The trend of the total:** the least-squares slope in GB per day over the 7 days up to the newest record. It uses
  complete values only, and needs at least 4 points spanning at least 24 hours. Otherwise it is `INSUFFICIENT_DATA`.
  * An incomplete or failed collection, a damaged record and a record marked `CLOCK_SKEW` are gaps.
  * A group's trend uses the collections in which that group was measured completely.
  * The "other" group (the groups summed past the 64 largest) counts in the total and has no trend of its own.
* **Up to 5 groups** (provider / project / class) with the largest trend.
* **The thresholds:** the defaults, the file `monitor.json`, or the file refused with its code and reason.
* **The alerts,** each followed by the command it names. **An alert never runs anything.** It only says which command
  to run yourself, and that command then makes its own collection, plan and confirmation.

| Alert | Fires when the value is strictly greater than | Command it names |
|---|---|---|
| `MON_TOTAL` | the latest complete total > `totalGiB` | `agent-temp preview`, then `agent-temp clean` |
| `MON_GROWTH` | the trend of the total > `growthGiBPerDay` (never with `INSUFFICIENT_DATA`) | `agent-temp audit` |
| `MON_ORPHAN_SUSPECTED` | the bytes in `ORPHAN_SUSPECTED` groups of the latest complete record > `orphanSuspectedGiB` | `agent-temp preview`, then `agent-temp isolate` |
| `MON_LIVENESS_UNKNOWN` | the bytes in `LIVENESS_UNKNOWN` groups of the latest complete record > `livenessUnknownGiB` | `agent-temp diagnose` |
| `MON_COLLECTION` | none of the `failedCollections` newest collections is complete (a damaged record counts as not complete) | `agent-temp monitor status` |
| `MON_CONFIG_INVALID` | `monitor.json` was refused; the defaults are in use | this section |

The two class sums leave out the "other" group, so they are a lower bound when a record summed any groups. A synthetic
example with the gate open (planted values, not a real profile):

```
Monitoring is available in this copy. agent-temp monitor enable creates your own collection task, after showing its plan and asking for its phrase.
Collection task: none for this user.
To create it (not elevated): agent-temp monitor enable
History: 6 record(s) in %LOCALAPPDATA%\AgentTempManager\Monitor.
Latest: 2026-11-18 12:00 UTC, outcome OK, 2 group(s), 15360 MB measured.
Latest complete total: 15 GB (2026-11-18 12:00 UTC).
Since the collection before: +1 GB.
Trend of the total (7 days, 5 complete points): 1 GB per day.
Groups with the largest trend (at most 5):
  claude-code / proj / RECENT: 1 GB per day.
  claude-code / other / ORPHAN_SUSPECTED: 0 GB per day.
Thresholds: from monitor.json.
MON_TOTAL: the latest complete total, 15 GB, is over the threshold of 14.5 GB.
  To look further, run it yourself: agent-temp preview, then agent-temp clean. This alert ran nothing.
MON_GROWTH: the total grows 1 GB per day, over the threshold of 0.5 GB per day.
  To look further, run it yourself: agent-temp audit. This alert ran nothing.
Nothing was collected, created or changed.
```

### `monitor.json`: the thresholds

The thresholds live in `monitor.json`, in the history folder `%LOCALAPPDATA%\AgentTempManager\Monitor`, one per user.
**You write it yourself; the product never writes, creates or fixes it** (V0.5 has no command for it). Without the file,
the defaults apply and there is no alert about it. Every member is optional; a missing member takes its default:

| Member | Default | Bounds (both ends included) |
|---|---|---|
| `totalGiB` | 20 | 1 to 4096 |
| `growthGiBPerDay` | 2 | 0.1 to 1024 |
| `orphanSuspectedGiB` | 5 | 1 to 4096 |
| `livenessUnknownGiB` | 5 | 1 to 4096 |
| `failedCollections` | 3 | 2 to 30, a whole number (`3.0` is accepted, `3.5` is not) |

The trend window is fixed at 7 days and has no member. A synthetic example:

```json
{ "totalGiB": 30, "growthGiBPerDay": 1.5, "failedCollections": 4 }
```

The file is refused **as a whole**, and then the defaults apply and `MON_CONFIG_INVALID` shows the reason, when:

* it, or a folder in the history folder's path, is a reparse point: `REPARSE`;
* it is a folder: `NOT_A_FILE`;
* its owner is not you (or your token's default owner, the Administrators group for an elevated administrator):
  `OWNER`;
* it is over 4 KB (4096 bytes): `SIZE`;
* it is not strict UTF-8: `ENCODING`. One leading byte order mark is accepted, since Windows PowerShell 5.1's
  `Out-File -Encoding utf8` writes one;
* it is not JSON: `JSON`;
* it is JSON, but not an object: `TYPE`;
* it has a member not in the table: `UNKNOWN_KEY`. Names are case-sensitive, so `TotalGiB` is unknown;
* a value is not a number (a string, `true`, `null`, an array): `TYPE`;
* a value is outside its bounds: `RANGE`.

A refused file is left exactly as it is. Changing the file changes only which alerts show; an alert authorizes nothing.
The rotation of the history never removes `monitor.json`. A `monitor.json` with another owner, or a folder or junction
with that name, makes the rotation refuse, as any other unexpected item does.

Exit codes of `monitor`: `0` for `monitor status`, the task created and read back by `monitor enable`, or the task
removed and read back absent by `monitor disable` (whatever happened to the folder), or every history file removed by
`monitor remove-history` (whatever happened to the folder); `2` usage (no subverb, a subverb other than `status`,
`enable`, `disable` or `remove-history`, an option `monitor` does not take, `-IntervalHours` with `status`, `disable`
or `remove-history`, or an interval not in the list); `3` `monitor enable`, `monitor disable` or `monitor
remove-history` refused, not confirmed or stopped (nothing scheduled or removed, except the files a stopped
`remove-history` names in its count; always refused, with the gate closed); `6` `monitor enable`, `monitor disable` or
`monitor remove-history` needs an interactive console. `monitor status`, `monitor disable` and `monitor
remove-history` take no option other than `-Lang` and the display switches `-NoProgress` and `-Ascii`; `monitor
enable` also takes `-IntervalHours`.

### In the TUI, the GUI and the audit (V0.5 M5; view only)

The history and the alerts also appear in the TUI, the desktop GUI (`agent-temp gui`, disabled in every copy) and
`agent-temp audit`. None of them runs, schedules, writes or removes anything. With the monitoring gate closed, as in
every copy, they say that monitoring is not available in this release, show the history as it is (normally none), and
show no trend, threshold or alert.

* **TUI, key `M`** ("Preventive monitoring: history and alerts (view only)"). Entering the screen reads once and shows
  the lines of `monitor status`, the state of your collection task included. `U` reads again, and so does leaving and
  pressing `M` again. Scrolling reads nothing. A failed read shows its code only.
* **GUI, the "Preventive monitoring" area** (key `M` or its button; `Alt+M` stays the live monitoring check box). Each
  opening reads once. The area shows the lines of `monitor status` without the task's. With the gate open it also
  shows the latest complete total and the change, the trend, up to 5 groups, the thresholds' state and the alerts.
  Each command an alert names is text for you to run in a console. The live monitoring's refresh and `F5` never read
  it. A failed read leaves the window where it is, with the code only.
* **`agent-temp audit`.** With the gate open (no copy), at most one line under the first header, for example
  `Preventive monitoring: 2 alert(s) (MON_TOTAL, MON_GROWTH). See agent-temp monitor status; this audit ran nothing
  for them.` A failed read gives one line with its code, and the audit goes on. There is no line when there is no
  alert. With the gate closed (every copy) nothing of the monitoring is read and the audit's output is unchanged. The
  line is never part of `-ExportJson` and never changes the exit code.

## Verify (installed copy)

`agent-temp verify` checks every file the installation's `manifest.json` lists (SHA-256) before any product code is
loaded, and prints one line per item: `OK`, or `FAIL` for a problem (exit code `5`, nothing loaded).

It also walks the whole installation, hidden and system files included, and prints a yellow `WARN` line, with the
relative name only, for:

* a file the manifest does not list (`manifest.json` and `install-state.json` at the root are the only files left out);
* a reparse point (junction, symbolic link), which is never followed;
* a folder that cannot be listed (no exception text).

The summary says how many warnings there were. **Warnings never change the exit code**: `0` with no problem, even with
warnings; `5` with problems (and the warnings are shown too); `4` outside an installation. An unlisted file is never
loaded: the launcher loads a fixed list of libraries and only the listed providers, and an unlisted provider is a
problem (`FAIL`), not a warning. The other commands do not walk the installation. Example (synthetic):

```text
  OK   providers\ClaudeDesktop.ps1
  WARN lib\notes.txt (not in manifest / fora do manifesto)
Version x.y.z; 0 mismatching file(s).
1 warning(s) (WARN: not covered by the manifest and never loaded; the exit code does not change).
```

## Exit codes

`0` ok (for `diagnose`, partial coverage included; `monitor status`) · `1` unknown command · `2` invalid clean invocation, or a refused
`-PseudonymKeyFile`, or `authorize` without `-Path`/`-RecordFile`, or `isolate` without a path or with
`-IncludeOtherUsers`, or a `recover` usage error (`RECOVERY_NOT_DECLARED` included), or a `monitor` usage error · `3` clean aborted (nothing
deleted), `isolate`, `quarantine restore` or `quarantine purge` stopped
after the plan (nothing moved or purged), `quarantine schedule-autopurge` or `unschedule-autopurge` refused or not
confirmed (nothing scheduled or removed), `monitor enable` or `monitor disable` refused or not confirmed (nothing scheduled or removed), `recover plan` refused (nothing changed), or, only with
deletion enabled (not in any published copy), stopped before completing (Clean log, above); `authorize`: nothing recorded ·
`4` no manifest (source checkout, `verify` only) · `5` integrity mismatch (a listed file missing, altered or
unreadable, a missing or unreadable `providers` directory, an unlisted library or provider, an unreadable or
invalid manifest, or an installed copy without one; nothing is loaded) · `6` TUI, `authorize`, `quarantine schedule-autopurge` or `unschedule-autopurge`, `monitor enable` or `monitor disable`, or `clean` with real deletion enabled (not in any published copy) needs an interactive console · `7` `gui`: the desktop GUI gate is closed (`GUI_GATE_CLOSED`, every copy; no window) · `8` `gui`: no window can be shown here (`GUI_NOT_STA`, `GUI_NO_INTERACTIVE_DESKTOP`, `GUI_WINFORMS_UNAVAILABLE`) · `10` unexpected error,
or a `diagnose` export refused or not written (nothing deleted because of it), or a failed `recover` collection
(nothing changed). `recover start` and `recover undo` also use `20` to `31` and `40` to `44`, listed under Recover
(above); in every copy they end with `27`.

## Project names

Project recognition is informational and never affects eligibility. Order: the owner's home profile
(`Perfil (home)`), optional site rules, the agent's own session evidence (a recorded working directory whose
scope matches; conflicting evidence is ignored), otherwise **`Projeto não identificado`** (reports keep each
unidentified scope separate and show its directory name). No configuration is required.

### Optional site-specific rules

Project recognition is informational. Put local rules in `config\projects.local.json`
(see `projects.local.example.json`) or pass `-ProjectsFile` to the installer. This file is never versioned.
