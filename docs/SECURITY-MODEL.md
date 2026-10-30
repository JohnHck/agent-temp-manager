# Security model

## Principles

1. **Read first, delete last.** `audit` and `preview` never create, modify, move, rename or delete anything
   inside audited paths. `preview` opens short-lived handles (no data access) only on eligible candidates
   to detect files in use, and closes them immediately.
2. **Fail closed.** Any error, ambiguity, incomplete measurement or unobservable condition blocks deletion.
3. **No authority from classification.** `ORPHAN_SUSPECTED` is informational; age > 72 h and absence of
   references never prove inactivity.
4. **Human approval of exact paths.** Cleanup requires an explicit allowlist of exact absolute paths, an exact
   plan display and a typed phrase (`APAGAR <N> CAMINHOS`; past the deletion gate, V0.3 AUT-2: per-root declarations
   and `APAGAR <N> CAMINHOS <plan id>` bound to the exact set).

## Permissions are distinct

| Capability | Granted by |
|---|---|
| Run the tool | Being able to execute the installed files (all users; install dir is read-only for them). |
| See other users' data | Windows ACLs only. Non-administrators see other profiles as inaccessible ("cobertura incompleta"). |
| Audit a directory | Read access to it and to every ancestor's attributes. |
| Delete | Every gate below. In practice deletion requires an **elevated administrator**: without elevation, processes of other accounts are unobservable, so the process-coverage gate always blocks. Other users' paths additionally require `-IncludeOtherUsers`. Permissive ACLs never count as authorization. |

The tool never grants permissions, never changes ACLs or ownership, never enables privileges
(backup/restore/take-ownership), and never elevates itself.

## Privileges and UAC

Requirements PRIV-1 to PRIV-11, with the status of each one in V0.1 (implemented, partial or planned) and what has
been validated, are in [ELEVATION.md](ELEVATION.md).

Current behaviour (V0.1):

* **Manual elevation.** The tool never elevates itself and never handles credentials; only the installer scripts
  need an elevated PowerShell, which the user opens through the Windows UAC prompt, and they refuse to run without
  it before changing anything.
* Everything else runs without administrative rights; missing rights reduce coverage and are reported, never
  guessed.
* Decisions use the **process** identity. After elevating with another account's credentials, that is the
  administrator's account, so the requesting user's profile is treated as another user's.

Requirements for any future elevated or destructive operation: re-validate inputs, paths, ACLs and installed-file
integrity in the process that acts, and still require the typed confirmation of the exact plan there: consenting to
UAC authorizes a process, not an operation. Changing the elevation model is a documented decision before V0.3.

## Release gate (V0.1)

`Engine.Clean.ps1` ships with `$script:AtmRealDeletionEnabled = $false`. `clean` (CLI and TUI) validates the
allowlist, runs every gate and presents the exact plan, then stops with `EXCLUSAO_REAL_DESABILITADA_V0_1`
**without asking for confirmation**. No parameter, environment variable, configuration file or UI option can
change it; enabling deletion requires a code change in the administrator-owned, manifest-verified install,
released under a specific authorization. The automated suite flips it only in its own process, against its
isolated sandbox.

## Clean gates (all must pass, re-run immediately before each deletion)

1. Allowlist syntax: absolute local path, no wildcards, no `.`/`..`, no ADS, no 8.3 short names, no trailing
   dots/spaces/separators, canonical (`GetFullPath` round-trip), exact case.
2. Scope: the path must be an inventoried `SessionRoot` partition (profile -> TEMP -> base -> scope -> root);
   profile, TEMP, base, scope and drive roots are refused.
3. Ancestor chain: every component exists, is readable and is not a reparse point; fixed drive only.
4. Ownership and ACL: the root, its scope directory and the base must be owned by the profile SID and must
   not grant write/delete/re-permission rights to anyone except that SID, SYSTEM, Administrators,
   TrustedInstaller, CREATOR OWNER and OWNER RIGHTS. `%WINDIR%\Temp` is always treated as shared. Other
   users require elevation + explicit switch.
5. Liveness: no direct command-line reference, no live session in the agent registry, no recent transcript,
   no ancestor/ambiguous reference, registry and config readable, class `ORPHAN_SUSPECTED` without flags.
6. Process coverage: must be complete. There is no override. Processes of other accounts (services,
   automations, elevated sessions) are invisible to non-administrators, and protected processes stay
   uninspectable even for administrators, so on a typical Windows host this gate blocks deletion.
7. Measurement: complete, no read errors, no reparse points, no read-only/system files.
8. Handle probe: every file and directory opened with `DELETE` access and share mode 0 (no data access);
   any sharing violation or access denial blocks.
9. Fingerprint: unchanged since preview (if supplied) and since confirmation.
10. Pinned plan: once the deleter has pinned the tree, its own enumeration must match the validated measurement
    exactly (files, directories, bytes, newest write); each file must still have its planned write time when
    opened exclusively for deletion.

Deletion itself (`AtmDeleter`) never trusts names between checks:

* every ancestor of the root (volume root excluded) and every directory of the tree is opened top-down and
  **kept open without `FILE_SHARE_DELETE`** for the whole operation, so no process can rename or delete any of
  them; tree directories are additionally pinned **without `FILE_SHARE_WRITE`**. Share modes do **not** stop
  another handle with `FILE_WRITE_ATTRIBUTES` from converting an emptied directory into a junction in place
  (`FSCTL_SET_REPARSE_POINT`; corrected in FINAL-A, review M-1, finding F-10): that conversion is refused by the
  re-checks below (still a directory, not a reparse point) and by the final-path check of every opened file;
* each pinned directory is re-checked through its handle (still a directory, not a reparse point) before it
  is enumerated and before it is deleted;
* each handle is verified (directory, not a reparse point, `GetFinalPathNameByHandle` equals the expected
  path, never a remote path);
* files are opened with share mode 0, re-verified and deleted **through the handle**
  (`FileDispositionInfo`); directories are deleted bottom-up through their pinned handles;
* it aborts before deleting anything on a reparse point, protected file or enumeration error, and stops at
  the first failure; entries created after planning make the parent removal fail instead of being deleted.

## Process control (V0.2, D-4)

The diagnostics engine runs Git (ADR-0006) only through one native runner (`AtmJobRunner` in `lib\Native.cs`,
called by `Invoke-AtmGitCommand`):

* Each run creates a Windows job object of its own. The child is created **inside** that job
  (`PROC_THREAD_ATTRIBUTE_JOB_LIST`): when that is not possible nothing runs, so no process ever exists outside the
  job. The job kills its processes when its handle is closed, limits job memory and active processes, allows no
  breakaway, and its limits are read back before anything starts. The child inherits only stdin (`NUL`), stdout and
  stderr.
* On timeout the runner terminates **that job** (`TerminateJobObject` on the handle it created), and the job's
  processes end when the handle is closed at the end of every run. This is the only termination in the product: no
  other process is opened, signalled or terminated (`TerminateProcess`, `OpenProcess`, `CreateRemoteThread` are
  absent from `Native.cs`, checked by the layering test). Pre-existing processes are never affected.
* **Result contract (V0.2 stage 1, additive).** The runner's result reports:
  * **Termination.**
    * `TerminationRequested` is set before the first `TerminateJobObject` call, at the deadline or when a member still
      held the output after the child ended (at most two calls).
    * `TerminationFailed` means termination was requested and no call succeeded (`JobTerminated` false).
    * `TerminationWin32Error` is the error of the **first** refused call, read right after it and kept even if a later
      call succeeded; `-1` when that call gave no error code, `0` only when no call was refused.
    * A refusal followed by a success therefore reads `TerminationFailed` false, `JobTerminated` true and a non-zero
      error: the refusal never disappears.
  * **Output collection.** `ReadersCompleted` is true when both readers stopped before the result was built.
    `ReaderFaulted` is true when one stopped on a read error; an error is never taken for the end of output, while a
    broken pipe is the end of output.
  * **Active processes.** `ActiveProcessesAtEnd` comes from the job's own accounting after the readers' joins.
    * While members are still active, the count is polled for at most 2 s. A console child's console host is a job
      member that leaves shortly after its last client.
    * What is still active then is reported, and those members end when the job handle closes.
    * `-1` means unknown (a query failed), never `0`. No process is looked up or opened.

  The bytes kept are a consistent copy taken under the reader's lock, which never covers a blocking read or a wait.
  Every wait is bounded. `KILL_ON_JOB_CLOSE` is a backstop, not evidence that a termination succeeded.

  `Invoke-AtmGitCommand` returns the gravest condition as `Reason` and all of them, most severe first, in
  `Conditions`. One table for both consumers:

  | Condition | Git result | Test harness |
  |---|---|---|
  | not started | `FAILED` `GIT_JOB_UNAVAILABLE` / `GIT_START_FAILED` | `CHILD_RUNNER_<code>` |
  | termination requested, no call succeeded | `FAILED` `GIT_JOB_TERMINATE_FAILED` | `CHILD_RUNNER_JOB_TERMINATE_FAILED` |
  | output not read to its end | `PARTIAL` `GIT_OUTPUT_INCOMPLETE` (below the next two) | `CHILD_RUNNER_OUTPUT_INCOMPLETE` |
  | deadline | `TIMEOUT` `GIT_TIMEOUT` | `CHILD_TIMEOUT` |
  | exit code not 0 | `FAILED`, classified from the error text | exit code reported |
  | members terminated after the exit | `PARTIAL` `GIT_JOB_TERMINATED_AFTER_EXIT` | accepted, `JobTerminated` kept |
  | members still active at the end | `PARTIAL` `GIT_JOB_ACTIVE_AT_END` | accepted |
  | active count unknown | `PARTIAL` `GIT_JOB_STATE_UNKNOWN` | accepted |
  | truncation | `PARTIAL` `GIT_OUTPUT_TRUNCATED` | `[SAIDA_TRUNCADA]` |

  The Git column's precedence is: termination failed > deadline > exit code > incomplete output > terminated after
  the exit > active at the end > count unknown > truncation.

  Deliberate differences:
  * **Incomplete output.** It ranks above the deadline for the harness, which needs the whole output: a test cannot
    pass on a partial one. For Git a deadline stays `TIMEOUT`, with `GIT_OUTPUT_INCOMPLETE` kept in `Conditions`.
  * **The last three job conditions.** They are evidence about the job, not about the output, so they fail nothing
    in the harness. Git reports them, because a Git observation is complete evidence only when the job also ended
    cleanly.

  **Exit codes.** For every allowed Git operation, 0 is the only success; any other code is `FAILED`. No operation in
  this contract accepts another code: the callers run `--version`, `status` and `rev-parse`. `cat-file -e` and
  `config` are allowed but not called; they exit 1 for "not found", which would be `GIT_COMMAND_FAILED`.

  `COMPLETE` requires exit code 0 and no condition. An unknown active count is never `COMPLETE`.

  **Coverage.** The local-work status coverage (`StatusCoverage`: `Status`, `Reason`) carries only the gravest reason
  of the Git call. The secondary conditions stay in the Git call's `Conditions` and do not follow into that schema.

  **What is tested where.**
  * Real runs inside the job, for:
    * normal exit, truncation and the deadline;
    * a descendant holding the output;
    * a descendant active at the end without the output;
    * a read error on a sandbox file without read access (`UnauthorizedAccessException`);
    * an `IOException` from a byte range locked in a sandbox file.
  * The propagation to the local-work status coverage, on a sandbox repository.
  * A refused termination, a refusal followed by a success, a reader still running in a real run, and a failed job
    accounting query are tested on synthetic results only; those real failures are not tested.

  There is no switch, variable or parameter that simulates a result in the product.
* Only allow-listed, read-only Git commands are started, with `--no-optional-locks` (the read commands take no lock,
  so there is none to leave behind when one is terminated), every transport refused by name on the command line
  (`protocol.allow=never` plus `protocol.<file|git|ssh|http|https|ext>.allow=never`, which a repository's own setting
  cannot override) and `GIT_NO_LAZY_FETCH=1` (effective from the Git version that supports it; the minimum version is
  fixed when object reads are added in P3-C). The working directory must have no reparse point in its path, so the
  discovery ceiling cannot be bypassed through a junction.
* **Worktree diagnostics gate (P3-B0):** reading repositories and running Git in them are both behind
  `$script:AtmWorktreeDiagnosticsEnabled`, `$false` in every shipped copy (checked by the test suite and the install
  e2e). Only `git --version` runs while it is closed. Opening it for real repositories is a maintainer decision.
* **Services (P2-A, ADR-0005):** one local `Get-CimInstance Win32_Service` query, only for the exact names providers
  declare, the allowed properties only, with a CIM operation timeout (enforced by CIM; not a guaranteed cancellation).
  No service is started, stopped, paused or reconfigured; no CIM method is invoked; no other machine and no CIM
  session is used; nothing is run from a service command line (static tests). `PathName` is reduced in memory to the
  executable (full path only under the Windows or program files folders, otherwise the file name) and dropped. It
  is read as untrusted text only: no existence, attribute or metadata check, nothing opened or resolved (a fixed drive
  letter does not prove that a folder on the way is not redirected); an unquoted candidate with white space, a
  network or device form or an unknown variable gives a code. Its arguments never reach evidence, coverage, the
  report, the JSON or an error (adversarial tests, including misquoted command lines and later `.exe` arguments).
  Account names are never exported: only the kind, and a standard identifier for the three built-in service accounts
  (ADR-0012). A service PID is linked to a process only
  when the snapshot taken after the query holds it with a verified identity created before the query; no process is
  opened for it. The order of the query end and the snapshot start is compared on the monotonic clock (FINAL-A-S,
  F-11: the UTC readings mixed two clocks, so Windows PowerShell 5.1 refused proved links where its clock is coarse;
  an unproved link was never accepted).
* **Virtualization (P2-B, ADR-0005):** local read-only CIM queries only: the hypervisor flag, the `__NAMESPACE`
  instances that list `root\virtualization\v2`, the `vmms` service state, and `Msvm_ComputerSystem` only when the
  namespace is listed and `vmms` is running (its provider runs in `vmms.exe`; a stopped service is never started by
  a query of this tool). No VM operation (`Start-VM`, `Stop-VM`, `Save-VM`, `Checkpoint-VM`, `RequestStateChange`),
  no CIM method, no Hyper-V module, no remote CIM, no disk or configuration class (static tests). VM names, GUIDs,
  the host name and raw worker process names never leave memory (keyed pseudonyms). No virtualization state
  authorizes deleting anything, stopping a service or shutting down a virtual machine.
* **Claude Desktop provider (P2-C):** declares only published or publicly reported signatures (a process marker, the
  `CoworkVMService` name) and reads nothing of the installation: no file, log, registry key, configuration or package
  database. Its service and processes are observed through the read-only collectors; nothing is started, stopped,
  reconfigured or terminated, and no command line, account name, profile path or VM name is exported.
* **Dependency graph (P4-A, ADR-0002):** a correlation layer over the evidence already collected in the run: no
  query, file read, process access or collector call of its own (static test). It lives in memory for the run and is
  not persisted; it exports only keys, provider ids, relations, strengths, codes and coverage. Its summaries are not
  finding states and authorize nothing: no deletion, termination or state change follows from them.
* **Paths from other users (FINAL-A, F-01):** values read from other users' registry or environment (TEMP,
  `CLAUDE_CONFIG_DIR`, `CLAUDE_CODE_TMPDIR`) are used only in a drive-absolute form on a non-network drive letter;
  UNC, device and WebDAV forms are refused before any file-system call (an elevated run never authenticates to a host a
  user chose), and the gap is reported (base `INVALID`, session evidence unreadable). Collected names shown on the console
  have control characters replaced (F-03).
* **Partition states (P4-B, ADR-0002 rule 6):** temporary partitions and worktrees take their diagnose state from the
  graph of the same run (`IN_USE` only with a `DIRECT` edge from a verified process; `UNKNOWN` otherwise;
  `NO_DEPENDENCY_OBSERVED` only with conclusive coverage, which a V0.2 run never has). Nothing is collected for it,
  and no diagnose state is read by the audit, the preview or `clean`.
* **Diagnose export gate (P5-B-S):** `$script:AtmDiagnoseExportEnabled`, `$false` in every shipped copy (single
  assignment in `Report.ps1`; no option, environment variable or configuration file; checked by the suite and the
  install e2e). Closed, `diagnose -ExportJson` is refused before anything is collected or checked
  (`EXPORT_SECURITY_GATE_CLOSED`, exit code 10) and no file is created; the destination check and the writer refuse
  on their own too. Reason (P5-B-S): the destination was checked by name and the file created by name, so a folder
  replaced by a junction in between redirected the new file (a harness counter-proof still shows it for a by-name
  creation); the document holds the machine name, the account and its SID. **FINAL-A: mitigated in code, export still
  disabled.** The writer now pins the folder and every ancestor by handle (no reparse point, no redirection, not
  renamable or replaceable while pinned; a folder turned into a junction in place through another handle is refused by
  the re-checks), evaluates the destination policy inside that
  window, creates the file relative to the folder handle (`NtCreateFile`, `RootDirectory`, `OBJ_DONT_REPARSE`,
  `FILE_CREATE`) with a protected DACL, verifies it through its handle and only then writes (release/V0.2-SECURITY-AUDIT,
  X-01, with fixture evidence and limits). Opening the gate remains a maintainer decision; the fixtures also run on
  Windows 11 ARM64 with Windows PowerShell 5.1; ARM64 with PowerShell 7 is NOT TESTED.
* **Diagnose export, when its gate is open (tests only, P5-B; disabled in every copy):** written only with
  `-ExportJson`, to a new file (never overwrites) at an absolute local path whose parent chain has no reparse point,
  not on a `subst` drive, outside every audited base and not inside a Git repository or worktree (an ancestor holding
  `.git`, or a bare repository; existence checks only, no Git; an ancestor that cannot be checked refuses), through the
  pinned writer above. A junction planted at the destination is refused; so is a file symbolic link there (tested on
  the CI runners; NOT TESTED locally, where creating one needs a privilege or Developer Mode).
* **Audit export (`audit -ExportJson`, V0.1, enabled):** keeps its V0.1 rules and, since FINAL-A, creates its file
  through the same pinned writer (F-02: a race or a `subst` alias is refused; the stricter creation is listed in USAGE).
  The V0.1 refusal message stays (`cli.exportRefused`, exit code 10), now preceded by the refusal code.
* **Export outcomes (both writers, FINAL-A-S reconciliation):** (1) refused before any file is created: nothing is
  created and the refusal code is printed (never an exception message); (2) refused after the file was created (codes
  `EXPORT_CREATE_CREATED_*`: the folder changed after the creation, or verifying or writing failed): an empty or partial
  file may remain at the destination; the CLI says so and never claims that no file was created; nothing more is
  written to it and nothing is deleted automatically (files are removed only inside test fixtures); (3) success: the
  file was created, verified through its handle and written. Every refusal fails closed. Residuals: the X-01 limits
  (volume root not pinned; a refusal after the creation can leave a file) and the reads by textual path after earlier
  checks (F-01 residual) are listed in release/V0.2-SECURITY-AUDIT. `clean -LogFile` (F-04): the published 0.2.0
  still appends by name (latent while the deletion gate is closed); V0.3 T1 replaces it, unreleased (next item).
* **Clean log (V0.3 T1, F-04; unreleased; reached only past the deletion gate):** one new file per run, created
  relative to the pinned folder (`OBJ_DONT_REPARSE`, `FILE_CREATE`, reparse points refused, protected DACL: owner,
  SYSTEM, Administrators) and kept open for the run: append-only access, write-through, shared for reading only. Before
  each record the handle is checked again (plain file, one link, same volume, final path as created); each record is
  flushed. A folder outside the policy (owner, or any other account able to add or delete entries or change its
  permissions) is refused and never changed. Order: log and plan records, then the confirmation (recorded), then per
  root: revalidation, `intent` flushed, deleter, `result` flushed. Anything but a complete, verified deletion, or any log
  failure, stops the run; `run-end` and close failures never replace the main reason. Limits: a flush does not
  guarantee durability across a power loss or a disk cache; an `intent` without a `result` is an unknown outcome; the
  folder is pinned only for the run; nothing is undone (no rollback). Who it protects against: another account cannot
  open the file (protected DACL) nor add or delete entries in its folder (folder policy). Processes of the same identity,
  SYSTEM and Administrators are not stopped by that: while the run lasts the share mode (read only, no delete) refuses
  another writer, a rename and a delete, but rights outside share modes (such as `FILE_WRITE_ATTRIBUTES`) remain, so a
  hard link to the open log is not excluded by construction (the standard tool was refused in a local trial; not
  guaranteed, not tested in CI). The link count, volume and final path are checked before each write: that detects a
  change made before the check, never one made between the check and the write; after the run the same identity can
  change or delete the log. Test seams (stand-in deleter, presence check and
  writer) exist only in `Invoke-AtmClean`, past the gate, and no other file references them (static test).
* **Discard authorization (V0.3 AUT-1; unreleased):** `agent-temp authorize` records the operator's declaration for ONE
  root bound to the plan just presented (`Invoke-AtmDiscardAuthorization`, Engine.Clean.ps1): three separate confirmations
  (task finished; the content decision, either "needed results preserved" (`OPERATOR_DECLARED`) or "nothing needed"
  (`NOTHING_NEEDED_DISCARD_ACCEPTED`); discard of the content presented), an interactive console required by the CLI
  (never proof of a person: B6 stays open), the plan presented again and compared before writing (any detected
  difference refuses, the justification included in a stable semantic form: `Get-AtmDiscardReasonSignature`), and a new
  file from the pinned writer (schema `atm.discard-authorization/2`). It is not a credential: nothing in the product
  reads it, no gate changes, and it makes nothing eligible; it records the technical result apart from the declarations.
  The association is the naming convention (root name = session id) corroborated by a transcript of the same id; the
  task and the content decision are the operator's declarations. `preservation.basis` never takes `TOOL_VERIFIED`:
  that value is reserved for a verification by the product, which does not exist; a typed phrase, a manifest path or an
  external report never produces it. B1 is recorded apart (`technical.processCoverage`): the coverage observed and
  the B1 gate's state in that evaluation (`BLOCKED`, `PASSED`, or `NOT_EVALUATED` when an earlier gate returned first;
  the gate only reports it, its order and behaviour are unchanged). The identity recorded is the process's (`identifiesRespondent: false`); the
  interaction block keeps the caller and its console requirement as reported (not verified) and the engine's own console
  observation in that call; a caller requiring a console when none is observed is refused before any question.
  The revalidation's semantic form includes the process keys (`pid@creationTicksUtc`, field `Sources` of each runtime
  refusal), so the same refusal code from another process is a divergence; it leaves out times and localized text.
  Gaps: a refusal without a process key (coverage gaps, an unverified session) is compared by its other fields only,
  and the V0.1 evidence lines are not compared (their references reach the comparison only through runtime refusals);
  not every new relevant evidence is guaranteed to be detected. Recording succeeded only when the command returns success (line written, flushed, file closed); after a
  failure past the creation the file is kept as it is, never reopened or removed, and may hold a complete line: neither
  the line nor the file proves a recording, and the format provides no atomicity or authenticity. Limits: statistics are
  compared, not content (a write that keeps every statistic is not detected); read-only use is not observed; the record
  can be changed afterwards by processes of the same identity. **Approved by the maintainer as a priority: finished task and discardable content;
  not approved yet: the code of any exception.** The exact points a future decision would change:
  * **B1:** `Get-AtmCandidateGate` (Engine.Clean.ps1), the block `if (-not $Inventory.ProcessCoverageComplete)` that adds
    `COBERTURA_DE_PROCESSOS_INCOMPLETA` for every root when any command line cannot be read.
  * **RECENT:** `Set-AtmClassification` (Engine.Audit.ps1) sets the class `RECENT` when the newest write is less than
    `$script:AtmRecentHours` (72) old, and `Get-AtmCandidateGate` blocks `ACTIVE_EVIDENCE` and `RECENT` before every
    other gate; so a root written in the last 72 h cannot be evaluated as eligible. Age is shown as information only.
* **Plan-bound confirmation in clean (V0.3 AUT-2; unreleased; past the deletion gate only):** `Invoke-AtmCleanCore`
  (no other executor) requires an interactive console observed by the engine (`Test-AtmDiscardConsoleObserved`; the
  suite replaces it through `$script:AtmCleanConsoleSource`, `$null` in every copy, assigned once, read only past the
  gate) and checked by the CLI; asks, for each root of the executable set with its path, the task and the AUT-1 content
  decision (shared helpers `Get-AtmContentDecisions`, `Get-AtmPreservationBasis`, `Test-AtmTypedPhrase`); then one phrase
  bound to the plan id (full SHA-256 of the run id and every root's path and statistics, kept in the state and the
  log; the typed phrase carries only its first 8 characters, which is neither the full hash, nor a signature, nor proof
  of who typed it) and the exact count. Declarations and
  confirmation are written and flushed before any `intent`; a fresh plan check before execution refuses any change
  (`PLAN_CHANGED_BEFORE_EXECUTION`) instead of adjusting the plan; a per-root revalidation refusal after the
  confirmation stops the run before that root (`REVALIDATION_REFUSED`, maintainer's decision), as a non-complete outcome
  or a log failure does. Not all-or-nothing and no rollback: earlier operations stay done; the result and `run-end`
  name the completed operations, the root that stopped the run and the roots not attempted. With the gate
  closed the plan-only flow is unchanged (no question, console or log). No AUT-1 record is read. Limits: declarations
  are not verified; the console is not proof of presence; the identity is the process's; the plan id rests on
  statistics (a write that keeps them all is not seen); the users/sessions/elevation matrix is not tested.
* **Runtime evidence as refusals (V0.3 B2-1; unreleased):** preview, the clean plan and each root's revalidation run the
  V0.2 collectors once over the inventory just taken (`Get-AtmRuntimeRefusals`, Engine.Diagnose.ps1; the clean engine
  only consumes its refusals and never reads the dependency correlation itself). A refusal can only keep or raise a
  category (BLOCKED > INVESTIGATE > ELIGIBLE); the V0.1 gates, B1 (process coverage) included, are unchanged and run
  first; the class of a partition is never changed. Blocking needs positive evidence tied to the root: a DIRECT edge
  from a verified process (`REFERENCES_PATH`; `HOLDS_HANDLE_IN` and `WORKING_DIRECTORY_IN` never occur in a shipped
  copy) or the LIVE session whose id is the root's name. Ambiguous or derived relations, unverified sessions, key
  collisions, unreadable references, correlation limits and a dependent collector that FAILED or timed out are
  INVESTIGATE. Services and virtual machines have no edge to a partition, so they never refuse a root by themselves.
  Gaps that are the same for every root are run notices. What B2-1 adds over V0.1 is narrow: V0.1 already blocks direct
  references and live sessions; B2-1 adds verified identities and provenance, a stricter session check, and refusals
  for failed or timed-out collection. **It adds reasons to refuse; it does not demonstrate non-use and does not resolve
  the authorization of real deletion.**
* **Clean lock (V0.3 B8; unreleased; past the deletion gate only):** `Invoke-AtmClean` takes the named kernel mutex
  `Global\AgentTempManager.Clean` (`AtmCleanLock`, Native.cs) without waiting, before the first inventory, and releases it
  last, after the log, in a `finally`, once and only by the owner thread; a nested acquisition in the same process is
  refused without touching the outer one. The name is fixed (no local, per-user or random fallback; the suite uses its
  own `Global\AgentTempManager.Test.<hex>` names, never the product name). `CreateMutexExW` creates or opens the name
  atomically; the descriptor (protected DACL: SYSTEM and Administrators, Authenticated Users only `SYNCHRONIZE` and
  `READ_CONTROL`; Medium mandatory label so elevated and non-elevated runs share it) applies only when the call creates
  the object, and the DACL and label of the object behind the handle, created or existing, are checked against that
  policy and never changed; ownership is decided only by the zero-timeout wait, which is atomic. Requested rights:
  `SYNCHRONIZE` and `READ_CONTROL`. An existing object of another type, a denied access or a policy mismatch is a
  refusal. An abandoned mutex (`WAIT_ABANDONED`) is released at once and the run stops (`CLEAN_LOCK_ABANDONED`); that state
  exists only while another handle keeps the object alive (the object is destroyed with its last handle, and the next
  run then creates a new one with no trace), so it is an opportunistic signal, never a persistent record of an
  interruption (that evidence is the T1 log). `MUTEX_MODIFY_STATE` is not requested nor granted: Microsoft documents it
  as reserved, `SYNCHRONIZE` as the right to wait, and `ReleaseMutex` as requiring ownership only; release through an
  opened handle with `SYNCHRONIZE | READ_CONTROL` is tested for processes of the same identity only. Mutual exclusion
  does not depend on who created the object or on the policy check (the policy check refuses foreign-looking objects):
  ownership is exclusive in the kernel, only the owner thread can release it, and every cooperating run uses the same
  fixed name in the global namespace. Limits:
  only cooperating clean runs are excluded; other processes can still change the trees; any local account can create
  or hold the name first, which refuses every clean run (denial of service, documented, its acceptance left to the
  future deletion gate); a release that cannot be done stays reserved in the process (fail closed) and the system
  releases the mutex when the thread ends. The automated tests cover two processes of the same identity; other users,
  sessions and elevation levels are operator-only and NOT TESTED.
* **TUI diagnostics area (P5-A, ADR-0009):** presentation only. It runs `Invoke-AtmDiagnose` on an explicit action
  (entering the area without a result, or `U`) and renders the diagnose JSON export of that result: no collector,
  Git, Restart Manager, registry or file access of its own, no state change, no gate opened (static test); the
  identity block, the machine name and the V0.1 inventory are not shown there. A failure shows the exception type
  only and keeps the previous result marked as outdated; nothing is retried by itself.
* **Open-file diagnostics gate (P1-C-S):** the Restart Manager collector (`handles`, D-2) is behind
  `$script:AtmHandleDiagnosticsEnabled`, `$false` in every shipped copy (single assignment; no option, environment
  variable or configuration file; checked by the test suite and the install e2e). It is checked by the diagnose and
  again by the sampler and the collector. Closed, no file is listed and no Restart Manager session is started;
  `handles` is `NOT_OBSERVABLE` (`HANDLE_SECURITY_GATE_CLOSED`). Reason: a sampled path is checked and then handed to
  `RmRegisterResources` as text, and a concurrent replacement of an ancestor in that window is not excluded (TOCTOU,
  not resolved).
* **Preflight (P3-B0), before any Git call on a target:** the files Git would follow are read directly (the `.git`
  file, `commondir`, the configuration with a strict parser, every administrative `gitdir`, the alternates chain), and
  every path in them goes through one resolver before any file-system call: UNC and device forms, URLs, `~` and other
  expansions, drives that are not fixed (mapped network drives) and reparse points are refused, and so is any included
  configuration (`include`, `includeIf`), reserved device names, `core.worktree` (any value), a path-valued key whose
  value is refused, and any value written as a path on a drive that is not fixed. Paths stored in Git files (`.git`
  file, `commondir`, administrative `gitdir`) are taken exactly as Git reads them (only a trailing line break dropped).
  The Git directory must be valid as Git validates it (`HEAD`, `objects`, `refs`); a target that itself holds `HEAD`,
  `objects` and `refs` is refused (Git would read it as a bare repository, with its own configuration). No reparse
  point may sit in `refs`, `packed-refs`, `reftable` or an administrative entry's lock or `HEAD`. A refused target never gets a Git process. The runner does not trust the caller's preflight: it takes
  a fresh one immediately before each run and requires it to agree. Every path Git reports goes through the same
  resolver before it is used. `status` also needs the D-3 preconditions: no filter driver, textconv or submodule in the
  repository. Git runs only in repositories a discovery source led to (a repository reached only through a worktree's
  `gitdir` is registered from its files, never given to Git). The `PATH` lookup of `git.exe` goes through the same
  resolver: drives that are not fixed and paths with a reparse point are skipped (so a Git reached through a junction,
  as some package managers install it, is not found: fail closed).
* **Configuration isolation (P3-B0):** no global, XDG or system configuration or attributes (`GIT_CONFIG_GLOBAL=NUL`,
  `GIT_CONFIG_NOSYSTEM=1`, `GIT_ATTR_NOSYSTEM=1`, `core.excludesFile=NUL`, `core.attributesFile=NUL`), `HOME`,
  `USERPROFILE` and `XDG_CONFIG_HOME` pointing to a directory that does not exist in the Git installation; configuration
  names are counted, never returned (they can carry credentials); Git's error text is never returned. Minimum Git
  2.45.0 (`GIT_NO_LAZY_FETCH`), on top of every transport refused by name.
* **Elevated runs (P3-B0):** the launcher, the program it starts (`mingw64`/`clangarm64`), every program and library in
  that program's directory, and every directory above both up to the volume root must pass the installer's ACL rule.
  The volume root is not checked (its default ACL lets users create folders) and the time between the check and the
  start is not covered.
* Still open: a child running as the same user could in principle duplicate the job handle from this process (that
  requires code running in the child, which the allow-list, the preflight and D-3 prevent); handles are inheritable
  for a short time while the child is created (the handle list requires it).
* **Read pins (P3-C0):** for each Git call the runner opens, for reading and without write or delete sharing, every
  file the preflight validated (`.git` file, `HEAD`, `commondir`, configuration files, alternates files,
  `packed-refs`) and the `objects`, `objects\info`, `refs` and alternate object directories, then runs a fresh
  preflight under those pins and requires it to agree; the pins are held
  until Git exits. `GIT_COMMON_DIR` is set to the validated common directory. `worktree list` is not run. `status`
  always runs with `--ignore-submodules=all`.
* **TOCTOU: NOT RESOLVED (partially mitigated).** Vector matrix, each row proved on fixtures with a local target:

  | Vector (created or changed after the preflight) | Result |
  |---|---|
  | include or includeIf added to the configuration; configuration, `HEAD`, `.git` file, `packed-refs` replaced; `.git`, the repository, `objects` or `refs` renamed (and replaced by a junction) | prevented while pinned |
  | `commondir` created in the Git directory | not read (`GIT_COMMON_DIR`) |
  | `config.worktree` created (extension off) | ignored by Git |
  | new administrative entry (`worktrees\<name>\gitdir`) | not reached (`worktree list` not run) |
  | `objects\info\alternates` created (any command that reads objects, such as `status`) | **open**: followed by Git |
  | `.git` file dropped in the work tree (untracked scan of `status`) | **open**: its target is resolved |
  | file symbolic link to a network path created where a file was absent, or replacing a loose ref (not pinned, so that other processes can still commit) | **open**: needs the symbolic-link privilege or Developer Mode; junctions cannot point to network paths |

  A file that does not exist cannot be pinned, so creation cannot be prevented within the accepted architecture. The
  worktree diagnostics gate stays closed. **Interference:** while pinned, another process cannot rewrite the pinned
  files (a concurrent `git config` write, `checkout` or rewrite of `packed-refs` fails for the duration of one Git
  call, returned as `PinnedMs`; Git for Windows may retry or ask "Should I try again?" in a console); index and loose
  ref updates and new objects are not blocked.
* **Shared reads (P3-D):** every repository file the engine reads itself is opened with read, write and delete
  sharing, so reading never stops another process from rewriting or renaming over it, and without following a
  reparse point (refused on the handle, so a swap after the path check is never followed); bytes are read as Git reads
  them; strict parsers refuse a torn read. References are read in two passes that must agree. Limits, recorded:
  shared reads reduce interference but do not prevent replacements; two equal passes are not a transactional
  snapshot; a partly rewritten file may still be syntactically valid; none of this may be used as proof that a
  worktree can be discarded.
* **NOT RESOLVED - ancestor TOCTOU of direct reads (P3-D).** The path chain is validated, then the file is opened by
  name, and only the final component is opened without following a reparse point: an ancestor directory replaced in
  between (renamed, a junction in its place) redirects the read, proved on fixtures with a local junction. There is no
  guarantee that every read stays on the local volume under adversarial concurrency. No SMB authentication was
  attempted. The worktree diagnostics gate stays closed. Publication facts come from files only (no process); a
  remote URL is never resolved or opened. ADR-0011 (PROPOSED) describes file-based diagnostics without Git.
* **Preflight reuse (P3-E):** within one discovery run, the common-directory part of the preflight is reused while a
  fingerprint (kind, size, last-write time of the files and directories it depends on) is unchanged. The fingerprint
  is not a guarantee (a change keeping size and time, or one deeper in `refs\` or inside an administrative entry, is
  not seen; the alternates files found are watched too), so the cache is never used by the runner: before any Git
  process the runner takes its own uncached preflight. Reuse never crosses runs; a refusal reused within the run only
  refuses more. The diagnose resolver's native chain check refuses a path too long for the plain API.
* **Local work is never complete:** `status` runs with `--ignore-submodules=all`, so changes inside a gitlink (which
  can exist without `.gitmodules`) are not seen, nor entries flagged assume-unchanged or skip-worktree; its coverage is
  always `PARTIAL` (`HIDDEN_ENTRIES_NOT_OBSERVED`). A stash that cannot be attributed (detached or unreadable `HEAD`) or
  a stash ref without its reflog makes the files coverage partial, never "no stash".

## Known limits (documented, not hidden)

* **TOCTOU**: a process may open a file between the last check and the deletion. The window is reduced to a
  single path, and redirection of names is prevented by pinning, but Windows offers no atomic "delete if
  unused" for trees. A file opened after its own exclusive open is impossible; a file opened before it makes
  the deletion stop.
* **Probe interference**: the handle probe and the deleter open entries with restrictive sharing for a few
  milliseconds; an agent opening the same file at that instant gets a sharing violation. Only candidates
  older than 72 h without any activity evidence are probed.
* **Pinned ancestors**: during a deletion, renaming any ancestor directory (e.g. the profile folder) fails
  briefly.
* **Unobservable handles**: handles opened with full sharing (including `FILE_SHARE_DELETE`) and no data
  access are not detected by the probe. Process working directories and environment variables are not
  observable (V0.1; in V0.2 the D-1 working-directory reading is deferred, ADR-0004 amendment: the diagnose reports it
  as `NOT_OBSERVABLE`).
* **Open-file evidence (V0.2 diagnose, D-2; closed by the open-file diagnostics gate, validated on fixtures only):**
  sampled paths are validated and then registered with Restart Manager by name; no guarantee was demonstrated against
  a concurrent replacement of an ancestor component between the check and `RmRegisterResources` (TOCTOU of text
  paths, NOT RESOLVED; what Restart Manager does with a redirected path was not established). When the gate is opened
  (tests only), Restart Manager lists the processes holding a bounded sample of files
  of each indexed item (start session, register, list, end session; never shut down or restart; sessions always
  ended). It sees files only (not directories nor working directories), so a sample never proves an item free; a
  holder is identified by PID and start time against the process snapshot, otherwise reported as unverified; no file
  path or process name is exported. `RmGetList` cannot be cancelled: one query is bounded only by the few files
  registered.
* **Services not listed for the account (P2-A-S)**: the service control manager may leave out a service whose
  security descriptor denies the account the right to query it (a known way to hide a service). A declared name that
  is not listed is therefore `UNKNOWN`, never `NOT_PRESENT`, and the query is `PARTIAL`; no other source (for example
  the registry) is read. A real hidden service was not tested (it needs a modified security descriptor); an injected
  source simulates it. No service state, `UNKNOWN` included, authorizes deleting anything, stopping a service or
  shutting down a virtual machine.
* **Service and process link (P2-A)**: a linked PID is a temporal observation (the process owned the PID during the
  query), not continuous monitoring.
* **Process coverage**: protected processes remain uninspectable even for administrators. On a real Windows
  installation there are always some (17 on the CI runners), so the coverage gate blocks every candidate: in V0.1
  `clean` stops before the release gate is even reached. Enabling real deletion (V0.3) requires a reviewed decision
  on how known protected system processes are treated; the gate is not relaxed before that.
* **Agent discovery and unreadable command lines (V0.2, O2).** Agent processes are found from three sources:
  * the provider's image name (readable for every process);
  * the session registries;
  * path references from the V0.1 command lines.

  A process whose command line cannot be read (another account's, or a protected one) yields no path reference. An
  agent that only such a reference would have shown therefore stays unseen.
  * The diagnose reports that gap as a reason of `agent-processes` even when no candidate was found:
    * `PATH_REFERENCES_INCOMPLETE` for command lines that could not be read;
    * `LEGACY_SNAPSHOT_UNAVAILABLE` for a V0.1 snapshot that is missing, failed or empty.
  * `agent-processes` is then `PARTIAL`. `agent-resources` reports no zero as complete: with no agent process found,
    its sums are `null`.
  * On a real machine some processes are always unreadable, so this reason is expected there.
  * Processes found by other sources stay, and no finding is made up for the gap.
  * Tested on synthetic inputs. A real hidden agent was not demonstrated.
  * **Bases (O2B).** References are only searched in the bases the inventory discovered and read. The diagnose
    reports `PATH_REFERENCE_BASES_INCOMPLETE` in these cases:
    * a base that was inaccessible, invalid or not enumerated, or a TEMP location that could not be verified
      (`temp-profiles` not conclusive);
    * profiles the discovery may have missed (`profile-discovery` not conclusive);
    * either record missing.

    `PATH_REFERENCE_UNVERIFIED` is reported for an ambiguous reference under an audited base, which never makes its
    process a candidate.
  * **Base states (O2C).** A base refused because its path holds a reparse point (`REPARSE_IN_PATH`) or is not on a
    fixed drive (`UNSUPPORTED_DRIVE`) is not inventoried (`temp-profiles` reports it as `PROFILES_NOT_AUDITED`, below). The diagnose reads the
    state of every base: any state other than read (`OK`) or confirmed absent (`NOT_FOUND`, `NOT_DIRECTORY`) gives
    `PATH_REFERENCE_BASES_INCOMPLETE`, and so does a state it does not know. The refusal itself is unchanged: such a base
    is still not followed or read.
  * **Ambiguous references without a partition (O2C).** The inventory's count of ambiguous references is read too, so a
    reference under an empty base or project folder gives `PATH_REFERENCE_UNVERIFIED`.
  * **References without a partition (O2D).** The reference index also counts, where each reference is attached, the
    ancestor and ambiguous references that no partition carries (an empty base or project folder). Any such reference,
    a count that is missing (a failed snapshot evaluated nothing), not a whole number or negative gives
    `PATH_REFERENCE_UNVERIFIED`; a reference attached to at least one partition is not counted. Matching, traversal,
    classification and eligibility are unchanged.
  * **Heuristic discovery (R20).** Path references are found only where a command line holds an audited base, as one
    unbroken text, in its long or 8.3 form. A relative path, an environment variable, a `..` segment that breaks the
    base text, a path mixing long and 8.3 components or an administrative share is not recognized: such a reference is
    neither attached nor counted, and its absence cannot be detected either. (A `..` right after the base is an
    unresolved name: ambiguous, reported.) The matcher is not extended, and nothing resolves the working directory or
    environment of another process. Instead, the limitation is declared on every run where a source was searched:
    `agent-processes` always carries `AGENT_DISCOVERY_HEURISTIC` and is never `COMPLETE`, also when every input was read,
    beside any specific reason. A finished collection shows which agents were found, never that every agent was. The
    agents found and their evidence stay, nothing is made up, and `agent-resources` never reports a complete zero
    (with no agent found its sums are `null`; with agents, the sums of what was read, not complete). Consequently the
    diagnose `coverageComplete` is always `false`. Tested on synthetic forms; a real hidden agent was not demonstrated.
  * **Bases not audited (V0.1 coverage).** A base refused for safety, in a state not known, or an alias whose canonical
    base (read with its final state) was not audited makes the V0.1 coverage incomplete: `CoverageComplete` is `false`,
    `temp-profiles` is `PARTIAL` with `PROFILES_NOT_AUDITED` (beside `PROFILES_INACCESSIBLE` and
    `TEMP_LOCATION_UNVERIFIED` when they also apply, a profile already inaccessible still not being listed as
    `TEMP_LOCATION_UNVERIFIED`; a profile is counted once), and a profile with an audited base and
    a base not audited is labelled `AUDITADO_PARCIAL`, never `AUDITADO`. Elevation is reported as not helping only for a
    refusal for safety; a state not known stays `UNKNOWN`. The refusal itself, traversal, eligibility and cleaning are
    unchanged. Before 0.2.0 (0.1.0 and 0.1.1) such a base was not counted: the V0.1 coverage could read complete and a
    profile with a base read and a base refused was labelled `AUDITADO`; no 0.1.x update is made for it here.
  * **Read errors (typed `catch`, Windows PowerShell 5.1).** Windows PowerShell 5.1 can run a typed `catch` clause for
    the wrong exception once a script block has run a few dozen times (with synthetic exceptions and no product code:
    an `UnauthorizedAccessException` caught by a `DirectoryNotFoundException` clause, any other error by the last
    typed clause; seen on 5.1.19041 x64 and x86 and on 5.1.26100 x64 and ARM64, and not seen on PowerShell 7.6.7 and
    7.6.8, where the suite only records it without asserting it). File system read errors are
    therefore caught untyped and classified by their real type (`Get-AtmFileErrorKind`; only
    `MethodInvocationException` is unwrapped, at most 4 levels, so an exception with several causes is never taken
    apart): only a file or directory not found is an absence; access denied and any other error are not known. This
    covers the path chain check (an inaccessible base is never `NOT_FOUND`), the post-delete verification of a
    cleaning (never `Verified` on a path that cannot be read), the repository check of a diagnose export destination
    (an ancestor that cannot be read refuses the export), the Claude Code sessions folder (unreadable, never
    skipped) and the activity evidence of a root (a project folder that exists but cannot be looked at gives
    `TRANSCRIPTS_UNREADABLE`, so the root goes to INVESTIGATE, never ELIGIBLE; `Directory.Exists` answers false in
    that case and is no longer used there). The suite calls the path chain check, the presence check used by the cleaning verification and the
    export check, the export destination check and the sessions folder 200 times each in a fresh process on the job's
    own host, past the point where the defect appears, and repeats the inventory there; the cleaning verification
    itself is checked in the suite process after 200 calls; and no typed `catch` is left in `src`. The same typed clauses are in 0.1.0 and 0.1.1 (path chain
    check, cleaning verification, sessions folder); no 0.1.x update is made here.
* **Allocation** is an estimate (cluster rounding; MFT-resident files overestimated).
* **Discovery visibility** (V0.2 P4-B: now reported, still a limit): if the `ProfilesDirectory` value of the Windows
  profile list cannot be resolved or listed, folders under it that have no profile-list entry (residual profiles) are
  not listed; if a profile's volatile environment cannot be read, `%LOCALAPPDATA%`/`%APPDATA%` fall back to the
  profile's default folders; a user hive that is not loaded gives the default TEMP folder. Each case is now a note in
  the audit report (*Discovery*) and a reason of the `profile-discovery` coverage in `diagnose` (codes only), never
  hidden and never read as "does not exist"; an unreadable profile list fails the discovery instead of returning no
  profiles. The audit can still under-report in these cases; deletion stays safe (only inventoried paths can be
  candidates), and the V0.1 classes, flags, gates and `clean` are unchanged. The registry and directory sources are
  injectable for tests (`-ProfileSource`); the default reads HKLM and HKU with read-only calls only (no write, no hive
  loading, no remote registry; static test).
* The agent itself may run its own periodic cleanup independently of this tool.

## Execution policy

The launcher runs `powershell.exe -NoProfile -ExecutionPolicy Bypass -File <installed script>` with
`PSModulePath` pinned to the system module directory for that child process: a process-scoped policy for one
administrator-owned, ACL-protected script. Machine and user policies are not modified; Group Policy
(`MachinePolicy`/`UserPolicy`) still takes precedence. `agent-temp verify` checks the installed files against
their SHA-256 manifest.

Native code: installed copies load `lib\AgentTempManager.Native.dll`, compiled by the installer inside the
admin-only install directory (compiler temp files redirected there too) and loaded only if its SHA-256
matches `manifest.json`. No compilation happens in a user-writable `%TEMP%` during elevated runs. Source
checkouts compile `Native.cs` in memory.

Integrity at install and at every run:

* The installer requires the source to match the release's `src\manifest.json` exactly (no extra, missing or
  modified file); a source without a manifest needs the explicit `-SourceWithoutManifest` switch. The parent
  of the install directory must not be writable by standard users.
* Every installed run, `verify` included, first checks every file listed in `manifest.json` (SHA-256, computed
  with .NET) before any product code is loaded, and refuses to start (exit code 5) if anything differs or cannot be
  read (a file, or the `providers` directory; reported by relative name only), if a
  library the launcher loads or a provider file is not listed, if the manifest cannot be read or has an invalid
  entry (absolute path, `..`, duplicate, malformed hash), or if an installed copy (`install-state.json`) has no
  manifest; only listed providers are loaded. `verify` reports every problem and loads nothing when one exists; it
  loads only the verified message catalog for its summary when every file matches (R-B5). An installation
  without its precompiled DLL refuses to compile at run time.
* The administrative scripts load the message catalog (`lib\I18n.ps1`, code) only after its SHA-256 matches the
  package's `src\manifest.json` or, for uninstall and rollback, the installed copy's manifest. A package without a
  manifest (a git checkout) is loaded unverified only with the explicit `-SourceWithoutManifest`; otherwise
  built-in texts are shown. `install\*.ps1` themselves are covered by the release `SHA256SUMS`, not by
  `src\manifest.json`.
* Rollback checks `<InstallDir>.previous` (manifest, SHA-256, exact file set) before moving anything, and keeps the
  current copy until the restored one passes `verify`; on failure (or an exception) both copies are put back. If
  putting them back fails too, nothing is deleted and the error names where each copy is.
* Update (R-B6) deletes nothing before the new version verified: the staged copy verifies itself first, an older
  `.previous` is set aside in `<InstallDir>.recovery-*`, and a failure or exception after the swap puts the installed
  copy and the older `.previous` back. Update and rollback write `<InstallDir>.transaction.json` before the first
  rename and remove it only once they completed or every copy is back; while it or a recovery directory exists,
  update, rollback and uninstall refuse before changing anything. Only one administrative operation runs on an
  installation at a time: each takes an exclusive, delete-on-close handle on `<InstallDir>.lock` before its first
  change, released by the OS when the process ends (the marker, not the lock, records an unfinished operation).
  Recovery messages are built into the installer
  (never taken from an installed, possibly older, catalog). A run killed abruptly is detected at the next run, not
  recovered: no atomicity across an interruption is promised.
* Limits: the local manifest proves integrity against the release, not authenticity against an administrator who
  can also change the launcher and the manifest. A file could change between its hash check and its load; both
  happen inside the administrator-only install directory. Source checkouts have no integrity guarantee.
* Uninstall removes the PATH entry only if the installer added it.

Operational advice:

* Run the installer from an administrator-only location holding a release whose `SHA256SUMS.txt` you verified.
* From `cmd.exe`, Windows searches the current directory before `PATH`; when elevated, run `agent-temp` from
  PowerShell or from a trusted directory.

## Privacy

Command lines, tokens, credentials and file contents are never printed or exported; references show only
PID, process name and the inventoried path. The agent's session registry is parsed for `pid`, `sessionId`
and `procStart`, plus the leaf name of `cwd` (for project naming) - the full working directory is not kept.
Reports contain paths and aggregates. `-ExportJson` output includes the machine name,
user names, SIDs, profile paths and project slugs: review it before sharing.

CI artifacts (FINAL-B): test reports, install e2e evidence, static analysis and the release package pass through
`tools\Protect-AtmArtifact.ps1` before upload. It replaces the runner's identifiers (paths under the profile and TEMP,
account, machine, domain, profile folder names, account SIDs) with placeholders, then runs the privacy scanner. It
fails closed: a finding, or a scan that cannot be trusted, fails the job and skips the upload, and only file, line and
kind are printed. Archives are scanned, never modified. The test suite's case details use the same placeholders and its
report carries an account kind, not the account name. The jobs' public console logs are not covered beyond the suite's
details.

## Commit identity

Public Git history must not expose personal e-mail addresses. `tools/Test-AtmCommitIdentity.ps1` checks the
author, the committer and the `Co-authored-by` / `Signed-off-by` trailers of every commit in a range:

* accepted: GitHub noreply addresses (users and bots), the fixed address GitHub uses as committer of commits it
  creates, and, in trailers only, organizational addresses (AI assistant co-author lines, Dependabot sign-off);
* reported: any other address, printed masked (first letter and domain initial only), never in full;
* exceptions: `.github/commit-identity-allowlist.txt` lists addresses a contributor chose to publish (added with a
  maintainer's approval) and reviewed historical commits that are deliberately kept.

CI runs it on every pull request (base..head) and on every push to `main` (before..after). It is informative and is
not a required check, so it never blocks an external contribution by itself; a maintainer decides.

Limits, stated plainly:

* A check after a push only **detects**: the commit is already public. Rewriting history afterwards does not remove
  copies (clones, caches, references by SHA).
* A pull-request check cannot see the commit GitHub creates when it merges (merge, squash or rebase); that commit's
  committer comes from the account that clicks merge. Only the account setting "Keep my email addresses private"
  prevents it, and the push check detects it.
* Prevention therefore relies on: commits made locally with the noreply address, the account settings "Keep my
  email addresses private" and "Block command line pushes that expose my email", and no public e-mail on the
  maintainer's profile.

Known exception: commit `586f09a` (rebase merge of PR #2) carries the maintainer account's primary address as
committer. The history was kept on purpose; the commit is listed in the allow-list.