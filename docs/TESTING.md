# Testing

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1                 # Windows PowerShell 5.1
pwsh       -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1                 # PowerShell 7
...\Run-Tests.ps1 -SkipHeavy                 # skip the 200k-file scale test
...\Run-Tests.ps1 -ReportFile results.json   # machine-readable report
```

* Self-contained harness (no Pester).
* Every write happens inside a sandbox `%TEMP%\atm-tests-<random>` created and removed by the suite,
  **outside** any real agent temp directory. Junctions are unlinked before removal; `rd` never follows them.
* Tests touching the real machine are read-only (profile discovery, full inventory, CLI `verify`/`version`).
* Optional: set `ATM_PRIVATE_NEEDLES` to a file (kept outside the repository) listing private identifiers;
  the privacy test fails if any of them appears in the repository.

## Coverage

| Area | Cases |
|---|---|
| Empty collections | no profiles, missing base, empty base, empty process list |
| Paths | spaces, Unicode (Latin + CJK), case-insensitive references, forward slashes |
| Classification | RECENT, ORPHAN_SUSPECTED, clock skew, loose files, non-UUID dirs, invalid scopes, unrecognised base, shared TEMP |
| Partitions | sum of partitions = independent total; no duplicates; logical vs allocated |
| Permissions | unreadable subdirectory, unreadable base, no delete right, read-only file, other user (non-admin / admin), NTFS owner mismatch |
| Processes | uninspectable processes, snapshot failure, real process referencing a root, self-exclusion of the launcher chain |
| References | direct, ancestor-only (scope/base), ambiguous (8.3/wildcard) |
| Sessions | live sessions in two profiles, PID reuse, PID without start time, corrupt registry, recent transcript, unloaded profile |
| Reparse points | junction as root, junction inside root, junction in ancestor (TEMP), directory symlink (if permitted) |
| In use | open file (exclusive and fully shared), process working directory inside root |
| Allowlist | traversal, relative, UNC, `\\?\`, wildcards, ADS, trailing separator/dot, 8.3, whitespace, double separators, profile/TEMP/base/scope/drive roots, case mismatch, duplicates, outside allowlist |
| Clean flow | missing presenter/reader, absent/wrong confirmation, change between preview and clean, change after confirmation, root removed, successful deletion with siblings intact, post-audit |
| Read-only | audit + preview leave the sandbox byte-for-byte and timestamp identical |
| TUI | headless navigation of every screen, ASCII fallback, 60x20 terminal, cleanup through the engine |
| Layering | TUI/report contain no deletion APIs; audit engine neither prints nor deletes; single deletion call site |
| Providers | contract validation, test-only second provider through the same engine and gates |
| Installer | copy + manifest + verify, tamper detection, ACL audit, refusal without elevation, launcher exit codes |
| Security review regressions | rename/junction swap of subdirectory, scope and base during deletion is impossible (with a no-pin control), pre-existing redirection refused, third-party write ACL on base blocks, `%WINDIR%\Temp` shared, unexpected `procStart` never means "ended", drill-down/output path validation, no command-line fragments in evidence |
| Native assembly | installer-compiled DLL loads only with matching manifest hash (5.1 and 7); tampered DLL refused |
| I18n | catalog parity and identical placeholders; every used key translated; language resolution and safe fallback; en-US audit/preview/plan/TUI with no pt-BR text; identical engine codes across languages; CLI `-Lang`/`ATM_LANG`; ASCII transliteration |
| Clean environment | Windows Sandbox configuration generator (valid `.wsb`, networking disabled, release read-only); the in-sandbox script itself needs an administrator-enabled Windows Sandbox or VM (`NAO_TESTADO` on this machine) |
| Scale | 200,000 files in one root, bounded managed memory |
| Privacy | scanner self-test with planted data; working tree and Git index free of SIDs, e-mails, user paths, tokens, machine/user names and private identifiers; only `dist/` ignored |
| Portability | one user; several users (audited / inaccessible / hive not loaded / no Claude Code); profile on another drive letter (`subst`); no Claude Code; empty TEMP and empty root; unidentified projects and session-based identification with collision handling; Unicode, spaces, apostrophe, `&`, `#`, parentheses in profile and install paths; per-profile TEMP expansion (redirected, other drive, unresolvable variable) |

## Privilege matrix

Requirement PRIV-11 ([ELEVATION.md](ELEVATION.md)): behaviour that depends on privileges is verified with **real**
tokens, not only with the injected test identities the suite uses for gate logic. Expected results for V0.1:

| Scenario | Expected | Covered today |
|---|---|---|
| Standard user, not elevated | audit/preview/TUI work; other profiles inaccessible and other accounts' processes not observable are reported; coverage incomplete; clean blocked; installer scripts refuse | Suite and probe, locally (Windows 10, PS 5.1 and 7; earlier session, evidence outside the repository, not re-verified for 0.1.0); installed product as a real standard user in CI (`install e2e`: Windows Server 2025, Windows Server 2022, Windows 11 ARM64), who also cannot write the install directory |
| Administrator, not elevated (filtered UAC token) | Same as a standard user (`elevated administrator: NO`) | Probe, Windows 10 x64, PS 5.1 (manual) |
| Administrator, elevated (consent prompt) | Full process coverage where Windows allows; other users' paths need `-IncludeOtherUsers`; installer works | Elevated session (no prompt: CI runners start elevated): suite and real install / update / rollback / uninstall in CI (`install e2e`). The consent prompt itself: probe after approving it, Windows 10 x64, PS 5.1 (manual) |
| Elevated with another account's credentials (standard user, or policy requiring credentials) | Process identity = that administrator account (its profile is "own"); the requester's profile is another user's and needs `-IncludeOtherUsers`; installer records the administrator | Not yet (manual; needs a second administrator account) |
| UAC prompt cancelled | No elevated session, nothing changed | Windows 10 x64 (manual): no elevated window opened |
| Non-interactive session (SSH, WinRM, scheduled task) | Runs with the caller's token; never waits for a prompt | Partial: `-NonInteractive` host from an existing session, Windows 10 x64, PS 5.1; SSH, WinRM and scheduled task not yet |
| Windows 11 | Same results as Windows 10 for every row above | Windows 11 ARM64 in CI (`install e2e`); Windows 11 x64: not yet (manual) |

Manual rows: [docs/release/PRIVILEGE-MATRIX-RUNBOOK.md](release/PRIVILEGE-MATRIX-RUNBOOK.md) and the read-only probe
`tools/privilege-matrix/Invoke-PrivilegeProbe.ps1`.

## Real installation (CI, disposable VMs)

`tests/e2e/Invoke-InstallE2E.ps1` (job `install e2e`) refuses to run outside a GitHub-hosted runner. A `build package`
job builds the release once; each `install e2e` job installs that same zip (SHA-256 checked) on Windows Server 2025,
Windows Server 2022 or Windows 11 ARM64, with the installer under PowerShell 5.1 or 7, and checks: installed release
gate, CLI from a new process with the machine PATH, clean of an old session root stops without deleting it, update,
rollback, tamper detection (exit 5) and repair, a real standard user (created only in the VM) running audit, preview
and verify without write access to the install directory, uninstall (directory and PATH entry removed). Evidence is
uploaded as artifacts.

Then each published version is installed and taken through the same cycle on every OS and installer shell: 0.1.0,
0.1.1 and 0.2.0, the latest published version. Each package is the asset of its GitHub Release, accepted only with the
SHA-256 published in that release's `SHA256SUMS.txt`, pinned in the script. The cycle is:

1. install the published version and check `version` and `verify`;
2. update to the package under test (`-Update`) and check `version` and `verify`, the older copy kept as `.previous`,
   and the six installed gates `$false` (deletion, worktree diagnostics, handle diagnostics, diagnose export and, since
   0.3.x, isolation (phase P2) and purge (phase P4)); the `shipped-purge-gate` step also checks that no policy file is
   installed, that `version` shows the purge gate disabled and the default policy, and that `quarantine purge` of an
   entry that does not exist only plans (exit code `3`, no quarantine created);
3. roll back and check the published version again;
4. update again;
5. uninstall: the directories and the PATH entry are removed.

The 0.2.0 cycle also checks the installed manifest's version at each step. A download that fails is `NAO_TESTADO`,
never a pass.

## Real clean on disposable VMs (V0.3 V2)

The same `install e2e` jobs (every OS and installer shell of the matrix) also run the **real** clean, end to end, through
`tests/e2e/Invoke-CleanE2E.ps1`, before the uninstall. The harness is CI-only: `tools/Build-Release.ps1` leaves it out of
the release archive and refuses an archive that contains it, and the e2e checks the extracted package.

* **Gate.** It loads the *installed* engine into its own process and opens the deletion gate there only, in memory,
  as the suite does for its sandbox. The installed files keep the single assignment to `$false`; the harness compares
  their SHA-256 before and after and runs `agent-temp verify`. No variable, option or file opens the gate in a copy.
* **Real parts.** The real deleter, the T1 log in a real file, the real B8 lock name, the real revalidation and the
  real profile discovery (the variables are set in the test account's user environment). The only seam is the console
  observation (`TEST_SEAM`, checked in the log): **every confirmation is automated by the harness, never a human
  acceptance.**
* **Containment.** Everything it can hand to clean is under a run root it creates atomically in that run, with a
  protected DACL, refused if the name exists; each planted root carries the run's nonce, and every entry is checked
  against both before clean is called. Real roots of the VM are never entries. The environment check
  (`GITHUB_ACTIONS`, or `-DisposableMachine`) only guards against an accidental run.
* **Recency is simulated.** The "old" planted roots and their transcripts get write times set back by 120 hours
  (recorded as `recencySimulated`); RECENT itself (72 hours) is unchanged.
* **Leg A**, the VM's standard user (not elevated), B1 restricted exception: preview (`ELIGIBLE_WITH_DECLARED_RISK`
  for the old roots, `BLOCKED`/`RECENT` for the new one); refusals that delete nothing (lock held by another process,
  existing log file, no `-AcceptB1ResidualRisk`, a recent root, two roots under the exception, a wrong final phrase);
  `REVALIDATION_REFUSED` when a root changes between the confirmation and its deletion; one root deleted by the real
  deleter with the log read back from the file (`run-start, plan, declaration, confirmation, plan-check, intent,
  result, run-end`) and the lock seen `BUSY` from another process during the run and free after it.
* **Leg B**, the elevated runner account: `ELIGIBLE` only when the process coverage measured in that run is complete;
  then two roots, the first deleted by the real deleter and the second, changed after the confirmation, stopping the run.
  Coverage measured incomplete: `NAO_TESTADO`, never forced.
* **Snapshot.** The whole run root before and after: only the deleted roots, the new log files and the declared change
  may differ. The account's temp folder is compared too; other processes write there, so a change of a pre-existing
  entry is reported as inconclusive (`NAO_TESTADO`), not attributed.
* **Evidence.** Only the harness summary is uploaded (codes, counts and labels; no path, account name or SID), through
  the artifact sanitizer and the privacy scanner. The raw clean logs stay in the VM.
* **Not tested here.** The CLI and the TUI past the gate (opening the gate there would mean changing the installed copy);
  a refusal inside the deleter after the revalidation (no deterministic trigger without a seam; covered by the suite on
  its own fixtures); partial, exception and inconclusive-verification outcomes with the real deleter (V3); `ELIGIBLE`
  without elevation; an abandoned lock; UAC prompts and filtered tokens (the runners have UAC disabled).

## Adversarial cases on disposable VMs (V0.3 V3, phase V3a)

The same harness, after the V2 runs, plants more roots the same way (run nonce, recency simulated, real discovery) and
attacks them in each window of the flow: before the plan; between the plan and the final confirmation (the harness's
own confirmation reader); between the confirmation and the revalidation (`-BeforeDeleteHook`); between the revalidation
and the deleter, and inside the deleter once everything is pinned. For the last two the harness passes the engine's
existing deleter test seam a **wrapper that calls the real `AtmDeleter` with exactly the engine's arguments** plus the
attack (`afterPinning`); a static test of the suite compares the two calls. No seam was added to the product.

* **Each case asserts** its specific code for its leg, the records read back from the log file, the number of `intent`
  records (= calls to the deleter) and that nothing outside the planned root and the declared attack changed (a
  snapshot of the run root before and after; sentinels and link targets live in the run root, outside the base). A final
  case checks the whole phase: only the V3 scopes and logs differ.
* **Legs.** Leg A (standard user, B1 exception) runs one root per clean. There a refusal of the lock probe, an ACL or
  runtime evidence removes the exception, so it shows as B1 itself in the plan or `B1_EXCEPTION_NO_LONGER_APPLIES` at the
  revalidation, never as `EM_USO`. Leg B (elevated) reaches the deleter only with `ELIGIBLE`; with the process coverage
  measured incomplete those cases are `NAO_TESTADO`, never forced. A refusal before the attack caused by new processes
  of the runner is retried (up to 3 runs) and, if every attempt is refused that way, is `NAO_TESTADO` with the identities
  that explain it, as in V2.
* **Reparse points and links:** a junction, a directory and a file symbolic link inside a root, an entry that is a
  junction and a scope that is a junction (refused while planning); the root replaced by a junction between the
  preview and clean (`ALTERADO_DESDE_O_PREVIEW`), before the final confirmation (`PLAN_CHANGED_BEFORE_EXECUTION`), before
  the revalidation (`REVALIDATION_REFUSED`) and before the deleter (`ROOT_REPARSE_POINT`); the scope replaced by a junction
  before the deleter (`ANCESTOR_REPARSE_POINT`); renames of the tree, the scope and the base inside the deleter (refused
  by the system, the deletion completes); an empty pinned folder turned into a junction or a directory symbolic link in
  place inside the deleter (`PINNED_DIR_CHANGED`, `PARTIAL`, the target never traversed).
* **Files and folders in use:** a file held with and without `FILE_SHARE_DELETE` before the plan and before the
  revalidation (refused, nothing deleted) and inside the deleter on the last file of the tree (`DELETE_FILE_REFUSED:
  IN_USE`, `PARTIAL`, the held file intact: the partial outcome **with the real deleter**); a process whose working
  directory is in the root (refused while planning). Measured against an accepted set, with the same result on every
  image of the matrix: a handle with no data access and full sharing (invisible to the lock probe) on the last file
  gives `PARTIAL` (`DELETE_DIR_FAILED`, the deleted file pending) and on the root folder `VERIFICATION_FAILED`; a process
  started with its working directory in a pinned folder starts, and the deletion completes (SECURITY-MODEL,
  "Unobservable handles").
* **Symbolic links** (`SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE`) could be created by the standard user on the
  runners; where they cannot, those cases are `NAO_TESTADO`. The suite also covers the in-place symbolic link on its
  own fixtures.
* **Not tested in this phase:** a subst drive in the flow (refused before by the path checks; the deleter case is in
  the suite); the in-deleter cases of leg B while its process coverage is incomplete; the other V3 cases (new entries,
  ACL, processes, deleter outcomes, log, interruption, concurrency and shared bases) are later phases.

## New entries, ACL and processes after the plan (V0.3 V3, phase V3b)

Same harness, same rules (code per leg, log read back, intents counted, nothing outside the planned root changed), on
roots planted with the V3a ones and covered by the same phase snapshot.

* **New entry or change:** a file added between the preview and clean (`ALTERADO_DESDE_O_PREVIEW`, both legs), before
  the final confirmation (`PLAN_CHANGED_BEFORE_EXECUTION`) and between the revalidation and the deleter
  (`PLAN_DIFFERS_FROM_VALIDATED_MEASUREMENT`, nothing attempted); a planned file changed inside the deleter
  (`FILE_CHANGED_AFTER_PLANNING`, `PARTIAL`, the changed file intact). Between the confirmation and the revalidation it is
  V2's case. Measured on every image: a file can be created in a pinned folder inside the deleter; it is not in the
  plan, stays intact, and the run stops as `PARTIAL` (`DELETE_DIR_FAILED`). A hard link inside the root to a sentinel
  outside it: only the name inside the root is removed, the sentinel is intact (the link count is not checked).
* **Third-party ACL** (a fixture: one explicit ACE for `Users` on a root planted in that run, never a folder of the VM):
  before clean it is refused in **both** legs (`ESCRITA_CONCEDIDA_A_TERCEIROS`: the ACL gate runs before B1); before the
  final confirmation `PLAN_CHANGED_BEFORE_EXECUTION`; before the revalidation `REVALIDATION_REFUSED`. Inside the deleter
  the ACL is not read again: the deletion completes (a declared limit, SECURITY-MODEL).
* **Processes:** a process of the same account naming the root started before the revalidation (`REVALIDATION_REFUSED`,
  use observed); in leg A, a process of **another account** started before the revalidation
  (`B1_EXCEPTION_NEW_UNINSPECTABLE_PROCESS`) or before the final confirmation (`PLAN_CHANGED_BEFORE_EXECUTION`). That
  process is started by a watcher of the runner account that the e2e launches before leg A; leg A asks through a file
  and the watcher starts one fixed short command that ends by itself. No process is ever terminated.
* **Not tested:** a write that keeps every statistic (no content hash, by design); leg B in-deleter cases while its
  coverage is incomplete.

## Deleter outcomes, the log, interrupted runs, concurrency and shared bases (V0.3 V3, phase V3c)

* **Outcomes with the real deleter:** `PARTIAL` (from the V3a/V3b cases that stop inside the deleter); a root folder
  created again right after the real deletion gives `VERIFICATION_FAILED`; an exception raised by the deleter call
  after the real deletion gives `EXCEPTION` with the outcome unknown (`verifiedGone = UNKNOWN`, counts not presumed).
  The last two are provoked by the harness (declared).
* **The log:** renaming the log folder during a run is refused (it is pinned while the log is open) and the log is
  complete.
* **A run that ends inside itself:** the harness starts itself again as a child (same account, the real lock name, only
  on disposable runners); the child ends by itself (`Environment.Exit`, never terminated) inside the real deleter after
  pinning, or right after the real deletion. The log ends at the `intent` (no `result`: the outcome is unknown). While
  another handle keeps the lock object (the harness opens one with `SYNCHRONIZE` only), the next clean is refused with
  `CLEAN_LOCK_ABANDONED` (no inventory, no log), and the following one acquires the lock and plans from scratch (the root
  deleted, or no longer there). Measured: when no other handle exists, the lock object ends with the process and the
  next clean simply acquires it; the log's `intent` without `result` is then the only trace of the interruption.
* **Concurrency:** a second complete clean of the same root while the first holds the lock: `CLEAN_LOCK_BUSY` at once (no
  plan shown, no log, no deleter), and the first deletes the root once. Across identities (the standard user and the
  elevated runner account, in both orders) the other side gets `BUSY`, never `DENIED` (the e2e step
  `v3-x2-lock-across-identities`; CI evidence, not the V4 row). Another kind of object under the lock name:
  `CLEAN_LOCK_TYPE_MISMATCH`.
* **Shared bases:** a base under the Windows temp folder is shared, refused with `SHARED_TEMP` (both legs). A base claimed
  by two accounts is tried in leg B when the other account's environment is readable; otherwise it is measured as
  `NAO_TESTADO`.

## V3 as a whole

Every case asserts its own code, the log read back from the file, the number of calls to the deleter and that nothing
outside the planned root and the declared attack changed. Leg A (standard user, B1 exception, one root per run) runs
every case; leg B (elevated) runs the cases refused while planning, and the others only when its process coverage is
complete, which it was not on any runner. A refusal caused by new processes of the runner before an attack is retried
and, if it persists, reported as `NAO_TESTADO` with the identities that explain it. **Not tested, by design or by
decision:** a write that keeps every statistic (no content hash); a real exception inside the deleter (it reports
codes, it does not throw); a real failure of the log write (no size-limited volume on the runners); an interruption in
the middle of the tree (no per-file hook, no forced termination). Proved limits are in SECURITY-MODEL (unobservable
handles, a working directory entering a pinned folder, the ACL not read again once pinned, hard links).

Gate logic for administrators and other users is also exercised with injected identities (`IsAdmin`, profile SID
different from the process SID) in every run, on both shells. Manual rows are recorded in the release notes as
done or `NAO_TESTADO`, never assumed.

Results are `PASS`, `FAIL` or `NAO_TESTADO` (a prerequisite was unavailable, e.g. no free drive letter for
`subst` or no symlink privilege); `NAO_TESTADO` is never counted as a pass.

## Local runs and the console encoding (P5-B)

The suite decodes native and child-process output (Git, the CLI) as UTF-8, like the CLI itself; with a redirected
console Windows uses the OEM code page (850 on pt-BR systems), and a profile path or text with non-ASCII characters
was misread, which failed tests on such machines without any product defect. Side effect: with a UTF-8 console the
headless TUI defaults to Unicode on Windows PowerShell 5.1 too; the ASCII fallback stays covered by the tests that pass
`-Ascii`. The previous encoding is restored when the suite ends, also after an abort. A local run can still fail for
environmental reasons that the product reports correctly (for example a TEMP folder that other local accounts can
write: the sandbox then inherits that ACL and the gates block it, as they should). Those failures stay failures; the
record of a local run and its causes is in [release/V0.2-LOCAL-TEST-ENVIRONMENT.md](release/V0.2-LOCAL-TEST-ENVIRONMENT.md).

## Isolation in the suite (0.3.x phases P1 to P4)

The isolation gate stays `$false` in the suite's process; the cases past it open it only around each call and restore it.
The quarantine is a folder of the sandbox (the `AtmIsolationQuarantineRoot` seam; the shipped value `$null` means
`%LOCALAPPDATA%\AgentTempManager\Q`).

* **P1 (native):**
  * the mover, `CreateNewDirectory` and `OpenExisting` on sandbox trees: reparse points, open handles (measured), long
    paths, Unicode, another volume (CI only), an existing destination, a diverging measurement;
  * the `install e2e` step `iso-p1-rename-with-open-handles` on every image.
* **P2 (plan only):**
  * the gate in source, build, e2e and `version`;
  * the 0.3.x target rule;
  * with the gate closed: no lock (another process holds it), no question, no log, no quarantine, no move;
  * the CLI in a child process.
* **P3a (isolate past the gate, one session root):**
  * the complete run: content intact in the entry, the log and manifest records, no file names in the manifest, the
    plan id prefix;
  * every refusal before the mover leaves no entry: wrong phrase, no log, a log inside the quarantine, no console, two
    roots, the clean lock busy, the plan changed during the questions, the revalidation refused;
  * the mover's outcomes through the `-MoveTreeImpl` seam and the real mover:
    * the intent is in the log and the manifest when the mover is called;
    * a refusal, an exception, a file open inside the tree (the real mover refuses) and a change in the window (moved,
      not verified) each stop the run, with the outcome recorded;
  * the B1 exception per root (its risk phrase, then the confirmation);
  * the quarantine: created with protected DACLs, an acceptable existing one used unchanged, a junction refused;
  * another volume (ISO-FIX-VOL): the quarantine seam on a drive letter that does not exist on the machine (`NAO_TESTADO`
    with none free), so nothing can be created there. The root is refused at the plan with exactly `MOVE_OTHER_VOLUME`:
    gate closed (another process holds the lock), past the gate (no question, no log, no entry, the lock free
    afterwards) and under the B1 exception; with the gates refusing, the code is reported with theirs. The shared rule
    (path roots, ignoring case), one literal of the code, called by the isolate and restore plans, before the capacity
    rules and the stop of the gate;
  * an interruption: a child process that ends itself inside the stand-in mover leaves `move-intent` without
    `move-result` in both files (the entry is incomplete);
  * 200,000 files (heavy: `NAO_TESTADO` with `-SkipHeavy`, as in CI);
  * static checks: a single mover call, after the intent; the seams only in the engine.
* **P3b (quarantine management and restore):**
  * list, inspect and verify with the gate closed: bytes and times identical, manifests included;
  * derived states (FAILED from a refused move, INCOMPLETE, ABANDONED, invalid manifests, junctions never opened);
  * verify: `DIFFERS`, `PAYLOAD_MISSING`; the restore refuses a differing entry;
  * restore with the gate closed (plan only), past it (original path), on a conflict (the generated alternative, its own
    phrase, no merge), with reconciliation of an interrupted entry (T-ISO-5), the mover's outcomes, every refusal;
  * the CLI in a child process; the TUI headless in both languages; static layering (two mover calls).
* **P4 (purge, retention, quota, policy):** the purge gate stays `$false` in the suite's process. `Invoke-PurOpen` opens
  it only around each call, after checking that the quarantine is the sandbox's, and restores it. The real deleter runs
  only on payloads in the sandbox's quarantine. A policy file is written only in a config folder of the sandbox, never
  in the source's.
  * the six gates: one assignment to `$false` each; the purge gate checked by the build, the e2e and `version`;
  * the gates are independent in both directions:
    * with the isolation gate open (and the deletion gate, which the suite opens), `purge` still stops at
      `EXPURGO_REAL_DESABILITADO` without asking;
    * with the purge gate open, `isolate`, `restore` and a `clean` with its own gate closed stop at their own gates;
    * the purge needs only its own gate;
  * the purge gate closed: the plan only (its plan id prefix and phrase); no question, no lock (another process holds it),
    no log, nothing purged; the report says no space is freed; the quarantine and manifests identical in bytes and times;
  * a complete purge past the gate:
    * the declarations of the purge itself, then the phrase;
    * `purge-intent` and `purge-result` (`automatic: false`) in the manifest and the log, with no file names;
    * the payload gone, the entry `PURGED`, and a second purge or a restore refused;
  * a refusal for every state: `ABANDONED`, `DIFFERS`, `PAYLOAD_MISSING`, `PURGED`, `INCOMPLETE`, `FAILED`, `RESTORED`,
    `UNRECOGNIZED` (a junction), an invalid manifest and an entry that does not exist;
  * every refusal before the deleter, with the manifest and payload intact:
    * an invalid id, no presenter or reader, a wrong phrase, a refused declaration;
    * no log, a log inside the quarantine, no console, the clean lock busy;
    * a command line naming the quarantine (`RUNTIME_QUARANTINE_REFERENCED`), while a name that only starts like it
      does not refuse;
    * a payload changed after the questions (revalidation refused);
  * the deleter's outcomes:
    * a divergent measurement through the real deleter: refused before the first deletion, code only, the entry still
      `ISOLATED` and purgeable later;
    * an exception: `FAILED`;
    * a file in use: refused by the in-use probe at plan time; opened after the revalidation, it is never deleted;
  * retention through the suite's clock seam (`AtmQuarantineClock`, never the CLI):
    * `EXPIRED` with the default and with a 60-day policy;
    * only `ISOLATED` becomes `EXPIRED`, and nothing is written;
    * an `EXPIRED` entry purged by the confirmed command;
  * the quota refuses an isolation before any question, and nothing is purged;
  * the policy: missing, valid (with and without BOM), invalid in every way (counted as off with a warning),
    `autoPurge: true` read and warned with no effect; the free-space minimum fixed in code;
  * the policy preserved byte for byte by `-Update` (in the new manifest; `verify` passes), an invalid one too, and
    `version` of the installed copy showing it;
  * the CLI in a child process with the gate closed; the TUI headless in both languages (`EXPIRED`, `PURGED`, the
    policy, the purge command; it never purges);
  * static checks:
    * the deleter has one product call in clean and one in purge, after the gate stop and the intent;
    * the report, the TUI and the launcher never call the deleter, and only the launcher calls the purge, once;
    * `autoPurge` is only read and shown;
    * the clock seam is a single `$null` assignment.

## Real isolation on disposable VMs (0.3.x ISO-P5a and P5b)

The same `install e2e` jobs (every OS and installer shell of the matrix) also run the **real** isolation, restore and
purge, end to end, through `tests/e2e/Invoke-IsolateE2E.ps1`, after the V2 legs and before the uninstall. The pattern is
the V2 one; what differs:

* **CI-only.** `tools/Build-Release.ps1` leaves the harness out of the release archive and refuses an archive that
  contains it; the e2e step `package-excludes-ci-harness` checks the extracted package.
* **Gates.** It loads the *installed* engine into its own process and opens the isolation gate and the purge gate there
  only, in memory. The deletion gate of clean stays closed in it (the purge reads only its own gate); only the child
  that contends for the lock as clean (P5b) opens that gate, in its own memory, and always answers a wrong final phrase,
  so it never deletes. The six installed gates and the SHA-256 of every installed file are checked before and after,
  with `agent-temp verify`.
* **Real parts.** The real mover, the real deleter of the purge, the T1 logs (`atm.isolatelog/1`, `atm.purgelog/1`) in
  real files, the manifests, the real B8 lock name, the real revalidation, and the **real quarantine of each account**
  (`%LOCALAPPDATA%\AgentTempManager\Q`, never the suite's seam). The only seam is the console observation
  (`TEST_SEAM`): every confirmation is automated by the harness, never a human acceptance. The entries stay in the VM's
  quarantine as the trail.
* **Containment.** As V2: a run root created atomically with a protected DACL, the run's nonce in each planted root,
  every entry checked before isolate is called and again by the plan presenter before any question. The restore's
  destination must be under the run's base and the purge takes only entries created in that run.
* **One scope per case.** The restore refuses when a sibling of its destination is `RECENT` or `ACTIVE_EVIDENCE`, so
  each case plants its root in a scope of its own. Recency is simulated (120 hours, recorded as `recencySimulated`).
* **Cases, in both legs** (A: the standard user, B1 restricted exception with `-AcceptB1ResidualRisk`; B: elevated):
  * the whole base and a scope directory: refused (`NENHUM_CAMINHO_ISOLAVEL` with `ISOLAMENTO_BASE_NAO_LIBERADA_0_3X` /
    `ISOLAMENTO_ESCOPO_NAO_LIBERADO_0_3X`, J-ISO-9 a); no question, no log, the quarantine unchanged;
  * leg A only: without `-AcceptB1ResidualRisk`, refused by B1;
  * one session root isolated by the real mover: the log (`run-start, plan, confirmation, plan-check, move-intent,
    move-result, run-end`) and the manifest (`entry, move-intent, move-result`) read back from their files, the entry
    `ISOLATED`, the original path gone, the lock `BUSY` from another process during the run and free after it;
  * restore to the free original path: the tree identical by SHA-256, size and write time; the entry `RESTORED`;
  * restore on a conflict (the original path recreated after the isolation): the engine's alternative
    `<name>.restored-<id8>` with its own phrase; the recreated path unchanged (nothing overwritten or merged, T-ISO-8);
  * purge of one entry after the purge's own declarations: the payload gone, the entry and manifest kept, `PURGED`;
  * snapshots: the run root (only the purged root, the scopes a case changed and checked itself, and the run's logs may
    differ) and the quarantine's area (only the run's entries may appear); the temp folder reported as in V2.
* **Leg B** isolates only when the process coverage measured in that run is complete; otherwise the isolate, restore
  and purge cases are `NAO_TESTADO`, never forced. The refusals run in both legs.
* **Process churn.** A refusal before the mover caused by new processes of the runner (`PLAN_CHANGED_BEFORE_EXECUTION`
  or `REVALIDATION_REFUSED`, new uninspectable identities) is retried up to 3 fresh runs; if every attempt is refused
  that way, the case is `NAO_TESTADO` with the identities that explain it. An unexplained refusal fails.
* **Evidence.** Only the harness summary is uploaded (codes, counts and labels; no path, account name or SID), through
  the artifact sanitizer. The raw logs stay in the run root and the manifests in the quarantine.
* **Section 6.1 (rename with an open handle inside the tree)** is measured on every image (Windows Server 2022 and
  2025, Windows 11 ARM64), in both legs, by the harness itself (`measure-6.1-rename-open-handle`, recorded as
  `section61` in its summary): the installed mover on trees of the run root outside the base, with nothing open, a
  file open exclusively, a file open with full sharing, and a process (ending by itself) whose working directory is
  inside. The step `iso-p1-rename-with-open-handles` keeps measuring the same in the installer's shell.
* **Adversarial cases and scale (P5b), leg A** (leg B: `NAO_TESTADO` while its coverage is incomplete, never forced).
  The windows inside the flow use the engine's existing mover seam with a wrapper that calls the **real** mover with
  exactly the engine's arguments, plus the attack (no new seam in the product):
  * a file held (no sharing) by another process of the harness before the plan: the in-use probe sees it and removes
    the B1 exception, so the root is refused (`NENHUM_CAMINHO_ISOLAVEL`); no question, no log. Leg B is `NAO_TESTADO`
    by design: B1 refuses before the probe there;
  * a file held open (full sharing) by another process of the harness between the revalidation and the mover: the real
    mover refuses, `STOPPED_AFTER_REFUSED`, the entry `FAILED` with no payload, the root identical;
  * an interruption: the harness started again as a child isolates a root and ends by itself right after the real mover
    (`Environment.Exit`, never a forced termination): the log ends at `move-intent`, the entry is `INCOMPLETE` with the
    payload present and the original absent; the restore reconciles it first (`reconcile`, T-ISO-5) and brings the tree
    back identical (`RESTORED`). Up to 3 children when one is refused before the mover by process churn;
  * concurrency, both orders, with the real lock name: isolate holding the lock at its final phrase while a child runs a
    complete clean (`CLEAN_LOCK_BUSY` at once, no log); a child clean holding the lock at its final phrase while isolate
    runs (`CLEAN_LOCK_BUSY` at once, no inventory, no log, no entry). Each holder is then given a wrong phrase: nothing is
    moved or deleted;
  * a junction swapped in for the root (to a sentinel outside the base) between the revalidation and the mover: the real
    mover refuses, nothing is moved through the junction; the sentinel, the junction and the root (renamed aside) are
    unchanged;
  * another fixed volume: a base planted on the runner's second fixed volume (the user environment pointed at it for
    that case only). Since ISO-FIX-VOL the plan must refuse it (`MOVE_OTHER_VOLUME`, `NENHUM_CAMINHO_ISOLAVEL`): no
    question, no log, no entry, the root and the volume identical. A refusal by the mover (`OTHER_VOLUME`, the second
    barrier) fails the case. No second fixed volume, or one this account cannot write to: `NAO_TESTADO`;
  * 200,000 files (one root of 200 folders of 1,000 one-byte files), in **one x64 job only** (windows-2025, installer
    pwsh, `ATM_E2E_HEAVY`): the plant, the isolation and the restore timed (`heavy` in the summary), the statistics
    identical before and after. The case must end within 35 minutes of the harness start, so the job keeps room for its
    later steps: the plant stops early, and the isolation and the restore start only when their projection (from a
    measured inventory of the root) fits; otherwise `NAO_TESTADO` with the partial timings. One attempt only (process
    churn there is `NAO_TESTADO`). The other jobs report it `NAO_TESTADO` by design.
* **Not tested here.** The CLI and the TUI past the gates (opening them there would mean changing the installed copy);
  isolation without the B1 exception in leg A (a standard user's coverage is incomplete); UAC prompts and filtered
  tokens (the runners have UAC disabled).

## Future: isolation, quarantine and Recovery Mode (0.3.x and V0.4)

Criteria proposed by [ADR-0013](adr/ADR-0013-isolation-quarantine-recovery-mode.md) for accepting an implementation.
The rows about another user's profile apply to V0.4 (Recovery Mode); every other row applies from 0.3.x (own profile,
ISO-D1). Nothing here runs today. Destructive cases run **only** on disposable VMs, through the pattern of the V2/V3 harness:
CI-only, never shipped, planted targets under a run root with a nonce, the installed copy's gates checked by SHA-256,
only a sanitized summary uploaded. They never run on a real profile. The cross-profile rows that need a real second
administrator or a real sign-in belong to the operator, like the V4 rows.

| Area | Cases |
|---|---|
| Scale | 200,000 files in one target (the suite's scale fixture); time and managed memory bounded; counts, bytes and newest write equal before and after the move |
| Shells and identities | Windows PowerShell 5.1 and PowerShell 7; Windows 10 and 11; standard user, elevated administrator, administrator acting on **another** profile (the VM's second account) |
| Paths | long paths (beyond `MAX_PATH`); Unicode (Latin and CJK), spaces, apostrophe; traversal, relative, UNC and device paths refused; a profile, TEMP root, drive root or `%WINDIR%\Temp` as a target refused |
| Reparse points | junction, directory symlink and file symlink as the target, inside it and in an ancestor: refused, never followed; a swap between the plan and the move refused |
| In use | a locked file, an open directory and a process working directory inside the target: the move refuses or fails cleanly, the target stays in place, nothing is partially moved |
| Activity | a live agent session; recent activity; an interactive session of the target user; a process of that user, elevated or not; development processes (an editor, a build, Git) holding the target; a loaded profile with no visible session: refused, or the loaded state confirmed explicitly, as ADR-0013 section 10 says |
| Ownership and ACL | an owner that cannot be identified; a third-party write ACE; a restrictive ACL that denies the acting account (refused, never taken over); the quarantine folder's DACL verified after creation; no existing ACL or owner changed (before/after comparison) |
| Destination | an existing destination name refused; insufficient free space refused before anything moves; another volume refused; a non-NTFS or removable volume refused |
| Interruption and concurrency | the process ends after the `intent` record (the entry reported incomplete, never restorable as complete); a second isolation, or a clean, while the lock is held (`BUSY`); the same isolation repeated (idempotent refusal, no second move) |
| Integrity | a change inside the target between the plan and the move refuses; the manifest compared with the content after the move; a damaged manifest or entry reported as failed |
| Restore | to a free original location; with a conflict (the base or root recreated by a new session) refused by default and the conflicts listed; to another free location; a partial restore reported exactly; old and new sessions never mixed |
| Quarantine management | list, inspect and verify are read-only (byte and timestamp identical); expired, abandoned and incomplete entries reported; a quota refuses new isolations; purge confirmed by default, refused while its own purge gate is closed (0.3.x P4: J-ISO-1 (C), independent of the deletion gate), one entry per run with its own confirmation |
| Automatic purge (opt-in, ISO-D4) | off by default and shown as off; once enabled by an administrator, shown in `version` and the reports; purges only expired entries whose manifest verifies in the same run; skips incomplete, abandoned, damaged and unexpired entries; never touches the active environment; each purge logged; any failure skips the entry (fail closed); nothing purged while the purge gate is closed (J-ISO-1 (C)) |
| Isolation as the default (ISO-D5) | isolation offered as the default action; direct deletion only through the unchanged V0.3 flow with its own confirmation |
| Worktrees and evidence | a Git worktree or a folder of preserved evidence inside a target: reported, and the target refused unless the person names it explicitly |
| Privacy | manifest and summary without file names, contents, command lines, account names or SIDs; exports pseudonymized (ADR-0010); the artifact sanitizer and the privacy scanner pass |
| Layering | presentation never moves or deletes; only the isolation engine moves, and only the clean engine's deleter deletes (purge) |
