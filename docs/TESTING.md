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
| Installer | copy + manifest + verify, tamper detection, ACL audit, refusal without elevation, launcher exit codes; `verify` warns (`WARN`, relative name, exit code unchanged) about unlisted files in `lib`, the root, `config`, a new folder, a hidden file, the policy outside the manifest (with its hint) and a reparse point, never followed (F14-VERIFY-WARN) |
| Security review regressions | rename/junction swap of subdirectory, scope and base during deletion is impossible (with a no-pin control), pre-existing redirection refused, third-party write ACL on base blocks, `%WINDIR%\Temp` shared, unexpected `procStart` never means "ended", drill-down/output path validation, no command-line fragments in evidence |
| Native assembly | installer-compiled DLL loads only with matching manifest hash (5.1 and 7); tampered DLL refused |
| I18n | catalog parity and identical placeholders; every used key translated; language resolution and safe fallback; en-US audit/preview/plan/TUI with no pt-BR text; identical engine codes across languages; CLI `-Lang`/`ATM_LANG`; ASCII transliteration |
| Clean environment | Windows Sandbox configuration generator (valid `.wsb`, networking disabled, release read-only); the in-sandbox script itself needs an administrator-enabled Windows Sandbox or VM (`NAO_TESTADO` on this machine) |
| Scale | 200,000 files in one root, bounded managed memory |
| Privacy | scanner self-test with planted data; working tree and Git index free of SIDs, e-mails, user paths, tokens, machine/user names and private identifiers; only `dist/` ignored |
| V5 tools | the read-only evidence tools of the V5 pilot (`tools/v5-pilot/`, ADR-0015): snapshot, compare and summary on synthetic sandbox folders, T1 logs and isolate, restore and purge logs (see [V5 pilot evidence tools](#v5-pilot-evidence-tools-in-the-suite-v5-tools)) |
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
rollback, tamper detection (exit 5) and repair, an unlisted file in `lib\` shown by `verify` as `WARN` with exit 0
and gone once moved out, a real standard user (created only in the VM) running audit, preview
and verify without write access to the install directory, uninstall (directory and PATH entry removed). Evidence is
uploaded as artifacts.

Then each published version is installed and taken through the same cycle on every OS and installer shell: 0.1.0,
0.1.1, 0.2.0 and 0.3.0, the latest published version. Each package is the asset of its GitHub Release, accepted only with the
SHA-256 published in that release's `SHA256SUMS.txt`, pinned in the script. The cycle is:

1. install the published version and check `version` and `verify`;
2. update to the package under test (`-Update`) and check `version` and `verify`, the older copy kept as `.previous`,
   and the seven installed gates `$false` (deletion, worktree diagnostics, handle diagnostics, diagnose export and, since
   0.3.x, isolation (phase P2) and purge (phase P4), and since V0.2.1 P1 the desktop GUI); the `shipped-purge-gate` step also checks that no policy file is
   installed, that `version` shows the purge gate disabled and the default policy, and that `quarantine purge` of an
   entry that does not exist only plans (exit code `3`, no quarantine created);
3. roll back and check the published version again;
4. update again;
5. uninstall: the directories and the PATH entry are removed.

The 0.2.0 and 0.3.0 cycles also check the installed manifest's version at each step. The 0.3.0 cycle also checks the
four 0.3.0 gates `$false` once 0.3.0 is installed and after the rollback. A download that fails is `NAO_TESTADO`,
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
  * the six gates of the engine and the report (the GUI's seventh gate has its own case, under the desktop GUI below):
    one assignment to `$false` each; the purge gate checked by the build, the e2e and `version`;
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
    `autoPurge: true` read and warned (`AUTOPURGE_ON`; list, inspect and verify never purge); the free-space minimum
    fixed in code;
  * the policy preserved byte for byte by `-Update` (in the new manifest; `verify` passes), an invalid one too, and
    `version` of the installed copy showing it;
  * the CLI in a child process with the gate closed; the TUI headless in both languages (`EXPIRED`, `PURGED`, the
    policy, the purge command; it never purges);
  * static checks:
    * the deleter has one product call in clean and one in purge, after the gate stop and the intent;
    * the report, the TUI and the launcher never call the deleter, and only the launcher calls the purge, once;
    * `autoPurge` is read only by the policy and by the automatic pass, and shown by the report;
    * the clock seam is a single `$null` assignment.
* Automatic purge entry point (0.3.x P6a, area `Isolamento P6a`). Each in-process case uses a quarantine of its own in
  the sandbox and the clock seam; the purge gate opens only around each call:
  * the policy missing, invalid or off: `AUTOPURGE_OFF`, one status line, no lock (another process holds it), no log
    folder, the `EXPIRED` entry identical;
  * on, past the gate: before expiry nothing is purged (`STATE_ISOLATED`); once expired only the `EXPIRED` entry whose
    verify is `OK` is purged through the real deleter; `DIFFERS`, `FAILED`, `INCOMPLETE`, `ABANDONED`, `UNRECOGNIZED`
    and `FUTURE_DATE` (a manifest record and an entry id dated after the clock) are skipped with their reason and stay
    identical; `purge-intent` and `purge-result` carry `automatic: true` and `declaredBy: AUTOMATIC_POLICY` in the
    manifest and in the new log (`atm.autopurgelog/1`, outside the quarantine, no file names); a 7-day retention (the
    minimum) is accepted;
  * the purge gate closed: report only (`WOULD_PURGE`), no lock, no log, no log folder, the quarantine identical;
  * limits: a 5-day retention refused before the quarantine is read; the clean lock busy (`CLEAN_LOCK_BUSY`, nothing
    purged, no log); a plan changed before the deleter skipped (`REVALIDATION_REFUSED`), a deleter refusal skipped and
    the pass going on, an exception stopping the pass (the rest `NOT_REACHED`); the lock free afterwards;
  * the notice in both languages: on, the policy lines and every report say `AUTOMATIC PURGE ON`; off, invalid or
    missing, nothing;
  * the entry point in child processes on a staged copy with a manifest (never where it would read the runner's own
    quarantine): an argument (exit 2); no manifest, a library or the entry point itself changed, an unlisted provider
    (exit 5); the policy missing, invalid or off (exit 0, one status line, nothing created); a 5-day retention (exit 3);
    `version` and `diagnose` of the copy with `autoPurge: true` showing the notice;
  * static checks: only the entry point calls the pass, and the CLI and the TUI never do; the entry point has no
    parameter block, refuses arguments first and checks the manifest before loading, is ASCII only and never calls the
    deleter; the pass has no reader, presenter or phrase; one deleter reference in the engine; the minimum fixed in
    code; every report function shows the notice; the texts in both languages; the installer and the build require
    the entry point.
* Install e2e step `installed-autopurge-entry-point`: the installed entry point is in the manifest; with no policy it
  exits 0 with one status line and creates nothing; an argument exits 2; the installer created no scheduled task.
* The user's scheduled task of the automatic purge (0.3.x P6b, area `Isolamento P6b`). **A real task is created only
  in CI**, on the disposable runner, always with a name marked as a test (`AutoPurgeTest-<8 hex>`, the only name the
  engine accepts in place of the product's) and removed by the case; anywhere else that case is `NAO_TESTADO`. The
  suite's elevated process reaches the rest of `schedule-autopurge` only through a test seam for the token:
  * static: the Task Scheduler is reached only through `Connect-AtmTaskScheduler`; `RegisterTaskDefinition`,
    `DeleteTask`, `CreateFolder` and `NewTask` appear once each, in their functions; registering is called only by
    `schedule-autopurge` and removing only by `unschedule-autopurge`, both only from the CLI's two subcommands; the TUI,
    the reports, the entry point and the uninstall never change the scheduler; the definition (interactive, limited,
    `TASK_CREATE`, no password), the order of the refusals, the single-assignment seams, the same folder and name rule
    in the engine and the uninstall, the texts in both languages and the `Write-Host` exception of the entry point;
  * the definition, built and never registered (its XML): the SID as the user, `InteractiveToken`, `LeastPrivilege`,
    no password, daily at 12:00 local time with up to 1 hour of random delay, the first run in the future with no time
    zone, `StartWhenAvailable`, on battery too, one instance, a 2-hour limit, one exact action; the name rule; the
    token rule (elevated, full, high or unknown refused; standard and filtered accepted); the exact match, with each
    divergence and its reason;
  * refusals before anything is asked or registered: the real elevated token of CI and the seam's variants, a copy
    that is not installed, no presenter, no console, a wrong phrase (policy off and on), unschedule with no task; the
    CLI in child processes (schedule: exit 3 with nothing asked; unschedule without a console: exit 6; `version` and
    `help`);
  * the real task (CI only): created with the policy on (only the main phrase) and read back as the process user,
    interactive, limited, no password, the exact action, the first run in the future and never run; a second
    `schedule-autopurge` refused with nothing asked or changed, and `TASK_CREATE` refusing to overwrite; a wrong
    unschedule phrase removes nothing; unschedule removes it and the folder stays; with the policy off, the warning's
    phrase and then the main one; a task whose action the test changed is `DIVERGENT` and is refused by unschedule with
    nothing asked or touched;
  * the TUI headless in both languages: with `autoPurge: true` the notice is under the header of every frame (menu,
    dashboard, help, quarantine, busy); the quarantine area shows the task's state, read once when the area opens
    (through a test reader); without the policy, no notice.
* Install e2e, P6b steps:
  * `autopurge-task-elevated-refused`: the installer created no scheduler folder; `schedule-autopurge` in the elevated
    shell exits 3 (`AUTOPURGE_TASK_REQUIRES_STANDARD_TOKEN`) with nothing asked or created; `unschedule-autopurge`
    without a console exits 6; `version` and `quarantine list` show no task;
  * `autopurge-task-standard-user`: as the real standard user of the VM, the installed engine registers that user's
    task (a test name) and creates the product's folder; read back, it is that user's, interactive, limited, with no
    password, the exact action and the first run in the future; a second registration is refused; the engine removes
    it. The helper writes only booleans and codes;
  * `autopurge-task-before-uninstall` and `autopurge-task-after-uninstall`: this account's task (the product's name)
    is registered by the installed engine and `version` shows it; the uninstall warns about it and keeps it; its own
    action, run as registered once the installation is gone, exits non-zero with nothing created (fail closed); the
    harness then removes it.

## Desktop GUI in the suite (V0.2.1 phases P1 to P6)

The suite areas `GUI P1`, `GUI P2`, `GUI P3`, `GUI P4a`, `GUI P4b`, `GUI P5` and `GUI P6` cover `agent-temp gui` ([ADR-0014](adr/ADR-0014-desktop-gui-winforms.md)). None
of their cases opens a window in a shipped copy: the gate stays closed in every file, and the cases that go past it open
it only in their own process memory.

`GUI P1`, the skeleton:

| Case | What it checks |
|---|---|
| Seventh gate | all seven gates are a single `$false` assignment in `src/lib`; the GUI gate is closed in the suite's process and assigned nowhere else; exit codes 7 and 8; the build's gate list, the install e2e table and the installer's file list name it; the manifest lists both GUI files; the launcher's `version` shows the gate disabled in en-US and pt-BR |
| Gate closed | `agent-temp gui` exits with code 7 and the bilingual `GUI_GATE_CLOSED` message, by `-Lang` and (since P6) by `ATM_LANG` alone, with `-Lang` winning over `ATM_LANG`; a new process that loads the libraries and runs `version` and `gui` has no Windows Forms assembly loaded before or after |
| Simulated environment | through test seams, in the suite's process: the closed gate returns 7 before any environment check; a multithreaded apartment (`GUI_NOT_STA`), no interactive desktop (`GUI_NO_INTERACTIVE_DESKTOP`) and a failing assembly load (`GUI_WINFORMS_UNAVAILABLE`, no exception text) each return 8 |
| Identity header | elevated, non-elevated and unreadable identities give the right title, identity and elevation lines (PRIV-10), with no exception text |
| Closed list | a static check of `src/lib/Gui*.ps1`: load-time statements are function definitions and constant assignments only; no class, `using` or load-time assembly; every command is one of the files' own functions or the allowed engine and catalog functions (P2 added exactly eight); no deletion, move, write, process, task or clipboard API (ADR-0014 section 3) and no other feature's gate. Seventeen planted violations in temporary copies are each detected (P2 added a quarantine function of the report, P3 the CLI path drill-down, P4a an engine helper outside the list, and P4b another JSON export of the engine, a read of a TUI table and the JSON reader outside its one place); the real files are unchanged |
| GUI-D7 measurement | prints the edition, the thread's apartment, the environment check and whether Windows Forms loads. On Windows PowerShell it requires STA and a loaded assembly; on PowerShell 7 it only records the result (ADR-0014, P1 record) |

`GUI P2`, the dashboard. The dubbed inventories are:
* complete: a RECENT root and an ORPHAN_SUSPECTED one;
* partial: an uninspectable process;
* denied: a second profile whose base is owned by Administrators, dubbed through the owner seam, with no ACL change;
* unknown: before the first audit.

| Case | What it checks |
|---|---|
| View models | no window, en-US and pt-BR, the four inventories: the four groups of the TUI and the classes in its order; the counts; the state words (`CURRENT` with the UTC time, `PARTIAL`, `UNKNOWN`); before an audit every value is the word `UNKNOWN`, and no number appears |
| Parity with the TUI | over the same inventories, each number of the four groups and of each class equals the one `Get-AtmTuiDashboardLines` writes, through the same catalog keys and helpers; the audit time too. The case note carries the table. Unknown: the TUI draws no dashboard before an audit |
| Audit failure | a first failed audit stays `UNKNOWN` with the exception type and no invented number; after a good audit (through the real engine), a failure keeps the earlier result, marked `STALE` with the type and the time of the result shown, never the exception text; the progress keeps only percentages, never the engine's messages; three requests, three audits |
| Automatic purge notice | GUI-D1, en-US and pt-BR: the TUI's line with `autoPurge: true` in a dubbed policy; nothing with the policy off or absent; read once, when the window's session is created; the source never gets a policy |
| Refresh during an audit, close during an audit | two requests while an audit runs are ignored, never queued; a close request between two progress callbacks cancels the audit at the next one, and the earlier result stays; a new audit then works |
| Static (P2) | the closed list has exactly the eight new names; the inventory seam is a single `$null` assignment; no timer, no editable text field, no closure; only labels, lists and buttons on one form, the lists without editing; the inventory arguments equal the launcher's, and the launcher is unchanged; the state keys exist in both languages |
| Real window | Windows PowerShell only, in a job-object process with a timeout, with the inventory source dubbed. The window opens and runs the first audit. It shows the title, the identity, the elevation, the language, `CURRENT` and the dashboard numbers, and `F5` refreshes it once. An `F5` during the audit is ignored. A close request during the next audit cancels it, and the window closes with code 0. The progress label only ever shows the percentage text. Runs in en-US and pt-BR; no child process and no new file is left behind. `NAO_TESTADO` on PowerShell 7 and when no window can be shown |

`GUI P3`, the drill-down. It adds a multi inventory to the P2 ones: two users, four projects (one identified by a
session file, the others by slug only), the four classes, and two roots of the same size, so that the order of ties
is tested.

| Case | What it checks |
|---|---|
| Parity with the TUI | no window, en-US and pt-BR, the complete, partial, denied and multi inventories: users, projects, roots, the roots of each user and of each project, the roots of each class, the detail of every root and the coverage and errors screen. Each screen's lines equal the ones the TUI writes for the same screen, cell by cell, in the same order. The case note carries the table: screen, TUI lines, view-model lines, equal |
| Navigation | the round's walk with no window: dashboard, `2`, `Enter`, `Enter`, `Esc` three times, `9`, `Esc`; every digit key; `Esc` on the dashboard closes; the selected row comes back with `Esc`; keys are ignored during an audit; an inventory read back from a CLIXML export gives the same screens |
| Detail that is gone | after a new audit without the root of the open detail, the window goes back to the list with the catalog text, in en-US and pt-BR; a detail whose root stays is kept; the roots of a user who is gone are an empty list; before the first audit no line is invented |
| Static (P3) | the closed list has exactly the four new names; a planted call to the CLI path drill-down is detected; no timer, no editable text field, no closure; the controls are only labels, lists and buttons; each screen has a button with an accessible name from the catalog; the new keys exist in both languages |
| Real window (P3) | Windows PowerShell only, in a job-object process with a timeout, with the inventory dubbed. The walk dashboard, `2`, `Enter`, `Enter`, `Esc` three times, `9`, `Esc`, the projects button, `Esc`, and `Esc` on the dashboard, which closes the window. Each step checks the screen title, a known line of the screen, the identity and the state. Runs in en-US and pt-BR; no child process and no new file is left behind. `NAO_TESTADO` on PowerShell 7 and when no window can be shown |

`GUI P4a`, the preview of the cleanup (keys `P` and `8`). Over the P3 inventories, the preview is dubbed with rows of
the four categories (`BLOCKED`, `INVESTIGATE`, `ELIGIBLE`, `ELIGIBLE_WITH_DECLARED_RISK`); two roots of the same size are
both `BLOCKED`, so that the order of ties is tested. P3's navigation case now expects `8` to open the blocked paths.

| Case | What it checks |
|---|---|
| Parity with the TUI | no window, en-US and pt-BR, the complete, partial, denied and multi inventories: the rows of `P` and `8` equal the TUI's `gates` rows for the same preview, cell by cell, in the same order (category, then bytes descending); the titles, the columns and the notice; the short label of `ELIGIBLE_WITH_DECLARED_RISK`; `Enter` on every row of `P` opens a detail equal to the TUI's detail lines with one `Preview` line; a detail opened from the roots screen has no `Preview` line and no notice. The case note carries the table: inventory, screen, TUI lines, view-model lines, equal |
| When the preview runs | before the first audit `P` and `8` make no call; the first audit makes none either; the first `P` calls once, then `8`, `Enter` and `Esc` use the kept result; the call gets the session's inventory and the launcher's arguments; the fixed text is set before the call; requests during an audit or a preview are ignored; a new audit discards the result and goes back to the dashboard with the catalog text; a failed audit keeps it; a failed preview shows only the exception type, never its message, and the next opening calls again; the call counts are checked at each step; an inventory and a preview read back from a CLIXML export give the same screens |
| Static (P4a) | the closed list gains no name in P4a (21 names then, 23 since P4b); `Invoke-AtmPreview` appears once in the GUI files, inside `Invoke-AtmGuiPreview`; the preview seam is a single `$null` assignment; no timer, no editable text field, no closure, no cancel button; a planted call to `Test-AtmCandidate`, an engine helper outside the list, is detected; the keys are `1` to `9` and `P` (and `D` since P4b); the form handles `P` in its key handler, defers a close during the preview and shows the notice; the new keys exist in both languages |
| Real window (P4a) | Windows PowerShell only, in a job-object process with a timeout, with the inventory and the preview dubbed. The walk dashboard, `P`, `Enter` (the detail with the `Preview` line), `Esc`, `8`, `Esc`, `F5`, `P` (the preview is called again). The second preview call asks the window to close: the window stays open until the call ends, then closes. Each step checks the screen title, the visible rows, the notice line, the `Preview` line and the audit and preview call counts. Runs in en-US and pt-BR; no child process and no new file is left behind. `NAO_TESTADO` on PowerShell 7 and when no window can be shown |

`GUI P4b`, the diagnostics area (keys `D` and `U`). The diagnose results are dubbed in memory, built from the suite's
diagnose fixtures and read through the schema view, as the window reads them. The dubbed views are: complete; partial
coverage; partial and outdated (a failed refresh); a collector missing; `UNKNOWN` items with a graph reason; an
`AMBIGUOUS` edge; a node with more than 40 edges each way; and the four V0.2 gates closed. Since P4b, the static case of
P1 also refuses a GUI variable that reads one of the TUI's (a planted read of a TUI table), a planted call to another
JSON export of the engine, and `ConvertFrom-Json` outside its one place; P2 to P4a count 23 names in the closed list, and
P4a's keys are `1` to `9`, `P` and `D`.

| Case | What it checks |
|---|---|
| Parity with the TUI | no window, en-US and pt-BR, every dubbed view: every screen of the area (the menu, each category, the detail of every coverage record, finding and node) has the TUI's lines, cell by cell and in the same order, the TUI's columns, the lines above the table and the empty text. The only difference allowed is the gate lines ("disabled in this version"). The CI log prints one line per view and screen, starting `   paridade: `: language, view, screen, TUI lines, GUI lines, gate lines added, equal |
| V0.2 gates | no window, both languages: each of the four gate codes has a "disabled in this version" line with its catalog text, in the summary and in the category it affects; the worktrees category shows the worktree and Git lines; a category with a gate line never shows the text for "none", even when its coverage is conclusive |
| When the diagnose runs | no window: the first `D` runs it once, with the TUI's arguments (the session's inventory arguments with the progress callback); the next `D` uses the kept result; `U` outside the area does nothing; `U` inside runs it again and goes back to the area; navigation reuses the same result, `U` gives a new one; an audit keeps the result; a request during a run is ignored; a close stops the inventory phase and discards the result; a failure with an earlier result marks it outdated with the exception code only; with no earlier result the area does not open; nothing repeats by itself; a result read back from a CLIXML export gives the same export |
| Privacy | no window, both languages: with a dubbed identity and machine name in the result, neither appears in any text of any screen of the area (titles, columns, rows, the lines above the table, gate lines), nor in an outdated result |
| Static (P4b) | the closed list has exactly the two new names (23) and `ConvertFrom-Json` as the fourth allowed cmdlet; `Invoke-AtmDiagnose`, `ConvertTo-AtmDiagnoseJson` and `ConvertFrom-Json` appear in one place only, `Invoke-AtmGuiDiagnose`; planted violations (another JSON export, a read of a TUI table, `ConvertFrom-Json` elsewhere) are refused; the diagnose seam is a single `$null` assignment; no timer, editable text field, closure, cancel button, JSON serializer, `Out-*` or `Export-*`; the GUI's copies of the TUI's tables and of its UTC time format equal the TUI's; keys `D` and `U`; the new keys exist in both languages |
| Real window (P4b) | Windows PowerShell only, in a job-object process with a timeout, with the inventory and the diagnose dubbed in that process only. The walk `D`, `Enter` on the summary, `Esc`, the worktrees category (with its "disabled in this version" line), `Enter`, `Esc`, `U` (the diagnose is called again), `F5`, `D` (no new call), then close. Each step checks the title, a known line, the lines above the table, that `U` is enabled only inside the area, and the call counts; the result's identity and machine name appear in no control. Runs in en-US and pt-BR; no child process, timer or file is left behind in the sandbox, the configuration or the TEMP folder. `NAO_TESTADO` on PowerShell 7 and when no window can be shown |

The read-only case (sandbox identical in names, sizes, times and attributes) also runs a GUI session, with no window,
that audits the sandbox three times through the real engine and walks the new screens between the audits: users, a
user's roots and a detail; projects, a project's roots and a detail; coverage and errors, then roots and a detail.
Since P4a it also opens `P`, `8` and `P` again with the real preview engine (one call, then the kept result), opens the
detail of a preview row, and checks the sandbox is still identical. Since P4b it also opens `D` twice with the real
diagnose engine (one run, then the kept result), checks the worktree and handle gate lines, walks every category of the
area with `Enter` on its first row, and checks the sandbox is still identical. Since P5 it also turns the live
monitoring on and runs two due ticks with the real inventory (only the clock is dubbed): two audits, the area's screen
stays, no new diagnose, and the sandbox is still identical.

`GUI P5`, the live monitoring. The decision of each tick is `Invoke-AtmGuiTick`, tested with no window over a dubbed
UTC clock (`$script:AtmGuiClockSource`) and a dubbed inventory that advances the clock by the audit's duration. Since
P5, the timer checks of P1 to P4b accept only the live monitoring's one ticker (they read the files without its single
creation), the static check of P1 refuses any other timer, job, runspace or event subscription, and the audit failure
pins of P2 expect the exception code.

| Case | What it checks |
|---|---|
| Intervals and turning on | no window: only the six values (30 s to 15 min), 60 s when the window opens, any other value refused with nothing changed; off when the window opens; turning on calls nothing; `SKIPPED_NOT_DUE` before the due time with no call, also within 500 ms of it; at the due time one audit, also before the first audit, and `CURRENT`; a wake up to 500 ms early counts; a new interval starts the count from that moment; turning off stops it; the status line in en-US and pt-BR |
| Tick during another call | no window, always at the due time: a tick fired from inside the progress callback of the dubbed inventory (during an `F5` audit and during a tick's own audit), from inside the dubbed preview source and from inside the progress callback of the dubbed diagnose returns `SKIPPED_BUSY` and calls nothing; nothing is queued: the next due tick audits once and the one after it is not due |
| Limits | no window, both languages: an audit slower than half the interval marks `STALE` (slow, with its duration) and the next tick waits max(interval, 2 x duration) from its end, with `SKIPPED_BACKOFF` before; exactly half is not slow; a good, fast cycle clears both; more than twice the interval with no good audit marks `STALE` (old) with the time, only with the monitoring on, evaluated on every tick; a failure keeps the result and its lines, marks `STALE` with the exception code only (never the message), and the next tick tries again; `F5` with the monitoring off is never slow |
| Screens | no window: the tick never calls the diagnose, and the result of `D` stays the same object, never outdated, even after a failed tick; the screen stays (the diagnostics area, a project's roots); a detail whose root is gone goes back to its list with the catalog text; a gone user's roots are an empty list; on `P`, `8` or a detail opened from them, the tick computes the preview again and its time counts in the duration (a slow preview makes it slow); on another screen the kept preview is discarded; `F5` on `P` or `8` goes back to the dashboard (P4a), on a project's roots it stays |
| Memory | no window: 20 due ticks, each audit returning a new dubbed inventory with 1 MB of ballast, measured with `[GC]::GetTotalMemory($true)`; the first inventory is collected (a weak reference), and the growth from the first to the twentieth audit stays under the declared limit; the case note carries the numbers |
| Static (P5) | no new name in the closed list (23) and no new cmdlet; exactly one `System.Windows.Forms.Timer`, created in `Start-AtmGui`, and the word timer nowhere else in the GUI files; the clock seam and the 500 ms tolerance are single assignments; `Invoke-AtmGuiTick` names no diagnose function and audits through `Invoke-AtmGuiRefresh`, the `F5` path; one ticker handler; the interval is a `DropDownList`, with no editable text field; the close stops and releases the ticker. Planted and refused, in copies: a second Forms timer, `System.Timers.Timer`, `System.Threading.Timer`, a timer type, `Register-ObjectEvent`, `Start-Job`, `Start-ThreadJob`, `[runspacefactory]`, and each diagnose function inside a function named `Invoke-AtmGuiTick`. The check box's access key `M` collides with no other, and the new keys exist in both languages |
| Real window (P5) | Windows PowerShell only, in a job-object process with a timeout, with the inventory, the diagnose and the clock dubbed in that process only; the ticker's handler is called directly. When the window opens (read during its first audit): `UNKNOWN`, the box unchecked, the list at 60 s with the six values, `DropDownList`, off. Then: the ticker stopped; on: 60000 ms and no audit; 30 s: 30000 ms; a due tick: one audit, `CURRENT`; a project opened and a tick: the same screen; a tick with the inventory failing: `STALE` with the code and the earlier lines; a tick from inside an `F5` audit's callback and from inside a dubbed diagnose: `SKIPPED_BUSY`; the clock before the due time: `SKIPPED_NOT_DUE`, no call; off: the ticker stopped; close: the ticker released, a tick after it does nothing, exit 0. Runs in en-US and pt-BR; no child process, timer or file is left behind. `NAO_TESTADO` on PowerShell 7 and when no window can be shown |

`GUI P6`, languages, accessibility and the close end to end. The window cases run in a job-object process with a
timeout, the gate opened only in that process and the inventory, preview, diagnose and clock dubbed; keys reach the
window as Windows delivers them (`PreProcessMessage`, then the window procedure; `WM_SYSCHAR` for the access keys).

| Case | What it checks |
|---|---|
| Catalog | no window: every `gui.*` key exists in en-US and pt-BR, not empty, with the same `{n}` placeholders; the keys whose value is the same in both languages are exactly the 12 declared in the test (formats with no word of their own, units, the product's name and the TUI's terms `gui.term.*`); every `gui.*` key the GUI files name exists in both catalogs |
| DPI scale | no window: `Get-AtmGuiScaled` gives pixels × DPI / 96 at 96, 120, 144 and 192 for every fixed width of the window, rounded half away from zero; an unknown DPI counts as 96 |
| Visible texts | no window, both languages: the header, the states, the monitoring lines, the buttons, the intervals, the dashboard groups and every screen (titles, columns, lines above the table, field labels, notes, notices and messages) match a value of that language's catalog, formatted values included, and contain no piece of the other language's; engine codes and numbers are the only allowed data. A planted literal and a planted text of the other language are refused |
| Static (P6) | no new name in the closed list (23) and no new cmdlet; the real files have no fixed color and no visible literal; every column width and list size goes through `Get-AtmGuiScaled`; `AutoScaleMode` is `Dpi`; the DPI comes from the form; `Enter` on a focused button presses it; the list gets the focus through `ActiveControl`. Planted and refused, in copies: a named `Color`, `FromArgb`, a `BackColor` outside `SystemColors`, `$b.Text = 'Refresh'`, a literal `AccessibleName`, a label with a literal text, a column with a literal header. Accepted: system colors and an empty text |
| Real window (P6) | Windows PowerShell only, both languages. Every `Text`, `AccessibleName`, column header, field label and interval item of the dashboard, users, a detail, coverage and errors, the preview and the diagnostics area comes from the case's catalog and from no other; every control has an accessible name; `TabIndex` is unique in each container and follows the visual order; the `SelectNextControl` sequence is the expected one; the access keys are unique. The keyboard walk: `2`, `Alt+M`, `Enter` on the box (nothing opens), Space twice, `Alt+I`, `Enter` on the interval (nothing opens), the down arrow (2 min), `2` from the interval, `Enter` on rows (roots, detail), `Esc` twice, `3` to `9`, `P`, `1`, `D`, `Enter` and `Esc` in the area, `U`, `Alt+U`, `F5`, the Refresh access key, `Alt+2`, `Enter` on the focused Refresh by the message path and straight to `KeyDown`, Space on it (one audit each, the screen stays), `Enter` on the focused button 3, `Esc`, and the Close access key. The column widths equal `Get-AtmGuiScaled` at the runner's DPI. The case note carries the DPI and the tab order. `NAO_TESTADO` on PowerShell 7 and when no window can be shown |
| Close end to end | Windows PowerShell only: one child process per path and language (12): `Esc` on the dashboard, `Form.Close()`, close during an audit (cancelled at the next callback, then the window closes), during the preview (it finishes, then the window closes), during the diagnose (cancelled at the next callback, no result kept) and with the monitoring on right after a tick that audited. Each: exit 0, the ticker released, a tick an hour later does nothing, no child process, no new file in the sandbox, the configuration or TEMP, no new key or value under `HKCU\Software\AgentTemp*`. The case note carries each child's time and the total. `NAO_TESTADO` on PowerShell 7 and when no window can be shown |

The install e2e adds the step `shipped-gui-gate`: the installed `lib\Gui.ps1` has the single `$false` assignment, both
GUI files are in the manifest, `version` shows the gate disabled, and `agent-temp gui` exits with code 7 in en-US and
pt-BR. The installed gates table has seven rows, in the install e2e and in the real isolation harness.

## Real isolation on disposable VMs (0.3.x ISO-P5a and P5b)

The same `install e2e` jobs (every OS and installer shell of the matrix) also run the **real** isolation, restore and
purge, end to end, through `tests/e2e/Invoke-IsolateE2E.ps1`, after the V2 legs and before the uninstall. The pattern is
the V2 one; what differs:

* **CI-only.** `tools/Build-Release.ps1` leaves the harness out of the release archive and refuses an archive that
  contains it; the e2e step `package-excludes-ci-harness` checks the extracted package.
* **Gates.** It loads the *installed* engine into its own process and opens the isolation gate and the purge gate there
  only, in memory. The deletion gate of clean stays closed in it (the purge reads only its own gate); only the child
  that contends for the lock as clean (P5b) opens that gate, in its own memory, and always answers a wrong final phrase,
  so it never deletes. The seven installed gates and the SHA-256 of every installed file are checked before and after,
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

## V5 pilot evidence tools in the suite (V5-TOOLS)

The three read-only tools of the V5 pilot ([ADR-0015](adr/ADR-0015-v5-pilot-disposable-vm.md), section 6 and its
implementation record), tested in the suite's area `V5 tools`. The pilot itself is not run anywhere, and no gate is
opened. The cases use synthetic folders of the suite's sandbox only. Nothing in them deletes anything: a removal is two
snapshots compared in the reverse order of their creation, or, in the isolation sequence (V5-TOOLS-ISO), a folder
moved inside the sandbox and out of the snapshot's roots. The T1 logs are written by the engine's own
`Write-AtmCleanLogRecord`, with the fields of the records of `Invoke-AtmCleanCore` (`src/lib/Engine.Clean.ps1`). The
isolate, restore and purge logs, and the entries' manifests, are written by its `Write-AtmIsolationRecord`, with the
fields of the records of `Invoke-AtmIsolateCore`, `Invoke-AtmRestoreCore` and `Invoke-AtmPurgeCore`
(`src/lib/Engine.Isolate.ps1`). Only the writer is a stand-in, so the format is the one the engine writes. No isolation
gate is touched.

* **Snapshot** (`Get-AtmPilotSnapshot.ps1`):
  * covers files, nested folders, an empty file, a name with accents and one with a space, a junction to a folder
    outside the root, and a file held open with exclusive sharing;
  * the SHA-256 matches `Get-FileHash`, and the size matches the file's;
  * last write and creation times are unchanged after the snapshot. The last access time follows the volume's policy
    and is not asserted;
  * the junction is recorded as `REPARSE_DIR` and never followed: nothing of its target appears;
  * the locked file gets `SHARING_VIOLATION` and no content;
  * entries and the console carry no absolute path.
* **Snapshot refusals**, each with nothing written:
  * `-Out` inside a root, also when the root is given in another letter case with a trailing backslash;
  * an `-Out` that already exists (its content is unchanged);
  * a junction on the path of `-Out`;
  * overlapping roots.
* **Symbolic link to a file:** recorded as `REPARSE_FILE`, with no size and no hash; the target is never read. Without
  the privilege to create the link: `NAO_TESTADO`.
* **Compare** (`Compare-AtmPilotSnapshot.ps1`):
  * no change;
  * only the expected removal (the parent folder may change its last write time only);
  * a removal without `-ExpectedRemoved`, and an expected removal that did not happen;
  * new items expected by exact name, by folder prefix and as a whole root (`R2:\`);
  * an unexpected new item;
  * a changed file;
  * the output keys in order, with no absolute or relative path in the file or on the console;
  * an existing `-Out` refused.
* **Compare roots and refusals:**
  * a root missing in one snapshot is unexpected, except when it is exactly `-ExpectedRemoved` (`R2:`);
  * snapshots of other roots, or with the labels in another order, are refused;
  * an unknown format, a truncated snapshot and an unknown label are refused.
* **Summary** (`Get-AtmPilotSummary.ps1`):
  * **The deleting run.** A `COMPLETE` log plus a compare output gives: the record types in order; `consoleBy`; the
    outcome; the counts; the yes/no answers of ADR-0015, section 6; and `null` for what the log cannot answer.
  * **Nothing private leaks** into the summary: no path, SID, account, run id, plan id or process identity. A finding in
    another file of the same folder does not count.
  * **An F-A refusal.** `REVALIDATION_REFUSED` with `B1_EXCEPTION_NEW_UNINSPECTABLE_PROCESS (2)` gives 2 new identities.
  * **Runs with no log** use `-NoLog`:
    * `CLEAN_LOCK_BUSY`: the engine refuses the lock before any log is opened, so the code and exit code come from the
      console, and the absence of the log file is checked;
    * exit `6`.
  * **Parameter refusals:** a missing log without `-NoLog`; `-NoLog` with no code; an existing `-Out`.
* **Summary, planted values**, each one alone: a path, a SID, the runner's `USERNAME`, an e-mail and a code outside the
  list.
  * Each gives exit `3`, no final output, and one `.REFUSED` file naming the field and the rule broken.
  * The value appears neither in that file nor on the console.
  * A code typed by the operator outside the list is refused the same way.
* **Summary and the privacy scanner:**
  * a private needle found in the summary: exit `4`, the summary kept under its `.REFUSED` name, no final output;
  * a missing needles file and a missing scanner are refused before anything is written.
* **Summary of isolate, restore and purge** (V5-TOOLS-ISO):
  * one `COMPLETE` log of each kind gives `log.kind` (`isolate`, `restore`, `purge`), the record types in order,
    `log.fullRunOrder`, the outcome, and the counts moved, restored or purged;
  * the purge gives `declaredBy` `OPERATOR`, `verifiedByTool` false and `automatic` false;
  * a field that does not apply to the kind is `null`;
  * no entry id, plan id (whole or its 8 characters), digest, path, SID or account in the summary;
  * runs with the gate closed (`ISOLAMENTO_REAL_DESABILITADO`, `EXPURGO_REAL_DESABILITADO`,
    `RESTAURACAO_REAL_DESABILITADA`) use `-NoLog`, and `log.kind` is `null`;
  * a log of the automatic purge (`atm.autopurgelog/1`) and a log of two schemas are refused before anything is
    written.
* **Summary of isolate, restore and purge, planted values**, each one alone, refused with exit `3` and one `.REFUSED`
  file naming the field and the rule:
  * an entry id, of this log or another (`ENTRY_ID`);
  * a plan id (`PLAN_ID`);
  * the 8 characters of this log's plan id or entry id inside a code of an allowed family;
  * a stop code of another kind of log, and a code outside every list;
  * a plan-check reason outside the list;
  * `automatic` true in the purge.
* **Compare, format 2:**
  * a root born between the snapshots is expected only when `-ExpectedNew '<label>:\'` covers it whole; uncovered, or
    covered by a folder of it only, it is unexpected; a root that disappears stays unexpected with `'<label>:\'`;
  * `-ExpectedTouched` accepts only a change of last write time of the named folder (exact, ignoring case, `/` or
    `\`), counted in `touched.expected`; another change of that folder, a child folder whose date changed and a named
    file stay unexpected;
  * an `-ExpectedTouched` that names no folder, or an unknown label, is refused.
* **Isolation sequence of the pilot's run sheet** (I-4, I-6, I-7, E-3): isolate, restore, isolate again, purge, on five
  roots (base, installed copy, checkout, evidence folder and the quarantine, born at I-4). Each compare, with the
  parameters the run sheet uses, gives `onlyExpectedChange`; I-6 without `-ExpectedTouched` does not. Each summary of
  the step's log with that compare exits `0`, with the right kind, and holds no id, plan id or path.
* **New process:** snapshot, compare and summary run from the command line (`-File`), with no engine loaded, and give
  exit codes `0`, `1` and `2`.
* **Static:** the three tools contain no gate, test seam, lock name or `Invoke-AtmClean`, and call no function defined in
  `src/lib`. They use no cmdlet or method that deletes, moves, copies or writes:
  * one new file per tool (`CreateNew`);
  * one rename, the summary's, after the scanner;
  * no file redirection (checked on the parsed syntax tree);
  * no network.

  `Set-StrictMode`, `Stop` and the exit codes are in each header.
* **Package:** `Build-Release.ps1` copies the whole `tools` folder, and no `$ciOnly` entry is a pilot tool, so
  `tools/v5-pilot/` ships as read-only operator tools. The folder holds exactly the three tools, and the privacy
  scanner finds nothing in them. The `build package` job runs the same scanner on the real staged package.
* **Not tested here:** a real pilot root, a real Claude Code session, a real console, UAC, and the operator's VM (they
  are the pilot itself, ADR-0015); a file symbolic link where the account cannot create one; a real isolation, restore
  or purge, and the real mover's and deleter's effect on the parent folder's dates (the sequence moves folders with
  .NET).

## Service fault signals in the suite (V0.4 R0)

The read-only signals of phase R0 of [ADR-0016](adr/ADR-0016-v04-assisted-recovery.md) (see its R0 implementation
record), tested in the suite's area `V0.4 R0`, in both shells. Service rows, dependencies and the wait before the
second read are injected. No service is started, stopped or changed, and no case sleeps: the wait is a recorded seam.

* **Stopped services:**
  * `STOPPED_CLEAN` (exit 0), `STOPPED_NEVER_STARTED` (1077) and `STOPPED_FAILED` (1066 with its service-specific code,
    and another code);
  * `STOPPED_EXIT_UNREADABLE` for an exit code that is null, text or out of range;
  * a running service gets no condition, and the state of the finding never changes;
  * an unreadable signal gives its `_UNREADABLE` code and `service-properties` `PARTIAL`;
  * a row injected without the signals gives `SERVICE_SIGNALS_NOT_COLLECTED`, with no `PARTIAL`.
* **Pending services, two reads:**
  * `PENDING_PROGRESSING`, `PENDING_STALLED`, `PENDING_UNCHANGED` (a `WaitHint` over the cap, or 0),
    `PENDING_STATE_CHANGED` and `PENDING_SINGLE_READ` (not listed again, checkpoint unreadable);
  * one wait, the largest `WaitHint` capped at 2000 ms (at least 250 ms);
  * the second read asks for the pending names only.
* **No second read:**
  * an injected source without a wait (`NOT_COLLECTED`, nothing waited);
  * a deadline closer than the wait plus one query (`DEADLINE`, nothing waited);
  * a denied or failed read;
  * a duplicate row;
  * an unreadable state.
* **Dependencies:**
  * both directions, each with its state;
  * named only when declared or a system service (an executable or driver under the Windows folder);
  * a third-party, profile or missing service has no name;
  * no dependency at all;
  * denied, failed, related states failed, over the cap, the deadline, and not collected.
* **`ExpectedImage`:**
  * the contract: accepted file names and placeholders; refused drive letters, profile and other variables, `..`, `~`;
    a malformed value makes the provider's hints `FAILED`;
  * `IMAGE_MATCH`, `IMAGE_MISMATCH` and `IMAGE_UNKNOWN`: by name, by full path, a packaged app folder, an unreadable
    executable, two providers that disagree, a placeholder whose folder is not set;
  * `CoworkVMService` declares none (`SERVICE_IMAGE_NOT_DECLARED`).
* **Static:** the services collector calls no control cmdlet, `sc.exe`, `ServiceController`, control method or service
  manager handle. It queries only `Win32_Service`, `Win32_DependentService` and `Win32_BaseService`, the file keeps
  exactly two `Win32_Service` queries, and the only wait is the second read's. The test area itself has no real sleep.
* **Diagnose and privacy:**
  * the seams reach the collector through `Invoke-AtmDiagnose`;
  * the CLI shows the new line;
  * no path or account appears in the new line, in the new evidence details or in the JSON.
* **CI runner, read only:** the real signals and dependencies of `EventLog` and `Winmgmt`, with their states and start
  modes compared before and after. Elsewhere it is `NAO_TESTADO`.
* **Not tested here:**
  * a real pending service, so the real second read runs only with the injected wait;
  * a real denied or failed dependency read;
  * a real failed service;
  * a provider's real `ExpectedImage`, because no shipped provider declares one.

## Assisted recovery in the suite (V0.4 R1 to R6)

Phases R1 to R6 of [ADR-0016](adr/ADR-0016-v04-assisted-recovery.md), each tested in its own area of the suite
(`V0.4 R1` to `V0.4 R6`), in both shells. R6 also runs a CI-only harness in the install e2e, described after the area
list. Each phase's implementation record in the ADR lists every case and what is
not tested. The recovery gate `AtmRecoveryEnabled` is loaded closed. A case that needs it open opens it in the suite's
process only and closes it again. In the in-process cases, providers, identities, service rows and dependencies are
injected. The CLI cases of R1 and R4 run in a new process with every gate closed, and they compare the real
`CoworkVMService` state, when the service exists, before and after. No case starts, stops or opens a real service with
a control right, requests elevation or opens a UAC prompt.

* **`V0.4 R1`: list and plan, read only.**
  * the closed catalog, refusal codes, not-offered line and texts in both languages;
  * the offered case, with its capture, dependencies, undo and elevation from three tokens;
  * one case per `RECOVERY_*` refusal code, with the real `CoworkVMService` declaration among them;
  * the plan id and the privacy of the plan and the list;
  * the closed gate by instrumentation: no prompt, lock, log, file write or CIM query, and no B8 mutex (with a positive
    control);
  * statics: one gate assignment and no service control API outside its allowed places. The diagnose does not call the
    engine. Since R5, the TUI and the GUI call only its three read functions. The launcher loads the engine in exactly
    four blocks: `recover`, `version`, `tui` and `gui`;
  * the CLI in a new process: exit codes, `version` and the help in both languages.
* **`V0.4 R2`: the start, past the gate, through the start seam.**
  * the closed gate by instrumentation, with positive controls for the injected and the default seam;
  * one case per outcome (`COMPLETE`, `PARTIAL`, `FAILED`, `REFUSED`, `EXCEPTION`), each with its diff and its records
    in order;
  * AUT-2 refusals, one revalidation case per captured field, and B8 busy and abandoned;
  * the log's privacy, and `SERVICE_IMAGE_NOT_DECLARED` refused before anything is asked;
  * statics: the start API only in the default seam, and lock, log and console only past the gate.
* **`V0.4 R3`: the undo of one start, past the gate, through the stop seam.**
  * `REC-SVC-STOP` stays outside the catalog;
  * the closed gate by instrumentation;
  * one case per outcome, and one case per source-log failure code;
  * the criteria table, AUT-2, the revalidation, a second undo, B8 and the log's privacy;
  * statics: the stop class in `Native.cs` asks for no other right, and only the default stop seam reaches it.
* **`V0.4 R4`: `recover start` and `recover undo`, with UAC on demand.**
  * the closed gate: plan or request, then exit 27, with nothing asked, locked or logged;
  * the requester and the relaunched copy, with the elevated launcher, the requester evidence, the key and the fixed log
    folder injected;
  * PRIV-4 outcomes 40 to 44, PRIV-5 evidence, PRIV-9 (a second operation exits 30) and the exit code of every engine
    result;
  * the fixed folder's security check, and its creation by the installer (elevated only);
  * the CLI in a new process;
  * statics: the elevation verb appears once in `src`, in the default launcher, which only the command calls.
* **`V0.4 R5`: the read-only view in the TUI and the GUI.**
  * the shared formatters give the CLI's lines of `recover list` and `recover plan`, in order, in both languages:
    offered, refused and undeclared targets, an empty list, and a forged open gate;
  * the headless TUI and the GUI's session and view model:
    * the area and the plans show every line and code;
    * the undeclared name is never listed;
    * there is one collection per entry, and none from moving, `Enter`, `Esc`, a live monitoring tick or `F5`;
    * no service name is typed, and a failure shows its code only;
  * instrumentation: no call to `Invoke-AtmRecover*`, the launcher, the service seams, the log, the lock, a
    confirmation, `Read-Host` or CIM, and no B8 mutex (with positive controls);
  * statics:
    * the GUI's closed list, with five read names, refuses the execution names, `AtmRecoveryEnabled` and a collection
      in the tick (each planted in a copy);
    * a new TUI static covers the same names;
    * each read is called only in its expected place.
* **`V0.4 R6`: the CI-only harness of the real recovery, in the suite.**
  * its refusal path: outside a disposable machine, `Setup`, `A` and `B` refuse and create nothing (no summary, work
    folder, state file, `ATM-E2E-REC-*` root or `AtmRecE2E-*` service);
  * statics on the harness: the recovery gate is opened in its own process memory only, after the installed engine is
    loaded, and nothing from the R4 launcher or elevation is used; every engine call passes `-Providers` and the guard
    wrappers; the default seams are called only inside the wrappers, after the name check; services are touched only
    through one helper that accepts only this run's names; roots are created atomically with a protected DACL; the
    harness stays out of the package; `src` never cites it;
  * the real run is not tested in the suite: it runs only in the install e2e.
* **R6 in the install e2e (CI only, disposable runners).** After the ISO legs, the elevated context runs the harness's
  `Setup`: it compiles an inert service executable (through Windows PowerShell 5.1 `Add-Type`) in a run root it
  creates, and creates seven own services `AtmRecE2E-<nonce>-<key>`, manual or disabled, with the default account.
  Leg A (the VM's standard user) then leg B (elevated) load the installed engine, open the recovery gate in memory only,
  and run `Invoke-AtmRecover` and `Invoke-AtmRecoverUndo` with an in-memory provider and guard wrappers around the
  default seams. Leg B covers the start and its undo, the four refusals before the seam with zero seam calls, the
  dependencies, the undo of leg A's log (provenance), and ends by stopping every own service that is not stopped; none
  is removed. The eight installed gates and the SHA-256 of every installed file are compared before and after. Only a
  summary with codes and counts is uploaded. The measured results per runner and leg are in the ADR's R6 record. In
  the first CI run, all six jobs agreed:
  * leg A got `ACCESS_DENIED` from the real seam, with nothing changed;
  * leg B's refusals before the seam and the provenance across legs held;
  * the services all ended STOPPED, and the installed copy was unchanged;
  * leg B's real start reached the seam, but the harness then failed on its own diff field names. That was fixed in
    the same PR.
* **Not tested here:**
  * the default start and stop seams: never called by the suite; the CI calls them only in the R6 harness, on its own
    services;
  * a real service started or stopped, by any verb, outside the R6 harness's own services: no CI test controls any
    other service, and no shipped provider declares an `ExpectedImage`;
  * the seam's own `DEPENDENT_SERVICES_RUNNING`: R3 refuses an undo while a dependent runs before the seam is called,
    so the R6 harness cannot reach it;
  * the real UAC prompt and relaunch: never called by the suite or the CI;
  * the real verification of the requester (PRIV-5): not implemented, by design;
  * B8 between an elevated and a non-elevated holder: for the VM or the operator's e2e;
  * a real GUI window, or a real console, where `S` collects the real services.

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
