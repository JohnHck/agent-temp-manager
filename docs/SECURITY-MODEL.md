# Security model

## Principles

1. **Read first, delete last.** `audit` and `preview` never create, modify, move, rename or delete anything
   inside audited paths. `preview` opens short-lived handles (no data access) only on eligible candidates
   to detect files in use, and closes them immediately.
2. **Fail closed.** Any error, ambiguity, incomplete measurement or unobservable condition blocks deletion.
3. **No authority from classification.** `ORPHAN_SUSPECTED` is informational; age > 72 h and absence of
   references never prove inactivity.
4. **Human approval of exact paths.** Cleanup requires an explicit allowlist of exact absolute paths, an exact
   plan display and a typed phrase (`APAGAR <N> CAMINHOS`).

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
  them; tree directories are additionally pinned **without `FILE_SHARE_WRITE`**, so an emptied directory
  cannot be opened for writing and converted into a junction in place (share modes are enforced by the kernel
  regardless of the other process's privileges);
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
* Only allow-listed, read-only Git commands are started, with `--no-optional-locks` (the read commands take no lock,
  so there is none to leave behind when one is terminated), every transport refused by name on the command line
  (`protocol.allow=never` plus `protocol.<file|git|ssh|http|https|ext>.allow=never`, which a repository's own setting
  cannot override) and `GIT_NO_LAZY_FETCH=1` (effective from the Git version that supports it; the minimum version is
  fixed when object reads are added in P3-C). The working directory must have no reparse point in its path, so the
  discovery ceiling cannot be bypassed through a junction.
* Known before P3-B uses the runner on real repositories: configuration a repository controls (include paths,
  alternates, a `gitdir:` file) can make Git read UNC paths (SMB, with the user's credentials), and configuration names
  can carry credentials; the runner's output stays in memory. A child running as the same user could in principle
  duplicate the job handle from this process; that requires code running in the child, which the allow-list and D-3
  are there to prevent.
* An elevated run starts `git.exe` only if the file and its directory pass the installer's ACL rule (only SYSTEM,
  Administrators, TrustedInstaller and CREATOR OWNER may own or write them). The check covers the resolved launcher
  (`cmd\git.exe` in Git for Windows); the program it starts is not checked.

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
  observable without debugging privileges (not used).
* **Process coverage**: protected processes remain uninspectable even for administrators. On a real Windows
  installation there are always some (17 on the CI runners), so the coverage gate blocks every candidate: in V0.1
  `clean` stops before the release gate is even reached. Enabling real deletion (V0.3) requires a reviewed decision
  on how known protected system processes are treated; the gate is not relaxed before that.
* **Allocation** is an estimate (cluster rounding; MFT-resident files overestimated).
* **Discovery visibility**: if the `ProfilesDirectory` value of the Windows profile list cannot be resolved, folders
  under it that have no profile-list entry (residual profiles) are not listed and no note says so; if a profile's
  volatile environment cannot be read, `%LOCALAPPDATA%`/`%APPDATA%` fall back to the profile's default folders.
  Deletion stays safe in both cases (only inventoried paths can be candidates), but the audit can under-report.
  Planned for V0.2 diagnostics, with injectable registry sources so it can be tested.
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