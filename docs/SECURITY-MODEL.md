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
* **Process coverage**: protected processes remain uninspectable even for administrators.
* **Allocation** is an estimate (cluster rounding; MFT-resident files overestimated).
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
* Every installed run first checks every file listed in `manifest.json` (SHA-256) and refuses to start if
  anything differs or if a provider file is not listed; only listed providers are loaded. An installation
  without its precompiled DLL refuses to compile at run time.
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
